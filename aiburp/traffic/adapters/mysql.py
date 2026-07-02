"""
MySQL 协议适配器 - 弱口令 + 信息收集.

MySQL 未授权/弱口令是数据库攻击的标准入口:
    - root 无密码或弱密码 -> UDF 提权 RCE / 数据导出 / 写 webshell
    - 默认端口 3306, 内网常开放
    - MySQL 协议握手包含版本号 + 主机名 + 字符集 (信息泄露)

检测思路:
    - probe():    不带密码连接, 从握手包提取版本/主机名 (无需认证)
    - send():     用指定 credentials 连接
    - check_unauth(): 尝试常见弱口令 (root/admin/mysql + 弱密码)

设计:
    - 组合 pymysql (已安装, 不手写握手协议)
    - pymysql 的异常区分密码错/拒绝/超时 - 用于精确判断
    - 不实现完整 SQL 执行 (那是 exploit 层, adapter 只做检测)
"""

import asyncio
from typing import List, Optional, Tuple

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .fingerprints import split_host_port


# pymysql 异常类型 (延迟导入, 失败时降级)
def _get_pymysql_errors():
    """返回 pymysql 的异常类, 导入失败时用通用 Exception 替代"""
    try:
        import pymysql
        return (
            pymysql.err.OperationalError,
            pymysql.err.InterfaceError,
            pymysql.err.InternalError,
        )
    except ImportError:
        return (ConnectionError, OSError, RuntimeError)


class MysqlAdapter(ProtocolAdapter):
    """
    MySQL 协议适配器 - 弱口令检测 + 版本指纹.

    用法:
        async with MysqlAdapter() as m:
            resp = await m.probe("10.0.0.1:3306")           # 握手拿版本
            resp = await m.check_unauth("10.0.0.1:3306")     # 弱口令爆破
    """

    protocol = "mysql"
    description = "MySQL weak credentials + version fingerprint"

    DEFAULT_PORT = 3306

    # 常见弱用户名
    COMMON_USERS = ["root", "admin", "mysql", "user", "test", "db"]
    # 常见弱密码
    COMMON_PASSWORDS = ["", "root", "password", "123456", "admin", "mysql",
                        "toor", "root123", "pass", "qwerty"]

    def __init__(self, timeout: float = 5.0, concurrency: int = 5,
                 proxy: Optional[str] = None):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False
        self._proxy = proxy

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活: 连接拿握手包 (不需要密码, 服务器先发 Server Greeting).
        提取版本号 + 主机名 + 服务器能力标志.
        """
        if self._closed:
            return self._closed_resp(target)

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        result = await asyncio.to_thread(
            self._probe_sync, host, port, kw.get("timeout", self.timeout)
        )
        return result

    def _probe_sync(self, host: str, port: int, timeout: float) -> TrafficResponse:
        """同步握手探测 (在 to_thread 中运行)"""
        import pymysql
        start_ts = _now_ms()

        try:
            # 连接会触发握手, 即使密码错也能拿到 greeting
            pymysql.connect(
                host=host, port=port,
                user="probe_nonexistent_user_xxx",
                password="x",
                connect_timeout=timeout,
                read_timeout=timeout,
                write_timeout=timeout,
                client_flag=0,
            )
            # 走到这里说明匿名访问成功?! (极端情况)
            conn = pymysql.connect(
                host=host, port=port, user="root", password="",
                connect_timeout=timeout,
            )
            conn.close()
            return TrafficResponse(
                protocol="mysql", ok=True, status=1,
                banner="mysql(anonymous)",
                target=f"{host}:{port}",
                tags=["MYSQL", "UNAUTH-OK", "HIGH-VALUE"],
                anomalies=["anonymous-access", "no-auth-required"],
                time_ms=_elapsed_ms(start_ts),
            )
        except pymysql.err.OperationalError as e:
            # OperationalError 1045 (密码错) - 但我们拿到了 greeting!
            # e.args[0] 是 (code, message) 元组
            code = e.args[0][0] if e.args and isinstance(e.args[0], tuple) else 0
            msg = e.args[0][1] if e.args and isinstance(e.args[0], tuple) else str(e)

            if code == 1045:
                # Access denied - 但握手成功, 从错误消息提取版本
                # 格式: "Access denied for user 'x'@'host' (using password: YES)"
                version = _extract_mysql_version(msg)
                hostname = _extract_hostname(msg)
                banner_parts = []
                if version:
                    banner_parts.append(version)
                if hostname:
                    banner_parts.append(f"host={hostname}")
                return TrafficResponse(
                    protocol="mysql", ok=True, status=1,
                    banner="mysql/" + (";".join(banner_parts) if banner_parts else "unknown"),
                    text=f"MySQL {version}\nHost: {hostname}\nError: {msg[:100]}",
                    target=f"{host}:{port}",
                    tags=["MYSQL"],
                    anomalies=[f"version:{version}" if version else "version:unknown",
                               "handshake-success"],
                    time_ms=_elapsed_ms(start_ts),
                )
            elif code == 1130:
                # Host not allowed to connect - 服务器可达但 ACL 拒绝
                return TrafficResponse(
                    protocol="mysql", ok=True, status=1,
                    banner="mysql(host-blocked)",
                    target=f"{host}:{port}",
                    tags=["MYSQL", "HOST-ACL"],
                    anomalies=["host-not-allowed"],
                    error=str(e)[:100],
                    time_ms=_elapsed_ms(start_ts),
                )
            elif code in (2003, 2002):
                # Can't connect to MySQL server - 不可达
                return TrafficResponse(
                    protocol="mysql", ok=False, status=0,
                    target=f"{host}:{port}",
                    error="mysql-unreachable",
                    time_ms=_elapsed_ms(start_ts),
                )
            else:
                # code=0 通常意味着连接失败但异常结构异常, 视为不可达
                if code == 0:
                    return TrafficResponse(
                        protocol="mysql", ok=False, status=0,
                        target=f"{host}:{port}",
                        error="mysql-unreachable",
                        time_ms=_elapsed_ms(start_ts),
                    )
                return TrafficResponse(
                    protocol="mysql", ok=True, status=1,
                    banner="mysql?",
                    target=f"{host}:{port}",
                    tags=["MYSQL"],
                    error=f"code-{code}",
                    anomalies=[f"error-code:{code}"],
                    time_ms=_elapsed_ms(start_ts),
                )
        except (pymysql.err.InterfaceError, pymysql.err.InternalError, OSError) as e:
            return TrafficResponse(
                protocol="mysql", ok=False, status=0,
                target=f"{host}:{port}",
                error=f"{type(e).__name__}: {str(e)[:80]}",
                time_ms=_elapsed_ms(start_ts),
            )
        except Exception as e:
            return TrafficResponse(
                protocol="mysql", ok=False, status=0,
                target=f"{host}:{port}",
                error=f"{type(e).__name__}: {str(e)[:80]}",
                time_ms=_elapsed_ms(start_ts),
            )

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        用指定 credentials 尝试连接.
        req.meta.user / req.meta.password 指定凭据.
        """
        if self._closed:
            return self._closed_resp(req.target)

        host, port = split_host_port(req.target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        user = req.meta.get("user", "root")
        password = req.meta.get("password", "")

        result = await asyncio.to_thread(
            self._try_login, host, port, user, password,
            kw.get("timeout", self.timeout),
        )
        result.protocol = "mysql"
        result.target = req.target
        result.payload = f"{user}:{password}"
        return result

    def _try_login(self, host: str, port: int, user: str, password: str,
                   timeout: float) -> TrafficResponse:
        """尝试登录"""
        import pymysql
        start_ts = _now_ms()
        try:
            conn = pymysql.connect(
                host=host, port=port,
                user=user, password=password,
                connect_timeout=timeout,
                read_timeout=timeout,
            )
            # 成功! 拿版本信息
            with conn.cursor() as cur:
                cur.execute("SELECT VERSION(), CURRENT_USER(), @@hostname")
                row = cur.fetchone()
                version, current_user, hostname = row if row else ("?", "?", "?")
            conn.close()
            return TrafficResponse(
                protocol="mysql", ok=True, status=1,
                banner=f"mysql/{version}",
                text=f"Version: {version}\nUser: {current_user}\nHost: {hostname}",
                tags=["MYSQL", "LOGIN-SUCCESS"],
                anomalies=[f"version:{version}", f"user:{current_user}",
                           f"host:{hostname}", "weak-credentials"],
                time_ms=_elapsed_ms(start_ts),
            )
        except pymysql.err.OperationalError as e:
            code = e.args[0][0] if e.args and isinstance(e.args[0], tuple) else 0
            return TrafficResponse(
                protocol="mysql", ok=False, status=0,
                error=f"denied(code={code})",
                anomalies=["access-denied"],
                time_ms=_elapsed_ms(start_ts),
            )
        except Exception as e:
            return TrafficResponse(
                protocol="mysql", ok=False, status=0,
                error=f"{type(e).__name__}: {str(e)[:80]}",
                time_ms=_elapsed_ms(start_ts),
            )

    # ============================================================
    #                  check_unauth (弱口令爆破)
    # ============================================================

    async def check_unauth(self, target: str, users: Optional[List[str]] = None,
                           passwords: Optional[List[str]] = None,
                           timeout: Optional[float] = None) -> TrafficResponse:
        """
        一键 MySQL 弱口令检测.

        流程:
            1. 先 probe 拿版本 (确认是 MySQL)
            2. 笛卡尔积尝试常见 user x password 组合
            3. 命中任一 = LOGIN-SUCCESS + HIGH-VALUE
        """
        if self._closed:
            return self._closed_resp(target)

        users = users or self.COMMON_USERS
        passwords = passwords or self.COMMON_PASSWORDS
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        # 1. 先确认可达
        probe_resp = await self.probe(target, timeout=t)
        if not probe_resp.ok:
            return probe_resp  # 不可达

        # 2. 弱口令组合 (优先 root)
        combos = []
        # root 优先 (最常见)
        for pwd in passwords:
            combos.append(("root", pwd))
        # 其它用户
        for u in users:
            if u == "root":
                continue
            for pwd in passwords[:5]:  # 非 root 用户只试前 5 个密码
                combos.append((u, pwd))

        # 3. 逐个尝试 (MySQL 有连接频率限制, 不并发)
        for user, pwd in combos:
            result = await asyncio.to_thread(
                self._try_login, host, port, user, pwd, t
            )
            if result.ok and "LOGIN-SUCCESS" in result.tags:
                result.tags.extend(["UNAUTH-CONFIRMED", "HIGH-VALUE"])
                result.anomalies.extend([
                    f"cracked:{user}:{pwd if pwd else '(empty)'}",
                    "weak-credentials",
                    "rce-possible",  # root + UDF = RCE
                ])
                return result

        # 全部失败
        return TrafficResponse(
            protocol="mysql", ok=True, status=1,
            target=target, banner=probe_resp.banner,
            tags=["MYSQL", "SECURED"],
            anomalies=[f"tried-{len(combos)}-combos", "no-weak-credentials"],
        )

    # ============================================================
    #                       生命周期
    # ============================================================

    def _closed_resp(self, target: str) -> TrafficResponse:
        return TrafficResponse(
            protocol="mysql", ok=False, status=0,
            target=target, error="adapter-closed",
            anomalies=["adapter 已 close"],
        )

    async def close(self):
        self._closed = True


# ============================================================
#                       工具函数
# ============================================================

import time as _time

def _now_ms() -> float:
    return _time.monotonic()

def _elapsed_ms(start: float) -> float:
    return (_time.monotonic() - start) * 1000


def _extract_mysql_version(error_msg: str) -> str:
    """
    从 MySQL Access denied 错误消息提取版本号.

    注意: 错误消息里通常不含版本号 (版本在握手包里, 不在错误文本里).
    只有少数 MySQL 发行版 (如 MariaDB) 会在错误消息末尾带版本.
    必须严格匹配 "MySQL X.Y.Z" 或 "MariaDB X.Y.Z" 模式, 避免把客户端
    IP 地址 (如 10.0.0.5) 误判为版本号.
    """
    import re
    # 严格匹配: 必须有 MySQL/MariaDB 前缀, 后跟版本号
    # 避免匹配 @'10.0.0.5' 里的 IP
    m = re.search(r'(?:MySQL|MariaDB)[-\s]*v?(\d+\.\d+\.\d+[-\w]*)', error_msg, re.I)
    return m.group(1) if m else ""


def _extract_hostname(error_msg: str) -> str:
    """从错误消息提取客户端主机名 (Access denied for user 'x'@'hostname')"""
    import re
    m = re.search(r"@'([^']+)'", error_msg)
    if m:
        return m.group(1)
    # 有些版本用双引号
    m = re.search(r'@"([^"]+)"', error_msg)
    return m.group(1) if m else ""
