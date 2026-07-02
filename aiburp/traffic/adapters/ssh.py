"""
SSH 协议适配器 - 弱口令检测 + 命令执行.

SSH 弱口令是红队横向移动的标准手段:
    - 默认凭据 (msfadmin:msfadmin / root:root / admin:admin)
    - 密码策略弱 (短密码/常见词)
    - V4 之前只能指纹, 不能认证 - 这是最大的缺口

检测思路:
    - probe():    TCP 连接拿 SSH banner (版本指纹)
    - check_weak_creds(): 常见弱口令爆破
    - exec_cmd(): 用已知凭据执行命令 (验证 RCE)

设计:
    - 组合 paramiko (标准 SSH 库)
    - paramiko 是同步库, 用 to_thread 包装
    - check_weak_creds 并发尝试多个凭据
"""

import asyncio
from typing import List, Optional, Tuple

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .fingerprints import split_host_port

try:
    import paramiko
    _PARAMIKO_AVAILABLE = True
except ImportError:
    _PARAMIKO_AVAILABLE = False


# 默认弱口令列表 (Metasploitable + 常见)
DEFAULT_WEAK_CREDS = [
    ("root", "root"), ("root", "toor"), ("root", ""),
    ("msfadmin", "msfadmin"),
    ("admin", "admin"), ("admin", "password"),
    ("user", "user"), ("user", "password"),
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("vagrant", "vagrant"),
    ("postgres", "postgres"),
    ("oracle", "oracle"),
]


class SshAdapter(ProtocolAdapter):
    """
    SSH 协议适配器 - 版本指纹 + 弱口令 + 命令执行.

    用法:
        adapter = SshAdapter(timeout=5)
        resp = await adapter.probe("10.0.0.1:22")          # 拿版本
        resp = await adapter.check_weak_creds("10.0.0.1:22")  # 弱口令爆破
        resp = await adapter.exec_cmd("10.0.0.1:22", "root", "root", "id")  # 执行命令
    """

    protocol = "ssh"
    description = "SSH version + weak credentials + command exec (paramiko)"

    DEFAULT_PORT = 22

    def __init__(self, timeout: float = 5.0, concurrency: int = 3,
                 proxy: Optional[str] = None):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False
        self._proxy = proxy
        # 如果有 SOCKS 代理, 配置 paramiko 的 sock 工厂
        self._sock_factory = None
        if proxy:
            self._setup_socks_proxy(proxy)

    def _setup_socks_proxy(self, proxy_url: str):
        """配置 PySocks 代理"""
        import socks
        from urllib.parse import urlparse
        p = urlparse(proxy_url)
        proxy_type = socks.SOCKS5
        if p.scheme == "socks4":
            proxy_type = socks.SOCKS4
        proxy_host = p.hostname
        proxy_port = p.port or 1080

        def _make_sock():
            s = socks.socksocket()
            s.set_proxy(proxy_type, proxy_host, proxy_port)
            return s

        self._sock_factory = _make_sock

    def _check_closed(self, target: str = "") -> Optional[TrafficResponse]:
        if self._closed:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                target=target, error="adapter-closed",
            )
        return None

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """探活: TCP 连接拿 SSH banner"""
        closed = self._check_closed(target)
        if closed:
            return closed

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=kw.get("timeout", self.timeout),
            )
        except (asyncio.TimeoutError, OSError) as e:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                target=target, error=type(e).__name__,
            )

        try:
            banner_raw = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            banner = banner_raw.decode("utf-8", "replace").strip()

            is_ssh = banner.startswith("SSH-")
            tags = ["SSH", "BRUTEFORCE-TARGET"]
            version = ""
            if is_ssh:
                # SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
                parts = banner.split("-")
                if len(parts) >= 3:
                    version = parts[2]
                # CVE 检测
                if "OpenSSH_6" in banner or "OpenSSH_5" in banner:
                    tags.append("CVE-2016-10009-CHECK")
                if "OpenSSH_6.6" in banner or "OpenSSH_6.7" in banner:
                    tags.append("CVE-2018-15473-CHECK")

            return TrafficResponse(
                protocol="ssh",
                ok=is_ssh,
                status=1 if is_ssh else 0,
                raw=banner_raw,
                text=banner,
                banner=f"ssh/{version}" if version else "",
                target=target,
                tags=tags,
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """send 等同 probe (SSH 是会话协议)"""
        return await self.probe(req.target, **kw)

    # ============================================================
    #              check_weak_creds (弱口令爆破)
    # ============================================================

    async def check_weak_creds(self, target: str,
                                creds: Optional[List[Tuple[str, str]]] = None,
                                timeout: Optional[float] = None) -> TrafficResponse:
        """
        SSH 弱口令检测.

        逐个尝试常见 user:password 组合 (paramiko 同步, 串行).
        命中任一 = 弱口令确认 (HIGH-VALUE).
        """
        closed = self._check_closed(target)
        if closed:
            return closed

        if not _PARAMIKO_AVAILABLE:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                target=target, error="paramiko-not-installed",
            )

        creds = creds or DEFAULT_WEAK_CREDS
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        for user, pwd in creds:
            result = await asyncio.to_thread(
                self._try_login, host, port, user, pwd, t,
            )
            if result.ok:
                result.tags.extend(["WEAK-CREDS", "HIGH-VALUE", "RCE-PATH"])
                result.anomalies.extend([
                    f"cracked:{user}:{pwd}",
                    "ssh-shell-possible",
                ])
                return result

        return TrafficResponse(
            protocol="ssh", ok=True, status=1,
            target=target, banner="ssh(secure)",
            tags=["SSH", "SECURED"],
            anomalies=[f"tried-{len(creds)}-creds", "no-weak-credentials"],
        )

    def _try_login(self, host: str, port: int, user: str, pwd: str,
                   timeout: float) -> TrafficResponse:
        """paramiko 同步登录尝试"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # SOCKS 代理支持
            connect_kw = dict(
                hostname=host, port=port,
                username=user, password=pwd,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=timeout,
            )
            if self._sock_factory:
                # 通过 SOCKS 建立 socket, 传给 paramiko
                sock = self._sock_factory()
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.settimeout(timeout)
                connect_kw["sock"] = sock

            client.connect(**connect_kw)
            return TrafficResponse(
                protocol="ssh", ok=True, status=1,
                target=f"{host}:{port}",
                banner=f"ssh(login:{user})",
                text=f"Login: {user}:{pwd}",
                tags=["SSH", "LOGIN-SUCCESS"],
                anomalies=[f"cracked:{user}:{pwd}"],
            )
        except paramiko.AuthenticationException:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                error="auth-failed",
            )
        except (paramiko.SSHException, OSError, Exception) as e:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                error=f"{type(e).__name__}:{e}",
            )
        finally:
            try:
                client.close()
            except Exception:
                pass

    # ============================================================
    #              exec_cmd (命令执行 - RCE 验证)
    # ============================================================

    async def exec_cmd(self, target: str, user: str, password: str,
                       command: str = "id",
                       timeout: Optional[float] = None) -> TrafficResponse:
        """
        用已知凭据登录并执行命令.

        用途: 确认 RCE (从弱口令到代码执行的最后一步).
        """
        closed = self._check_closed(target)
        if closed:
            return closed

        if not _PARAMIKO_AVAILABLE:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                target=target, error="paramiko-not-installed",
            )

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        result = await asyncio.to_thread(
            self._exec_sync, host, port, user, password, command,
            timeout or self.timeout,
        )
        return result

    def _exec_sync(self, host: str, port: int, user: str, pwd: str,
                   cmd: str, timeout: float) -> TrafficResponse:
        """paramiko 同步执行命令"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            connect_kw = dict(
                hostname=host, port=port,
                username=user, password=pwd,
                timeout=timeout,
                allow_agent=False, look_for_keys=False,
            )
            if self._sock_factory:
                sock = self._sock_factory()
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.settimeout(timeout)
                connect_kw["sock"] = sock

            client.connect(**connect_kw)
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace").strip()
            err = stderr.read().decode("utf-8", "replace").strip()
            client.close()

            tags = ["SSH", "LOGIN-SUCCESS", "RCE-CONFIRMED", "HIGH-VALUE"]
            anomalies = [f"cmd:{cmd}", "code-executed"]

            return TrafficResponse(
                protocol="ssh", ok=True, status=1,
                target=f"{host}:{port}",
                banner=f"ssh(rce:{user})",
                text=f"Command: {cmd}\nOutput: {out}\nError: {err}",
                tags=tags,
                anomalies=anomalies,
            )
        except paramiko.AuthenticationException:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                error="auth-failed",
            )
        except Exception as e:
            return TrafficResponse(
                protocol="ssh", ok=False, status=0,
                error=f"{type(e).__name__}:{e}",
            )
        finally:
            try:
                client.close()
            except Exception:
                pass

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        self._closed = True
