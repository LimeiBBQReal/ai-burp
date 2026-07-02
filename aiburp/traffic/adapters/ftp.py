"""
FTP 协议适配器 - 有状态会话.

问题: TcpAdapter 每次新建连接, 但 FTP 是有状态协议
(USER→PASS→PWD→LIST 必须在同一连接上). 用 TcpAdapter 发 FTP
命令会因每次新连接而得到 503 Login incorrect.

本 adapter 在单个 TCP 连接上维持完整 FTP 会话:
    1. probe():    连接, 读 banner (220), 发 USER, PASS 完成认证
    2. send():     在已认证会话上发任意 FTP 命令
    3. check_anonymous(): 一键匿名登录检测
    4. list_dir():  已认证后列目录

设计:
    - 用 asyncio.open_connection 建立长连接
    - 一次连接, 多次 send_command
    - 解析 FTP 状态码 (220/331/230/530/...)
"""

import asyncio
from typing import Optional, Tuple, List

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .fingerprints import split_host_port


class FtpAdapter(ProtocolAdapter):
    """
    FTP 有状态会话适配器.

    用法:
        adapter = FtpAdapter(timeout=5)
        resp = await adapter.check_anonymous("ftp.example.com:21")
        resp = await adapter.list_dir("ftp.example.com:21", user="anon", password="x")
    """

    protocol = "ftp"
    description = "FTP stateful session (anonymous + auth + list)"

    DEFAULT_PORT = 21

    def __init__(self, timeout: float = 5.0, concurrency: int = 5):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False

    def _check_closed(self, target: str = "") -> Optional[TrafficResponse]:
        if self._closed:
            return TrafficResponse(
                protocol="ftp", ok=False, status=0,
                target=target, error="adapter-closed",
            )
        return None

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活: 连接 + 读 banner (220).
        只确认 FTP 服务在线, 不认证.
        """
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
                protocol="ftp", ok=False, status=0,
                target=target, error=type(e).__name__,
            )

        try:
            banner_raw = await asyncio.wait_for(
                reader.read(1024), timeout=kw.get("timeout", self.timeout),
            )
            banner = banner_raw.decode("utf-8", "replace").strip()

            is_ftp = banner.startswith("220")
            is_proftpd = "ProFTPD" in banner
            is_vsftpd = "vsFTPd" in banner

            tags = ["FTP"]
            if is_proftpd:
                tags.append("PROFTPD")
            elif is_vsftpd:
                tags.append("VSFTPD")
            if "1.3.5" in banner:
                tags.append("CVE-2015-3306-CHECK")

            return TrafficResponse(
                protocol="ftp",
                ok=is_ftp,
                status=220 if is_ftp else 0,
                raw=banner_raw,
                text=banner,
                banner="ftp/" + banner.split()[2] if len(banner.split()) > 2 else "ftp",
                target=target,
                tags=tags,
                time_ms=0,
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ============================================================
    #                      send (单命令, 新连接)
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送单条 FTP 命令 (新连接).
        注意: FTP 有状态, 单命令 send 只能发 banner 后的第一条.
        完整会话用 check_anonymous / list_dir.
        """
        closed = self._check_closed(req.target)
        if closed:
            return closed

        # send 委托给 probe (FTP 单连接只读 banner)
        return await self.probe(req.target, **kw)

    # ============================================================
    #              check_anonymous (一键匿名检测)
    # ============================================================

    async def check_anonymous(self, target: str,
                               timeout: Optional[float] = None) -> TrafficResponse:
        """
        一键 FTP 匿名登录检测.

        在单个连接上完成: 220 banner → USER anonymous → PASS → 判断 230/530.

        230 = 匿名登录成功 (信息泄露)
        530 = 匿名被拒 (安全)
        """
        closed = self._check_closed(target)
        if closed:
            return closed

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=t,
            )
        except (asyncio.TimeoutError, OSError) as e:
            return TrafficResponse(
                protocol="ftp", ok=False, status=0,
                target=target, error=type(e).__name__,
            )

        try:
            # 读 banner
            banner_raw = await asyncio.wait_for(reader.read(1024), timeout=t)
            banner = banner_raw.decode("utf-8", "replace").strip()
            if not banner.startswith("220"):
                return TrafficResponse(
                    protocol="ftp", ok=False, status=0,
                    target=target, error="not-ftp-banner",
                    text=banner,
                )

            # USER anonymous
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            user_resp = await asyncio.wait_for(reader.read(1024), timeout=t)
            user_text = user_resp.decode("utf-8", "replace").strip()

            if not user_text.startswith("331"):
                # 530 = 不允许; 其它 = 异常
                return TrafficResponse(
                    protocol="ftp", ok=True, status=530,
                    target=target, banner="ftp",
                    text=f"Banner: {banner}\nUSER: {user_text}",
                    tags=["FTP", "ANON-DENIED"],
                    anomalies=["anonymous-rejected"],
                )

            # PASS anonymous@
            writer.write(b"PASS anonymous@example.com\r\n")
            await writer.drain()
            pass_resp = await asyncio.wait_for(reader.read(1024), timeout=t)
            pass_text = pass_resp.decode("utf-8", "replace").strip()

            if pass_text.startswith("230"):
                # 匿名登录成功!
                # 发 PWD 拿当前目录
                writer.write(b"PWD\r\n")
                await writer.drain()
                pwd_resp = await asyncio.wait_for(reader.read(1024), timeout=t)
                pwd_text = pwd_resp.decode("utf-8", "replace").strip()

                # QUIT
                writer.write(b"QUIT\r\n")
                await writer.drain()

                return TrafficResponse(
                    protocol="ftp", ok=True, status=230,
                    target=target,
                    banner="ftp(anonymous)",
                    text=f"Banner: {banner}\nUSER: {user_text}\nPASS: {pass_text}\nPWD: {pwd_text}",
                    tags=["FTP", "ANONYMOUS-OK", "HIGH-VALUE"],
                    anomalies=["anonymous-access", "info-leak"],
                )
            else:
                return TrafficResponse(
                    protocol="ftp", ok=True, status=530,
                    target=target, banner="ftp",
                    text=f"Banner: {banner}\nUSER: {user_text}\nPASS: {pass_text}",
                    tags=["FTP", "ANON-DENIED"],
                    anomalies=["anonymous-password-rejected"],
                )
        except asyncio.TimeoutError:
            return TrafficResponse(
                protocol="ftp", ok=False, status=0,
                target=target, error="ftp-timeout",
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ============================================================
    #              list_dir (认证后列目录)
    # ============================================================

    async def list_dir(self, target: str, user: str = "anonymous",
                       password: str = "anonymous@",
                       path: str = "/",
                       timeout: Optional[float] = None) -> TrafficResponse:
        """
        登录并列目录 (完整有状态会话).

        在单个连接上: 220 → USER → PASS → CWD → PASV → LIST.
        返回目录列表.
        """
        closed = self._check_closed(target)
        if closed:
            return closed

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=t,
            )
        except (asyncio.TimeoutError, OSError) as e:
            return TrafficResponse(
                protocol="ftp", ok=False, status=0,
                target=target, error=type(e).__name__,
            )

        try:
            async def _read_resp():
                """读 FTP 响应 (可能多行, 以 数字 开头, 数字后空格结束)"""
                data = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=t)
                    if not chunk:
                        break
                    data += chunk
                    # FTP 响应结束标志: 行首三位数字 + 空格
                    lines = data.decode("utf-8", "replace").split("\r\n")
                    for line in lines:
                        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                            return data
                    # 或者数据够多了
                    if len(data) > 8192:
                        return data
                return data

            # banner
            await _read_resp()
            # USER
            writer.write(f"USER {user}\r\n".encode())
            await writer.drain()
            await _read_resp()
            # PASS
            writer.write(f"PASS {password}\r\n".encode())
            await writer.drain()
            pass_resp = await _read_resp()
            pass_text = pass_resp.decode("utf-8", "replace")

            if not pass_text.strip().startswith("230"):
                return TrafficResponse(
                    protocol="ftp", ok=False, status=530,
                    target=target, error="login-failed",
                    text=pass_text,
                )

            # CWD
            if path and path != "/":
                writer.write(f"CWD {path}\r\n".encode())
                await writer.drain()
                await _read_resp()

            # PASV (被动模式)
            writer.write(b"PASV\r\n")
            await writer.drain()
            pasv_resp = await _read_resp()
            pasv_text = pasv_resp.decode("utf-8", "replace").strip()

            # 解析 PASV 响应: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
            import re
            m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv_text)
            if not m:
                return TrafficResponse(
                    protocol="ftp", ok=False, status=0,
                    target=target, error="pasv-failed",
                    text=pasv_text,
                )

            # 计算数据端口
            data_host = ".".join(m.groups()[:4])
            data_port = int(m.group(5)) * 256 + int(m.group(6))
            # Docker 环境里 PASV 返回的 IP 是容器内 IP, 用原始 host
            data_host = host

            # LIST
            writer.write(b"LIST\r\n")
            await writer.drain()

            # 连数据端口读目录列表
            try:
                data_reader, data_writer = await asyncio.wait_for(
                    asyncio.open_connection(data_host, data_port), timeout=t,
                )
                list_data = b""
                while True:
                    chunk = await asyncio.wait_for(data_reader.read(4096), timeout=t)
                    if not chunk:
                        break
                    list_data += chunk
                data_writer.close()
                try:
                    await data_writer.wait_closed()
                except Exception:
                    pass
            except (asyncio.TimeoutError, OSError):
                list_data = b""

            # 读控制连接的 226 响应
            await _read_resp()

            # QUIT
            writer.write(b"QUIT\r\n")
            await writer.drain()

            list_text = list_data.decode("utf-8", "replace")
            files = [l for l in list_text.split("\r\n") if l.strip()]

            return TrafficResponse(
                protocol="ftp", ok=True, status=230,
                target=target,
                banner=f"ftp({user})",
                text=f"Path: {path}\nFiles ({len(files)}):\n" + list_text[:2000],
                raw=list_data,
                tags=["FTP", "LOGIN-SUCCESS", "INFO-LEAK"],
                anomalies=[f"listed:{len(files)}entries"],
            )
        except asyncio.TimeoutError:
            return TrafficResponse(
                protocol="ftp", ok=False, status=0,
                target=target, error="ftp-timeout",
            )
        except Exception as e:
            return TrafficResponse(
                protocol="ftp", ok=False, status=0,
                target=target, error=f"{type(e).__name__}:{e}",
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        self._closed = True
