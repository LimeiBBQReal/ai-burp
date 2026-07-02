"""
SMB 协议适配器 - 共享枚举 + 弱口令 (可选 impacket).

SMB (Server Message Block) 是 Windows 文件共享协议, 红队核心攻击面:
    - EternalBlue (MS17-010): SMBv1 RCE, 直接系统权限
    - 空会话 (null session): 枚举用户/组/共享 (信息泄露)
    - 弱口令: 横向移动的标准入口 (Pass-the-Hash 前置)
    - 默认端口 445 (SMB 直接) / 139 (NetBIOS over TCP)

实现策略 (两级降级):
    1. impacket 可用: 完整 SMB2 协商 + 会话 + 共享枚举
    2. impacket 不可用: TCP banner 探测 (SMBv1 协商请求 + 看响应)

不做完整 EternalBlue 利用 - 那是 exploit 层 (MSF/metasploit).

设计:
    - impacket 是可选依赖 (pip install impacket), 缺失时降级
    - 降级模式用 TcpAdapter 的 _connect_and_read 做 SMBv1 协商探测
"""

import asyncio
import struct
from typing import List, Optional

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .fingerprints import split_host_port


# 检查 impacket 是否可用
try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.smb import SMB_DIALECT
    _IMPACKET_AVAILABLE = True
except ImportError:
    _IMPACKET_AVAILABLE = False
    SMBConnection = None
    SessionError = Exception


# SMBv1 协商请求 (Negotiate Protocol Request), 用于降级 banner 探测
# 这是标准的 SMB1 协商包, 服务器会回 Negotiate Response
def _build_smb1_negotiate() -> bytes:
    """构造 SMB1 Negotiate Protocol Request"""
    # NetBIOS Session Service header
    nbss = b"\x00\x00\x00\x00"  # type=Session Message, length 填后

    # SMB1 header
    smb_header = b"\xff\x53\x4d\x42"  # \xffSMB (SMB1 magic)
    smb_header += b"\x72"              # Command: Negotiate (0x72)
    smb_header += b"\x00\x00\x00\x00"  # Status
    smb_header += b"\x18"              # Flags
    smb_header += b"\x53\xc8"          # Flags2 (unicode + nt status)
    smb_header += b"\x00\x00"          # PID High
    smb_header += b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    smb_header += b"\x00\x00"          # Reserved
    smb_header += b"\x00\x00"          # Tree ID
    smb_header += b"\x00\x00"          # Process ID
    smb_header += b"\x00\x00"          # User ID
    smb_header += b"\x00\x00"          # Multiplex ID

    # Negotiate dialects
    dialects = [b"\x02PC NETWORK PROGRAM 1.0\x00",
                b"\x02LANMAN1.0\x00",
                b"\x02Windows for Workgroups 3.1a\x00",
                b"\x02LM1.2X002\x00",
                b"\x02LANMAN2.1\x00",
                b"\x02NT LM 0.12\x00"]

    dialect_count = len(dialects)
    params = struct.pack("<H", dialect_count)  # WordCount + DialectIndex
    body = params + b"".join(dialects)

    # 填 NetBIOS length
    total_len = len(smb_header) + len(body)
    nbss = b"\x00" + struct.pack(">I", total_len)[1:]  # 3 bytes length

    return nbss + smb_header + body


class SmbAdapter(ProtocolAdapter):
    """
    SMB 协议适配器 - 共享枚举 + 弱口令 (可选 impacket).

    用法:
        async with SmbAdapter() as s:
            resp = await s.probe("10.0.0.1:445")           # SMB 版本指纹
            resp = await s.check_null_session("10.0.0.1")  # 空会话枚举
            resp = await s.check_unauth("10.0.0.1")        # 弱口令爆破
    """

    protocol = "smb"
    description = "SMB share enum + weak credentials (optional impacket)"

    DEFAULT_PORT = 445

    # 常见弱凭据 (SMB 用 user:password:domain)
    COMMON_CREDS = [
        ("", "", ""),              # 匿名
        ("guest", "", ""),         # guest 空密码
        ("Administrator", "", ""), # Administrator 空密码
        ("Administrator", "123456", ""),
        ("admin", "admin", ""),
    ]

    def __init__(self, timeout: float = 5.0, concurrency: int = 3):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        SMB 探活.
        - impacket 可用: SMB2 协商拿 OS 版本 + 域名
        - impacket 不可用: SMB1 Negotiate banner 探测
        """
        if self._closed:
            return self._closed_resp(target)

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        timeout = kw.get("timeout", self.timeout)

        if _IMPACKET_AVAILABLE:
            return await asyncio.to_thread(self._probe_impacket, host, port, timeout, target)
        else:
            return await asyncio.to_thread(self._probe_banner, host, port, timeout, target)

    def _probe_impacket(self, host: str, port: int, timeout: float,
                        target: str) -> TrafficResponse:
        """用 impacket 做 SMB2 协商 (信息丰富)"""
        import time as _time
        start = _time.monotonic()
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            # negotiate_protocol 不需要认证
            os_version = conn.getServerOS()
            domain = ""
            try:
                domain = conn.getServerDomain() or ""
            except Exception:
                pass
            server_name = ""
            try:
                server_name = conn.getServerName() or ""
            except Exception:
                pass
            conn.close()

            elapsed = (_time.monotonic() - start) * 1000
            banner_parts = [f"smb({os_version})"]
            if domain:
                banner_parts.append(f"domain={domain}")
            if server_name:
                banner_parts.append(f"name={server_name}")

            return TrafficResponse(
                protocol="smb", ok=True, status=1,
                banner=";".join(banner_parts),
                text=f"OS: {os_version}\nDomain: {domain}\nServer: {server_name}",
                target=target,
                tags=["SMB", "HIGH-VALUE"],
                anomalies=[f"os:{os_version}",
                           f"domain:{domain}" if domain else "no-domain"],
                time_ms=elapsed,
            )
        except SessionError as e:
            elapsed = (_time.monotonic() - start) * 1000
            # SMB 协议错误 - 但服务器响应了 (是 SMB)
            return TrafficResponse(
                protocol="smb", ok=True, status=1,
                banner="smb",
                target=target,
                tags=["SMB"],
                error=f"session-error:{str(e)[:60]}",
                time_ms=elapsed,
            )
        except (OSError, Exception) as e:
            elapsed = (_time.monotonic() - start) * 1000
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target,
                error=f"{type(e).__name__}: {str(e)[:60]}",
                time_ms=elapsed,
            )

    def _probe_banner(self, host: str, port: int, timeout: float,
                      target: str) -> TrafficResponse:
        """降级: SMB1 Negotiate banner 探测"""
        import socket
        import time as _time
        start = _time.monotonic()

        negotiate = _build_smb1_negotiate()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except (ConnectionRefusedError, ConnectionResetError, socket.timeout,
                OSError) as e:
            elapsed = (_time.monotonic() - start) * 1000
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target, error=type(e).__name__,
                time_ms=elapsed,
            )
        try:
            sock.settimeout(timeout)
            sock.sendall(negotiate)
            response = sock.recv(4096)
            elapsed = (_time.monotonic() - start) * 1000

            if not response:
                return TrafficResponse(
                    protocol="smb", ok=False, status=0,
                    target=target, error="no-response",
                    time_ms=elapsed,
                )

            # 检查 SMB 响应特征
            # SMB1 响应以 \xffSMB 开头, SMB2 以 \xfeSMB 开头
            is_smb1 = response[:4] == b"\xff\x53\x4d\x42"
            is_smb2 = response[:4] == b"\xfe\x53\x4d\x42"

            if is_smb1 or is_smb2:
                version = "smbv1" if is_smb1 else "smbv2+"
                tags = ["SMB", "HIGH-VALUE"]
                anomalies = [f"version:{version}"]
                if is_smb1:
                    tags.append("SMBC1-EXPOSED")  # SMBv1 暴露 = EternalBlue 风险
                    anomalies.append("ms17-010-risk")

                return TrafficResponse(
                    protocol="smb", ok=True, status=1,
                    banner=f"smb/{version}",
                    raw=response,
                    text=f"SMB Version: {version}\nResponse: {response[:32].hex()}",
                    target=target,
                    tags=tags,
                    anomalies=anomalies,
                    time_ms=elapsed,
                )
            else:
                return TrafficResponse(
                    protocol="smb", ok=False, status=0,
                    target=target,
                    error="not-smb",
                    raw=response,
                    anomalies=["non-smb-response"],
                    time_ms=elapsed,
                )
        except (socket.timeout, OSError) as e:
            elapsed = (_time.monotonic() - start) * 1000
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target, error=type(e).__name__,
                time_ms=elapsed,
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """send 等同 probe (SMB 是会话协议, 不像 HTTP 那样 per-request)"""
        return await self.probe(req.target, **kw)

    # ============================================================
    #              check_null_session (空会话枚举)
    # ============================================================

    async def check_null_session(self, target: str,
                                 timeout: Optional[float] = None) -> TrafficResponse:
        """
        空会话检测 (Windows 经典信息泄露).

        空会话 (IPC$ + 空凭据) 能枚举:
            - 用户列表 (SAM)
            - 共享列表
            - 域信息
        """
        if self._closed:
            return self._closed_resp(target)

        if not _IMPACKET_AVAILABLE:
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target, error="impacket-not-installed",
                anomalies=["pip install impacket 后可用"],
            )

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        return await asyncio.to_thread(self._null_session_sync, host, port, t, target)

    def _null_session_sync(self, host: str, port: int, timeout: float,
                           target: str) -> TrafficResponse:
        """同步空会话枚举"""
        import time as _time
        start = _time.monotonic()
        try:
            # 空会话: user="" password="" 用 IPC$ 共享
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            conn.login("", "")  # 匿名登录

            # 枚举共享
            shares = conn.listShares()
            share_names = [s["shi1_netname"][:-1] for s in shares]

            conn.close()
            elapsed = (_time.monotonic() - start) * 1000

            return TrafficResponse(
                protocol="smb", ok=True, status=1,
                banner="smb(null-session)",
                text=f"Shares ({len(share_names)}):\n" + "\n".join(
                    f"  - {s}" for s in share_names[:20]
                ),
                target=target,
                tags=["SMB", "NULL-SESSION-OK", "HIGH-VALUE", "INFO-LEAK"],
                anomalies=["anonymous-access", f"shares:{len(share_names)}",
                           "sam-enum-possible"],
                time_ms=elapsed,
            )
        except SessionError as e:
            elapsed = (_time.monotonic() - start) * 1000
            # 空会话被拒 = 安全配置
            return TrafficResponse(
                protocol="smb", ok=True, status=1,
                target=target, banner="smb(restricted)",
                tags=["SMB", "SECURED"],
                anomalies=["null-session-rejected", "restrictanonymous-set"],
                error=f"null-session-denied:{str(e)[:50]}",
                time_ms=elapsed,
            )
        except Exception as e:
            elapsed = (_time.monotonic() - start) * 1000
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target, error=f"{type(e).__name__}: {str(e)[:50]}",
                time_ms=elapsed,
            )

    # ============================================================
    #              check_unauth (弱口令爆破)
    # ============================================================

    async def check_unauth(self, target: str,
                           creds: Optional[List] = None,
                           timeout: Optional[float] = None) -> TrafficResponse:
        """SMB 弱口令爆破"""
        if self._closed:
            return self._closed_resp(target)

        if not _IMPACKET_AVAILABLE:
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target, error="impacket-not-installed",
            )

        creds = creds or self.COMMON_CREDS
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        for user, pwd, domain in creds:
            result = await asyncio.to_thread(
                self._try_login, host, port, user, pwd, domain, t, target
            )
            if result.ok and "LOGIN-SUCCESS" in result.tags:
                return result

        return TrafficResponse(
            protocol="smb", ok=True, status=1,
            target=target, banner="smb(secured)",
            tags=["SMB", "SECURED"],
            anomalies=[f"tried-{len(creds)}-creds", "no-weak-credentials"],
        )

    def _try_login(self, host: str, port: int, user: str, pwd: str,
                   domain: str, timeout: float, target: str) -> TrafficResponse:
        import time as _time
        start = _time.monotonic()
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            conn.login(user, pwd, domain)
            os_ver = conn.getServerOS()
            shares = []
            try:
                shares = [s["shi1_netname"][:-1] for s in conn.listShares()]
            except Exception:
                pass
            conn.close()
            elapsed = (_time.monotonic() - start) * 1000
            return TrafficResponse(
                protocol="smb", ok=True, status=1,
                banner=f"smb/{os_ver}",
                text=f"User: {user or '(anonymous)'}\nShares: {shares[:10]}",
                target=target,
                tags=["SMB", "LOGIN-SUCCESS", "UNAUTH-CONFIRMED", "HIGH-VALUE"],
                anomalies=[f"cracked:{user}:{pwd or '(empty)'}",
                           f"os:{os_ver}", "lateral-movement-possible"],
                time_ms=elapsed,
            )
        except Exception:
            elapsed = (_time.monotonic() - start) * 1000
            return TrafficResponse(
                protocol="smb", ok=False, status=0,
                target=target, error="access-denied",
                time_ms=elapsed,
            )

    # ============================================================
    #                       生命周期
    # ============================================================

    def _closed_resp(self, target: str) -> TrafficResponse:
        return TrafficResponse(
            protocol="smb", ok=False, status=0,
            target=target, error="adapter-closed",
            anomalies=["adapter 已 close"],
        )

    async def close(self):
        self._closed = True
