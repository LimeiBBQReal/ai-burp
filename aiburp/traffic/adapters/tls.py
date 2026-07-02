"""
TLS/SSL 协议适配器 - 证书侦察 + 弱套件检测.

TLS 层攻击面 (与 HTTP 应用层不同):
    1. 证书 SAN (Subject Alternative Names) 泄露子域名 - 无需扫描, 一拿一大把
    2. 自签名证书 / CN 与请求域名不匹配 - 可能是钓鱼/未配置
    3. 弱套件 (RC4/3DES/EXPORT) / TLS 1.0/1.1 - 可被 BEAST/POODLE/LUCKY13
    4. 证书过期 / 证书透明度缺失
    5. Heartbleed (CVE-2014-0160) 等漏洞 (本 adapter 只做指纹, 不做利用)

设计:
    - 用 Python 标准库 ssl (无外部依赖)
    - probe(): TLS 握手 + 拿证书链 + 解析 SAN/有效期/签名算法
    - send(): 不直接支持 (TLS 是传输层, 应用层用 HttpAdapter)
    - 组合而非继承 - TLS 是 TCP+SSL 包装

注意: TLS 是传输层, 不是应用层. probe 只拿证书信息, 不发 HTTP 请求.
真正的应用层交互 (HTTPS) 走 HttpAdapter (verify=False 跳过证书校验).
"""

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from ..base import (
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
)
from .fingerprints import split_host_port


# 弱加密套件关键字 (出现在 cipher 名里 = 弱)
WEAK_CIPHER_KEYWORDS = ("RC4", "3DES", "DES", "EXPORT", "NULL", "MD5", "anon")
# 弱 TLS 版本
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TlsAdapter(ProtocolAdapter):
    """
    TLS/SSL 协议适配器 - 证书侦察.

    用法:
        async with TlsAdapter() as t:
            resp = await t.probe("target.com:443")
            # resp.banner 含颁发者, resp.text 含 SAN 列表, resp.tags 标弱套件
    """

    protocol = "tls"
    description = "TLS/SSL certificate recon (SAN / weak cipher detection)"

    DEFAULT_PORT = 443

    def __init__(self, timeout: float = 5.0, concurrency: int = 10,
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
        TLS 握手 + 拿证书链.

        target: host:port (端口缺省 443)
        返回信息: SAN 列表 / CN / 颁发者 / 有效期 / 签名算法 / 协商的 cipher + 版本
        """
        if self._closed:
            return self._closed_resp(target)

        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        # SNI 用 host (不能是 IP)
        sni = host if not _is_ip(host) else None
        timeout = kw.get("timeout", self.timeout)

        async with self._sem:
            try:
                cert_info, cipher, version, elapsed = await asyncio.to_thread(
                    self._do_handshake, host, port, sni, timeout
                )
            except (ssl.SSLError, ConnectionRefusedError, OSError, socket.timeout) as e:
                return TrafficResponse(
                    protocol="tls", ok=False, status=0,
                    target=target, error=f"{type(e).__name__}: {str(e)[:100]}",
                )
            except Exception as e:
                return TrafficResponse(
                    protocol="tls", ok=False, status=0,
                    target=target, error=f"{type(e).__name__}: {str(e)[:100]}",
                )

        # 解析证书
        tags = ["TLS"]
        anomalies: List[str] = []
        text_parts: List[str] = []
        banner_parts: List[str] = []

        if cert_info:
            subject_cn = cert_info.get("subject_cn", "")
            issuer_cn = cert_info.get("issuer_cn", "")
            sans = cert_info.get("sans", [])
            not_after = cert_info.get("not_after")
            sig_alg = cert_info.get("signature_algorithm", "")
            self_signed = cert_info.get("self_signed", False)

            banner_parts.append(f"cn={subject_cn}" if subject_cn else "no-cn")

            text_parts.append(f"Subject CN: {subject_cn}")
            text_parts.append(f"Issuer: {issuer_cn}")
            text_parts.append(f"Signature: {sig_alg}")
            if not_after:
                text_parts.append(f"Not After: {not_after}")
            if sans:
                text_parts.append(f"SAN ({len(sans)}):")
                for san in sans[:30]:
                    text_parts.append(f"  {san}")
                if len(sans) > 30:
                    text_parts.append(f"  ...还有 {len(sans)-30} 个")
                if len(sans) > 1:
                    tags.append("SAN-LEAK")
                    anomalies.append(f"sans:{len(sans)}")

            # 自签名检测
            if self_signed:
                tags.append("SELF-SIGNED")
                anomalies.append("self-signed")

            # 过期检测
            if not_after:
                days_left = _days_until(not_after)
                if days_left < 0:
                    tags.append("EXPIRED")
                    anomalies.append(f"expired:{-days_left}days")
                elif days_left < 30:
                    tags.append("EXPIRING-SOON")
                    anomalies.append(f"expiring:{days_left}days")

        # cipher / version 弱检测
        if cipher:
            text_parts.append(f"Cipher: {cipher}")
            if any(kw in cipher for kw in WEAK_CIPHER_KEYWORDS):
                tags.append("WEAK-CIPHER")
                anomalies.append(f"weak-cipher:{cipher}")

        if version:
            text_parts.append(f"TLS Version: {version}")
            if version in WEAK_TLS_VERSIONS:
                tags.append("WEAK-TLS-VERSION")
                anomalies.append(f"weak-version:{version}")

        banner = " ".join(b for b in banner_parts if b)

        return TrafficResponse(
            protocol="tls",
            ok=True,
            status=1,
            text="\n".join(text_parts),
            banner=banner,
            time_ms=elapsed,
            target=target,
            tags=tags,
            anomalies=anomalies,
        )

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        TLS 是传输层, send 语义等同 probe (重新握手).
        不支持应用层数据交互 - 那是 HttpAdapter 的职责.
        """
        return await self.probe(req.target, **kw)

    # ============================================================
    #                     内部: TLS 握手
    # ============================================================

    def _do_handshake(
        self, host: str, port: int, sni: Optional[str], timeout: float
    ) -> tuple:
        """
        同步执行 TLS 握手, 拿证书 + 协商信息.
        在 to_thread 中调用.

        Returns: (cert_info_dict, cipher_name, tls_version, elapsed_ms)
        """
        start = time.monotonic()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False        # 红队场景: 不校验域名
        ctx.verify_mode = ssl.CERT_NONE   # 不校验证书链 (自签名也能握手)

        # 弱套件探测: 允许所有套件看服务端会选什么
        try:
            ctx.set_ciphers("ALL:eNULL")
        except ssl.SSLError:
            pass  # 某些 OpenSSL 不支持 eNULL, 用默认

        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ssl_sock = ctx.wrap_socket(sock, server_hostname=sni, do_handshake_on_connect=True)
            try:
                # 拿协商信息
                cipher_name = ""
                tls_version = ""
                try:
                    cipher_tuple = ssl_sock.cipher()
                    if cipher_tuple:
                        cipher_name = cipher_tuple[0] or ""
                        tls_version = cipher_tuple[1] or ""
                except Exception:
                    pass

                # 拿证书
                cert_der = ssl_sock.getpeercert(binary_form=True)
                cert_info = _parse_cert(cert_der) if cert_der else None

                elapsed = (time.monotonic() - start) * 1000
                return cert_info or {}, cipher_name, tls_version, elapsed
            finally:
                try:
                    ssl_sock.close()
                except Exception:
                    pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ============================================================
    #                       生命周期
    # ============================================================

    def _closed_resp(self, target: str) -> TrafficResponse:
        return TrafficResponse(
            protocol="tls", ok=False, status=0,
            target=target, error="adapter-closed",
            anomalies=["adapter 已 close"],
        )

    async def close(self):
        if self._closed:
            return
        self._closed = True


# ============================================================
#                       工具函数
# ============================================================

def _is_ip(host: str) -> bool:
    """判断 host 是不是 IP 地址 (SNI 不能用 IP)"""
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def _parse_cert(cert_der: bytes) -> Dict[str, Any]:
    """解析 DER 证书, 提取红队关心的字段"""
    info: Dict[str, Any] = {}
    try:
        # 用 ssl 模块的 DER 解析 (Python 3.8+ DERTYPE)
        cert = ssl.DER_cert_to_PEM_cert(cert_der)
        # 用 cryptography 库解析更详细 (如果可用)
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())

            # Subject CN
            try:
                attrs = obj.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                info["subject_cn"] = attrs[0].value if attrs else ""
            except Exception:
                info["subject_cn"] = ""

            # Issuer CN
            try:
                attrs = obj.issuer.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                info["issuer_cn"] = attrs[0].value if attrs else ""
            except Exception:
                info["issuer_cn"] = ""

            # SAN
            try:
                san_ext = obj.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                sans = []
                for name in san_ext.value:
                    try:
                        sans.append(name.value)
                    except Exception:
                        pass
                info["sans"] = sans
            except x509.ExtensionNotFound:
                info["sans"] = []
            except Exception:
                info["sans"] = []

            # 有效期 (cryptography 新版用 _utc 后缀, 旧版用 naive datetime)
            try:
                if hasattr(obj, "not_valid_after_utc"):
                    info["not_after"] = obj.not_valid_after_utc.isoformat()
                else:
                    info["not_after"] = obj.not_valid_after.isoformat()
            except Exception:
                info["not_after"] = ""

            # 签名算法
            try:
                info["signature_algorithm"] = obj.signature_algorithm_oid._name
            except Exception:
                info["signature_algorithm"] = ""

            # 自签名: subject == issuer
            info["self_signed"] = (obj.subject == obj.issuer)

        except ImportError:
            # cryptography 不可用, 用 ssl 模块解析 (功能有限)
            # 这种情况 SAN 解析会少, 但不会崩
            info["subject_cn"] = ""
            info["issuer_cn"] = ""
            info["sans"] = []
            info["not_after"] = ""
            info["signature_algorithm"] = ""
            info["self_signed"] = False
    except Exception:
        pass

    return info


def _days_until(iso_date: str) -> int:
    """计算从现在到 iso_date 的天数 (负数=已过期)"""
    try:
        # 处理多种 ISO 格式
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (dt - now).days
    except Exception:
        return 999  # 解析失败返回大数 (不当成过期)
