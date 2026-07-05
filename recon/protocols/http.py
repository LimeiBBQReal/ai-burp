"""
Recon Pipeline V2 - HTTP/HTTPS 协议探测
"""
from .base import BaseProtocolProbe, ProbeResult


class HTTPProbe(BaseProtocolProbe):
    """HTTP 协议探测"""

    protocol_name = "http"
    default_ports = [80, 8080, 8000, 8888, 3000, 5000, 9000, 9090, 8081, 8443]
    max_concurrency = 100

    @property
    def probe_packet(self) -> bytes:
        return b"HEAD / HTTP/1.0\r\nHost: probe\r\nConnection: close\r\n\r\n"

    def parse_response(self, response: bytes) -> ProbeResult:
        try:
            text = response.decode('utf-8', errors='ignore')
            if text.startswith("HTTP/"):
                # 提取 Server 头
                server = ""
                for line in text.split('\r\n'):
                    if line.lower().startswith('server:'):
                        server = line.split(':', 1)[1].strip()
                        break

                # 提取状态码
                status_code = 0
                try:
                    status_code = int(text.split()[1])
                except:
                    pass

                return ProbeResult(
                    protocol="http",
                    is_match=True,
                    confidence=1.0,
                    banner=server,
                    config={"status_code": status_code},
                )
        except:
            pass

        return ProbeResult(protocol="http", is_match=False, confidence=0)


class HTTPSProbe(BaseProtocolProbe):
    """HTTPS 协议探测"""

    protocol_name = "https"
    default_ports = [443, 8443]
    max_concurrency = 50

    @property
    def probe_packet(self) -> bytes:
        # TLS Client Hello 简化版
        return b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"

    def parse_response(self, response: bytes) -> ProbeResult:
        # 检查 TLS Server Hello
        if len(response) > 5 and response[0] == 0x16:
            return ProbeResult(
                protocol="https",
                is_match=True,
                confidence=1.0,
                banner="TLS",
            )
        return ProbeResult(protocol="https", is_match=False, confidence=0)

    def probe(self, ip: str, port: int) -> ProbeResult:
        """HTTPS 需要 SSL 包装"""
        import socket
        import ssl

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.connect((ip, port))
                # 获取证书信息
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                return ProbeResult(
                    protocol="https",
                    is_match=True,
                    confidence=1.0,
                    banner=f"TLS {version}",
                    config={
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "",
                        "has_cert": bool(cert),
                    },
                )
        except ssl.SSLError:
            return ProbeResult(protocol="https", is_match=False, confidence=0)
        except Exception as e:
            return ProbeResult(
                protocol="https", is_match=False, confidence=0,
                metadata={"error": str(e)},
            )
