"""
Recon Pipeline V2 - FTP 协议探测

检测匿名登录和版本信息。
"""
from .base import BaseProtocolProbe, ProbeResult


class FTPProbe(BaseProtocolProbe):
    """FTP 协议探测"""

    protocol_name = "ftp"
    default_ports = [21]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # FTP 服务器主动发送欢迎消息
        return b""

    def parse_response(self, response: bytes) -> ProbeResult:
        try:
            text = response.decode('utf-8', errors='ignore').strip()

            # FTP 欢迎消息以 220 开头
            if text.startswith("220"):
                banner = text[4:].strip()
                if banner.startswith("-"):
                    banner = banner[1:].strip()

                return ProbeResult(
                    protocol="ftp",
                    is_match=True,
                    confidence=1.0,
                    banner=banner,
                    config={"welcome": text},
                )

            # 有些 FTP 服务器返回其他格式
            if "ftp" in text.lower():
                return ProbeResult(
                    protocol="ftp",
                    is_match=True,
                    confidence=0.8,
                    banner=text,
                )
        except:
            pass

        return ProbeResult(protocol="ftp", is_match=False, confidence=0)

    def probe(self, ip: str, port: int) -> ProbeResult:
        """
        FTP 特殊探测流程:
        1. 接收欢迎消息
        2. 尝试匿名登录 (anonymous)
        """
        result = super().probe(ip, port)

        if result.is_match:
            # 尝试匿名登录
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))

                # 接收欢迎消息
                sock.recv(1024)

                # 发送匿名登录
                sock.send(b"USER anonymous\r\n")
                resp1 = sock.recv(1024).decode('utf-8', errors='ignore')

                if "331" in resp1 or "230" in resp1:
                    sock.send(b"PASS anonymous@example.com\r\n")
                    resp2 = sock.recv(1024).decode('utf-8', errors='ignore')

                    if "230" in resp2:
                        result.config["anonymous_login"] = True
                        result.banner += " (anonymous allowed)"

                sock.close()
            except:
                pass

        return result
