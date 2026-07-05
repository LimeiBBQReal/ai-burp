"""
Recon Pipeline V2 - Redis 协议探测

检测未授权访问和版本信息。
"""
from .base import BaseProtocolProbe, ProbeResult


class RedisProbe(BaseProtocolProbe):
    """Redis 协议探测"""

    protocol_name = "redis"
    default_ports = [6379]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # PING 命令检测是否未授权
        return b"*1\r\n$4\r\nPING\r\n"

    def parse_response(self, response: bytes) -> ProbeResult:
        # +PONG\r\n 表示无授权
        if response == b"+PONG\r\n":
            return ProbeResult(
                protocol="redis",
                is_match=True,
                confidence=1.0,
                banner="Redis",
                config={"unauthenticated": True},
            )

        # NOAUTH 表示需要密码
        if b"NOAUTH" in response or b"Authentication" in response:
            return ProbeResult(
                protocol="redis",
                is_match=True,
                confidence=0.9,
                banner="Redis (auth required)",
                config={"unauthenticated": False},
            )

        # -ERR 也是 Redis 响应
        if response.startswith(b"-ERR"):
            return ProbeResult(
                protocol="redis",
                is_match=True,
                confidence=0.95,
                banner="Redis",
            )

        # $0\r\n 空响应也是 Redis
        if response.startswith(b"$-1") or response.startswith(b"$0"):
            return ProbeResult(
                protocol="redis",
                is_match=True,
                confidence=0.8,
                banner="Redis",
            )

        return ProbeResult(protocol="redis", is_match=False, confidence=0)

    def probe(self, ip: str, port: int) -> ProbeResult:
        """
        Redis 特殊探测流程:
        1. 先发送 PING 检测是否未授权
        2. 如果未授权，发送 INFO 获取版本信息
        """
        result = super().probe(ip, port)

        if result.is_match and result.config.get("unauthenticated"):
            # 未授权，获取更多信息
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(b"*1\r\n$4\r\nINFO\r\n")
                info_response = sock.recv(8192)
                sock.close()

                # 解析版本
                text = info_response.decode('utf-8', errors='ignore')
                for line in text.split('\r\n'):
                    if line.startswith('redis_version:'):
                        result.version = line.split(':')[1]
                        result.config["version"] = result.version
                        break

                result.raw_response = info_response
            except:
                pass

        return result
