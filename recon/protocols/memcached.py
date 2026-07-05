"""
Recon Pipeline V2 - Memcached 协议探测

检测未授权访问和版本信息。
"""
from .base import BaseProtocolProbe, ProbeResult


class MemcachedProbe(BaseProtocolProbe):
    """Memcached 协议探测"""

    protocol_name = "memcached"
    default_ports = [11211]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # version 命令
        return b"version\r\n"

    def parse_response(self, response: bytes) -> ProbeResult:
        try:
            text = response.decode('utf-8', errors='ignore').strip()

            # VERSION x.x.x
            if text.startswith("VERSION "):
                version = text[8:].strip()
                return ProbeResult(
                    protocol="memcached",
                    is_match=True,
                    confidence=1.0,
                    banner=f"Memcached {version}",
                    version=version,
                    config={"unauthenticated": True},
                )

            # SERVER_ERROR 或 ERROR 也表示是 Memcached
            if text.startswith(("SERVER_ERROR", "ERROR", "CLIENT_ERROR")):
                return ProbeResult(
                    protocol="memcached",
                    is_match=True,
                    confidence=0.9,
                    banner="Memcached",
                )

            # STAT 响应
            if text.startswith("STAT"):
                return ProbeResult(
                    protocol="memcached",
                    is_match=True,
                    confidence=0.95,
                    banner="Memcached",
                )
        except:
            pass

        return ProbeResult(protocol="memcached", is_match=False, confidence=0)
