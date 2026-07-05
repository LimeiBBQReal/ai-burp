"""
Recon Pipeline V2 - PostgreSQL 协议探测

PostgreSQL 服务器在连接时会主动发送错误消息或要求 SSL。
"""
from .base import BaseProtocolProbe, ProbeResult


class PostgresProbe(BaseProtocolProbe):
    """PostgreSQL 协议探测"""

    protocol_name = "postgres"
    default_ports = [5432]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # SSLRequest 包 - 询问是否支持 SSL
        return (
            b"\x00\x00\x00\x08"  # length (8)
            b"\x04\xd2\x16\x2f"   # SSLRequest magic number
        )

    def parse_response(self, response: bytes) -> ProbeResult:
        """
        PostgreSQL 响应:
        - 'S' (0x53): 支持 SSL
        - 'N' (0x4e): 不支持 SSL
        - 错误消息以 'E' 开头
        """
        if len(response) < 1:
            return ProbeResult(protocol="postgres", is_match=False, confidence=0)

        first_byte = response[0]

        # SSL 支持
        if first_byte == 0x53:  # 'S'
            return ProbeResult(
                protocol="postgres",
                is_match=True,
                confidence=1.0,
                banner="PostgreSQL (SSL)",
                config={"ssl": True},
            )

        # SSL 不支持
        if first_byte == 0x4e:  # 'N'
            return ProbeResult(
                protocol="postgres",
                is_match=True,
                confidence=1.0,
                banner="PostgreSQL (no SSL)",
                config={"ssl": False},
            )

        # 错误消息
        if first_byte == 0x45:  # 'E'
            return ProbeResult(
                protocol="postgres",
                is_match=True,
                confidence=0.95,
                banner="PostgreSQL",
            )

        return ProbeResult(protocol="postgres", is_match=False, confidence=0)
