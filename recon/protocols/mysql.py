"""
Recon Pipeline V2 - MySQL 协议探测

MySQL 服务器会主动发送握手包，无需发送 probe_packet。
"""
from .base import BaseProtocolProbe, ProbeResult


class MySQLProbe(BaseProtocolProbe):
    """MySQL 协议探测"""

    protocol_name = "mysql"
    default_ports = [3306, 33060]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # MySQL 服务器主动发送握手包，无需发送
        return b""

    def parse_response(self, response: bytes) -> ProbeResult:
        """
        MySQL 握手包格式:
        - 第1字节: 协议版本 (0x0a = v10)
        - 接下来以 \x00 结尾: 版本字符串
        - 4字节: 连接 ID
        - 8字节: auth_plugin_data_part_1
        - 1字节: filler (0x00)
        - 2字节: capability_flags_lower
        ...
        """
        if len(response) < 5:
            return ProbeResult(protocol="mysql", is_match=False, confidence=0)

        # 检查协议版本
        if response[0] != 0x0a:
            return ProbeResult(protocol="mysql", is_match=False, confidence=0)

        try:
            # 提取版本字符串
            end = response.index(b'\x00', 1)
            version = response[1:end].decode('utf-8', errors='ignore')

            # 提取更多信息的偏移量
            offset = end + 1 + 4 + 8 + 1 + 2 + 1  # 跳过连接ID、auth数据等

            config = {"version": version}

            # 尝试提取字符集
            if offset < len(response):
                config["charset"] = response[offset]

            return ProbeResult(
                protocol="mysql",
                is_match=True,
                confidence=1.0,
                banner=f"MySQL {version}",
                version=version,
                config=config,
            )
        except (ValueError, IndexError):
            pass

        return ProbeResult(protocol="mysql", is_match=False, confidence=0)
