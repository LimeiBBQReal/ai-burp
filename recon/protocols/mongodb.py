"""
Recon Pipeline V2 - MongoDB 协议探测

检测未授权访问和版本信息。
"""
from .base import BaseProtocolProbe, ProbeResult


class MongoDBProbe(BaseProtocolProbe):
    """MongoDB 协议探测"""

    protocol_name = "mongodb"
    default_ports = [27017, 27018, 27019]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # MongoDB OP_QUERY 探测包 - isMaster 命令
        # 这是一个简化的 MongoDB wire protocol 消息
        return (
            b"\x3f\x00\x00\x00"          # messageLength (63)
            b"\0\x00\x00\x00"             # requestID (0)
            b"\0\x00\x00\x00"             # responseTo (0)
            b"\xd4\x07\x00\x00"           # opCode (OP_QUERY = 2004)
            b"\0\x00\x00\x00"             # flags (0)
            b"admin.$cmd\x00"             # fullCollectionName
            b"\0\x00\x00\x00"             # numberToSkip (0)
            b"\xff\xff\xff\xff"           # numberToReturn (-1)
            # document: {isMaster: 1}
            b"$\x00\x00\x00"
            b"\x02isMaster\x00\x00\x00\x00\x00"
            b"\x00"
        )

    def parse_response(self, response: bytes) -> ProbeResult:
        """
        MongoDB 响应格式 (OP_REPLY):
        - 4 bytes: messageLength
        - 4 bytes: requestID
        - 4 bytes: responseTo
        - 4 bytes: opCode (OP_REPLY = 1)
        - 4 bytes: responseFlags
        - 8 bytes: cursorID
        - 4 bytes: startingFrom
        - 4 bytes: numberReturned
        - documents...
        """
        if len(response) < 36:
            return ProbeResult(protocol="mongodb", is_match=False, confidence=0)

        # 检查 opCode 是否为 OP_REPLY (1)
        import struct
        try:
            op_code = struct.unpack('<I', response[12:16])[0]
            if op_code == 1:
                # 尝试提取版本信息
                text = response.decode('utf-8', errors='ignore')
                version = ""
                if "version" in text:
                    # 简单提取版本号
                    import re
                    match = re.search(r'(\d+\.\d+\.\d+)', text)
                    if match:
                        version = match.group(1)

                return ProbeResult(
                    protocol="mongodb",
                    is_match=True,
                    confidence=1.0,
                    banner=f"MongoDB {version}".strip(),
                    version=version,
                )
        except:
            pass

        return ProbeResult(protocol="mongodb", is_match=False, confidence=0)
