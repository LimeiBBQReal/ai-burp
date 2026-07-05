"""
Recon Pipeline V2 - 协议探测基类

所有协议探测模块必须继承此类，实现:
- protocol_name: 协议名称
- default_ports: 默认端口列表
- probe_packet: 探测包（发送到目标以获取响应）
- parse_response: 解析响应，返回 ProbeResult
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class ProbeResult:
    """协议探测结果"""
    protocol: str
    is_match: bool
    confidence: float          # 0-1 匹配置信度
    banner: str = ""           # 服务 Banner
    version: str = ""          # 版本信息
    config: Dict[str, Any] = field(default_factory=dict)  # 额外配置信息
    raw_response: bytes = b""  # 原始响应
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """尝试将响应解码为文本"""
        try:
            return self.raw_response.decode('utf-8', errors='ignore')
        except:
            return ""


class BaseProtocolProbe(ABC):
    """
    协议探测基类

    子类必须实现:
    - protocol_name (property)
    - default_ports (property)
    - probe_packet (property)
    - parse_response (method)
    """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """协议名称 (如 'http', 'ssh', 'redis')"""
        ...

    @property
    @abstractmethod
    def default_ports(self) -> list:
        """该协议默认端口列表"""
        ...

    @property
    def timeout(self) -> int:
        """连接超时（秒）"""
        return 5

    @property
    def max_concurrency(self) -> int:
        """最大并发数"""
        return 50

    @property
    def retry_count(self) -> int:
        """重试次数"""
        return 1

    @property
    @abstractmethod
    def probe_packet(self) -> bytes:
        """
        探测包 - 发送到目标以获取响应

        注意: 某些协议（如 MySQL）服务器会主动发送握手包，
        此时 probe_packet 可以返回空 bytes，只需接收即可。
        """
        ...

    @abstractmethod
    def parse_response(self, response: bytes) -> ProbeResult:
        """
        解析响应数据

        Args:
            response: 从目标接收的原始字节

        Returns:
            ProbeResult: 解析结果
        """
        ...

    def probe(self, ip: str, port: int) -> ProbeResult:
        """
        执行完整探测流程

        子类通常不需要重写此方法，
        只需实现 probe_packet 和 parse_response 即可。
        """
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # 发送探测包
            packet = self.probe_packet
            if packet:
                sock.send(packet)

            # 接收响应
            response = sock.recv(4096)
            sock.close()

            # 解析
            result = self.parse_response(response)
            result.raw_response = response
            return result

        except socket.timeout:
            return ProbeResult(
                protocol=self.protocol_name,
                is_match=False,
                confidence=0.0,
                metadata={"error": "timeout"},
            )
        except ConnectionRefusedError:
            return ProbeResult(
                protocol=self.protocol_name,
                is_match=False,
                confidence=0.0,
                metadata={"error": "connection_refused"},
            )
        except OSError as e:
            return ProbeResult(
                protocol=self.protocol_name,
                is_match=False,
                confidence=0.0,
                metadata={"error": str(e)},
            )

    def probe_with_retry(self, ip: str, port: int) -> ProbeResult:
        """带重试的探测"""
        result = self.probe(ip, port)

        if result.is_match:
            return result

        for _ in range(self.retry_count):
            result = self.probe(ip, port)
            if result.is_match:
                break

        return result
