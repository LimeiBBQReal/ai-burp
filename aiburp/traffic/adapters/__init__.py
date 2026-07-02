"""
协议适配器集合.

每个具体协议一个文件, 实现统一的 ProtocolAdapter 契约.
注册顺序即优先级 (当 smart_probe 自动识别时, 按此顺序尝试).
"""

from .fingerprints import (
    KNOWN_PORT_SERVICE,
    BANNER_SIGNATURES,
    detect_service_by_port,
    detect_service_by_banner,
    split_host_port,
)
from .http import HttpAdapter
from .tcp import TcpAdapter
from .dns import DnsAdapter
from .redis import RedisAdapter
from .docker import DockerAdapter
from .kubelet import KubeletAdapter
from .udp import UdpAdapter
from .tls import TlsAdapter
from .snmp import SnmpAdapter
from .mysql import MysqlAdapter
from .rmi import RmiAdapter
from .smb import SmbAdapter
from .ftp import FtpAdapter
from .ssh import SshAdapter

# WebSocket 是可选依赖 (需 websockets 库), 失败不阻断其它 adapter
try:
    from .websocket import WebSocketAdapter
    _WS_EXPORTED = True
except ImportError:
    WebSocketAdapter = None  # type: ignore
    _WS_EXPORTED = False

__all__ = [
    # 指纹工具
    "KNOWN_PORT_SERVICE",
    "BANNER_SIGNATURES",
    "detect_service_by_port",
    "detect_service_by_banner",
    "split_host_port",
    # 适配器
    "HttpAdapter",
    "TcpAdapter",
    "DnsAdapter",
    "RedisAdapter",
    "DockerAdapter",
    "KubeletAdapter",
    "UdpAdapter",
    "TlsAdapter",
    "SnmpAdapter",
    "MysqlAdapter",
    "RmiAdapter",
    "SmbAdapter",
    "FtpAdapter",
    "SshAdapter",
    "WebSocketAdapter",
]
