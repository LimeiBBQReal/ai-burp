"""
Recon Pipeline V2 - 协议注册表

管理所有协议探测模块的注册和查找。
新协议只需实现 BaseProtocolProbe 并调用 register_probe 即可自动注册。
"""
from typing import Dict, Optional, Type
from .base import BaseProtocolProbe


class ProtocolRegistry:
    """
    协议注册表 - 单例模式

    管理所有已注册的协议探测类，
    支持按名称或端口查找。
    """
    _instance = None
    _probes: Dict[str, Type[BaseProtocolProbe]] = {}
    _port_map: Dict[int, list] = {}  # port -> [protocol_name, ...]

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def register(self, probe_class: Type[BaseProtocolProbe]) -> None:
        """
        注册协议探测类

        Args:
            probe_class: 继承自 BaseProtocolProbe 的类
        """
        # 实例化以获取属性
        instance = probe_class()
        name = instance.protocol_name.lower()

        # 注册到名称映射
        self._probes[name] = probe_class

        # 注册到端口映射
        for port in instance.default_ports:
            if port not in self._port_map:
                self._port_map[port] = []
            if name not in self._port_map[port]:
                self._port_map[port].append(name)

    def get(self, name: str) -> Optional[Type[BaseProtocolProbe]]:
        """按名称获取协议探测类"""
        return self._probes.get(name.lower())

    def get_by_port(self, port: int) -> list:
        """按端口获取可能的协议列表"""
        return self._port_map.get(port, [])

    def create(self, name: str) -> Optional[BaseProtocolProbe]:
        """按名称创建协议探测实例"""
        cls = self.get(name)
        return cls() if cls else None

    def list_protocols(self) -> list:
        """列出所有已注册的协议"""
        return list(self._probes.keys())

    def list_ports(self) -> list:
        """列出所有已注册的端口"""
        return sorted(self._port_map.keys())

    def build_port_index(self) -> Dict[int, str]:
        """
        构建端口到协议的快速索引

        返回: {port: protocol_name, ...}
        如果多个协议共享同一端口，取第一个。
        """
        return {port: names[0] for port, names in self._port_map.items()}


# 全局注册表实例
registry = ProtocolRegistry()


def register_probe(probe_class: Type[BaseProtocolProbe]) -> Type[BaseProtocolProbe]:
    """
    协议注册装饰器/函数

    用法:
        @register_probe
        class MyProbe(BaseProtocolProbe):
            ...

    或:
        register_probe(MyProbe)
    """
    registry.register(probe_class)
    return probe_class


def auto_register_builtin():
    """自动注册所有内置协议模块"""
    from .http import HTTPProbe, HTTPSProbe
    from .ssh import SSHProbe
    from .ftp import FTPProbe
    from .mysql import MySQLProbe
    from .redis import RedisProbe
    from .mongodb import MongoDBProbe
    from .postgres import PostgresProbe
    from .memcached import MemcachedProbe
    from .elasticsearch import ElasticsearchProbe
    from .smtp import SMTPProbe

    registry.register(HTTPProbe)
    registry.register(HTTPSProbe)
    registry.register(SSHProbe)
    registry.register(FTPProbe)
    registry.register(MySQLProbe)
    registry.register(RedisProbe)
    registry.register(MongoDBProbe)
    registry.register(PostgresProbe)
    registry.register(MemcachedProbe)
    registry.register(ElasticsearchProbe)
    registry.register(SMTPProbe)
