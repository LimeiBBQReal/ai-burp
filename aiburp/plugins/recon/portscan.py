'''端口扫描插件'''
from typing import Dict, List, Optional
from ...plugins import AuxPlugin, PluginResult
from ...core.history import History
from ...portscan import PortScanner, NetworkScanner

class PortscanPlugin(AuxPlugin):
    name = "portscan"
    description = "端口扫描"
    
    def __init__(self, history: History = None):
        self.history = history
        self.scanner = PortScanner()
    
    def execute(self, target: str = "", ports: str = "top100", **kwargs) -> PluginResult:
        if not target:
            return PluginResult(success=False, error="Target required")
        try:
            result = self.scanner.scan(target, ports=ports)
            return PluginResult(success=True, data={"open_ports": [{"port": p.port, "service": p.service} for p in result.open_ports]})
        except Exception as e:
            return PluginResult(success=False, error=str(e))

class QuickAlivePlugin(AuxPlugin):
    name = "quick_alive"
    description = "存活探测"
    
    def __init__(self, history: History = None):
        self.history = history
    
    def execute(self, cidr: str = "", **kwargs) -> PluginResult:
        return PluginResult(success=True, data={"cidr": cidr})
