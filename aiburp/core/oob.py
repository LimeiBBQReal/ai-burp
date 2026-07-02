"""
Interactsh OOB 外带检测模块

支持:
- 从 interactsh 服务器获取临时 URL
- 轮询检查是否收到回调
- 支持 HTTP/DNS/SMTP 等多种协议

使用:
    oob = InteractshClient()
    url = oob.get_url()  # 获取 xxx.oast.fun
    # 发送 payload 包含这个 URL
    result = oob.poll()  # 检查是否收到回调
"""

import json
import time
import base64
import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

import requests


@dataclass
class OOBCallback:
    """OOB 回调记录"""
    protocol: str  # http, dns, smtp
    timestamp: str
    remote_address: str
    raw_request: str = ""
    data: Dict = field(default_factory=dict)


class InteractshClient:
    """
    Interactsh OOB 客户端
    
    使用示例:
        oob = InteractshClient()
        
        # 获取 OOB URL
        url = oob.get_url()
        print(f"Use this URL: {url}")
        
        # 发送包含 URL 的 payload 后...
        
        # 检查回调
        callbacks = oob.poll()
        if callbacks:
            print("Got callback!")
            for cb in callbacks:
                print(f"  {cb.protocol} from {cb.remote_address}")
    """
    
    DEFAULT_SERVER = "oast.fun"
    
    def __init__(self, server: str = None, token: str = None):
        self.server = server or self.DEFAULT_SERVER
        self.token = token
        self.correlation_id = None
        self.secret_key = None
        self._registered = False
        self._session = requests.Session()
    
    def register(self) -> str:
        """
        注册并获取 correlation ID
        
        Returns:
            OOB URL (如 xxx.oast.fun)
        """
        # 生成随机 correlation ID (33 字符)
        self.correlation_id = secrets.token_hex(16) + "a"
        self.secret_key = secrets.token_hex(16)
        
        # 注册到服务器
        url = f"https://{self.server}/register"
        data = {
            "public-key": "",
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id,
        }
        
        try:
            resp = self._session.post(url, json=data, timeout=10)
            if resp.status_code == 200:
                self._registered = True
                return f"{self.correlation_id}.{self.server}"
        except:
            pass
        
        # 如果注册失败，使用简化模式 (只生成 URL，手动检查)
        self._registered = False
        return f"{self.correlation_id}.{self.server}"
    
    def get_url(self, prefix: str = "") -> str:
        """
        获取 OOB URL
        
        Args:
            prefix: 可选前缀 (用于区分不同测试)
        
        Returns:
            完整 OOB URL
        """
        if not self.correlation_id:
            self.register()
        
        if prefix:
            return f"{prefix}.{self.correlation_id}.{self.server}"
        return f"{self.correlation_id}.{self.server}"
    
    def get_http_url(self, prefix: str = "") -> str:
        """获取 HTTP URL"""
        return f"http://{self.get_url(prefix)}"
    
    def get_https_url(self, prefix: str = "") -> str:
        """获取 HTTPS URL"""
        return f"https://{self.get_url(prefix)}"
    
    def poll(self, timeout: int = 30, interval: float = 2) -> List[OOBCallback]:
        """
        轮询检查回调
        
        Args:
            timeout: 超时时间 (秒)
            interval: 轮询间隔 (秒)
        
        Returns:
            OOBCallback 列表
        """
        if not self.correlation_id:
            return []
        
        callbacks = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                url = f"https://{self.server}/poll"
                params = {
                    "id": self.correlation_id,
                    "secret": self.secret_key or "",
                }
                
                resp = self._session.get(url, params=params, timeout=10)
                
                if resp.status_code == 200:
                    data = resp.json()
                    
                    for item in data.get("data", []):
                        cb = OOBCallback(
                            protocol=item.get("protocol", "unknown"),
                            timestamp=item.get("timestamp", ""),
                            remote_address=item.get("remote-address", ""),
                            raw_request=item.get("raw-request", ""),
                            data=item,
                        )
                        callbacks.append(cb)
                    
                    if callbacks:
                        return callbacks
                
            except Exception as e:
                pass
            
            time.sleep(interval)
        
        return callbacks
    
    def check_once(self) -> List[OOBCallback]:
        """单次检查 (不轮询)"""
        return self.poll(timeout=1, interval=0.5)
    
    def deregister(self):
        """注销"""
        if self._registered and self.correlation_id:
            try:
                url = f"https://{self.server}/deregister"
                data = {
                    "correlation-id": self.correlation_id,
                    "secret-key": self.secret_key,
                }
                self._session.post(url, json=data, timeout=5)
            except:
                pass
        
        self.correlation_id = None
        self.secret_key = None
        self._registered = False
    
    def __enter__(self):
        self.register()
        return self
    
    def __exit__(self, *args):
        self.deregister()


class OOBManager:
    """
    OOB 管理器 - 简化使用
    
    使用示例:
        oob = OOBManager()
        
        # 生成带标记的 URL
        ssrf_url = oob.generate("ssrf-test")
        sqli_url = oob.generate("sqli-test")
        
        # 发送 payload 后检查
        if oob.check("ssrf-test"):
            print("SSRF confirmed!")
    """
    
    def __init__(self, server: str = None):
        self.server = server or InteractshClient.DEFAULT_SERVER
        self._client = InteractshClient(server=self.server)
        self._client.register()
        self._markers: Dict[str, str] = {}
    
    def generate(self, marker: str) -> str:
        """
        生成带标记的 OOB URL
        
        Args:
            marker: 标记名 (用于后续检查)
        
        Returns:
            OOB URL
        """
        url = self._client.get_http_url(prefix=marker)
        self._markers[marker] = url
        return url
    
    def check(self, marker: str = None, timeout: int = 10) -> bool:
        """
        检查是否收到回调
        
        Args:
            marker: 标记名 (None 检查所有)
            timeout: 超时时间
        
        Returns:
            是否收到回调
        """
        callbacks = self._client.poll(timeout=timeout)
        
        if not callbacks:
            return False
        
        if marker:
            # 检查特定标记
            for cb in callbacks:
                if marker in cb.raw_request or marker in str(cb.data):
                    return True
            return False
        
        return len(callbacks) > 0
    
    def get_callbacks(self, timeout: int = 10) -> List[OOBCallback]:
        """获取所有回调"""
        return self._client.poll(timeout=timeout)
    
    def close(self):
        """关闭并清理"""
        self._client.deregister()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


# 便捷函数
def create_oob(server: str = None) -> OOBManager:
    """创建 OOB 管理器"""
    return OOBManager(server=server)
