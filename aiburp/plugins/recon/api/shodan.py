"""
Shodan API 集成

功能:
- IP 信息查询 (端口/服务/漏洞)
- 搜索 (关键词/org:/favicon.hash:)
- Favicon hash 计算和搜索
- DNS 查询

API 文档: https://developer.shodan.io/api
"""

import json
import hashlib
import base64
import struct
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests

from . import get_api_key
from ....plugins import AuxPlugin, PluginResult
from ....core.history import History
from ....core.models import Request, Response


@dataclass
class ShodanHost:
    """Shodan 主机信息"""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    os: str = ""
    org: str = ""
    isp: str = ""
    asn: str = ""
    country: str = ""
    city: str = ""
    services: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "ports": self.ports,
            "vulns": self.vulns,
            "os": self.os,
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "country": self.country,
            "city": self.city,
            "services": self.services,
        }


class ShodanClient:
    """Shodan API 客户端"""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or get_api_key("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError("SHODAN_API_KEY not set")
    
    def _request(self, endpoint: str, params: Dict = None) -> Dict:
        """发送 API 请求"""
        params = params or {}
        params["key"] = self.api_key
        
        url = f"{self.BASE_URL}{endpoint}"
        resp = requests.get(url, params=params, timeout=30)
        
        if resp.status_code == 401:
            raise ValueError("Invalid Shodan API key")
        elif resp.status_code == 429:
            raise ValueError("Shodan API rate limit exceeded")
        elif resp.status_code != 200:
            raise ValueError(f"Shodan API error: {resp.status_code}")
        
        return resp.json()
    
    def host(self, ip: str) -> ShodanHost:
        """
        查询 IP 信息
        
        Args:
            ip: IP 地址
        
        Returns:
            ShodanHost 对象
        """
        data = self._request(f"/shodan/host/{ip}")
        
        host = ShodanHost(ip=ip)
        host.hostnames = data.get("hostnames", [])
        host.ports = data.get("ports", [])
        host.vulns = list(data.get("vulns", {}).keys()) if data.get("vulns") else []
        host.os = data.get("os", "")
        host.org = data.get("org", "")
        host.isp = data.get("isp", "")
        host.asn = data.get("asn", "")
        host.country = data.get("country_name", "")
        host.city = data.get("city", "")
        
        # 服务详情
        for item in data.get("data", []):
            service = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:500],
            }
            
            # HTTP 信息
            if "http" in item:
                service["http"] = {
                    "title": item["http"].get("title", ""),
                    "server": item["http"].get("server", ""),
                    "status": item["http"].get("status"),
                }
            
            # SSL 信息
            if "ssl" in item:
                service["ssl"] = {
                    "cert_subject": item["ssl"].get("cert", {}).get("subject", {}),
                    "cert_issuer": item["ssl"].get("cert", {}).get("issuer", {}),
                }
            
            host.services.append(service)
        
        return host
    
    def search(self, query: str, limit: int = 100) -> List[ShodanHost]:
        """
        搜索
        
        Args:
            query: 搜索语句 (如 "org:Google", "http.favicon.hash:123456")
            limit: 返回数量
        
        Returns:
            ShodanHost 列表
        """
        data = self._request("/shodan/host/search", {"query": query})
        
        hosts = []
        for match in data.get("matches", [])[:limit]:
            host = ShodanHost(ip=match.get("ip_str", ""))
            host.hostnames = match.get("hostnames", [])
            host.ports = [match.get("port")]
            host.org = match.get("org", "")
            host.country = match.get("location", {}).get("country_name", "")
            host.city = match.get("location", {}).get("city", "")
            
            service = {
                "port": match.get("port"),
                "product": match.get("product", ""),
                "version": match.get("version", ""),
            }
            if "http" in match:
                service["http"] = {
                    "title": match["http"].get("title", ""),
                    "server": match["http"].get("server", ""),
                }
            host.services.append(service)
            
            hosts.append(host)
        
        return hosts
    
    def search_count(self, query: str) -> int:
        """获取搜索结果数量"""
        data = self._request("/shodan/host/count", {"query": query})
        return data.get("total", 0)
    
    def dns_resolve(self, hostnames: List[str]) -> Dict[str, str]:
        """DNS 解析"""
        data = self._request("/dns/resolve", {"hostnames": ",".join(hostnames)})
        return data
    
    def dns_reverse(self, ips: List[str]) -> Dict[str, List[str]]:
        """反向 DNS"""
        data = self._request("/dns/reverse", {"ips": ",".join(ips)})
        return data
    
    @staticmethod
    def favicon_hash(content: bytes) -> int:
        """
        计算 Favicon hash (Shodan/Fofa 格式)
        
        Args:
            content: favicon 文件内容
        
        Returns:
            MurmurHash3 值
        """
        # Base64 编码
        b64 = base64.b64encode(content).decode()
        # 添加换行 (Shodan 格式)
        b64_with_newlines = "\n".join([b64[i:i+76] for i in range(0, len(b64), 76)]) + "\n"
        # MurmurHash3
        return ShodanClient._mmh3_hash(b64_with_newlines.encode())
    
    @staticmethod
    def _mmh3_hash(data: bytes, seed: int = 0) -> int:
        """MurmurHash3 32-bit"""
        try:
            import mmh3
            return mmh3.hash(data, seed)
        except ImportError:
            # 简化实现
            h = seed
            for i in range(0, len(data), 4):
                k = int.from_bytes(data[i:i+4].ljust(4, b'\x00'), 'little')
                k = (k * 0xcc9e2d51) & 0xffffffff
                k = ((k << 15) | (k >> 17)) & 0xffffffff
                k = (k * 0x1b873593) & 0xffffffff
                h ^= k
                h = ((h << 13) | (h >> 19)) & 0xffffffff
                h = ((h * 5) + 0xe6546b64) & 0xffffffff
            h ^= len(data)
            h ^= h >> 16
            h = (h * 0x85ebca6b) & 0xffffffff
            h ^= h >> 13
            h = (h * 0xc2b2ae35) & 0xffffffff
            h ^= h >> 16
            # 转为有符号整数
            if h >= 0x80000000:
                h -= 0x100000000
            return h


class ShodanPlugin(AuxPlugin):
    """Shodan 插件"""
    
    name = "shodan"
    description = "Shodan API 查询 (IP信息/搜索/Favicon)"
    
    def __init__(self, history: History = None):
        self.history = history
        self._client = None
    
    @property
    def client(self) -> ShodanClient:
        if self._client is None:
            self._client = ShodanClient()
        return self._client
    
    def execute(
        self,
        action: str = "host",
        target: str = "",
        query: str = "",
        **kwargs
    ) -> PluginResult:
        """
        执行 Shodan 查询
        
        Args:
            action: 操作类型 (host/search/favicon/dns)
            target: 目标 (IP/域名/URL)
            query: 搜索语句
        
        Returns:
            PluginResult
        """
        try:
            if action == "host":
                return self._host_info(target)
            elif action == "search":
                return self._search(query or target)
            elif action == "favicon":
                return self._favicon_search(target)
            elif action == "dns":
                return self._dns_lookup(target)
            elif action == "org":
                return self._org_search(target)
            else:
                return PluginResult(success=False, error=f"Unknown action: {action}")
        
        except ValueError as e:
            return PluginResult(success=False, error=str(e))
        except Exception as e:
            return PluginResult(success=False, error=f"Shodan error: {e}")
    
    def _host_info(self, ip: str) -> PluginResult:
        """查询 IP 信息"""
        if not ip:
            return PluginResult(success=False, error="IP is required")
        
        host = self.client.host(ip)
        
        return PluginResult(
            success=True,
            data={
                "action": "host",
                "host": host.to_dict(),
            }
        )
    
    def _search(self, query: str) -> PluginResult:
        """搜索"""
        if not query:
            return PluginResult(success=False, error="Query is required")
        
        hosts = self.client.search(query)
        count = self.client.search_count(query)
        
        return PluginResult(
            success=True,
            data={
                "action": "search",
                "query": query,
                "total": count,
                "results": [h.to_dict() for h in hosts],
            }
        )
    
    def _favicon_search(self, url: str) -> PluginResult:
        """Favicon 搜索"""
        if not url:
            return PluginResult(success=False, error="URL is required")
        
        # 获取 favicon
        if not url.endswith("/favicon.ico"):
            if url.endswith("/"):
                url += "favicon.ico"
            else:
                url += "/favicon.ico"
        
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code != 200:
                return PluginResult(success=False, error="Failed to fetch favicon")
            
            # 计算 hash
            fav_hash = ShodanClient.favicon_hash(resp.content)
            
            # 搜索
            query = f"http.favicon.hash:{fav_hash}"
            hosts = self.client.search(query)
            count = self.client.search_count(query)
            
            return PluginResult(
                success=True,
                data={
                    "action": "favicon",
                    "url": url,
                    "hash": fav_hash,
                    "query": query,
                    "total": count,
                    "results": [h.to_dict() for h in hosts],
                }
            )
        
        except Exception as e:
            return PluginResult(success=False, error=f"Favicon error: {e}")
    
    def _dns_lookup(self, target: str) -> PluginResult:
        """DNS 查询"""
        if not target:
            return PluginResult(success=False, error="Target is required")
        
        # 判断是 IP 还是域名
        import re
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            # 反向 DNS
            result = self.client.dns_reverse([target])
            return PluginResult(
                success=True,
                data={
                    "action": "dns_reverse",
                    "ip": target,
                    "hostnames": result.get(target, []),
                }
            )
        else:
            # 正向 DNS
            result = self.client.dns_resolve([target])
            return PluginResult(
                success=True,
                data={
                    "action": "dns_resolve",
                    "hostname": target,
                    "ip": result.get(target),
                }
            )
    
    def _org_search(self, org: str) -> PluginResult:
        """组织搜索"""
        if not org:
            return PluginResult(success=False, error="Organization is required")
        
        query = f'org:"{org}"'
        return self._search(query)
