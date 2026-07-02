"""
Censys API 集成

功能:
- 主机搜索 (IP/端口/服务)
- 证书搜索 (发现子域名)
- 证书详情

API 文档: https://search.censys.io/api
免费额度: 100次/月
"""

import json
import base64
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests

from . import get_api_key
from ....plugins import AuxPlugin, PluginResult
from ....core.history import History


@dataclass
class CensysHost:
    """Censys 主机信息"""
    ip: str
    services: List[Dict] = field(default_factory=list)
    location: Dict = field(default_factory=dict)
    autonomous_system: Dict = field(default_factory=dict)
    operating_system: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "services": self.services,
            "location": self.location,
            "autonomous_system": self.autonomous_system,
            "operating_system": self.operating_system,
        }


@dataclass
class CensysCert:
    """Censys 证书信息"""
    fingerprint: str
    names: List[str] = field(default_factory=list)
    subject: Dict = field(default_factory=dict)
    issuer: Dict = field(default_factory=dict)
    validity: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "fingerprint": self.fingerprint,
            "names": self.names,
            "subject": self.subject,
            "issuer": self.issuer,
            "validity": self.validity,
        }


class CensysClient:
    """Censys API 客户端 (支持新版单 API Key)"""
    
    BASE_URL = "https://search.censys.io/api"
    
    def __init__(self, api_key: str = None, api_id: str = None, api_secret: str = None):
        # 新版: 单个 API Key
        self.api_key = api_key or get_api_key("CENSYS_API_KEY")
        
        # 旧版兼容: API ID + Secret
        self.api_id = api_id or get_api_key("CENSYS_API_ID")
        self.api_secret = api_secret or get_api_key("CENSYS_API_SECRET")
        
        if not self.api_key and not (self.api_id and self.api_secret):
            raise ValueError("CENSYS_API_KEY (or CENSYS_API_ID + CENSYS_API_SECRET) not set")
    
    def _request(self, endpoint: str, method: str = "GET", 
                 params: Dict = None, data: Dict = None) -> Dict:
        """发送 API 请求"""
        url = f"{self.BASE_URL}{endpoint}"
        
        headers = {}
        auth = None
        
        # 新版: Bearer Token
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        # 旧版: Basic Auth
        else:
            auth = (self.api_id, self.api_secret)
        
        if method == "GET":
            resp = requests.get(url, params=params, auth=auth, headers=headers, timeout=30)
        else:
            resp = requests.post(url, json=data, auth=auth, headers=headers, timeout=30)
        
        if resp.status_code == 401:
            raise ValueError("Invalid Censys API credentials")
        elif resp.status_code == 429:
            raise ValueError("Censys API rate limit exceeded")
        elif resp.status_code != 200:
            raise ValueError(f"Censys API error: {resp.status_code} - {resp.text}")
        
        return resp.json()
    
    def search_hosts(self, query: str, per_page: int = 25) -> List[CensysHost]:
        """
        搜索主机
        
        Args:
            query: 搜索语句
            per_page: 每页数量
        
        Returns:
            CensysHost 列表
        """
        data = self._request("/v2/hosts/search", method="GET", params={
            "q": query,
            "per_page": per_page,
        })
        
        hosts = []
        for hit in data.get("result", {}).get("hits", []):
            host = CensysHost(ip=hit.get("ip", ""))
            host.services = hit.get("services", [])
            host.location = hit.get("location", {})
            host.autonomous_system = hit.get("autonomous_system", {})
            host.operating_system = hit.get("operating_system", {}).get("product", "")
            hosts.append(host)
        
        return hosts
    
    def view_host(self, ip: str) -> CensysHost:
        """
        查看主机详情
        
        Args:
            ip: IP 地址
        
        Returns:
            CensysHost 对象
        """
        data = self._request(f"/v2/hosts/{ip}")
        
        result = data.get("result", {})
        host = CensysHost(ip=ip)
        host.services = result.get("services", [])
        host.location = result.get("location", {})
        host.autonomous_system = result.get("autonomous_system", {})
        host.operating_system = result.get("operating_system", {}).get("product", "")
        
        return host
    
    def search_certs(self, query: str, per_page: int = 25) -> List[CensysCert]:
        """
        搜索证书
        
        Args:
            query: 搜索语句 (如 "parsed.names: example.com")
            per_page: 每页数量
        
        Returns:
            CensysCert 列表
        """
        data = self._request("/v2/certificates/search", method="GET", params={
            "q": query,
            "per_page": per_page,
        })
        
        certs = []
        for hit in data.get("result", {}).get("hits", []):
            cert = CensysCert(fingerprint=hit.get("fingerprint_sha256", ""))
            cert.names = hit.get("names", [])
            cert.subject = hit.get("parsed", {}).get("subject", {})
            cert.issuer = hit.get("parsed", {}).get("issuer", {})
            cert.validity = hit.get("parsed", {}).get("validity", {})
            certs.append(cert)
        
        return certs
    
    def get_subdomains(self, domain: str) -> List[str]:
        """
        通过证书搜索获取子域名
        
        Args:
            domain: 域名
        
        Returns:
            子域名列表
        """
        query = f"parsed.names: {domain}"
        certs = self.search_certs(query, per_page=100)
        
        subdomains = set()
        for cert in certs:
            for name in cert.names:
                if name.endswith(domain) and not name.startswith("*"):
                    subdomains.add(name)
        
        return sorted(subdomains)


class CensysPlugin(AuxPlugin):
    """Censys 插件"""
    
    name = "censys"
    description = "Censys API 查询 (主机/证书/子域名)"
    
    def __init__(self, history: History = None):
        self.history = history
        self._client = None
    
    @property
    def client(self) -> CensysClient:
        if self._client is None:
            self._client = CensysClient()
        return self._client
    
    def execute(
        self,
        action: str = "host",
        target: str = "",
        query: str = "",
        **kwargs
    ) -> PluginResult:
        """
        执行 Censys 查询
        
        Args:
            action: 操作类型 (host/search/certs/subdomains)
            target: 目标 (IP/域名)
            query: 搜索语句
        
        Returns:
            PluginResult
        """
        try:
            if action == "host":
                return self._host_info(target)
            elif action == "search":
                return self._search_hosts(query or target)
            elif action == "certs":
                return self._search_certs(query or target)
            elif action == "subdomains":
                return self._get_subdomains(target)
            else:
                return PluginResult(success=False, error=f"Unknown action: {action}")
        
        except ValueError as e:
            return PluginResult(success=False, error=str(e))
        except Exception as e:
            return PluginResult(success=False, error=f"Censys error: {e}")
    
    def _host_info(self, ip: str) -> PluginResult:
        """查询主机信息"""
        if not ip:
            return PluginResult(success=False, error="IP is required")
        
        host = self.client.view_host(ip)
        
        return PluginResult(
            success=True,
            data={
                "action": "host",
                "host": host.to_dict(),
            }
        )
    
    def _search_hosts(self, query: str) -> PluginResult:
        """搜索主机"""
        if not query:
            return PluginResult(success=False, error="Query is required")
        
        hosts = self.client.search_hosts(query)
        
        return PluginResult(
            success=True,
            data={
                "action": "search",
                "query": query,
                "results": [h.to_dict() for h in hosts],
            }
        )
    
    def _search_certs(self, query: str) -> PluginResult:
        """搜索证书"""
        if not query:
            return PluginResult(success=False, error="Query is required")
        
        certs = self.client.search_certs(query)
        
        return PluginResult(
            success=True,
            data={
                "action": "certs",
                "query": query,
                "results": [c.to_dict() for c in certs],
            }
        )
    
    def _get_subdomains(self, domain: str) -> PluginResult:
        """获取子域名"""
        if not domain:
            return PluginResult(success=False, error="Domain is required")
        
        subdomains = self.client.get_subdomains(domain)
        
        return PluginResult(
            success=True,
            data={
                "action": "subdomains",
                "domain": domain,
                "count": len(subdomains),
                "subdomains": subdomains,
            }
        )
