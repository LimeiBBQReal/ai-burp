"""
crt.sh API 集成

功能:
- CT Logs 子域名查询
- 证书详情

API: https://crt.sh
免费: 无限制
"""

import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests

from ....plugins import AuxPlugin, PluginResult
from ....core.history import History


@dataclass
class CrtshCert:
    """crt.sh 证书信息"""
    id: int
    issuer_ca_id: int
    issuer_name: str
    common_name: str
    name_value: str  # 可能包含多个域名
    not_before: str
    not_after: str
    serial_number: str
    
    @property
    def domains(self) -> List[str]:
        """提取所有域名"""
        return [d.strip() for d in self.name_value.split("\n") if d.strip()]
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "issuer_ca_id": self.issuer_ca_id,
            "issuer_name": self.issuer_name,
            "common_name": self.common_name,
            "name_value": self.name_value,
            "domains": self.domains,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial_number": self.serial_number,
        }


class CrtshClient:
    """crt.sh 客户端"""
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    def search(self, domain: str, wildcard: bool = True, 
               dedupe: bool = True) -> List[CrtshCert]:
        """
        搜索证书
        
        Args:
            domain: 域名
            wildcard: 是否包含通配符子域名
            dedupe: 是否去重
        
        Returns:
            CrtshCert 列表
        """
        query = f"%.{domain}" if wildcard else domain
        
        params = {
            "q": query,
            "output": "json",
        }
        
        if dedupe:
            params["deduplicate"] = "Y"
        
        resp = requests.get(
            self.BASE_URL,
            params=params,
            timeout=self.timeout,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        if resp.status_code != 200:
            raise ValueError(f"crt.sh error: {resp.status_code}")
        
        # 可能返回空或非 JSON
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return []
        
        if not data:
            return []
        
        certs = []
        for item in data:
            cert = CrtshCert(
                id=item.get("id", 0),
                issuer_ca_id=item.get("issuer_ca_id", 0),
                issuer_name=item.get("issuer_name", ""),
                common_name=item.get("common_name", ""),
                name_value=item.get("name_value", ""),
                not_before=item.get("not_before", ""),
                not_after=item.get("not_after", ""),
                serial_number=item.get("serial_number", ""),
            )
            certs.append(cert)
        
        return certs
    
    def get_subdomains(self, domain: str) -> List[str]:
        """
        获取子域名
        
        Args:
            domain: 域名
        
        Returns:
            子域名列表 (去重、排序)
        """
        certs = self.search(domain, wildcard=True, dedupe=True)
        
        subdomains = set()
        for cert in certs:
            for name in cert.domains:
                # 清理
                name = name.lower().strip()
                # 跳过通配符
                if name.startswith("*"):
                    continue
                # 确保是目标域名的子域名
                if name.endswith(domain) or name == domain:
                    subdomains.add(name)
        
        return sorted(subdomains)
    
    def get_cert_detail(self, cert_id: int) -> Dict:
        """
        获取证书详情
        
        Args:
            cert_id: 证书 ID
        
        Returns:
            证书详情 dict
        """
        resp = requests.get(
            f"{self.BASE_URL}/?id={cert_id}",
            timeout=self.timeout,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        if resp.status_code != 200:
            raise ValueError(f"crt.sh error: {resp.status_code}")
        
        # 解析 HTML (简化)
        html = resp.text
        
        detail = {"id": cert_id}
        
        # 提取 PEM
        pem_match = re.search(r'<pre[^>]*>(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)</pre>', 
                             html, re.DOTALL)
        if pem_match:
            detail["pem"] = pem_match.group(1).strip()
        
        return detail


class CrtshPlugin(AuxPlugin):
    """crt.sh 插件"""
    
    name = "crtsh"
    description = "crt.sh CT Logs 查询 (子域名发现)"
    
    def __init__(self, history: History = None):
        self.history = history
        self.client = CrtshClient()
    
    def execute(
        self,
        action: str = "subdomains",
        domain: str = "",
        **kwargs
    ) -> PluginResult:
        """
        执行 crt.sh 查询
        
        Args:
            action: 操作类型 (subdomains/certs)
            domain: 目标域名
        
        Returns:
            PluginResult
        """
        if not domain:
            return PluginResult(success=False, error="Domain is required")
        
        try:
            if action == "subdomains":
                return self._get_subdomains(domain)
            elif action == "certs":
                return self._search_certs(domain)
            else:
                return PluginResult(success=False, error=f"Unknown action: {action}")
        
        except Exception as e:
            return PluginResult(success=False, error=f"crt.sh error: {e}")
    
    def _get_subdomains(self, domain: str) -> PluginResult:
        """获取子域名"""
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
    
    def _search_certs(self, domain: str) -> PluginResult:
        """搜索证书"""
        certs = self.client.search(domain)
        
        return PluginResult(
            success=True,
            data={
                "action": "certs",
                "domain": domain,
                "count": len(certs),
                "certs": [c.to_dict() for c in certs],
            }
        )
