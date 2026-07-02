"""
子域名枚举插件 (包装现有模块)

所有 HTTP 验证流量都记录到 History
"""

from typing import Dict, List, Any
from aiburp.plugins import AuxPlugin, PluginResult
from aiburp.core.history import History
from aiburp.core.models import Request, Response
from aiburp.subdomain import SubdomainEnum, EnumReport


class SubdomainPlugin(AuxPlugin):
    """子域名枚举插件"""
    
    name = "subdomain"
    description = "子域名枚举 (DNS + HTTP验证，流量记录到History)"
    
    def __init__(self, history: History = None):
        self.history = history
    
    def execute(
        self,
        domain: str = "",
        deep: bool = False,
        use_ct: bool = False,
        **kwargs
    ) -> PluginResult:
        """
        执行子域名枚举
        
        Args:
            domain: 目标域名
            deep: 是否深度枚举 (三级子域名)
            use_ct: 是否使用 CT Logs
        
        Returns:
            PluginResult with subdomains
        """
        if not domain:
            return PluginResult(success=False, error="Domain is required")
        
        try:
            enum = SubdomainEnumWithHistory(domain, history=self.history)
            
            # CT Logs
            ct_domains = []
            if use_ct:
                ct_domains = enum.get_ct_domains()
            
            # 枚举
            if deep:
                report = enum.deep_enumerate()
            else:
                report = enum.enumerate()
            
            # 转换结果
            return PluginResult(
                success=True,
                data={
                    "domain": domain,
                    "total_tested": report.total_tested,
                    "total_resolved": report.total_resolved,
                    "total_real": report.total_real,
                    "has_wildcard": report.has_wildcard,
                    "wildcard_ips": list(report.wildcard_ips),
                    "ct_domains": ct_domains,
                    "real_domains": [r.to_dict() for r in report.real_domains],
                    "all_results": [r.to_dict() for r in report.results],
                    "requests_logged": enum.requests_logged,
                }
            )
        
        except Exception as e:
            return PluginResult(success=False, error=str(e))


class SubdomainEnumWithHistory(SubdomainEnum):
    """带 History 记录的子域名枚举器"""
    
    def __init__(self, base_domain: str, history: History = None, **kwargs):
        super().__init__(base_domain, **kwargs)
        self.history = history
        self.requests_logged = 0
    
    def _check_http(self, domain: str, ip: str):
        """重写 HTTP 检查，记录到 History"""
        import requests as req_lib
        import urllib3
        urllib3.disable_warnings()
        
        from aiburp.subdomain import SubdomainResult
        result = SubdomainResult(domain=domain, ip=ip)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Host": domain,
        }
        
        # HTTPS
        try:
            url = f"https://{domain}"
            resp = req_lib.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # 记录到 History
            self._log_to_history(url, "GET", headers, resp)
            
            result.https_status = resp.status_code
            result.server = resp.headers.get("Server", "")
            result.content_length = len(resp.text)
            
            # 提取标题
            import re
            match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
            if match:
                result.title = match.group(1).strip()[:50]
            
            # 检查占位页面
            for pattern in self.PLACEHOLDER_PATTERNS:
                if pattern in resp.text.lower():
                    result.is_placeholder = True
                    break
                    
        except:
            pass
        
        # HTTP
        if not result.https_status:
            try:
                url = f"http://{domain}"
                resp = req_lib.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # 记录到 History
                self._log_to_history(url, "GET", headers, resp)
                
                result.http_status = resp.status_code
                if not result.server:
                    result.server = resp.headers.get("Server", "")
                if not result.content_length:
                    result.content_length = len(resp.text)
                if not result.title:
                    import re
                    match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
                    if match:
                        result.title = match.group(1).strip()[:50]
                        
                for pattern in self.PLACEHOLDER_PATTERNS:
                    if pattern in resp.text.lower():
                        result.is_placeholder = True
                        break
            except:
                pass
        
        # 判断是否真实
        if result.is_placeholder:
            result.is_real = False
        elif not result.http_status and not result.https_status:
            result.is_real = False
        elif result.content_length < 500 and not result.title:
            result.is_real = False
        
        return result
    
    def _log_to_history(self, url: str, method: str, headers: dict, resp):
        """记录请求到 History"""
        if not self.history:
            return
        
        try:
            # 创建 Request
            request = Request(
                method=method,
                url=url,
                headers=headers,
            )
            
            # 创建 Response
            response = Response(
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:10000],  # 限制大小
                time_ms=resp.elapsed.total_seconds() * 1000,
            )
            
            request.response = response
            
            # 添加标签
            request.tags = ["recon", "subdomain"]
            
            # 保存
            self.history.add(request)
            self.requests_logged += 1
            
        except Exception as e:
            pass  # 静默失败
