"""Open Redirect 检测插件 - 支持全部 3 个字典"""
import re
import time
from typing import Dict, List
from .. import ScanPlugin, PluginResult
from ...core.models import Request, Finding as CoreFinding
from ...core.repeater import Repeater
from ...core.payload_loader import get_loader


def make_finding(vuln_type: str, confidence: str, evidence: str, payload: str,
                 param: str, request: Request, details: Dict = None) -> CoreFinding:
    return CoreFinding(
        type=vuln_type, confidence=confidence, title=f"{vuln_type.upper()} in {param}",
        description=evidence, url=request.url, method=request.method,
        param=param, payload=payload, request=request.to_raw(), evidence=evidence,
    )


class RedirectPlugin(ScanPlugin):
    """Open Redirect 检测 - 支持全部字典"""
    
    name = "redirect"
    description = "开放重定向检测"
    
    DICT_MAP = {
        "quick": "quick",                        # 快速检测
        "bypass": "bypass",                      # 绕过技巧
        "params": "params",                      # 常见参数名
        "full": "full",                          # 完整 payload
        "cujanovic": "cujanovic_open_redirect",  # cujanovic 500+ payloads
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("redirect")
        return self.loader.load("redirect", self.DICT_MAP.get(method, "quick"))
    
    def get_params(self) -> List[str]:
        """获取常见重定向参数名"""
        return self.loader.load("redirect", "params")
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "payloads_tested": 0}
        
        try:
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 30)
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                status = result["response"].get("status", 0)
                headers = result["response"].get("headers", {})
                location = headers.get("Location", headers.get("location", ""))
                
                # 检测重定向
                if status in [301, 302, 303, 307, 308]:
                    # 检查是否重定向到外部域
                    if self._is_external_redirect(payload, location):
                        findings.append(make_finding("open_redirect", "confirmed",
                            f"Redirects to: {location}", payload, param, test_request))
                        break
                
                # 检测 meta refresh 或 JS 重定向
                body = result["response"].get("body", "")
                if self._check_body_redirect(payload, body):
                    findings.append(make_finding("open_redirect", "likely",
                        "Redirect in response body", payload, param, test_request))
                    break
                
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
    
    def _is_external_redirect(self, payload: str, location: str) -> bool:
        """检查是否重定向到外部"""
        evil_domains = ["evil.com", "attacker.com", "127.0.0.1"]
        for domain in evil_domains:
            if domain in location:
                return True
        # 检查 payload 中的域名是否出现在 location 中
        if "evil" in payload.lower() and "evil" in location.lower():
            return True
        return False
    
    def _check_body_redirect(self, payload: str, body: str) -> bool:
        """检查响应体中的重定向"""
        patterns = [
            r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=' + re.escape(payload[:20]),
            r'window\.location\s*=\s*["\']' + re.escape(payload[:20]),
            r'location\.href\s*=\s*["\']' + re.escape(payload[:20]),
        ]
        for pattern in patterns:
            if re.search(pattern, body, re.I):
                return True
        return False
