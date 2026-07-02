"""CRLF 注入检测插件 - 支持全部 3 个字典"""
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


class CRLFPlugin(ScanPlugin):
    """CRLF 注入检测 - 支持全部字典"""
    
    name = "crlf"
    description = "HTTP头注入检测"
    
    DICT_MAP = {
        "quick": "quick",              # 快速检测
        "headers": "headers",          # 头注入
        "bypass": "bypass",            # 绕过技巧
        "full": "full",                # 完整 payload
        "cujanovic": "cujanovic_crlf", # cujanovic CRLF payloads
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    # 注入成功的标志
    INDICATORS = [
        "Set-Cookie: crlf=injection",
        "X-Injected: header",
        "crlf=injection",
    ]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("crlf")
        return self.loader.load("crlf", self.DICT_MAP.get(method, "quick"))
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "payloads_tested": 0}
        
        try:
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 20)
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                headers = result["response"].get("headers", {})
                raw_headers = str(headers)
                body = result["response"].get("body", "")
                
                # 检查响应头中是否有注入的头
                for indicator in self.INDICATORS:
                    if indicator.lower() in raw_headers.lower():
                        findings.append(make_finding("crlf", "confirmed",
                            f"Injected header: {indicator}", payload, param, test_request))
                        break
                
                # 检查是否有 Set-Cookie 被注入
                if "crlf" in str(headers.get("Set-Cookie", "")).lower():
                    findings.append(make_finding("crlf", "confirmed",
                        "Cookie injection via CRLF", payload, param, test_request))
                
                # 检查响应体是否被注入 (HTTP Response Splitting)
                if "<script>alert(1)</script>" in body and "%0d%0a" in payload.lower():
                    findings.append(make_finding("crlf_xss", "confirmed",
                        "HTTP Response Splitting with XSS", payload, param, test_request))
                
                if findings:
                    break
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
