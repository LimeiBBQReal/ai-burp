"""XSS 检测插件 - 支持全部 8 个字典"""
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


class XSSPlugin(ScanPlugin):
    """XSS 检测 - 支持全部字典"""
    
    name = "xss"
    description = "XSS 检测"
    
    # 支持的所有字典 (对应 payloads/xss/ 下的文件)
    DICT_MAP = {
        "quick": "quick",                        # 快速检测 (10)
        "basic": "basic",                        # 基础payload (80)
        "bypass": "bypass",                      # 绕过技巧 (67)
        "waf_bypass": "waf_bypass",              # WAF绕过 (142)
        "polyglot": "polyglot",                  # 多态payload (44)
        "dom": "dom",                            # DOM XSS (85)
        "csp_bypass": "csp_bypass",              # CSP绕过 (33)
        "exotic": "exotic",                      # 特殊技巧 (90)
        "payloadbox": "payloadbox_intruder",     # PayloadBox (100+)
        "payloadsallthethings": "payloadsallthethings",  # PayloadsAllTheThings (150+)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    CANARY = "xss7e3f9a2b"
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        """获取指定字典的 payload"""
        if method == "all":
            return self.loader.load_merged("xss")
        dict_name = self.DICT_MAP.get(method, "quick")
        return self.loader.load("xss", dict_name)
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "reflects": False, "payloads_tested": 0}
        
        try:
            # 先检测是否反射
            test_req = request.with_param(param, self.CANARY)
            result = self.repeater.send(test_req)
            
            if not result["success"] or self.CANARY not in result["response"].get("body", ""):
                data["reflects"] = False
                return PluginResult(success=True, findings=[], data=data)
            
            data["reflects"] = True
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 50)
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                body = result["response"].get("body", "")
                
                if self._check_reflection(body, payload):
                    confidence = "likely" if "<script>" in payload.lower() else "possible"
                    findings.append(make_finding("xss", confidence,
                        f"Payload reflected", payload, param, test_request))
                    if confidence == "likely":
                        break
                
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
    
    def _check_reflection(self, body: str, payload: str) -> bool:
        key_parts = ["<script>", "</script>", "onerror=", "onload=", "javascript:", "alert("]
        for part in key_parts:
            if part in payload.lower() and part in body.lower():
                return True
        return payload in body
