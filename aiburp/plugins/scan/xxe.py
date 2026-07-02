"""XXE 检测插件 - 支持全部 4 个字典"""
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


class XXEPlugin(ScanPlugin):
    """XXE 检测 - 支持全部字典"""
    
    name = "xxe"
    description = "XML外部实体注入检测"
    
    DICT_MAP = {
        "quick": "quick",                    # 快速检测
        "file_read": "file_read",            # 文件读取
        "oob": "oob",                        # 外带检测 (基础)
        "oob_full": "oob_full",              # 外带检测 (完整)
        "bypass": "bypass",                  # 绕过技巧
        "detection": "detection",            # 检测 payload
        "seclists": "seclists_xxe",          # SecLists XXE
        "honoki": "honoki_xxe_bruteforce",   # Honoki XXE bruteforce
        "staaldraad": "staaldraad_xxe",      # Staaldraad XXE
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    INDICATORS = [
        r"root:.*:0:0:",           # /etc/passwd
        r"\[fonts\]",              # win.ini
        r"HTTP_USER_AGENT",        # /proc/self/environ
        r"PD9waHA",                # base64 <?php
        r"ENTITY",                 # XXE error
        r"DOCTYPE",                # XXE error
        r"parser error",           # XML parser error
    ]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("xxe")
        return self.loader.load("xxe", self.DICT_MAP.get(method, "quick"))
    
    def test(self, request: Request, param: str = None, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "payloads_tested": 0}
        
        try:
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 20)
            oob_server = options.get("oob_server", "BURP_COLLABORATOR")
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                
                # 替换 OOB 服务器占位符
                test_payload = payload.replace("BURP_COLLABORATOR", oob_server)
                
                # XXE 通常在 body 中，不是参数
                if param:
                    test_request = request.with_param(param, test_payload)
                else:
                    test_request = request.with_body(test_payload)
                    test_request = test_request.with_header("Content-Type", "application/xml")
                
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                body = result["response"].get("body", "")
                
                for pattern in self.INDICATORS:
                    if re.search(pattern, body, re.I):
                        findings.append(make_finding("xxe", "confirmed",
                            f"XXE indicator: {pattern}", test_payload, param or "body", test_request))
                        break
                
                if findings:
                    break
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
