"""SSTI 模板注入检测插件 - 支持全部 4 个字典"""
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


class SSTIPlugin(ScanPlugin):
    """SSTI 检测 - 支持全部字典"""
    
    name = "ssti"
    description = "模板注入检测"
    
    # 支持的所有字典 (对应 payloads/ssti/ 下的文件)
    DICT_MAP = {
        "quick": "quick",                        # 快速检测 (4)
        "detection": "detection",                # 多引擎检测 (81)
        "rce": "rce",                            # RCE payload (30)
        "exotic": "exotic",                      # 特殊技巧 (30)
        "payloadsallthethings": "payloadsallthethings",  # PayloadsAllTheThings (50+)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    INDICATORS = {
        "49": "math_eval",
        "object": "class_access",
        "__class__": "class_access",
        "Config": "config_leak",
    }
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("ssti")
        dict_name = self.DICT_MAP.get(method, "quick")
        return self.loader.load("ssti", dict_name)
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "engine": None, "payloads_tested": 0}
        
        try:
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 50)
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                body = result["response"].get("body", "")
                
                for indicator, vuln_type in self.INDICATORS.items():
                    if indicator in body and payload not in body.replace(indicator, ""):
                        data["engine"] = self._detect_engine(payload, body)
                        findings.append(make_finding("ssti", "confirmed",
                            f"SSTI indicator: {indicator}", payload, param, test_request))
                        break
                
                if findings:
                    break
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
    
    def _detect_engine(self, payload: str, body: str) -> str:
        if "49" in body and "{{7*7}}" in payload:
            return "jinja2/twig"
        if "__class__" in body:
            return "jinja2"
        return "unknown"
