"""LFI 本地文件包含检测插件 - 支持全部 5 个字典"""
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


class LFIPlugin(ScanPlugin):
    """LFI 检测 - 支持全部字典"""
    
    name = "lfi"
    description = "本地文件包含检测"
    
    # 支持的所有字典 (对应 payloads/lfi/ 下的文件)
    DICT_MAP = {
        "quick": "quick",                        # 快速检测 (5)
        "linux": "linux",                        # Linux路径 (69)
        "php_wrappers": "php_wrappers",          # PHP伪协议 (28)
        "bypass": "bypass",                      # 绕过技巧 (33)
        "exotic": "exotic",                      # 特殊技巧 (39)
        "payloadsallthethings": "payloadsallthethings_traversal",  # PayloadsAllTheThings (50+)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    INDICATORS = [
        r"root:.*:0:0:",      # /etc/passwd
        r"\[fonts\]",         # win.ini
        r"\[extensions\]",
        r"HTTP_USER_AGENT",   # /proc/self/environ
        r"<?php",             # PHP source
        r"PD9waHA",           # base64 <?php
    ]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("lfi")
        dict_name = self.DICT_MAP.get(method, "quick")
        return self.loader.load("lfi", dict_name)
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "file_type": None, "payloads_tested": 0}
        
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
                
                for pattern in self.INDICATORS:
                    if re.search(pattern, body, re.I):
                        data["file_type"] = "unix" if "root:" in body else "windows" if "[fonts]" in body else "php"
                        findings.append(make_finding("lfi", "confirmed",
                            f"LFI indicator: {pattern}", payload, param, test_request))
                        break
                
                if findings:
                    break
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
