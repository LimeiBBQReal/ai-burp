"""SSRF 检测插件 - 支持全部 5 个字典"""
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


class SSRFPlugin(ScanPlugin):
    """SSRF 检测 - 支持全部字典"""
    
    name = "ssrf"
    description = "SSRF 检测"
    
    # 支持的所有字典 (对应 payloads/ssrf/ 下的文件)
    DICT_MAP = {
        "quick": "quick",                        # 快速检测 (5)
        "internal": "internal",                  # 内网探测 (52)
        "cloud_metadata": "cloud_metadata",      # 云元数据 (50)
        "bypass": "bypass",                      # 绕过技巧 (51)
        "exotic": "exotic",                      # 特殊技巧 (47)
        "payloadsallthethings": "payloadsallthethings",  # PayloadsAllTheThings (80+)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    INDICATORS = [
        r"root:.*:0:0:", r"AWS", r"ami-id", r"instance-id",
        r"computeMetadata", r"redis_version", r"iam/security-credentials",
    ]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("ssrf")
        dict_name = self.DICT_MAP.get(method, "quick")
        return self.loader.load("ssrf", dict_name)
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "payloads_tested": 0}
        
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
                        findings.append(make_finding("ssrf", "confirmed",
                            f"SSRF indicator: {pattern}", payload, param, test_request))
                        break
                
                if findings:
                    break
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
