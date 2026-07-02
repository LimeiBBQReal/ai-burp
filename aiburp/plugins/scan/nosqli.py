"""NoSQL 注入检测插件 - 支持全部 2 个字典"""
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


class NoSQLiPlugin(ScanPlugin):
    """NoSQL 注入检测 - 支持全部字典"""
    
    name = "nosqli"
    description = "NoSQL 注入检测"
    
    # 支持的所有字典 (对应 payloads/nosqli/ 下的文件)
    DICT_MAP = {
        "quick": "quick",                        # 快速检测 (18)
        "auth_bypass": "auth_bypass",            # 认证绕过 (53)
        "payloadsallthethings": "payloadsallthethings",  # PayloadsAllTheThings (25+)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    INDICATORS = [
        r"MongoError", r"MongoDB", r"CouchDB",
        r"\$where", r"\$regex", r"\$ne",
        r"SyntaxError", r"ReferenceError",
    ]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("nosqli")
        dict_name = self.DICT_MAP.get(method, "quick")
        return self.loader.load("nosqli", dict_name)
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "payloads_tested": 0}
        
        try:
            baseline = self.repeater.send(request)
            baseline_len = baseline["response"].get("length", 0) if baseline["success"] else 0
            
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 50)
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                body = result["response"].get("body", "")
                length = result["response"].get("length", 0)
                status = result["response"].get("status", 0)
                
                # 检查错误特征
                for pattern in self.INDICATORS:
                    if re.search(pattern, body, re.I):
                        findings.append(make_finding("nosqli", "confirmed",
                            f"NoSQL indicator: {pattern}", payload, param, test_request))
                        break
                
                # 检查认证绕过
                if method == "auth_bypass" and status == 200 and abs(length - baseline_len) > 100:
                    findings.append(make_finding("nosqli_auth_bypass", "likely",
                        f"Response changed: {length - baseline_len:+d} bytes", payload, param, test_request))
                
                if findings:
                    break
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
