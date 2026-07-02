"""命令注入检测插件 - 支持全部 5 个字典"""
import re
import time
from typing import Dict, List
from .. import ScanPlugin, PluginResult
from ...core.models import Request, Finding as CoreFinding
from ...core.repeater import Repeater
from ...core.payload_loader import get_loader

def make_finding(vuln_type, confidence, evidence, payload, param, request, details=None):
    return CoreFinding(type=vuln_type, confidence=confidence, title=f"{vuln_type.upper()} in {param}",
        description=evidence, url=request.url, method=request.method, param=param, payload=payload,
        request=request.to_raw(), evidence=evidence)

class CMDiPlugin(ScanPlugin):
    name = "cmdi"
    description = "命令注入检测"
    DICT_MAP = {"quick": "quick", "linux": "linux", "windows": "windows", "blind": "blind", "exotic": "exotic", "payloadsallthethings": "payloadsallthethings"}
    methods = list(DICT_MAP.keys()) + ["all"]
    INDICATORS = [r"uid=\d+", r"gid=\d+", r"root:.*:0:0:", r"Directory of", r"Volume Serial Number"]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
        self.time_threshold = 4000
    
    def get_payloads(self, method="quick"):
        if method == "all": return self.loader.load_merged("cmdi")
        return self.loader.load("cmdi", self.DICT_MAP.get(method, "quick"))
    
    def test(self, request, param, method="quick", **options):
        findings, data = [], {"method": method, "os_type": None, "payloads_tested": 0, "baseline_time": 0}
        try:
            baseline = self.repeater.send(request)
            if baseline["success"]: data["baseline_time"] = baseline["response"].get("time_ms", 0)
            payloads = self.get_payloads(method)
            for payload in payloads[:options.get("max_payloads", 50)]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                if not result["success"]: continue
                body, time_ms = result["response"].get("body", ""), result["response"].get("time_ms", 0)
                for pattern in self.INDICATORS:
                    if re.search(pattern, body, re.I):
                        data["os_type"] = "unix" if "uid=" in body else "windows" if "Directory of" in body else "unknown"
                        findings.append(make_finding("cmdi", "confirmed", f"Command output: {pattern}", payload, param, test_request))
                        break
                if "sleep" in payload.lower() and time_ms > data["baseline_time"] + self.time_threshold:
                    findings.append(make_finding("cmdi_blind", "likely", f"Time delay: {time_ms - data['baseline_time']:.0f}ms", payload, param, test_request))
                if findings: break
                time.sleep(self.delay)
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
