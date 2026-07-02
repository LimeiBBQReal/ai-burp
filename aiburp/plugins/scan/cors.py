"""CORS 配置错误检测插件 - 支持全部 2 个字典"""
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
        type=vuln_type, confidence=confidence, title=f"{vuln_type.upper()}",
        description=evidence, url=request.url, method=request.method,
        param=param, payload=payload, request=request.to_raw(), evidence=evidence,
    )


class CORSPlugin(ScanPlugin):
    """CORS 配置错误检测 - 支持全部字典"""
    
    name = "cors"
    description = "CORS配置错误检测"
    
    DICT_MAP = {
        "quick": "quick",      # 快速检测
        "origins": "origins",  # 完整测试
        "full": "full",        # 完整 payload (90+ origins)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        if method == "all":
            return self.loader.load_merged("cors")
        return self.loader.load("cors", self.DICT_MAP.get(method, "quick"))
    
    def test(self, request: Request, param: str = None, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "origins_tested": 0}
        
        try:
            origins = self.get_payloads(method)
            target_domain = options.get("target_domain", "target.com")
            
            # 替换占位符
            origins = [o.replace("target.com", target_domain) for o in origins]
            
            for origin in origins:
                data["origins_tested"] += 1
                
                # 添加 Origin 头
                test_request = request.with_header("Origin", origin)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                headers = result["response"].get("headers", {})
                acao = headers.get("Access-Control-Allow-Origin", "")
                acac = headers.get("Access-Control-Allow-Credentials", "")
                
                # 检测 CORS 配置错误
                vuln_type = self._check_cors_vuln(origin, acao, acac)
                
                if vuln_type:
                    confidence = "confirmed" if acac.lower() == "true" else "likely"
                    findings.append(make_finding(vuln_type, confidence,
                        f"ACAO: {acao}, ACAC: {acac}", origin, "Origin", test_request,
                        {"acao": acao, "acac": acac}))
                    
                    # 高危漏洞直接返回
                    if vuln_type == "cors_credentials":
                        break
                
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
    
    def _check_cors_vuln(self, origin: str, acao: str, acac: str) -> str:
        """检测 CORS 漏洞类型"""
        if not acao:
            return ""
        
        # 最危险: 反射任意 Origin + Credentials
        if acao == origin and acac.lower() == "true":
            if "evil" in origin.lower() or "attacker" in origin.lower():
                return "cors_credentials"
        
        # 危险: 反射任意 Origin
        if acao == origin:
            if "evil" in origin.lower() or "attacker" in origin.lower():
                return "cors_reflect"
        
        # 危险: 允许 null origin + Credentials
        if acao == "null" and acac.lower() == "true":
            return "cors_null_credentials"
        
        # 中危: 允许 null origin
        if acao == "null":
            return "cors_null"
        
        # 中危: 通配符
        if acao == "*":
            return "cors_wildcard"
        
        return ""
