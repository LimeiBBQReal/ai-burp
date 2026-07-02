"""WAF 检测/绕过模块 - 支持全部 13 个 bypass 字典"""
import re
from typing import Dict, List, Tuple
from dataclasses import dataclass, field
import requests
import urllib3
urllib3.disable_warnings()

from ...plugins import AuxPlugin, PluginResult
from ...core.history import History
from ...core.payload_loader import get_loader


@dataclass
class WAFResult:
    detected: bool = False
    waf_name: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    bypass_tips: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "detected": self.detected, "waf_name": self.waf_name,
            "confidence": self.confidence, "evidence": self.evidence,
            "bypass_tips": self.bypass_tips,
        }


# WAF 指纹库
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": [("Server", r"cloudflare"), ("CF-RAY", r".+")],
        "cookies": [r"__cfduid", r"__cf_bm", r"cf_clearance"],
        "body": [r"Attention Required! \| Cloudflare", r"ray ID:"],
        "bypass_dict": "cloudflare",
    },
    "akamai": {
        "headers": [("Server", r"AkamaiGHost")],
        "cookies": [r"akamai", r"ak_bmsc"],
        "body": [r"Access Denied.*Akamai"],
        "bypass_dict": "akamai",
    },
    "aws_waf": {
        "headers": [("X-AMZ-CF-ID", r".+")],
        "body": [r"Request blocked", r"AWS WAF"],
        "bypass_dict": "aws_waf",
    },
    "modsecurity": {
        "headers": [("Server", r"ModSecurity")],
        "body": [r"ModSecurity", r"OWASP.*CRS", r"mod_security"],
        "bypass_dict": "modsecurity",
    },
    "imperva": {
        "headers": [("X-CDN", r"Incapsula")],
        "cookies": [r"incap_ses", r"visid_incap"],
        "body": [r"Incapsula incident ID"],
        "bypass_dict": "imperva",
    },
}


class WAFDetector:
    """WAF 检测器 - 支持全部 bypass 字典"""
    
    # 支持的所有 bypass 字典 (对应 payloads/bypass/ 下的文件)
    BYPASS_DICTS = {
        "cloudflare": "cloudflare",      # Cloudflare (39)
        "aws_waf": "aws_waf",            # AWS WAF (27)
        "modsecurity": "modsecurity",    # ModSecurity (43)
        "akamai": "akamai",              # Akamai (17)
        "imperva": "imperva",            # Imperva (17)
        "unicode": "unicode",            # Unicode绕过 (47)
        "http_smuggling": "http_smuggling", # HTTP走私 (48)
        "waf_encoding": "waf_encoding",  # 编码绕过 (31)
        "waf_keywords": "waf_keywords",  # 关键字绕过 (42)
        "waf_space": "waf_space",        # 空格绕过 (13)
        "waf_quotes": "waf_quotes",      # 引号绕过 (14)
        "waf_advanced": "waf_advanced",  # 高级绕过 (49)
        "exotic": "exotic",              # 特殊技巧 (61)
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.loader = get_loader()
    
    def get_bypass_payloads(self, waf_name: str = None, bypass_type: str = None) -> List[str]:
        """获取绕过 payload"""
        if bypass_type and bypass_type in self.BYPASS_DICTS:
            return self.loader.load("bypass", self.BYPASS_DICTS[bypass_type])
        
        if waf_name:
            bypass_dict = WAF_SIGNATURES.get(waf_name, {}).get("bypass_dict")
            if bypass_dict:
                return self.loader.load("bypass", bypass_dict)
        
        # 返回通用绕过
        return self.loader.load_merged("bypass", ["waf_encoding", "waf_keywords", "waf_space"])
    
    def get_all_bypass_payloads(self) -> List[str]:
        """获取全部绕过 payload"""
        return self.loader.load_merged("bypass")
    
    def detect(self, url: str, aggressive: bool = False) -> WAFResult:
        result = WAFResult()
        
        try:
            resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                timeout=self.timeout, verify=False, allow_redirects=True)
            
            waf, confidence, evidence = self._check_response(resp)
            if waf:
                result.detected = True
                result.waf_name = waf
                result.confidence = confidence
                result.evidence = evidence
                return result
        except:
            pass
        
        if aggressive:
            waf, confidence, evidence = self._aggressive_detect(url)
            if waf:
                result.detected = True
                result.waf_name = waf
                result.confidence = confidence
                result.evidence = evidence
        
        return result
    
    def _check_response(self, resp) -> Tuple[str, float, List[str]]:
        evidence = []
        for waf_name, signatures in WAF_SIGNATURES.items():
            matches = 0
            total = 0
            
            for header_name, pattern in signatures.get("headers", []):
                total += 1
                value = resp.headers.get(header_name, "")
                if re.search(pattern, value, re.I):
                    matches += 1
                    evidence.append(f"Header {header_name}: {value}")
            
            cookies_str = resp.headers.get("Set-Cookie", "") + str(resp.cookies)
            for pattern in signatures.get("cookies", []):
                total += 1
                if re.search(pattern, cookies_str, re.I):
                    matches += 1
            
            for pattern in signatures.get("body", []):
                total += 1
                if re.search(pattern, resp.text, re.I):
                    matches += 1
                    evidence.append(f"Body pattern: {pattern}")
            
            if matches > 0 and total > 0 and matches / total >= 0.3:
                return waf_name, matches / total, evidence
        
        return "", 0.0, []
    
    def _aggressive_detect(self, url: str) -> Tuple[str, float, List[str]]:
        test_payloads = [("?id=1'", "sqli"), ("?id=<script>alert(1)</script>", "xss")]
        
        for payload, attack_type in test_payloads:
            try:
                resp = requests.get(url.rstrip("/") + payload, headers={"User-Agent": "Mozilla/5.0"},
                    timeout=self.timeout, verify=False, allow_redirects=False)
                
                if resp.status_code in [403, 406, 429, 503]:
                    waf, confidence, evidence = self._check_response(resp)
                    if waf:
                        evidence.append(f"Blocked {attack_type} with {resp.status_code}")
                        return waf, confidence, evidence
                    return "unknown", 0.5, [f"Blocked {attack_type} with {resp.status_code}"]
            except:
                pass
        
        return "", 0.0, []


class WAFDetectPlugin(AuxPlugin):
    """WAF 检测插件"""
    
    name = "waf_detect"
    description = "WAF 检测和绕过建议"
    
    def __init__(self, history: History = None):
        self.history = history
        self.detector = WAFDetector()
    
    def execute(self, url: str = "", aggressive: bool = False, **kwargs) -> PluginResult:
        if not url:
            return PluginResult(success=False, error="URL is required")
        
        try:
            result = self.detector.detect(url, aggressive=aggressive)
            bypass_payloads = self.detector.get_bypass_payloads(result.waf_name) if result.detected else []
            
            return PluginResult(
                success=True,
                data={
                    "url": url, "waf": result.to_dict(),
                    "bypass_payloads_count": len(bypass_payloads),
                    "available_bypass_dicts": list(WAFDetector.BYPASS_DICTS.keys()),
                }
            )
        except Exception as e:
            return PluginResult(success=False, error=str(e))
