"""
被动流量语义分析器 — V4 的"眼睛".

核心理念: 一切皆流量. 不管 APP/Web/小程序, 本质都是请求-响应对.
理解了流量, 就理解了应用的一切.

与主动扫描器的区别:
    主动扫描器: 发 payload → 看响应 (可能触发 WAF/告警)
    被动分析器: 只看已有流量, 不发任何请求 (零噪音)

5 层分析:

    Layer 1: 敏感信息提取
        → 响应里的 JWT/Cookie/API Key/密码/内部 IP
        → 请求里的 Authorization/Token/Session

    Layer 2: 攻击面推断
        → URL 里的 /api/users/1001 → "IDOR 可能"
        → 参数 price=99.9 → "价格篡改可能"
        → Cookie role=user → "权限提升可能"

    Layer 3: 漏洞迹象检测
        → 响应含 SQL 错误 → "SQLi 迹象"
        → 响应含堆栈跟踪 → "信息泄露"
        → 响应反射了请求参数 → "XSS 可能"

    Layer 4: 流量模式分析
        → 同接口的不同请求对比 (找差异)
        → 响应大小/时间分布异常
        → 请求频率模式 (找未限速接口)

    Layer 5: 关联分析
        → 多个请求共享的 Token/Session
        → 越权检测 (不同用户访问同接口, 对比响应)

用法:
    analyzer = TrafficAnalyzer()

    # 分析单个请求-响应对
    findings = analyzer.analyze(request, response)

    # 分析一批流量 (从 History)
    findings = analyzer.analyze_batch(history.all())

    # 实时模式 (配合 Proxy)
    analyzer.on_traffic(callback)  # 每个请求自动分析
"""

import re
import json
import hashlib
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict


# ============================================================
#                   分析结果数据结构
# ============================================================

@dataclass
class TrafficFinding:
    """单个流量分析发现"""
    layer: str           # sensitive / attack-surface / vuln-sign / pattern / correlation
    finding_type: str    # jwt-leak / idor-possible / sqli-sign / ...
    severity: str        # critical / high / medium / low / info
    evidence: str        # 证据 (具体值/匹配内容)
    location: str = ""   # 位置 (URL/参数名/响应头)
    request_url: str = ""  # 来源请求 URL
    recommendation: str = ""  # 建议的下一步


@dataclass
class AnalysisReport:
    """流量分析报告"""
    total_requests: int = 0
    findings: List[TrafficFinding] = field(default_factory=list)
    attack_surface: Dict[str, List[str]] = field(default_factory=dict)
    sensitive_data: List[Dict] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def to_dict(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "findings": [
                {"layer": f.layer, "type": f.finding_type, "severity": f.severity,
                 "evidence": f.evidence[:100], "location": f.location,
                 "recommendation": f.recommendation}
                for f in self.findings
            ],
            "attack_surface": self.attack_surface,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def report_text(self) -> str:
        lines = ["="*60, f"流量分析报告 ({self.total_requests} 个请求)", "="*60]
        lines.append(f"发现: {len(self.findings)} | 严重: {self.critical_count} | 高危: {self.high_count}")
        lines.append("-"*60)

        by_layer = defaultdict(list)
        for f in self.findings:
            by_layer[f.layer].append(f)

        layer_labels = {
            "sensitive": "🔑 敏感信息泄露",
            "attack-surface": "🎯 攻击面推断",
            "vuln-sign": "🚨 漏洞迹象",
            "pattern": "📊 流量模式",
            "correlation": "🔗 关联分析",
        }

        for layer, findings in by_layer.items():
            label = layer_labels.get(layer, layer)
            lines.append(f"\n{label} ({len(findings)}):")
            for f in findings[:10]:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(f.severity, "⚪")
                lines.append(f"  {icon} [{f.finding_type}] {f.evidence[:60]}")
                if f.location:
                    lines.append(f"     位置: {f.location[:60]}")
                if f.recommendation:
                    lines.append(f"     建议: {f.recommendation[:60]}")

        return "\n".join(lines)


# ============================================================
#                   分析规则库
# ============================================================

# Layer 1: 敏感信息模式
SENSITIVE_PATTERNS = {
    "jwt-token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
        "severity": "high",
        "desc": "JWT Token",
        "recommendation": "用 JWTTool 解码/伪造/暴力破解",
    },
    "aws-key": {
        "pattern": r"AKIA[A-Z0-9]{16}",
        "severity": "critical",
        "desc": "AWS Access Key",
        "recommendation": "直接可用的云凭据, 检查是否可访问 S3/EC2",
    },
    "private-key": {
        "pattern": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        "severity": "critical",
        "desc": "私钥泄露",
        "recommendation": "可能是 TLS 私钥或 SSH 私钥",
    },
    "google-api-key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "desc": "Google API Key",
    },
    "slack-token": {
        "pattern": r"xox[baprs]-[0-9A-Za-z-]{10,}",
        "severity": "high",
        "desc": "Slack Token",
    },
    "password-in-response": {
        "pattern": r'(?i)("password"|"passwd"|"pwd"|"secret")["\']?\s*[:=]\s*["\']([^"\']{4,})',
        "severity": "high",
        "desc": "响应中含密码字段",
    },
    "internal-ip": {
        "pattern": r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",
        "severity": "medium",
        "desc": "内网 IP 泄露",
        "recommendation": "可用于 SSRF / 内网探测",
    },
    "database-connection": {
        "pattern": r"(?i)(mysql|postgres|redis|mongodb)://\w+:\S+@",
        "severity": "critical",
        "desc": "数据库连接字符串 (含密码)",
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "severity": "low",
        "desc": "邮箱地址",
    },
    "credit-card": {
        "pattern": r"\b(?:\d[ -]*?){13,16}\b",
        "severity": "critical",
        "desc": "可能的信用卡号",
    },
    "stack-trace": {
        "pattern": r"(Traceback|at\s+\w+\.\w+\(.*?:\d+\)|Caused by:|NullReferenceException)",
        "severity": "medium",
        "desc": "堆栈跟踪泄露",
        "recommendation": "泄露了技术栈/框架版本/文件路径",
    },
}

# Layer 2: 攻击面推断规则
ATTACK_SURFACE_RULES = {
    "idor": {
        "url_patterns": [r"/(?:api|v\d+)/[\w/]+/(\d+)", r"/(?:user|order|file|doc|account)/(\d+)"],
        "param_patterns": [r"(?i)^(id|uid|user_?id|order_?id|file_?id|doc_?id|account_?id|record_?id)$"],
        "severity": "high",
        "recommendation": "尝试修改 ID → IDOR/越权检测",
    },
    "price-tampering": {
        "param_patterns": [r"(?i)^(price|amount|cost|fee|total|discount|tax|balance|payment)$"],
        "severity": "high",
        "recommendation": "尝试修改价格为 0/-1/0.01",
    },
    "privilege-escalation": {
        "param_patterns": [r"(?i)^(role|admin|is_?admin|is_?staff|permission|privilege|level|user_?type)$"],
        "cookie_patterns": [r"(?i)(role|admin|privilege|level)"],
        "severity": "high",
        "recommendation": "尝试修改为 admin/root",
    },
    "ssrf-possible": {
        "param_patterns": [r"(?i)^(url|redirect|callback|webhook|image|proxy|fetch|source|target|next|goto|return)$"],
        "severity": "high",
        "recommendation": "尝试注入内网 IP/云元数据 URL",
    },
    "sqli-possible": {
        "param_patterns": [r"(?i)^(id|q|query|search|keyword|name|title|sort|order|filter|where)$"],
        "severity": "medium",
        "recommendation": "尝试 ' UNION SELECT 注入",
    },
    "file-inclusion": {
        "param_patterns": [r"(?i)^(file|path|page|include|template|load|lang|module|dir)$"],
        "severity": "high",
        "recommendation": "尝试 ../../etc/passwd",
    },
    "cmd-injection": {
        "param_patterns": [r"(?i)^(cmd|exec|command|ping|run|action|operation)$"],
        "severity": "high",
        "recommendation": "尝试 ; id 或 | id",
    },
    "auth-bypass": {
        "url_patterns": [r"/(?:login|signin|auth|register|signup|forgot)"],
        "severity": "medium",
        "recommendation": "SQL 注入认证绕过 (admin' OR '1'='1)",
    },
}

# Layer 3: 漏洞迹象模式
VULN_SIGN_PATTERNS = {
    "sqli-error": {
        "patterns": SQL_ERRORS if (SQL_ERRORS := {
            "mysql": [r"SQL syntax.*MySQL", r"You have an error in your SQL syntax", r"Warning.*mysql_"],
            "mssql": [r"Microsoft.*ODBC", r"SQL Server.*error", r"Unclosed quotation mark"],
            "oracle": [r"ORA-\d{5}", r"Oracle error"],
            "postgres": [r"PostgreSQL.*ERROR", r"pg_query"],
            "sqlite": [r"SQLite.*Exception", r"sqlite3.OperationalError"],
        }) else {},
        "severity": "high",
        "desc": "SQL 错误信息",
    },
    "xss-reflection": {
        # 这个需要对比请求参数和响应体, 单独处理
        "severity": "high",
        "desc": "参数被反射到响应",
    },
    "debug-mode": {
        "patterns": [r"(?i)(DEBUG\s*=\s*True|debug mode|Laravel.*exception|Whoops!|Django.*Debug)"],
        "severity": "high",
        "desc": "调试模式开启",
    },
    "cors-wildcard": {
        "header_patterns": [r"Access-Control-Allow-Origin:\s*\*"],
        "severity": "medium",
        "desc": "CORS 通配符 (任意域可跨域)",
    },
    "server-version": {
        "header_patterns": [r"Server:\s*(.+)", r"X-Powered-By:\s*(.+)"],
        "severity": "low",
        "desc": "服务器版本泄露",
    },
    "missing-security-headers": {
        "missing_headers": ["X-Content-Type-Options", "X-Frame-Options",
                           "Strict-Transport-Security", "Content-Security-Policy"],
        "severity": "low",
        "desc": "缺少安全响应头",
    },
}


# ============================================================
#                   TrafficAnalyzer
# ============================================================

class TrafficAnalyzer:
    """
    被动流量语义分析器.

    用法:
        analyzer = TrafficAnalyzer()

        # 分析单个请求-响应对
        findings = analyzer.analyze(url, method, headers, params, body,
                                     resp_status, resp_headers, resp_body)

        # 分析一批流量
        report = analyzer.analyze_batch(traffic_list)

        # 实时回调 (配合 Proxy)
        analyzer.set_callback(lambda findings: print(findings))
    """

    def __init__(self):
        self._callback: Optional[Callable] = None
        self._request_profiles: Dict[str, List[dict]] = defaultdict(list)  # 同接口的请求档案
        self._token_registry: Dict[str, set] = defaultdict(set)  # Token/Session 注册表

    def set_callback(self, callback: Callable):
        """设置实时分析回调 (每个请求分析后调用)"""
        self._callback = callback

    # ============================================================
    #                   单个请求分析
    # ============================================================

    def analyze(
        self,
        url: str = "",
        method: str = "GET",
        headers: Dict = None,
        params: Dict = None,
        body: str = "",
        resp_status: int = 0,
        resp_headers: Dict = None,
        resp_body: str = "",
    ) -> List[TrafficFinding]:
        """
        分析单个请求-响应对.

        这是核心方法 — 5 层分析.
        """
        headers = headers or {}
        params = params or {}
        resp_headers = resp_headers or {}

        findings: List[TrafficFinding] = []

        # Layer 1: 敏感信息提取
        findings.extend(self._layer1_sensitive(url, headers, params, resp_headers, resp_body))

        # Layer 2: 攻击面推断
        findings.extend(self._layer2_attack_surface(url, params, headers, body))

        # Layer 3: 漏洞迹象
        findings.extend(self._layer3_vuln_signs(url, params, resp_status, resp_headers, resp_body))

        # Layer 4: 流量模式 (需要多次请求累积, 单请求只记录)
        self._layer4_record(url, method, params, resp_status, resp_body)

        # 实时回调
        if self._callback and findings:
            self._callback(findings)

        return findings

    # ============================================================
    #                   Layer 1: 敏感信息提取
    # ============================================================

    def _layer1_sensitive(self, url, req_headers, params, resp_headers, resp_body) -> List[TrafficFinding]:
        """从请求头/参数/响应头/响应体提取敏感信息."""
        findings = []

        # 合并所有文本 (请求 + 响应)
        all_text = " ".join([
            json.dumps(req_headers, ensure_ascii=False),
            json.dumps(params, ensure_ascii=False),
            json.dumps(resp_headers, ensure_ascii=False),
            resp_body[:10000],  # 限制大小
        ])

        for name, rule in SENSITIVE_PATTERNS.items():
            pat = rule.get("pattern", "")
            if not pat:
                continue
            matches = re.findall(pat, all_text)
            if matches:
                # 匹配可能是 tuple (多 group) 或 str
                first_match = matches[0]
                if isinstance(first_match, tuple):
                    first_match = first_match[-1] if first_match else ""
                evidence = str(first_match)[:60]
                # 脱敏 (不显示完整值)
                if len(evidence) > 20:
                    evidence = evidence[:10] + "..." + evidence[-5:]

                findings.append(TrafficFinding(
                    layer="sensitive",
                    finding_type=name,
                    severity=rule.get("severity", "medium"),
                    evidence=f"{rule['desc']}: {evidence}",
                    location=url,
                    request_url=url,
                    recommendation=rule.get("recommendation", ""),
                ))

        # 请求头里的 Authorization
        auth_header = req_headers.get("Authorization", req_headers.get("authorization", ""))
        if auth_header:
            token_type = auth_header.split(" ")[0] if " " in auth_header else "unknown"
            findings.append(TrafficFinding(
                layer="sensitive",
                finding_type="auth-header",
                severity="info",
                evidence=f"Authorization: {token_type} ...",
                location="request-header",
                request_url=url,
                recommendation="保存此 Token, 可用于越权测试",
            ))
            # 注册 Token
            self._token_registry[token_type].add(auth_header[:50])

        # Cookie 分析
        cookie = req_headers.get("Cookie", req_headers.get("cookie", ""))
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    k, _, v = part.strip().partition("=")
                    k_lower = k.lower()
                    if any(s in k_lower for s in ("session", "token", "auth", "jwt")):
                        findings.append(TrafficFinding(
                            layer="sensitive",
                            finding_type="session-cookie",
                            severity="medium",
                            evidence=f"Cookie {k}={v[:15]}...",
                            location="request-cookie",
                            request_url=url,
                            recommendation="保存此 Cookie, 可用于会话固定/劫持测试",
                        ))

        return findings

    # ============================================================
    #                   Layer 2: 攻击面推断
    # ============================================================

    def _layer2_attack_surface(self, url, params, headers, body) -> List[TrafficFinding]:
        """从 URL/参数名推断可能的攻击面."""
        findings = []

        # URL 路径分析
        for rule_name, rule in ATTACK_SURFACE_RULES.items():
            # URL 模式匹配
            for url_pat in rule.get("url_patterns", []):
                if re.search(url_pat, url, re.I):
                    findings.append(TrafficFinding(
                        layer="attack-surface",
                        finding_type=rule_name,
                        severity=rule.get("severity", "medium"),
                        evidence=f"URL 模式匹配: {url[:50]}",
                        location=url,
                        request_url=url,
                        recommendation=rule.get("recommendation", ""),
                    ))

            # 参数名匹配
            for param_name in params:
                for param_pat in rule.get("param_patterns", []):
                    if re.match(param_pat, param_name, re.I):
                        findings.append(TrafficFinding(
                            layer="attack-surface",
                            finding_type=rule_name,
                            severity=rule.get("severity", "medium"),
                            evidence=f"参数 {param_name}={str(params[param_name])[:20]}",
                            location=f"param: {param_name}",
                            request_url=url,
                            recommendation=rule.get("recommendation", ""),
                        ))

            # Cookie 模式匹配
            cookie = headers.get("Cookie", headers.get("cookie", ""))
            for cookie_pat in rule.get("cookie_patterns", []):
                if re.search(cookie_pat, cookie, re.I):
                    findings.append(TrafficFinding(
                        layer="attack-surface",
                        finding_type=rule_name,
                        severity=rule.get("severity", "medium"),
                        evidence=f"Cookie 匹配: {cookie_pat}",
                        location="cookie",
                        request_url=url,
                        recommendation=rule.get("recommendation", ""),
                    ))

        # Body 参数分析 (POST)
        if body and "=" in body:
            for pair in body.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    for rule_name, rule in ATTACK_SURFACE_RULES.items():
                        for param_pat in rule.get("param_patterns", []):
                            if re.match(param_pat, k, re.I):
                                findings.append(TrafficFinding(
                                    layer="attack-surface",
                                    finding_type=rule_name,
                                    severity=rule.get("severity", "medium"),
                                    evidence=f"Body 参数 {k}={v[:20]}",
                                    location=f"body: {k}",
                                    request_url=url,
                                    recommendation=rule.get("recommendation", ""),
                                ))

        return findings

    # ============================================================
    #                   Layer 3: 漏洞迹象
    # ============================================================

    def _layer3_vuln_signs(self, url, params, resp_status, resp_headers, resp_body) -> List[TrafficFinding]:
        """检测响应中的漏洞迹象."""
        findings = []

        body_lower = resp_body.lower()
        headers_str = json.dumps(resp_headers, ensure_ascii=False)

        # SQL 错误
        for db_type, patterns in VULN_SIGN_PATTERNS["sqli-error"].get("patterns", {}).items():
            for pat in patterns:
                if re.search(pat, resp_body, re.I):
                    findings.append(TrafficFinding(
                        layer="vuln-sign",
                        finding_type="sqli-error",
                        severity="high",
                        evidence=f"SQL 错误 ({db_type}): {pat[:30]}",
                        location=url,
                        request_url=url,
                        recommendation="确认 SQLi: 发 ' UNION SELECT 注入",
                    ))
                    break

        # XSS 反射检测 (参数值出现在响应中)
        for param_name, param_value in params.items():
            if param_value and len(str(param_value)) > 2:
                if str(param_value) in resp_body:
                    findings.append(TrafficFinding(
                        layer="vuln-sign",
                        finding_type="xss-reflection",
                        severity="high",
                        evidence=f"参数 {param_name} 的值被反射到响应",
                        location=f"param: {param_name}",
                        request_url=url,
                        recommendation="注入 <script> 标签测试 XSS",
                    ))

        # 调试模式
        for pat in VULN_SIGN_PATTERNS["debug-mode"].get("patterns", []):
            if re.search(pat, resp_body, re.I):
                findings.append(TrafficFinding(
                    layer="vuln-sign",
                    finding_type="debug-mode",
                    severity="high",
                    evidence="调试模式开启",
                    location=url,
                    request_url=url,
                ))
                break

        # CORS 通配符
        acao = resp_headers.get("Access-Control-Allow-Origin", resp_headers.get("access-control-allow-origin", ""))
        if acao == "*":
            findings.append(TrafficFinding(
                layer="vuln-sign",
                finding_type="cors-wildcard",
                severity="medium",
                evidence="Access-Control-Allow-Origin: *",
                location="response-header",
                request_url=url,
            ))

        # 服务器版本
        server = resp_headers.get("Server", resp_headers.get("server", ""))
        if server:
            findings.append(TrafficFinding(
                layer="vuln-sign",
                finding_type="server-version",
                severity="low",
                evidence=f"Server: {server}",
                location="response-header",
                request_url=url,
                recommendation=f"检查 {server} 已知漏洞",
            ))

        # 缺失安全头
        missing = [h for h in VULN_SIGN_PATTERNS["missing-security-headers"]["missing_headers"]
                   if h.lower() not in {k.lower() for k in resp_headers}]
        if missing:
            findings.append(TrafficFinding(
                layer="vuln-sign",
                finding_type="missing-security-headers",
                severity="low",
                evidence=f"缺少: {', '.join(missing)}",
                location="response-header",
                request_url=url,
            ))

        # 5xx 错误
        if resp_status >= 500:
            findings.append(TrafficFinding(
                layer="vuln-sign",
                finding_type="server-error",
                severity="medium",
                evidence=f"HTTP {resp_status}: 可能触发异常",
                location=url,
                request_url=url,
                recommendation="分析错误信息, 可能含注入点",
            ))

        return findings

    # ============================================================
    #                   Layer 4: 流量模式记录
    # ============================================================

    def _layer4_record(self, url, method, params, resp_status, resp_body):
        """记录请求档案 (供批量分析做模式对比)."""
        # 用 URL 模板 (去掉 ID 等动态部分) 作为 key
        url_key = re.sub(r'/\d+', '/{id}', url)  # /api/users/1001 → /api/users/{id}
        url_key = re.sub(r'\?.*', '', url_key)    # 去掉 query string

        self._request_profiles[url_key].append({
            "method": method,
            "params": list(params.keys()),
            "status": resp_status,
            "body_length": len(resp_body),
            "body_hash": hashlib.md5(resp_body[:1000].encode()).hexdigest()[:8],
        })

    # ============================================================
    #                   批量分析 (Layer 4+5)
    # ============================================================

    def analyze_batch(self, traffic_list: List[Dict]) -> AnalysisReport:
        """
        批量分析一批流量.

        Args:
            traffic_list: [{"url":"...", "method":"GET", "params":{...},
                           "resp_status":200, "resp_body":"...", "resp_headers":{...}}]

        Returns:
            AnalysisReport
        """
        report = AnalysisReport(total_requests=len(traffic_list))

        # 先逐个分析 (Layer 1-3)
        for traffic in traffic_list:
            findings = self.analyze(
                url=traffic.get("url", ""),
                method=traffic.get("method", "GET"),
                headers=traffic.get("headers", {}),
                params=traffic.get("params", {}),
                body=traffic.get("body", ""),
                resp_status=traffic.get("resp_status", 0),
                resp_headers=traffic.get("resp_headers", {}),
                resp_body=traffic.get("resp_body", ""),
            )
            report.findings.extend(findings)

        # Layer 4: 流量模式分析
        report.findings.extend(self._layer4_batch_analysis())

        # Layer 5: 关联分析
        report.findings.extend(self._layer5_correlation())

        # 汇总攻击面
        report.attack_surface = self._summarize_attack_surface(report.findings)

        return report

    def _layer4_batch_analysis(self) -> List[TrafficFinding]:
        """分析累积的请求档案 (同接口的响应差异)."""
        findings = []

        for url_key, profiles in self._request_profiles.items():
            if len(profiles) < 2:
                continue

            # 同接口不同请求的状态码差异
            statuses = set(p["status"] for p in profiles)
            if len(statuses) > 1:
                findings.append(TrafficFinding(
                    layer="pattern",
                    finding_type="status-variation",
                    severity="medium",
                    evidence=f"{url_key}: 不同请求返回不同状态码 {statuses}",
                    location=url_key,
                    recommendation="分析为什么状态码不同 (可能存在权限差异)",
                ))

            # 同接口不同请求的响应大小差异
            lengths = [p["body_length"] for p in profiles]
            if max(lengths) - min(lengths) > 500:
                findings.append(TrafficFinding(
                    layer="pattern",
                    finding_type="size-variation",
                    severity="medium",
                    evidence=f"{url_key}: 响应大小差异 {min(lengths)}-{max(lengths)}b",
                    location=url_key,
                    recommendation="不同请求返回了不同大小的响应 (可能泄露了不同数据)",
                ))

            # 同接口参数变化 (不同请求用了不同参数)
            all_params = set()
            for p in profiles:
                all_params.update(p["params"])
            if len(all_params) > len(profiles[0]["params"]):
                extra = all_params - set(profiles[0]["params"])
                findings.append(TrafficFinding(
                    layer="pattern",
                    finding_type="param-variation",
                    severity="low",
                    evidence=f"{url_key}: 发现隐藏参数 {extra}",
                    location=url_key,
                    recommendation="测试这些隐藏参数是否可控",
                ))

        return findings

    def _layer5_correlation(self) -> List[TrafficFinding]:
        """关联分析 (Token 共享/越权可能)."""
        findings = []

        # Token 类型统计
        for token_type, tokens in self._token_registry.items():
            if len(tokens) > 1:
                findings.append(TrafficFinding(
                    layer="correlation",
                    finding_type="multiple-tokens",
                    severity="medium",
                    evidence=f"发现 {len(tokens)} 个 {token_type} Token",
                    recommendation="用不同 Token 访问同接口 → 越权检测",
                ))

        return findings

    def _summarize_attack_surface(self, findings: List[TrafficFinding]) -> Dict[str, List[str]]:
        """汇总攻击面"""
        surface = defaultdict(list)
        for f in findings:
            if f.layer == "attack-surface":
                if f.evidence not in surface[f.finding_type]:
                    surface[f.finding_type].append(f.evidence[:50])
        return dict(surface)
