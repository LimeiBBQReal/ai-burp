"""
AIBURP Repeater - 请求重放

AI 说改什么就改什么，AI 说发就发
工具只执行，不做决策
"""

import re
import time
import httpx
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from .models import Request, Response
from .history import History


# ============================================================
# 数据模型
# ============================================================

@dataclass
class VulnResult:
    """
    漏洞测试结果
    
    用于 test_sqli(), test_xss() 等方法的返回值
    """
    vulnerable: bool = False
    confidence: str = ""  # confirmed, likely, possible
    payload: str = ""
    evidence: str = ""
    request: Optional[Request] = None
    response: Optional[Response] = None
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": self.request.to_dict() if self.request else None,
            "response": self.response.to_dict() if self.response else None,
        }
    
    def __str__(self) -> str:
        if self.vulnerable:
            return f"[VULN] {self.confidence}: {self.payload} - {self.evidence}"
        return "[SAFE] No vulnerability found"


@dataclass
class CompareResult:
    """
    基线对比结果
    
    用于 compare_baseline() 方法的返回值
    """
    payload: str = ""
    status_changed: bool = False
    length_diff: int = 0
    time_diff: float = 0
    anomalies: List[str] = field(default_factory=list)
    reflects: bool = False
    response: Optional[Response] = None
    
    def to_dict(self) -> Dict:
        return {
            "payload": self.payload,
            "status_changed": self.status_changed,
            "length_diff": self.length_diff,
            "time_diff": self.time_diff,
            "anomalies": self.anomalies,
            "reflects": self.reflects,
            "response": self.response.to_dict() if self.response else None,
        }
    
    @property
    def is_interesting(self) -> bool:
        """是否值得关注"""
        return (
            len(self.anomalies) > 0 or
            self.reflects or
            self.status_changed or
            abs(self.length_diff) > 100 or
            self.time_diff > 2000  # 2秒以上延迟
        )
    
    def __str__(self) -> str:
        flags = []
        if self.status_changed:
            flags.append("status_changed")
        if self.reflects:
            flags.append("reflects")
        if self.anomalies:
            flags.append(f"anomalies={self.anomalies}")
        if abs(self.length_diff) > 100:
            flags.append(f"length_diff={self.length_diff}")
        return f"[{self.payload}] {', '.join(flags) if flags else 'normal'}"


@dataclass
class FuzzResult:
    """
    Fuzz 测试结果
    
    用于 fuzz() 方法的返回值
    """
    param: str = ""
    total: int = 0
    tested: int = 0
    results: List[CompareResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "param": self.param,
            "total": self.total,
            "tested": self.tested,
            "results": [r.to_dict() for r in self.results],
            "interesting": [r.to_dict() for r in self.results if r.is_interesting],
            "interesting_count": self.interesting_count,
        }
    
    @property
    def interesting_count(self) -> int:
        return sum(1 for r in self.results if r.is_interesting)
    
    @property
    def has_findings(self) -> bool:
        return self.interesting_count > 0


class Repeater:
    """
    请求重放器
    
    用法:
        repeater = Repeater(history)
        
        # 重放原始请求
        resp = repeater.send(request_id=123)
        
        # 修改参数重放
        resp = repeater.send(request_id=123, modify={"params": {"id": "1'"}})
        
        # 对比响应
        diff = repeater.diff(resp1, resp2)
    """
    
    # 错误特征（辅助 AI，标记异常）
    ERROR_PATTERNS = {
        # MySQL
        r"SQL syntax.*MySQL": "mysql_error",
        r"Warning.*mysql_": "mysql_error",
        r"MySqlException": "mysql_error",
        r"You have an error in your SQL syntax": "mysql_error",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR": "postgresql_error",
        r"pg_query": "postgresql_error",
        
        # MSSQL
        r"Microsoft.*ODBC": "mssql_error",
        r"SQL Server": "mssql_error",
        r"ODBC SQL Server Driver": "mssql_error",
        
        # Oracle
        r"ORA-\d{5}": "oracle_error",
        r"Oracle.*Driver": "oracle_error",
        
        # SQLite
        r"SQLite.*error": "sqlite_error",
        
        # Access
        r"Microsoft JET Database Engine": "access_error",
        r"Syntax error in string in query expression": "access_error",
        
        # 通用 SQL
        r"syntax error": "sql_syntax_error",
        r"unexpected end of SQL": "sql_error",
        
        # PHP
        r"<b>Warning</b>:": "php_warning",
        r"PHP Warning:": "php_warning",
        r"PHP Fatal error:": "php_error",
        r"Warning:.*in.*on line \d+": "php_warning",
        
        # ASP
        r"Microsoft VBScript runtime": "asp_error",
        r"error '800a": "asp_error",
        
        # 路径泄露
        r"[A-Z]:\\[^\s]+\.(php|asp|aspx|jsp)": "path_disclosure",
        r"/var/www/": "path_disclosure",
        r"/home/[^/]+/": "path_disclosure",
        
        # 堆栈跟踪
        r"at [a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(": "stack_trace",
        r"Traceback \(most recent call last\)": "python_traceback",
    }
    
    # WAF 特征
    WAF_PATTERNS = {
        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "imperva": ["incap_ses", "visid_incap"],
        "aws_waf": ["awswaf", "x-amzn-requestid"],
        "sucuri": ["x-sucuri", "sucuri"],
        "f5": ["x-wa-info", "bigip"],
        "modsecurity": ["mod_security", "modsec"],
    }
    
    def __init__(
        self,
        history: History = None,
        timeout: float = 30.0,
        delay: float = 1.0,
        verify_ssl: bool = False,
        follow_redirects: bool = False,
    ):
        self.history = history
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=follow_redirects,
        )
        self._last_request_time = 0.0
    
    def send(
        self,
        request: Request = None,
        request_id: int = None,
        modify: Dict = None,
    ) -> Response:
        """
        发送请求
        
        Args:
            request: Request 对象
            request_id: 从 History 获取请求
            modify: 修改内容
                - params: {"name": "value"} 修改 URL/Body 参数
                - headers: {"name": "value"} 修改请求头
                - body: "..." 替换整个 body
                - method: "POST" 修改方法
        
        Returns:
            Response 对象
        """
        # 获取请求
        if request_id and self.history:
            request = self.history.get(request_id)
            if not request:
                return Response(status=0, body=f"Request {request_id} not found")
        
        if not request:
            return Response(status=0, body="No request provided")
        
        # 应用修改
        if modify:
            request = self._apply_modify(request, modify)
        
        # 延迟
        self._wait()
        
        # 发送
        try:
            start_time = time.time()
            
            resp = self._client.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                content=request.body if request.body else None,
            )
            
            elapsed = (time.time() - start_time) * 1000
            
            response = Response(
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                time_ms=elapsed,
            )
            
            # 检测异常（辅助 AI）
            response.anomalies = self._detect_anomalies(response)
            
            return response
            
        except Exception as e:
            return Response(
                status=0,
                body=str(e),
                anomalies=["request_failed"],
            )
    
    def send_raw(self, raw: str, base_url: str = "") -> Response:
        """发送原始 HTTP 请求"""
        request = Request.from_raw(raw, base_url=base_url)
        return self.send(request)
    
    def diff(self, resp1: Response, resp2: Response) -> Dict:
        """
        对比两个响应
        返回差异信息（给 AI 分析）
        """
        return {
            "status_changed": resp1.status != resp2.status,
            "status": {"before": resp1.status, "after": resp2.status},
            
            "length_diff": resp2.length - resp1.length,
            "length": {"before": resp1.length, "after": resp2.length},
            
            "time_diff": resp2.time_ms - resp1.time_ms,
            "time": {"before": resp1.time_ms, "after": resp2.time_ms},
            
            "new_anomalies": [a for a in resp2.anomalies if a not in resp1.anomalies],
            "anomalies": {"before": resp1.anomalies, "after": resp2.anomalies},
            
            # 内容差异（简化版）
            "content_changed": resp1.body != resp2.body,
            "content_diff_ratio": self._diff_ratio(resp1.body, resp2.body),
        }
    
    def compare_baseline(
        self,
        request: Request,
        payloads: List[str],
        param: str,
    ) -> List[CompareResult]:
        """
        与基线对比测试
        
        先发原始请求获取基线，然后逐个测试 payload
        返回每个 payload 的 CompareResult
        
        Args:
            request: 原始请求
            payloads: payload 列表
            param: 要测试的参数名
        
        Returns:
            CompareResult 列表
        """
        # 基线
        baseline = self.send(request)
        
        results = []
        for payload in payloads:
            modified = request.with_param(param, payload)
            resp = self.send(modified)
            
            result = CompareResult(
                payload=payload,
                status_changed=resp.status != baseline.status,
                length_diff=resp.length - baseline.length,
                time_diff=resp.time_ms - baseline.time_ms,
                anomalies=resp.anomalies,
                reflects=payload in resp.body,
                response=resp,
            )
            results.append(result)
        
        return results
    
    # ==================== 漏洞测试方法 ====================
    
    def test_sqli(self, request: Request, param: str) -> VulnResult:
        """
        SQL 注入测试
        
        使用常见的 SQL 注入 payload 测试指定参数，
        通过检测响应中的数据库错误信息来判断是否存在漏洞。
        
        Args:
            request: 原始请求
            param: 要测试的参数名
        
        Returns:
            VulnResult 对象，包含漏洞检测结果
        
        Requirements: 6.1, 6.6
        """
        # SQL 注入测试 payload
        sqli_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1 AND 1=1",
            "1 AND 1=2",
            "' AND '1'='1",
            "' AND '1'='2",
            "1; SELECT 1--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",
            "') OR ('1'='1",
            "1 OR 1=1",
            "' OR 1=1--",
            "admin'--",
        ]
        
        # SQL 错误类型
        sql_error_types = [
            "mysql_error", "postgresql_error", "mssql_error",
            "oracle_error", "sqlite_error", "access_error",
            "sql_error", "sql_syntax_error"
        ]
        
        results = self.compare_baseline(request, sqli_payloads, param)
        
        for result in results:
            # 检查是否有 SQL 错误
            sql_errors = [a for a in result.anomalies if a in sql_error_types]
            if sql_errors:
                return VulnResult(
                    vulnerable=True,
                    confidence="confirmed",
                    payload=result.payload,
                    evidence=f"SQL error detected: {', '.join(sql_errors)}",
                    response=result.response,
                )
        
        # 检查布尔盲注 (AND 1=1 vs AND 1=2)
        and_true_results = [r for r in results if "AND 1=1" in r.payload]
        and_false_results = [r for r in results if "AND 1=2" in r.payload]
        
        if and_true_results and and_false_results:
            true_result = and_true_results[0]
            false_result = and_false_results[0]
            
            # 如果 AND 1=1 和 AND 1=2 响应长度差异显著
            if abs(true_result.length_diff - false_result.length_diff) > 50:
                return VulnResult(
                    vulnerable=True,
                    confidence="likely",
                    payload="Boolean-based blind SQLi",
                    evidence=f"Different responses for AND 1=1 (len_diff={true_result.length_diff}) vs AND 1=2 (len_diff={false_result.length_diff})",
                    response=true_result.response,
                )
        
        return VulnResult(vulnerable=False)
    
    def test_xss(self, request: Request, param: str) -> VulnResult:
        """
        XSS 测试
        
        使用常见的 XSS payload 测试指定参数，
        通过检测 payload 是否在响应中反射来判断是否存在漏洞。
        
        Args:
            request: 原始请求
            param: 要测试的参数名
        
        Returns:
            VulnResult 对象，包含漏洞检测结果
        
        Requirements: 6.2, 6.5
        """
        # XSS 测试 payload
        xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "<iframe src=\"javascript:alert(1)\">",
            "<input onfocus=alert(1) autofocus>",
        ]
        
        for payload in xss_payloads:
            modified = request.with_param(param, payload)
            resp = self.send(modified)
            
            # 检查 payload 是否反射
            if payload in resp.body:
                # 确认是否被编码
                encoded_checks = [
                    ("&lt;", "<"),
                    ("&gt;", ">"),
                    ("&quot;", "\""),
                    ("&#39;", "'"),
                ]
                
                is_encoded = False
                for encoded, original in encoded_checks:
                    if original in payload and encoded in resp.body:
                        is_encoded = True
                        break
                
                if not is_encoded:
                    return VulnResult(
                        vulnerable=True,
                        confidence="confirmed",
                        payload=payload,
                        evidence="Payload reflected in response without encoding",
                        response=resp,
                    )
                else:
                    # 部分反射但被编码
                    return VulnResult(
                        vulnerable=True,
                        confidence="possible",
                        payload=payload,
                        evidence="Payload reflected but may be encoded",
                        response=resp,
                    )
        
        return VulnResult(vulnerable=False)
    
    def fuzz(
        self,
        request: Request,
        param: str,
        payloads: List[str],
    ) -> FuzzResult:
        """
        自定义 Fuzz 测试
        
        使用自定义 payload 列表测试指定参数，
        返回所有测试结果供 AI 分析。
        
        Args:
            request: 原始请求
            param: 要测试的参数名
            payloads: 自定义 payload 列表
        
        Returns:
            FuzzResult 对象，包含所有测试结果
        
        Requirements: 6.3, 6.4
        """
        results = self.compare_baseline(request, payloads, param)
        
        return FuzzResult(
            param=param,
            total=len(payloads),
            tested=len(results),
            results=results,
        )
    
    # ==================== 内部方法 ====================
    
    def _wait(self):
        """请求间隔"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request_time = time.time()
    
    def _apply_modify(self, request: Request, modify: Dict) -> Request:
        """应用修改"""
        # 复制请求
        new_req = Request(
            method=modify.get("method", request.method),
            url=request.url,
            headers=dict(request.headers),
            body=request.body,
            id=request.id,
            timestamp=request.timestamp,
            tags=list(request.tags),
            notes=request.notes,
        )
        
        # 修改参数
        if "params" in modify:
            for name, value in modify["params"].items():
                new_req = new_req.with_param(name, value)
        
        # 修改头
        if "headers" in modify:
            for name, value in modify["headers"].items():
                new_req.headers[name] = value
        
        # 替换 body
        if "body" in modify:
            new_req.body = modify["body"]
        
        return new_req
    
    def _detect_anomalies(self, response: Response) -> List[str]:
        """
        检测响应异常
        这只是辅助 AI，不做决策
        """
        anomalies = []
        
        # 检测错误信息
        for pattern, anomaly_type in self.ERROR_PATTERNS.items():
            if re.search(pattern, response.body, re.I):
                if anomaly_type not in anomalies:
                    anomalies.append(anomaly_type)
        
        # 检测 WAF
        headers_str = str(response.headers).lower()
        body_lower = response.body.lower()
        for waf_name, signatures in self.WAF_PATTERNS.items():
            for sig in signatures:
                if sig in headers_str or sig in body_lower:
                    anomalies.append(f"waf_{waf_name}")
                    break
        
        # 检测拦截
        if response.status in [403, 406, 429, 503]:
            block_signs = ["blocked", "forbidden", "denied", "firewall", "waf"]
            if any(sign in body_lower for sign in block_signs):
                anomalies.append("blocked")
        
        # 检测反射（简单检查）
        # 这个需要知道 payload，所以在外部处理
        
        return anomalies
    
    def _diff_ratio(self, s1: str, s2: str) -> float:
        """计算两个字符串的差异比例"""
        if not s1 and not s2:
            return 0.0
        if not s1 or not s2:
            return 1.0
        
        # 简单的长度差异比例
        max_len = max(len(s1), len(s2))
        diff = abs(len(s1) - len(s2))
        return diff / max_len
    
    # ==================== 给 AI 用的接口 ====================
    
    def test_param(
        self,
        request_id: int,
        param: str,
        payload: str,
    ) -> Dict:
        """
        测试单个参数
        返回结构化结果给 AI
        """
        if not self.history:
            return {"error": "No history configured"}
        
        request = self.history.get(request_id)
        if not request:
            return {"error": f"Request {request_id} not found"}
        
        # 基线
        baseline = self.send(request)
        
        # 测试
        modified = request.with_param(param, payload)
        test_resp = self.send(modified)
        
        # 检查反射
        reflects = payload in test_resp.body
        
        return {
            "request_id": request_id,
            "param": param,
            "payload": payload,
            "baseline": {
                "status": baseline.status,
                "length": baseline.length,
                "time_ms": baseline.time_ms,
            },
            "test": {
                "status": test_resp.status,
                "length": test_resp.length,
                "time_ms": test_resp.time_ms,
                "anomalies": test_resp.anomalies,
                "reflects": reflects,
            },
            "diff": self.diff(baseline, test_resp),
        }
    
    def close(self):
        """关闭客户端"""
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
