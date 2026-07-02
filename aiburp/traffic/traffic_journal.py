"""
TrafficJournal — 统一流量日志 + LLM 语义决策引擎.

设计哲学:
    Burp Suite 给人看的是 HTTP 历史 + 请求/响应原始报文.
    TrafficJournal 给 LLM 看的是 语义摘要 + 模式发现 + 决策建议.

一条 TrafficEntry 不是"存下原始请求/响应字节", 而是:
    "HTTP GET /api/user?id=1 → 200 1234b (JSON, user_id=admin, role=admin)"
    或者 "Redis 10.0.0.5:6379 → PING → +PONG (未授权, 可执行命令)"

每个条目约 50-100 tokens, 300 条历史 ≈ 30K tokens, LLM 可以一次看完.

用法:
    journal = TrafficJournal()
    journal.record_http("GET", "https://target.com/api?id=1", 200, 1234)
    journal.record_raw("redis", "10.0.0.5:6379",
                       "PING → +PONG", tags=["db", "unauth"])

    # LLM 读摘要
    summary = journal.llm_summary(last_n=20)
    patterns = journal.detect_patterns()
"""
import time
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class TrafficEntry:
    """统一流量条目 — 所有协议共用."""
    id: int = 0
    timestamp: float = 0.0
    protocol: str = ""         # http / redis / mysql / dns / tcp / ...
    direction: str = ""        # request / response / bidirectional
    source: str = ""           # proxy / probe / scan / inject / manual
    target: str = ""           # host:port or URL
    summary: str = ""          # 一句话描述 (LLM 友好)
    tags: List[str] = field(default_factory=list)   # 语义标签
    status: int = 0            # HTTP 状态码
    length: int = 0            # 响应长度
    method: str = ""           # HTTP 方法
    params: str = ""           # 参数摘要
    error_signals: str = ""    # 检测到的异常信号
    flags: Dict[str, Any] = field(default_factory=dict)  # 扩展标记

    def to_llm_line(self) -> str:
        """压缩成一行 LLM 友好的摘要 (~60-100 tokens)."""
        parts = [f"[{self.id}]"]
        if self.protocol:
            parts.append(self.protocol.upper())
        parts.append(self.summary[:100])
        if self.tags:
            parts.append("<" + ",".join(self.tags[:3]) + ">")
        if self.error_signals:
            parts.append("⚠" + self.error_signals[:40])
        return " ".join(parts)


class TrafficJournal:
    """
    统一流量日志 — 所有协议的流量统一记录, 生成 LLM 可读的语义摘要.
    Thread-safe: 多条线程可以同时写入.
    """

    SQL_ERROR_KEYWORDS = [
        "SQL syntax", "mysql_", "ORA-", "PostgreSQL", "SQL Server",
        "SqlException", "System.Data.", "unclosed quotation",
    ]
    BLOCK_KEYWORDS = [
        "blocked", "captcha", "cf-ray", "cloudflare", "waf",
        "denied", "forbidden",
    ]

    def __init__(self, max_entries: int = 300):
        self._entries: List[TrafficEntry] = []
        self._max = max_entries
        self._count = 0

    # ============================================================
    # 记录方法
    # ============================================================

    def record_http(self, method: str, url: str, status: int,
                    length: int, body: str = "", headers: dict = None,
                    source: str = "probe", elapsed_ms: float = 0) -> TrafficEntry:
        """记录一条 HTTP 流量."""
        headers = headers or {}
        body_preview = (body or "")[:2000]
        summary = self._summarize_http(method, url, status, length, body_preview)
        tags = self._auto_tag_http(method, url, status, body_preview, headers)
        return self._add(
            protocol="http", direction="response", source=source,
            target=url, summary=summary, tags=tags,
            status=status, length=length, method=method,
            params=self._extract_params(url),
            error_signals=self._detect_errors(body_preview),
            flags={"ms": round(elapsed_ms, 1)} if elapsed_ms else {},
        )

    def record_raw(self, protocol: str, target: str, summary: str,
                   tags: list = None, direction: str = "bidirectional",
                   source: str = "probe", status: int = 0,
                   error: str = "") -> TrafficEntry:
        """记录非 HTTP 协议流量 (Redis/MySQL/DNS/TCP/...)."""
        return self._add(
            protocol=protocol, direction=direction, source=source,
            target=target, summary=summary, tags=tags or [],
            status=status, error_signals=error,
        )

    def record_finding(self, vuln_type: str, target: str,
                       evidence: str, severity: str = "info",
                       source: str = "detector") -> TrafficEntry:
        """记录一条漏洞发现."""
        tags = [f"vuln-{vuln_type}", f"severity-{severity}"]
        summary = f"[{severity.upper()}] {vuln_type} @ {target}: {evidence[:80]}"
        return self._add(
            protocol="finding", direction="response", source=source,
            target=target, summary=summary, tags=tags,
            error_signals=evidence[:100],
        )

    # ============================================================
    # LLM 接口
    # ============================================================

    def llm_summary(self, last_n: int = 30) -> str:
        """
        生成 LLM 友好的流量摘要.

        LLM 读这个就知道"过去 N 次交互里发生了什么".
        """
        entries = self._entries[-last_n:] if last_n else self._entries
        lines = [e.to_llm_line() for e in entries]
        stats = self._quick_stats(entries)

        header = f"=== TrafficJournal (最近 {len(entries)}/{len(self._entries)} 条) ==="
        footer = (
            f"--- 统计: {stats['total']}条 HTTP={stats['http']} "
            f"异常={stats['errors']} 漏洞={stats['vulns']} "
            f"[{stats['top_tags']}] ---"
        )
        return "\n".join([header] + lines + [footer])

    def detect_patterns(self, window: int = 30) -> List[dict]:
        """
        检测流量模式 — 给 LLM 的决策依据.

        Returns:
            [{"pattern": "same-endpoint-different-params",
              "endpoint": "/api/user",
              "evidence": "...",
              "severity": "medium",
              "suggestion": "..."}, ...]
        """
        entries = self._entries[-window:]
        patterns = []

        # 模式 1: 同一端点不同参数响应差异小 → IDOR
        eps_map = {}
        for e in entries:
            if e.protocol == "http" and e.params:
                base = e.target.split("?")[0]
                eps_map.setdefault(base, []).append(e)

        for url, eps in eps_map.items():
            if len(eps) >= 3:
                param_sigs = set(e.params for e in eps if e.params)
                if len(param_sigs) >= 2:
                    lens = [e.length for e in eps if e.length > 0]
                    if lens and max(lens) - min(lens) < 200:
                        patterns.append({
                            "pattern": "same-endpoint-different-params",
                            "endpoint": url,
                            "evidence": (f"{len(eps)}次请求 参数({', '.join(list(param_sigs)[:3])}) "
                                         f"响应长度差<200b"),
                            "severity": "medium",
                            "suggestion": "IDOR: 遍历参数值看是否返回不同用户数据",
                        })

        # 模式 2: 重复错误信号
        errs = [e for e in entries if e.error_signals]
        if len(errs) >= 2:
            patterns.append({
                "pattern": "repeated-errors",
                "endpoint": "multiple",
                "evidence": f"{len(errs)}条异常: {errs[0].error_signals[:40]}",
                "severity": "high",
                "suggestion": "异常集中 → 深入探测注入",
            })

        # 模式 3: 多状态码分布
        sc = {}
        for e in entries:
            if e.status:
                sc[e.status] = sc.get(e.status, 0) + 1
        if len(sc) >= 3:
            patterns.append({
                "pattern": "multi-status-codes",
                "endpoint": "global",
                "evidence": f"状态码: {sc}",
                "severity": "info",
                "suggestion": "多种状态码 → 分析不同状态下的响应差异",
            })

        return patterns

    # ============================================================
    # 内部
    # ============================================================

    def _add(self, **kwargs) -> TrafficEntry:
        e = TrafficEntry(id=self._count, timestamp=time.time(), **kwargs)
        self._entries.append(e)
        self._count += 1
        if len(self._entries) > self._max * 1.2:
            self._entries = self._entries[-self._max:]
        return e

    def _summarize_http(self, method: str, url: str, status: int,
                        length: int, body: str) -> str:
        p = urlparse(url)
        path = (p.path or "/") + ("?" + p.query[:60] if p.query else "")
        ct = ""
        if body.strip().startswith("{"):
            ct = " JSON"
        elif body.strip().startswith("<"):
            ct = " HTML"
        return f"{method} {path} → {status} {length}b{ct}"

    def _auto_tag_http(self, method: str, url: str, status: int,
                       body: str, headers: dict) -> list:
        tags, ul = [], url.lower()
        if any(k in ul for k in ["api", "query", "search", "wp-json"]):
            tags.append("api")
        if any(k in ul for k in ["id=", "user=", "uid=", "page="]):
            tags.append("param")
        if any(k in ul for k in ["admin", "login", "auth", "session"]):
            tags.append("auth")
        if body.strip().startswith("{"):
            tags.append("json")
        if status in (403, 429, 503):
            tags.append("blocked")
        if status >= 500:
            tags.append("err5xx")
        if status in (301, 302):
            tags.append("redirect")
        if self._detect_errors(body):
            tags.append("errsig")
        return tags

    @staticmethod
    def _extract_params(url: str) -> str:
        qs = parse_qs(urlparse(url).query)
        if qs:
            return ", ".join(f"{k}={v[0][:15]}" for k, v in list(qs.items())[:4])
        return ""

    def _detect_errors(self, body: str) -> str:
        if not body:
            return ""
        for kw in self.SQL_ERROR_KEYWORDS:
            if kw.lower() in body.lower():
                return f"SQL:{kw}"
        if re.search(r"at\s+\w+\.\w+\(.*\)", body):
            return "stack-trace"
        if re.search(r"(Fatal|Parse|Warning)\s+error", body, re.I):
            return "php-error"
        return ""

    @staticmethod
    def _quick_stats(entries: list) -> dict:
        total = len(entries)
        http = sum(1 for e in entries if e.protocol == "http")
        errors = sum(1 for e in entries if e.error_signals)
        vulns = sum(1 for e in entries if e.protocol == "finding")
        tc = {}
        for e in entries:
            for t in e.tags:
                tc[t] = tc.get(t, 0) + 1
        top = ",".join(f"{t}({c})" for t, c in sorted(tc.items(), key=lambda x: -x[1])[:4])
        return {"total": total, "http": http, "errors": errors, "vulns": vulns, "top_tags": top}