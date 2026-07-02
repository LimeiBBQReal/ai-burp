"""
TrafficJournal 单元测试.

覆盖:
    - record_http: HTTP 流量记录, 自动打标签/参数提取/错误检测
    - record_raw: 多协议流量记录
    - record_finding: 漏洞发现记录
    - llm_summary: 生成 LLM 友好摘要
    - detect_patterns: 模式发现 (IDOR/错误/状态码)
    - TrafficEntry.to_llm_line: 单行压缩
"""
import pytest
from aiburp.traffic.traffic_journal import TrafficJournal, TrafficEntry


# ============================================================
# TrafficEntry 序列化
# ============================================================

class TestTrafficEntry:
    def test_to_llm_line_basic(self):
        e = TrafficEntry(id=1, protocol="http",
                         summary="GET /api/user?id=1 → 200 120b JSON",
                         tags=["api", "param"])
        line = e.to_llm_line()
        assert "[1]" in line
        assert "HTTP" in line
        assert "api,param" in line
        assert "/api/user" in line

    def test_to_llm_line_with_error(self):
        e = TrafficEntry(id=5, protocol="http",
                         summary="GET /search?id=1' → 500 200b",
                         error_signals="SQL syntax error near")
        line = e.to_llm_line()
        assert "⚠" in line
        assert "SQL" in line


# ============================================================
# TrafficJournal 基础
# ============================================================

class TestTrafficJournal:
    def test_record_http_basic(self):
        j = TrafficJournal()
        e = j.record_http("GET", "http://target.com/api/user?id=1", 200, 120)
        assert e.protocol == "http"
        assert e.status == 200
        assert e.method == "GET"
        assert "api" in e.tags
        assert "id=1" in e.params

    def test_record_http_auto_tags(self):
        j = TrafficJournal()
        # API + 参数
        e = j.record_http("POST", "https://t.com/api/login?user=admin", 200, 500)
        assert "api" in e.tags
        assert "auth" in e.tags or "param" in e.tags

    def test_record_http_error_detection(self):
        j = TrafficJournal()
        e = j.record_http("GET", "http://t.com/page", 500, 300,
                          body='<html>SQL syntax error near MySQL</html>')
        assert e.error_signals
        assert "SQL" in e.error_signals

    def test_record_http_500_tags(self):
        j = TrafficJournal()
        e = j.record_http("GET", "http://t.com/err", 500, 50)
        assert "err5xx" in e.tags

    def test_record_http_redirect_tags(self):
        j = TrafficJournal()
        e = j.record_http("GET", "http://t.com/old", 302, 0)
        assert "redirect" in e.tags

    def test_record_raw(self):
        j = TrafficJournal()
        e = j.record_raw("redis", "10.0.0.5:6379", "PING → +PONG",
                         tags=["db", "unauth"])
        assert e.protocol == "redis"
        assert "PONG" in e.summary
        assert "unauth" in e.tags

    def test_record_finding(self):
        j = TrafficJournal()
        e = j.record_finding("sqli", "http://t.com?id=1'",
                             "SQL syntax error", severity="high")
        assert e.protocol == "finding"
        assert "vuln-sqli" in e.tags
        assert "severity-high" in e.tags
        assert "HIGH" in e.summary


# ============================================================
# llm_summary
# ============================================================

class TestLLMSummary:
    def test_summary_contains_stats(self):
        j = TrafficJournal()
        for i in range(5):
            j.record_http("GET", f"http://t.com/api?id={i}", 200, 100 + i)
        summary = j.llm_summary(last_n=10)
        assert "TrafficJournal" in summary
        assert "[0]" in summary
        assert "[4]" in summary
        assert "统计" in summary or "HTTP" in summary

    def test_summary_empty(self):
        j = TrafficJournal()
        s = j.llm_summary()
        assert "0条" in s or "0" in s


# ============================================================
# detect_patterns
# ============================================================

class TestDetectPatterns:
    def test_no_patterns_on_empty(self):
        j = TrafficJournal()
        assert j.detect_patterns() == []

    def test_same_endpoint_diff_params(self):
        """同一端点不同参数但响应长度相似 → IDOR 模式."""
        j = TrafficJournal()
        for i in [1, 2, 3]:
            j.record_http("GET", f"http://t.com/api/user?id={i}", 200, 100)
        patterns = j.detect_patterns()
        idor_patterns = [p for p in patterns if "params" in p.get("pattern", "")]
        assert len(idor_patterns) >= 1

    def test_not_enough_requests_no_pattern(self):
        """少于 3 次不触发 IDOR 模式."""
        j = TrafficJournal()
        j.record_http("GET", "http://t.com/api?id=1", 200, 100)
        j.record_http("GET", "http://t.com/api?id=2", 201, 200)
        patterns = j.detect_patterns()
        idor_pats = [p for p in patterns if "params" in p.get("pattern", "")]
        assert len(idor_pats) == 0

    def test_repeated_errors_pattern(self):
        j = TrafficJournal()
        for _ in range(3):
            j.record_http("GET", "http://t.com/x", 500, 50,
                         body="SQL syntax error")
        patterns = j.detect_patterns()
        err_pats = [p for p in patterns if p.get("pattern") == "repeated-errors"]
        assert len(err_pats) >= 1

    def test_multi_status_codes_pattern(self):
        j = TrafficJournal()
        for status in [200, 301, 403]:
            j.record_http("GET", f"http://t.com/{status}", status, 100)
        patterns = j.detect_patterns()
        sc_pats = [p for p in patterns if p.get("pattern") == "multi-status-codes"]
        assert len(sc_pats) >= 1


# ============================================================
# max_entries 裁剪
# ============================================================

class TestMaxEntries:
    def test_max_entries(self):
        j = TrafficJournal(max_entries=10)
        for i in range(15):
            j.record_http("GET", f"http://t.com/r?id={i}", 200, 100)
        assert len(j._entries) <= 12  # 1.2x buffer


# ============================================================
# ExtractParams
# ============================================================

class TestExtractParams:
    def test_single_param(self):
        assert TrafficJournal._extract_params("http://t.com/p?id=1") == "id=1"

    def test_multi_params(self):
        p = TrafficJournal._extract_params("http://t.com/p?id=1&name=test&page=2")
        assert "id=1" in p
        assert "name=test" in p

    def test_no_params(self):
        assert TrafficJournal._extract_params("http://t.com/p") == ""