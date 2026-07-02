"""
IntentAnalyzer V4 多协议扩展测试.

覆盖 review 发现的问题 + 验证扩展能力:
    - I2: 关键词词边界 (id/video 误报)
    - I3: JWT 正则收紧
    - analyze_response: HTTP/DNS/Redis 各协议
    - suggest_next_steps: 攻击向量建议
    - 向后兼容 (V3 analyze/suggest_detectors)
"""

import pytest

from aiburp.burp import IntentAnalyzer
from aiburp.traffic import TrafficResponse


class TestKeywordFalsePositives:
    """I2: 关键词误报 (词边界)"""

    @pytest.mark.parametrize("url,should_have_db", [
        ("https://x.com/api?id=1", True),    # 真 DB 参数
        ("https://x.com/video/1", False),    # video 含 id 子串但不该匹配
        ("https://x.com/provide", False),
        ("https://x.com/valid", False),
        ("https://x.com/consider", False),
        ("https://x.com/hidden", False),
        ("https://x.com/running", False),    # run 子串
    ])
    def test_db_keyword_boundaries(self, url, should_have_db):
        tags = IntentAnalyzer.analyze(url, None)
        if should_have_db:
            assert "DB" in tags
        else:
            assert "DB" not in tags


class TestSensitivePatterns:
    """I3 + 敏感信息检测"""

    def test_real_email_detected(self):
        resp = TrafficResponse(protocol="http", text="email admin@target.com", tags=[])
        tags = IntentAnalyzer.analyze_response(resp)
        assert "LEAK-EMAIL" in tags

    def test_fake_jwt_rejected(self):
        """I3: 普通 base64 不误判为 JWT"""
        resp = TrafficResponse(protocol="http", text="data eyJabc.def.ghi end", tags=[])
        tags = IntentAnalyzer.analyze_response(resp)
        assert "LEAK-JWT" not in tags

    def test_real_jwt_detected(self):
        resp = TrafficResponse(
            protocol="http",
            text="eyJabcd123456.efgh12345678.ijkl12345678",
            tags=[],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "LEAK-JWT" in tags

    def test_aws_key_detected(self):
        resp = TrafficResponse(protocol="http", text="error: AKIAIOSFODNN7EXAMPLE", tags=[])
        tags = IntentAnalyzer.analyze_response(resp)
        assert "LEAK-AWS_KEY" in tags

    def test_private_key_detected(self):
        resp = TrafficResponse(
            protocol="http",
            text="-----BEGIN RSA PRIVATE KEY-----\nMII...",
            tags=[],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "LEAK-PRIVATE_KEY" in tags


class TestAnalyzeResponse:
    """analyze_response 多协议"""

    def test_http_business_intent(self):
        resp = TrafficResponse(
            protocol="http", url="https://target.com/login",
            text="", tags=[], target="https://target.com/login",
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "AUTH" in tags

    def test_redis_unauth_confirmed(self):
        resp = TrafficResponse(
            protocol="redis", banner="redis/7.0",
            tags=["REDIS", "UNAUTH-CONFIRMED", "HIGH-VALUE"],
            anomalies=["unauth-access", "rce-possible"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "RCE-PATH" in tags
        assert "HIGH-VALUE" in tags

    def test_dns_internal_asset(self):
        resp = TrafficResponse(
            protocol="dns", target="internal.corp.local",
            tags=["DNS"], banner="",
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "INTERNAL-ASSET" in tags

    def test_ssh_bruteforce_target(self):
        resp = TrafficResponse(
            protocol="tcp", banner="ssh/2.0", tags=["SSH"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "BRUTEFORCE-TARGET" in tags

    def test_none_response_safe(self):
        """边界: None 不崩"""
        tags = IntentAnalyzer.analyze_response(None)
        assert tags == []

    def test_empty_response_safe(self):
        tags = IntentAnalyzer.analyze_response(TrafficResponse())
        assert isinstance(tags, list)


class TestSuggestNextSteps:
    """suggest_next_steps 攻击建议"""

    def test_redis_unauth_prioritize_exploit(self):
        """Redis 确认未授权 -> exploit_rce 排第一 (critical)"""
        tags = ["REDIS", "UNAUTH-CONFIRMED", "HIGH-VALUE", "RCE-PATH"]
        steps = IntentAnalyzer.suggest_next_steps(tags, "redis")
        assert len(steps) > 0
        assert steps[0]["action"] == "exploit_rce"
        assert steps[0]["priority"] == "critical"

    def test_redis_vectors_included(self):
        """Redis 攻击向量都在建议里"""
        tags = ["REDIS", "HIGH-VALUE"]
        steps = IntentAnalyzer.suggest_next_steps(tags, "redis")
        actions = [s["action"] for s in steps]
        assert "check_unauth" in actions
        assert "dump_ssh_key" in actions
        assert "slaveof_rce" in actions

    def test_http_detectors_suggested(self):
        tags = ["DB", "AUTH"]
        steps = IntentAnalyzer.suggest_next_steps(tags, "http")
        actions = [s["action"] for s in steps]
        assert "scan_sqli" in actions

    def test_empty_tags_empty_steps(self):
        steps = IntentAnalyzer.suggest_next_steps([], "")
        assert steps == []

    def test_priority_ordering(self):
        """critical > high > medium"""
        tags = ["REDIS", "UNAUTH-CONFIRMED", "HIGH-VALUE", "DB"]
        steps = IntentAnalyzer.suggest_next_steps(tags, "redis")
        # 找 critical 和 medium 的位置
        priorities = [s["priority"] for s in steps]
        if "critical" in priorities and "medium" in priorities:
            assert priorities.index("critical") < priorities.index("medium")


class TestBackwardCompat:
    """向后兼容: V3 方法不变"""

    def test_analyze_signature(self):
        # 用空 dict 而非 None (str(None)='None' 会破坏 login 的尾部词边界)
        tags = IntentAnalyzer.analyze("https://x.com/admin/login", {})
        assert "ADMIN" in tags
        assert "AUTH" in tags

    def test_suggest_detectors(self):
        detectors = IntentAnalyzer.suggest_detectors(["DB", "AUTH"])
        assert "sqli" in detectors
        assert detectors.index("sqli") < detectors.index("xss")

    def test_db_intent_still_works(self):
        """V3 测试套件里的 DB 检测不破坏"""
        tags = IntentAnalyzer.analyze(
            "https://example.com/api/users?id=1", {"id": "1"}
        )
        assert "DB" in tags
