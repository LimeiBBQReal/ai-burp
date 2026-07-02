"""
AI-Burp V3 核心测试
"""

import pytest
import asyncio
from aiburp import AsyncBurp, SyncBurp, Response, IntentAnalyzer


class TestAsyncBurp:
    """AsyncBurp 异步核心测试"""
    
    @pytest.mark.asyncio
    async def test_basic_get(self, httpbin_url):
        """基本 GET 请求"""
        async with AsyncBurp() as burp:
            r = await burp.get(f"{httpbin_url}/get")
            assert r.ok
            assert r.status == 200
            assert r.length > 0
    
    @pytest.mark.asyncio
    async def test_post_json(self, httpbin_url):
        """POST JSON 请求"""
        async with AsyncBurp() as burp:
            r = await burp.post(
                f"{httpbin_url}/post",
                json={"test": "value"}
            )
            assert r.ok
            assert r.status == 200
            assert "test" in r.body
    
    @pytest.mark.asyncio
    async def test_fuzz(self, httpbin_url):
        """批量 Fuzz"""
        async with AsyncBurp(concurrency=3) as burp:
            results = await burp.fuzz(
                f"{httpbin_url}/get?id=§",
                ["1", "2", "3"]
            )
            assert len(results) == 3
            for r in results:
                assert r.ok
    
    @pytest.mark.asyncio
    async def test_history(self, httpbin_url):
        """请求历史"""
        async with AsyncBurp() as burp:
            await burp.get(f"{httpbin_url}/get")
            await burp.get(f"{httpbin_url}/headers")
            assert len(burp.history) == 2


class TestSyncBurp:
    """SyncBurp 同步包装器测试"""
    
    def test_basic_get(self, httpbin_url):
        """基本 GET 请求"""
        with SyncBurp() as burp:
            r = burp.get(f"{httpbin_url}/get")
            assert r.ok
            assert r.status == 200
    
    def test_fuzz(self, httpbin_url):
        """批量 Fuzz"""
        with SyncBurp() as burp:
            results = burp.fuzz(
                f"{httpbin_url}/get?id=§",
                ["a", "b"]
            )
            assert len(results) == 2


class TestIntentAnalyzer:
    """语义分析器测试"""
    
    def test_db_intent(self):
        """数据库相关 URL"""
        tags = IntentAnalyzer.analyze(
            "https://example.com/api/users?id=1",
            {"id": "1"}
        )
        assert "DB" in tags
    
    def test_auth_intent(self):
        """认证相关 URL"""
        tags = IntentAnalyzer.analyze(
            "https://example.com/login",
            {"username": "admin", "password": "test"}
        )
        assert "AUTH" in tags
    
    def test_file_intent(self):
        """文件相关 URL"""
        tags = IntentAnalyzer.analyze(
            "https://example.com/download?file=report.pdf",
            {}
        )
        assert "FILE" in tags
    
    def test_suggest_detectors(self):
        """检测器建议"""
        detectors = IntentAnalyzer.suggest_detectors(["DB", "AUTH"])
        assert "sqli" in detectors
        assert detectors.index("sqli") < detectors.index("xss")


class TestResponse:
    """Response 对象测试"""
    
    def test_is_interesting(self):
        """有趣响应判断"""
        r = Response(error="mysql")
        assert r.is_interesting
        
        r2 = Response(reflects=True)
        assert r2.is_interesting
        
        r3 = Response(status=200)
        assert not r3.is_interesting
    
    def test_str_representation(self):
        """字符串表示"""
        r = Response(status=200, length=100, time_ms=50)
        s = str(r)
        assert "200" in s
        assert "100b" in s
