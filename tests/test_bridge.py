"""
V3↔V4 桥接 + 深度采集测试.

覆盖:
    - SimpleBurp (V3 兼容同步 HTTP 客户端)
    - create_bridge_burp (从 V4 engine 创建桥接)
    - DeepCollector (V4 扫描 → V3 DirFuzzer 目录爆破)
    - 协程零泄漏验证 (RuntimeWarning 严格模式)
"""

import pytest
import asyncio
import json


# ============================================================
# SimpleBurp 桥接客户端
# ============================================================

class TestSimpleBurp:

    def test_get_returns_simple_response(self):
        from aiburp.traffic.bridge import SimpleBurp
        burp = SimpleBurp(timeout=5)
        r = burp.get("http://127.0.0.1:80/")
        assert r.status in (200, 301, 403, 404, 0)
        assert hasattr(r, "body")
        assert hasattr(r, "headers")

    def test_post_interface(self):
        """post() 接口与 V3 SyncBurp 一致"""
        from aiburp.traffic.bridge import SimpleBurp
        burp = SimpleBurp(timeout=5)
        r = burp.post("http://127.0.0.1:80/", data="test=1")
        # 不崩就行
        assert hasattr(r, "status")

    def test_history_compat(self):
        """history 属性兼容 (DirFuzzer 可能访问)"""
        from aiburp.traffic.bridge import SimpleBurp
        burp = SimpleBurp(timeout=5)
        assert hasattr(burp, "history")
        assert isinstance(burp.history, list)

    def test_close_no_crash(self):
        from aiburp.traffic.bridge import SimpleBurp
        burp = SimpleBurp(timeout=1)
        burp.close()
        # 二次 close 不崩
        burp.close()


# ============================================================
# create_bridge_burp
# ============================================================

class TestBridgeBurp:

    def test_bridge_from_engine(self):
        """从 V4 engine 创建桥接 burp"""
        from aiburp.traffic import TrafficEngine
        from aiburp.traffic.bridge import create_bridge_burp

        # 不需要真正启动 engine (只读配置)
        engine = TrafficEngine()
        burp = create_bridge_burp(engine, delay=0)
        assert burp is not None
        assert hasattr(burp, "get")
        assert hasattr(burp, "post")
        engine_loop = asyncio.new_event_loop()
        engine_loop.run_until_complete(engine.close())
        engine_loop.close()


# ============================================================
# DeepCollector
# ============================================================

class TestDeepCollector:

    @pytest.mark.asyncio
    async def test_deep_collect_http(self, traffic_engine):
        """DeepCollector 对 HTTP 端口做目录爆破"""
        from aiburp.traffic.deep_collector import DeepCollector

        # 先扫描
        scan = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"], ports=[80], timeout=3,
        )

        # 深度采集
        collector = DeepCollector(traffic_engine)
        result = await collector.deep_collect(
            scan, dir_wordlist="quick", dir_bypass=False,
        )

        # 验证结构
        assert result.scan_result is not None
        assert "open_ports" in result.stats
        assert "dirs_found" in result.stats
        assert isinstance(result.discovered, list)

    @pytest.mark.asyncio
    async def test_deep_collect_to_json(self, traffic_engine):
        """DeepCollectResult.to_json 可序列化"""
        from aiburp.traffic.deep_collector import DeepCollector

        scan = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"], ports=[80], timeout=3,
        )
        collector = DeepCollector(traffic_engine)
        result = await collector.deep_collect(scan, dir_wordlist="quick")

        j = result.to_json()
        d = json.loads(j)
        assert "scan_summary" in d
        assert "discovered" in d
        assert "stats" in d

    @pytest.mark.asyncio
    async def test_deep_collect_closed_ports(self, traffic_engine):
        """对 closed port 做深度采集不崩"""
        from aiburp.traffic.deep_collector import DeepCollector

        scan = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"], ports=[1], timeout=0.5,
        )
        collector = DeepCollector(traffic_engine)
        result = await collector.deep_collect(scan, dir_wordlist="quick")

        # 应该有 stats 但没有深度发现
        assert result.stats["open_ports"] == 0

    @pytest.mark.asyncio
    async def test_no_coroutine_leak(self, traffic_engine):
        """
        关键: 桥接不应产生协程泄漏.
        RuntimeWarning: coroutine was never awaited = 失败.
        """
        import warnings

        scan = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"], ports=[80], timeout=3,
        )

        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            from aiburp.traffic.deep_collector import DeepCollector
            collector = DeepCollector(traffic_engine)
            # 如果桥接有协程泄漏, 这里会抛 RuntimeWarning
            result = await collector.deep_collect(
                scan, dir_wordlist="quick", dir_bypass=False,
            )
            # 走到这里 = 零泄漏
            assert result is not None
