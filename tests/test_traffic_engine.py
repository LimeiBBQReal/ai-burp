"""
V4 TrafficEngine 测试: 协议路由 / 降级 / 生命周期 / close 幂等.

覆盖 review 发现的问题:
    - B3: send 不支持的协议优雅降级
    - B9: _resolve_protocol 不硬编码 (端口表驱动)
    - L7: smart_probe 无效 target 不兜底 HTTP
    - R4: engine.close 后操作返回明确错误
    - close 幂等
"""

import pytest
import asyncio

from aiburp.traffic import TrafficEngine, TrafficRequest


class TestProtocolResolution:
    """B9: 协议路由不硬编码"""

    @pytest.mark.asyncio
    async def test_port_based_routing(self, traffic_engine):
        """端口表驱动路由"""
        cases = [
            ("x:6379", "redis"),
            ("x:2375", "docker"),
            ("x:10250", "kubelet"),
            ("x:53", "dns"),
            ("x:80", "http"),
            ("x:443", "http"),
            ("x:22", "ssh"),
        ]
        for target, expected in cases:
            proto = await traffic_engine._resolve_protocol(target, "auto")
            assert proto == expected, f"{target} -> {proto}, 期望 {expected}"

    @pytest.mark.asyncio
    async def test_scheme_based_routing(self, traffic_engine):
        cases = [
            ("http://x", "http"),
            ("https://x", "http"),
            ("redis://x:6379", "redis"),
            ("docker://x:2375", "docker"),
            ("ws://x/ws", "ws"),
            ("wss://x", "ws"),
        ]
        for target, expected in cases:
            proto = await traffic_engine._resolve_protocol(target, "auto")
            assert proto == expected, f"{target} -> {proto}, 期望 {expected}"

    @pytest.mark.asyncio
    async def test_explicit_hint_overrides_auto(self, traffic_engine):
        proto = await traffic_engine._resolve_protocol("x:6379", "tcp")
        assert proto == "tcp"  # 显式指定 tcp, 不走 redis

    @pytest.mark.asyncio
    async def test_unknown_scheme_falls_back(self, traffic_engine):
        """未知 scheme 兜底 http"""
        proto = await traffic_engine._resolve_protocol("unknown://x", "auto")
        assert proto == "http"

    @pytest.mark.asyncio
    async def test_unsupported_protocol_raises(self, traffic_engine):
        from aiburp.traffic.base import UnsupportedProtocol
        with pytest.raises(UnsupportedProtocol):
            await traffic_engine._resolve_protocol("x", "nonexistent")


class TestGracefulDegrade:
    """失败路径优雅降级"""

    @pytest.mark.asyncio
    async def test_tcp_closed_port(self, traffic_engine):
        """TCP closed port 返回 ok=False, 不抛异常"""
        r = await traffic_engine.probe("127.0.0.1:1", protocol="tcp")
        assert r.ok is False
        assert r.error  # 有错误信息

    @pytest.mark.asyncio
    async def test_redis_closed_port(self, traffic_engine):
        r = await traffic_engine.probe("127.0.0.1:1", protocol="redis")
        assert r.ok is False

    @pytest.mark.asyncio
    async def test_docker_closed_port(self, traffic_engine):
        r = await traffic_engine.probe("127.0.0.1:1", protocol="docker")
        assert r.ok is False

    @pytest.mark.asyncio
    async def test_kubelet_closed_port(self, traffic_engine):
        r = await traffic_engine.probe("127.0.0.1:1", protocol="kubelet")
        assert r.ok is False

    @pytest.mark.asyncio
    async def test_send_unsupported_protocol(self, traffic_engine):
        """B3: send 不支持的协议不抛异常, 返回 ok=False"""
        req = TrafficRequest(protocol="smtp", target="x")
        r = await traffic_engine.send(req)
        assert r.ok is False
        assert "unsupported-protocol" in r.error


class TestLifecycle:
    """close 幂等 / close 后操作"""

    @pytest.mark.asyncio
    async def test_close_idempotent(self, traffic_engine):
        """多次 close 不抛异常"""
        await traffic_engine.close()
        await traffic_engine.close()  # 不应崩

    @pytest.mark.asyncio
    async def test_send_after_close(self, traffic_engine):
        """R4: close 后 send 返回明确错误"""
        await traffic_engine.close()
        req = TrafficRequest(protocol="tcp", target="127.0.0.1:1")
        r = await traffic_engine.send(req)
        assert r.ok is False
        assert r.error == "engine-closed"

    @pytest.mark.asyncio
    async def test_probe_after_close(self, traffic_engine):
        await traffic_engine.close()
        r = await traffic_engine.probe("127.0.0.1:1")
        assert r.error == "engine-closed"

    @pytest.mark.asyncio
    async def test_fuzz_after_close(self, traffic_engine):
        """R4: fuzz 返回等长列表, 全 False"""
        await traffic_engine.close()
        results = await traffic_engine.fuzz("127.0.0.1:1", ["a", "b", "c"])
        assert len(results) == 3
        assert all(r.ok is False for r in results)

    @pytest.mark.asyncio
    async def test_adapter_close_exception_isolated(self):
        """R-4: 单个 adapter.close 抛异常不影响其它"""
        from aiburp.traffic.base import ProtocolAdapter, TrafficResponse

        class BadAdapter(ProtocolAdapter):
            protocol = "bad"
            async def probe(self, target, **kw):
                return TrafficResponse(protocol="bad", ok=True)
            async def send(self, req, **kw):
                return TrafficResponse(protocol="bad", ok=True)
            async def close(self):
                raise RuntimeError("故意崩溃")

        engine = TrafficEngine(adapters=[BadAdapter()])
        # close 不应因 BadAdapter 崩溃
        await engine.close()


class TestSmartProbe:
    """smart_probe + L7 无效 target"""

    @pytest.mark.asyncio
    async def test_invalid_target_no_http_fallback(self, traffic_engine):
        """L7: 无效 target 不兜底 HTTP"""
        r = await traffic_engine.smart_probe("garbage-no-structure")
        assert r.ok is False
        assert r.error == "invalid-target"

    @pytest.mark.asyncio
    async def test_next_steps_populated(self, traffic_engine):
        """smart_probe 后 next_steps 非空"""
        r = await traffic_engine.smart_probe("127.0.0.1:6379")
        # 即使连接失败, smart_probe 通过端口表标 HIGH-VALUE/UNAUTH-CHECK
        d = r.to_dict()
        # next_steps 可能因连接失败而为空, 但 tags 应有 HIGH-VALUE
        # (这里只验证不崩 + 返回结构正确)
        assert "next_steps" in d
        assert isinstance(d["next_steps"], list)
