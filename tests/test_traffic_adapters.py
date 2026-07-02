"""
V4 adapter 测试: TCP/HTTP/Redis 成功+失败路径.

覆盖 review 发现的问题:
    - B7: TcpAdapter send 成功路径 (用 echo_server, 不再依赖 closed port)
    - B11: Redis probe 非 Redis 不误判
    - Redis RESP 检测 + 未授权 + rce-possible
    - B14: Docker/Kubelet close 后 send
"""

import pytest
import asyncio

from aiburp.traffic import TrafficEngine, TrafficRequest


class TestTcpAdapter:
    """TcpAdapter - 用 echo_server 测成功路径"""

    @pytest.mark.asyncio
    async def test_probe_success_with_banner(self, traffic_engine, echo_server):
        """B7: 成功路径不崩, banner 识别"""
        r = await traffic_engine.probe(f"127.0.0.1:{echo_server}", protocol="tcp")
        assert r.ok is True
        assert "ssh" in r.banner.lower()
        assert "SSH" in r.tags

    @pytest.mark.asyncio
    async def test_send_success_path(self, traffic_engine, echo_server):
        """B7 修复点: 成功路径访问 resp 字段不崩"""
        req = TrafficRequest(
            protocol="tcp",
            target=f"127.0.0.1:{echo_server}",
            payload=b"HELLO\r\n",
        )
        r = await traffic_engine.send(req)
        assert r.ok is True
        assert r.protocol == "tcp"
        assert "HELLO" in r.text

    @pytest.mark.asyncio
    async def test_fuzz_success_path(self, traffic_engine, echo_server):
        """fuzz 成功路径 + R3: bytes payload 不 repr"""
        results = await traffic_engine.fuzz(
            f"127.0.0.1:{echo_server}",
            [b"CMD1\r\n", b"CMD2\r\n"],
            protocol="tcp",
        )
        assert len(results) == 2
        for r in results:
            assert r.ok is True
            # R3: payload 不应以 b' 开头 (repr 化)
            assert not r.payload.startswith("b'")

    @pytest.mark.asyncio
    async def test_fuzz_protocol_not_hardcoded(self, traffic_engine, echo_server):
        """B15: TcpAdapter.fuzz 的 protocol 用 self.protocol (多态)"""
        results = await traffic_engine.fuzz(
            f"127.0.0.1:{echo_server}",
            ["x"],
            protocol="tcp",
        )
        assert all(r.protocol == "tcp" for r in results)

    @pytest.mark.asyncio
    async def test_tcp_closed_port_degrade(self, traffic_engine):
        r = await asyncio.wait_for(
            traffic_engine.probe("127.0.0.1:1", protocol="tcp"),
            timeout=5,
        )
        assert r.ok is False

    @pytest.mark.asyncio
    async def test_tcp_syn_ack_but_silent_not_false_positive(self, traffic_engine, free_port):
        """
        P-1: TCP 握手成功但无数据 (CDN/ELB/WAF 假阳性) 不应判为开放.

        模拟: 起一个只 accept 不发数据的服务器 (像 CDN 的行为).
        """
        async def silent_handler(reader, writer):
            # 接受连接但不发任何数据 (模拟 CDN/ELB)
            await asyncio.sleep(2)
            writer.close()

        server = await asyncio.start_server(silent_handler, "127.0.0.1", free_port)
        try:
            r = await traffic_engine.probe(f"127.0.0.1:{free_port}", protocol="tcp")
            # 不应判为开放 (CDN 假阳性防护)
            assert r.ok is False
            assert "silent" in r.error or "syn-ack" in r.error
        finally:
            server.close()
            await server.wait_closed()


class TestRedisAdapter:
    """RedisAdapter - 用 fake_redis_server 测"""

    @pytest.mark.asyncio
    async def test_probe_redis_success(self, traffic_engine, fake_redis_server):
        r = await traffic_engine.probe(
            f"127.0.0.1:{fake_redis_server}", protocol="redis"
        )
        assert r.ok is True
        assert "REDIS" in r.tags

    @pytest.mark.asyncio
    async def test_check_unauth_confirmed(self, traffic_engine, fake_redis_server):
        """Redis 未授权 + rce-possible"""
        r = await traffic_engine.check_unauth(
            f"127.0.0.1:{fake_redis_server}", protocol="redis"
        )
        assert r.ok is True
        assert "UNAUTH-CONFIRMED" in r.tags
        assert "rce-possible" in r.anomalies

    @pytest.mark.asyncio
    async def test_probe_http_port_not_misjudged_as_redis(
        self, traffic_engine, free_port
    ):
        """B11: HTTP 服务不应被误判为 redis"""
        # 起一个返回 HTTP 响应的服务
        async def handle(reader, writer):
            data = await reader.read(1024)
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", free_port)
        try:
            r = await traffic_engine.probe(
                f"127.0.0.1:{free_port}", protocol="redis"
            )
            # HTTP 响应不以 +/-/$/*/://开头, 不应判 redis
            assert "REDIS" not in (r.tags or [])
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_redis_resp_command_injection_rejected(self):
        """B10: RESP 命令注入 (list 含 \\r\\n) 被拒绝"""
        from aiburp.traffic.adapters import RedisAdapter
        adapter = RedisAdapter(timeout=1)
        with pytest.raises(ValueError, match="换行"):
            adapter._encode_command(["GET", "key\r\nFLUSHALL"])


class TestDockerKubeletClose:
    """B14: Docker/Kubelet close 后 send"""

    @pytest.mark.asyncio
    async def test_docker_close_then_send(self):
        from aiburp.traffic.adapters import DockerAdapter
        a = DockerAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="docker", target="127.0.0.1:1", payload="/version")
        r = await a.send(req)
        assert r.error == "adapter-closed"

    @pytest.mark.asyncio
    async def test_kubelet_close_then_send(self):
        from aiburp.traffic.adapters import KubeletAdapter
        a = KubeletAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="kubelet", target="127.0.0.1:1", payload="/pods")
        r = await a.send(req)
        assert r.error == "adapter-closed"

    @pytest.mark.asyncio
    async def test_kubelet_no_verify_tls_param(self):
        """B12: verify_tls 参数已删除"""
        import inspect
        from aiburp.traffic.adapters import KubeletAdapter
        sig = inspect.signature(KubeletAdapter.__init__)
        assert "verify_tls" not in sig.parameters


class TestWebSocket:
    """WebSocket adapter 基础"""

    def test_normalize_url_schemes(self):
        from aiburp.traffic.adapters import WebSocketAdapter
        assert WebSocketAdapter._normalize_url("ws://x") == "ws://x"
        assert WebSocketAdapter._normalize_url("http://x") == "ws://x"
        assert WebSocketAdapter._normalize_url("https://x") == "wss://x"
        assert WebSocketAdapter._normalize_url("x.com") == "ws://x.com"

    def test_normalize_url_unknown_scheme_raises(self):
        """B13: 未知 scheme 报错"""
        from aiburp.traffic.adapters import WebSocketAdapter
        with pytest.raises(ValueError):
            WebSocketAdapter._normalize_url("ftp://x")
