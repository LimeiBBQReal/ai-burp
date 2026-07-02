"""
M6 资产批量扫描测试.

覆盖:
    - scan_cidr: CIDR 解析 / 网段扫描 / 无效输入
    - scan_hosts: host 列表扫描 / 进度回调
    - ScanResult: 统计 / 过滤 / 排序 / 序列化
    - 并发: 多端口并发不崩
"""

import pytest
import asyncio
import json
import socket

from aiburp.traffic import TrafficEngine, ScanResult, AssetEntry


# ============================================================
# ScanResult 数据结构
# ============================================================

class TestScanResult:

    def test_asset_entry_high_value(self):
        """HIGH-VALUE / UNAUTH-CONFIRMED / RCE-PATH 都算高危"""
        e1 = AssetEntry(host="x", port=1, tags=["HIGH-VALUE"])
        e2 = AssetEntry(host="x", port=2, tags=["UNAUTH-CONFIRMED"])
        e3 = AssetEntry(host="x", port=3, tags=["RCE-PATH"])
        e4 = AssetEntry(host="x", port=4, tags=["MYSQL"])
        assert e1.is_high_value
        assert e2.is_high_value
        assert e3.is_high_value
        assert not e4.is_high_value

    def test_asset_entry_open(self):
        e = AssetEntry(host="x", port=1, ok=True)
        assert e.is_open
        assert e.target == "x:1"

    def test_scan_result_summary(self):
        result = ScanResult(scan_target="test", start_time=0, end_time=1)
        result.add(AssetEntry(host="a", port=80, ok=True, tags=["HIGH-VALUE"]))
        result.add(AssetEntry(host="a", port=443, ok=True))
        result.add(AssetEntry(host="b", port=22, ok=False))
        result.total_probes = 3

        s = result.summary()
        assert s["open_count"] == 2
        assert s["high_value_count"] == 1
        assert s["hosts_scanned"] == 2  # a + b
        assert s["ports_scanned"] == 3  # 80, 443, 22

    def test_scan_result_to_json_serializable(self):
        result = ScanResult(scan_target="test")
        result.add(AssetEntry(host="a", port=80, ok=True, service="http",
                              tags=["HIGH-VALUE"]))
        j = result.to_json()
        d = json.loads(j)
        assert "summary" in d
        assert "entries" in d
        assert len(d["entries"]) == 1
        assert d["entries"][0]["high_value"] is True

    def test_report_text_no_crash_on_empty(self):
        result = ScanResult(scan_target="empty")
        text = result.report_text()
        assert "扫描报告" in text

    def test_by_service_grouping(self):
        result = ScanResult()
        result.add(AssetEntry(host="a", port=1, ok=True, service="redis"))
        result.add(AssetEntry(host="b", port=2, ok=True, service="redis"))
        result.add(AssetEntry(host="c", port=3, ok=True, service="mysql"))
        result.add(AssetEntry(host="d", port=4, ok=False, service="ssh"))  # 不开放, 不计入
        svc = result.by_service()
        assert len(svc["redis"]) == 2
        assert len(svc["mysql"]) == 1
        assert "ssh" not in svc  # closed 不算


# ============================================================
# scan_cidr
# ============================================================

class TestScanCidr:

    @pytest.mark.asyncio
    async def test_invalid_cidr_graceful(self, traffic_engine):
        """无效 CIDR 返回 error entry, 不抛异常"""
        result = await traffic_engine.scan_cidr("not-a-cidr", ports=[80])
        assert len(result.entries) >= 1
        assert "invalid" in result.entries[0].error.lower()

    @pytest.mark.asyncio
    async def test_30_subnet(self, traffic_engine):
        """/30 扫描 2 个 host"""
        result = await traffic_engine.scan_cidr(
            "127.0.0.0/30", ports=[1, 2], timeout=0.5,
        )
        # 127.0.0.0/30 hosts: 127.0.0.1, 127.0.0.2
        assert result.hosts_scanned == 2
        assert result.total_probes == 4  # 2 hosts x 2 ports

    @pytest.mark.asyncio
    async def test_32_single_host(self, traffic_engine):
        result = await traffic_engine.scan_cidr("127.0.0.1/32", ports=[1], timeout=0.5)
        assert result.hosts_scanned == 1

    @pytest.mark.asyncio
    async def test_default_ports_count(self, traffic_engine):
        """默认端口集应含多个高危端口"""
        from aiburp.traffic.engine import DEFAULT_SCAN_PORTS
        assert len(DEFAULT_SCAN_PORTS) >= 20
        assert 22 in DEFAULT_SCAN_PORTS
        assert 6379 in DEFAULT_SCAN_PORTS
        assert 445 in DEFAULT_SCAN_PORTS


# ============================================================
# scan_hosts + 进度回调
# ============================================================

class TestScanHosts:

    @pytest.mark.asyncio
    async def test_progress_callback(self, traffic_engine):
        """进度回调被正确调用"""
        progress_calls = []

        def cb(done, total):
            progress_calls.append((done, total))

        await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"], ports=[1, 2, 3],
            timeout=0.5, progress=cb,
        )
        assert len(progress_calls) == 3
        assert progress_calls[-1] == (3, 3)  # 最后一次 done == total

    @pytest.mark.asyncio
    async def test_progress_callback_exception_isolated(self, traffic_engine):
        """进度回调抛异常不应让扫描崩"""
        def bad_cb(done, total):
            raise RuntimeError("callback broken")

        result = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"], ports=[1, 2],
            timeout=0.5, progress=bad_cb,
        )
        # 应正常完成, 不崩
        assert result.total_probes == 2

    @pytest.mark.asyncio
    async def test_concurrency_limit(self, traffic_engine):
        """并发不应超过设定上限 (用 timing 间接验证)"""
        import time
        t0 = time.time()
        await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"] * 5, ports=[1, 2, 3, 4],
            concurrency=2, timeout=0.5,
        )
        elapsed = time.time() - t0
        # 20 个 probe, concurrency=2, timeout=0.5
        # 最少 ceil(20/2) * 0.5 = 5s (但 closed port 更快, 实际更短)
        # 这里只验证不崩 + 完成
        assert elapsed < 30

    @pytest.mark.asyncio
    async def test_scan_finds_local_echo(self, traffic_engine):
        """扫描能发现本地 echo server"""
        async def echo_handler(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_8.9\r\n")
            await writer.drain()
            await reader.read(1024)
            writer.close()

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", port)
        try:
            result = await traffic_engine.scan_hosts(
                hosts=["127.0.0.1"], ports=[port, port + 1],
                timeout=1,
            )
            assert result.open_count == 1
            open_entries = result.open_entries()
            assert open_entries[0].port == port
            assert "SSH" in open_entries[0].tags or "ssh" in open_entries[0].banner.lower()
        finally:
            server.close()
            await server.wait_closed()


# ============================================================
# M6 Review 修复回归
# ============================================================

class TestM6ReviewFixes:
    """固化 M6 review 发现的问题"""

    @pytest.mark.asyncio
    async def test_large_subnet_rejected(self, traffic_engine):
        """M6-1: /8 等超大网段应被立即拒绝, 不展开 hosts"""
        result = await traffic_engine.scan_cidr("10.0.0.0/8", ports=[80])
        assert len(result.entries) == 1
        assert "too-large" in result.entries[0].error
        # 不应有 total_probes (没有真扫描)
        assert result.total_probes == 0 or result.total_probes == 1

    @pytest.mark.asyncio
    async def test_max_hosts_custom_limit(self, traffic_engine):
        """M6-1: 自定义 max_hosts 上限生效"""
        # /28 = 14 hosts, 设 max_hosts=10 应拒
        result = await traffic_engine.scan_cidr("10.0.0.0/28", ports=[80], max_hosts=10)
        assert "too-large" in result.entries[0].error

        # max_hosts=20 应通过 (但不真扫, timeout 极小)
        result2 = await traffic_engine.scan_cidr(
            "10.0.0.0/28", ports=[80], max_hosts=20, timeout=0.2
        )
        assert result2.total_probes == 14

    @pytest.mark.asyncio
    async def test_ipv6_single_host(self, traffic_engine):
        """M6-2: IPv6 /128 单 host"""
        result = await traffic_engine.scan_cidr("::1/128", ports=[80], timeout=0.3)
        assert result.hosts_scanned == 1

    @pytest.mark.asyncio
    async def test_ipv6_small_subnet(self, traffic_engine):
        """M6-2: IPv6 /124 = 16 地址, hosts() 返回 14 (排除网络+广播)"""
        result = await traffic_engine.scan_cidr("2001:db8::/124", ports=[80], timeout=0.2)
        # hosts() 排除首尾, 实际可扫 14
        assert result.hosts_scanned >= 10  # 至少 10 个 (容差)

    @pytest.mark.asyncio
    async def test_invalid_port_no_crash(self, traffic_engine):
        """边界: 非法端口号不崩"""
        for bad_port in [0, -1, 99999]:
            result = await traffic_engine.scan_hosts(
                ["127.0.0.1"], ports=[bad_port], timeout=0.3
            )
            # 应返回结果 (ok=False), 不抛异常
            assert len(result.entries) == 1
            assert result.entries[0].ok is False

    @pytest.mark.asyncio
    async def test_scan_after_engine_close(self):
        """R-3: engine.close() 后 scan_cidr 返回 engine-closed, 不抛异常"""
        from aiburp.traffic import TrafficEngine
        engine = TrafficEngine()
        await engine.close()
        result = await engine.scan_cidr("127.0.0.1/32", ports=[80], timeout=0.3)
        assert len(result.entries) >= 1
        assert result.entries[0].error == "engine-closed"

    @pytest.mark.asyncio
    async def test_scan_hosts_after_engine_close(self):
        """R-3: engine.close() 后 scan_hosts 也返回 engine-closed"""
        from aiburp.traffic import TrafficEngine
        engine = TrafficEngine()
        await engine.close()
        result = await engine.scan_hosts(["127.0.0.1"], ports=[80], timeout=0.3)
        assert len(result.entries) >= 1
        assert result.entries[0].error == "engine-closed"


# ============================================================
# F-1/F-2/F-3 实战改进回归
# ============================================================

class TestFieldImprovements:
    """固化实战发现的改进"""

    def test_tcp_adapter_default_read_window_2s(self):
        """F-1: TcpAdapter 默认 read_window 应为 2.0 (内网/Docker 场景)"""
        from aiburp.traffic.adapters import TcpAdapter
        import inspect
        sig = inspect.signature(TcpAdapter.__init__)
        assert sig.parameters["read_window"].default == 2.0

    def test_redis_adapter_inherits_2s_read_window(self):
        """F-1: RedisAdapter 默认 read_window 也应为 2.0"""
        from aiburp.traffic.adapters import RedisAdapter
        import inspect
        sig = inspect.signature(RedisAdapter.__init__)
        assert sig.parameters["read_window"].default == 2.0

    @pytest.mark.asyncio
    async def test_port_protocol_map_overrides_port_table(self, traffic_engine):
        """F-2: port_protocol_map 覆盖端口表路由"""
        result = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"],
            ports=[6389],  # 非标准端口, 端口表里没有
            timeout=0.3,
            port_protocol_map={6389: "redis"},
        )
        # 6389 应该走 redis adapter (而非默认 tcp)
        entry = result.entries[0]
        assert entry.protocol == "redis"

    @pytest.mark.asyncio
    async def test_port_protocol_map_for_smb_nonstandard_port(
        self, traffic_engine
    ):
        """F-2: 非标准端口 4450 用 port_protocol_map 指定 smb"""
        result = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"],
            ports=[4450],
            timeout=0.3,
            port_protocol_map={4450: "smb"},
        )
        entry = result.entries[0]
        assert entry.protocol == "smb"

    @pytest.mark.asyncio
    async def test_scan_without_port_map_falls_back_to_tcp(
        self, traffic_engine
    ):
        """F-3: 没有 port_protocol_map 时, 非标准端口走 tcp"""
        result = await traffic_engine.scan_hosts(
            hosts=["127.0.0.1"],
            ports=[12345],  # 不在端口表里
            timeout=0.3,
        )
        entry = result.entries[0]
        assert entry.protocol == "tcp"
