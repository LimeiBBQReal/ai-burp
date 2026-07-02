"""
M5 新协议测试: MySQL / RMI / SMB.

覆盖:
    - MysqlAdapter: BER 无关, pymysql 异常区分 + 弱口令 + 降级
    - RmiAdapter: 魔术字节探测 + 降级 + close
    - SmbAdapter: SMB1 negotiate banner + impacket 缺失降级 + close
    - 协议路由 (新端口 3306/1099/445/139)
"""

import pytest
import asyncio

from aiburp.traffic import TrafficEngine, TrafficRequest


# ============================================================
# 协议路由 (M5 新端口)
# ============================================================

class TestM5ProtocolRouting:

    @pytest.mark.asyncio
    async def test_new_port_routing(self, traffic_engine):
        cases = [
            ("x:3306", "mysql"),
            ("x:1099", "rmi"),
            ("x:445", "smb"),
            ("x:139", "smb"),
        ]
        for target, expected in cases:
            proto = await traffic_engine._resolve_protocol(target, "auto")
            assert proto == expected, f"{target} -> {proto}, 期望 {expected}"


# ============================================================
# MysqlAdapter
# ============================================================

class TestMysqlAdapter:

    @pytest.mark.asyncio
    async def test_closed_port_degrade(self, traffic_engine):
        """closed port 返回 ok=False"""
        r = await traffic_engine.probe("127.0.0.1:1", protocol="mysql")
        assert r.ok is False
        assert r.error  # 有错误信息

    @pytest.mark.asyncio
    async def test_close_then_send(self):
        from aiburp.traffic.adapters import MysqlAdapter
        a = MysqlAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="mysql", target="127.0.0.1:1")
        r = await a.send(req)
        assert r.error == "adapter-closed"

    @pytest.mark.asyncio
    async def test_close_idempotent(self):
        from aiburp.traffic.adapters import MysqlAdapter
        a = MysqlAdapter(timeout=1)
        await a.close()
        await a.close()  # 二次不崩

    @pytest.mark.asyncio
    async def test_check_unauth_secure_on_closed(self, traffic_engine):
        """closed port 弱口令检测: 全部失败, 不应确认 UNAUTH"""
        r = await traffic_engine.check_unauth("127.0.0.1:1", protocol="mysql")
        assert "UNAUTH-CONFIRMED" not in r.tags


# ============================================================
# RmiAdapter
# ============================================================

class TestRmiAdapter:

    def test_rmi_magic_constant(self):
        """RMI 魔术字节常量正确"""
        from aiburp.traffic.adapters.rmi import RMI_MAGIC
        assert RMI_MAGIC == b"\x4a\x52\x4d\x49"  # "JRMI"

    @pytest.mark.asyncio
    async def test_closed_port_degrade(self, traffic_engine):
        r = await traffic_engine.probe("127.0.0.1:1", protocol="rmi")
        assert r.ok is False

    @pytest.mark.asyncio
    async def test_close_then_send(self):
        """M5 review fix: RmiAdapter close 后返回 adapter-closed"""
        from aiburp.traffic.adapters import RmiAdapter
        a = RmiAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="rmi", target="127.0.0.1:1")
        r = await a.send(req)
        assert r.error == "adapter-closed"

    @pytest.mark.asyncio
    async def test_check_deserial_on_closed(self, traffic_engine):
        """closed port 不应确认反序列化漏洞"""
        r = await traffic_engine.adapter("rmi").check_deserial("127.0.0.1:1")
        assert r.ok is False or "DESERIAL-VULNERABLE" not in r.tags


# ============================================================
# SmbAdapter
# ============================================================

class TestSmbAdapter:

    def test_smb1_negotiate_packet_structure(self):
        """SMB1 Negotiate 报文结构正确"""
        from aiburp.traffic.adapters.smb import _build_smb1_negotiate
        pkt = _build_smb1_negotiate()
        # 应含 SMB1 magic \xffSMB
        assert b"\xff\x53\x4d\x42" in pkt
        # 应含 Negotiate command (0x72)
        assert b"\x72" in pkt
        # 应含至少一个方言 (NT LM 0.12)
        assert b"NT LM 0.12" in pkt

    @pytest.mark.asyncio
    async def test_closed_port_degrade(self, traffic_engine):
        """M5 review fix: SMB closed port 不抛 ConnectionRefusedError"""
        r = await traffic_engine.probe("127.0.0.1:1", protocol="smb")
        assert r.ok is False
        assert r.error  # 有错误, 不崩

    @pytest.mark.asyncio
    async def test_close_then_send(self):
        from aiburp.traffic.adapters import SmbAdapter
        a = SmbAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="smb", target="127.0.0.1:1")
        r = await a.send(req)
        assert r.error == "adapter-closed"

    @pytest.mark.asyncio
    async def test_check_null_session_without_impacket(self):
        """impacket 缺失时, check_null_session 返回明确错误"""
        from aiburp.traffic.adapters.smb import SmbAdapter, _IMPACKET_AVAILABLE
        if _IMPACKET_AVAILABLE:
            pytest.skip("impacket 已安装, 跳过降级测试")
        a = SmbAdapter(timeout=1)
        r = await a.check_null_session("127.0.0.1:1")
        assert r.error == "impacket-not-installed"
        await a.close()


# ============================================================
# IntentAnalyzer 对 M5 新协议的语义识别
# ============================================================

class TestM5IntentAnalyzer:

    def test_mysql_unauth_confirmed(self):
        from aiburp.burp import IntentAnalyzer
        from aiburp.traffic import TrafficResponse
        resp = TrafficResponse(
            protocol="mysql", banner="mysql/5.7.30",
            tags=["MYSQL", "UNAUTH-CONFIRMED"],
            anomalies=["cracked:root:"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "HIGH-VALUE" in tags
        assert "RCE-PATH" in tags

    def test_rmi_deserial_target(self):
        from aiburp.burp import IntentAnalyzer
        from aiburp.traffic import TrafficResponse
        resp = TrafficResponse(
            protocol="rmi", banner="rmi(stream)",
            tags=["RMI", "DESERIAL-CHECK"],
            anomalies=["deserialization-target"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "HIGH-VALUE" in tags

    def test_smb_login_success(self):
        from aiburp.burp import IntentAnalyzer
        from aiburp.traffic import TrafficResponse
        resp = TrafficResponse(
            protocol="smb", banner="smb/Windows",
            tags=["SMB", "LOGIN-SUCCESS", "UNAUTH-CONFIRMED"],
            anomalies=["cracked:Administrator:"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "HIGH-VALUE" in tags
        assert "RCE-PATH" in tags

    def test_smb_next_steps_include_ms17_010(self):
        """SMB 建议应含 EternalBlue"""
        from aiburp.burp import IntentAnalyzer
        steps = IntentAnalyzer.suggest_next_steps(["SMB", "HIGH-VALUE"], "smb")
        actions = [s["action"] for s in steps]
        assert "ms17_010" in actions
        assert "check_null_session" in actions


# ============================================================
# M5 Review 修复回归
# ============================================================

class TestM5ReviewFixes:
    """固化 M5 review 发现的问题"""

    def test_mysql_version_not_confused_with_ip(self):
        """M5-1: 客户端 IP 不应被误判为 MySQL 版本号"""
        from aiburp.traffic.adapters.mysql import _extract_mysql_version
        # 客户端 IP 在 @'10.0.0.5' 里, 不应提取
        assert _extract_mysql_version(
            "Access denied for user 'root'@'10.0.0.5' (using password: YES)"
        ) == ""
        assert _extract_mysql_version(
            "Access denied for user 'x'@'192.168.1.100'"
        ) == ""
        # 真实版本 (带 MySQL/MariaDB 前缀) 应提取
        assert _extract_mysql_version("... MariaDB 10.6.4 ...") == "10.6.4"
        assert _extract_mysql_version("... MySQL 8.0.31 ...") == "8.0.31"

    @pytest.mark.asyncio
    async def test_rmi_not_misjudge_http_port(self):
        """M5-3: RMI probe 不应把 HTTP 端口标成 RMI"""
        import asyncio

        async def http_handler(reader, writer):
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            await writer.drain()
            writer.close()

        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        server = await asyncio.start_server(http_handler, "127.0.0.1", port)
        try:
            from aiburp.traffic.adapters import RmiAdapter
            adapter = RmiAdapter(timeout=1)
            r = await adapter.probe(f"127.0.0.1:{port}")
            # HTTP 端口不应被标 RMI
            assert not any("RMI" in t for t in r.tags)
            await adapter.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_rmi_not_misjudge_ssh_port(self):
        """M5-3: SSH banner 不应被标成 RMI"""
        import asyncio

        async def ssh_handler(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_8.9\r\n")
            await writer.drain()
            await reader.read(1024)
            writer.close()

        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        server = await asyncio.start_server(ssh_handler, "127.0.0.1", port)
        try:
            from aiburp.traffic.adapters import RmiAdapter
            adapter = RmiAdapter(timeout=1)
            r = await adapter.probe(f"127.0.0.1:{port}")
            assert not any("RMI" in t for t in r.tags)
            await adapter.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_smb_closed_port_not_timeout_forever(self, traffic_engine):
        """M5-2: SMB closed port 应快速失败 (不无限超时)"""
        import time
        t0 = time.time()
        r = await traffic_engine.probe("127.0.0.1:1", protocol="smb")
        elapsed = time.time() - t0
        assert r.ok is False
        # 应在 timeout (3s) 内返回
        assert elapsed < 5
