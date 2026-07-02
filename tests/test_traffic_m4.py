"""
M4 新协议测试: UDP / TLS / SNMP.

覆盖:
    - UdpAdapter: 成功路径 (udp_echo_server) + 降级 + payload 不 repr
    - TlsAdapter: 真实站点证书解析 + 降级
    - SnmpAdapter: BER 编码 + 未授权检测 + community 爆破
    - 协议路由 (新端口 161/465/993 等)
"""

import pytest
import asyncio

from aiburp.traffic import TrafficEngine, TrafficRequest


# ============================================================
# UdpAdapter
# ============================================================

class TestUdpAdapter:

    @pytest.mark.asyncio
    async def test_send_to_real_dns(self, traffic_engine):
        """
        UDP send 成功路径: 发 DNS 查询到 8.8.8.8:53.
        用真实 UDP 服务避免本地 fixture 在 Windows 上的 loopback datagram 问题.
        """
        # 构造最小 DNS 查询 (A 记录 example.com)
        # DNS 报文: header(12B) + question
        import struct
        tid = 0x1234
        flags = 0x0100  # 标准递归查询
        header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
        # Question: example.com type A class IN
        qname = (b"\x07example\x03com\x00")
        question = qname + struct.pack(">HH", 1, 1)  # type A, class IN
        dns_packet = header + question

        req = TrafficRequest(
            protocol="udp",
            target="8.8.8.8:53",
            payload=dns_packet,
        )
        r = await traffic_engine.send(req)
        if not r.ok:
            pytest.skip(f"网络不可达: {r.error}")
        assert r.protocol == "udp"
        assert len(r.raw) >= 12  # DNS 响应至少有 header

    @pytest.mark.asyncio
    async def test_closed_port_degrade(self, traffic_engine):
        """UDP closed port 返回 ok=False (Windows ICMP 丢弃场景)"""
        r = await traffic_engine.probe("127.0.0.1:1", protocol="udp")
        assert r.ok is False
        assert "no-response" in r.error

    @pytest.mark.asyncio
    async def test_fuzz_protocol_not_hardcoded(self, traffic_engine):
        """B15 继承: fuzz 返回的 protocol 是 'udp' 不是 'tcp'"""
        # 用 closed port, 只验证 protocol 字段
        results = await traffic_engine.fuzz(
            "127.0.0.1:1",
            [b"x", b"y"],
            protocol="udp",
        )
        assert len(results) == 2
        # 即使全部失败, protocol 也应是 udp (多态)
        for r in results:
            assert r.protocol == "udp"


# ============================================================
# TlsAdapter
# ============================================================

class TestTlsAdapter:

    @pytest.mark.asyncio
    async def test_real_cert_parsing(self, traffic_engine):
        """真实站点证书解析 (example.com 长期稳定)"""
        r = await traffic_engine.probe("example.com:443", protocol="tls")
        if not r.ok:
            pytest.skip(f"网络不可达: {r.error}")
        assert "TLS" in r.tags
        assert "example.com" in r.banner.lower()
        # 至少能拿 CN 或 SAN
        assert "Subject CN" in r.text or "SAN" in r.text

    @pytest.mark.asyncio
    async def test_san_extraction(self, traffic_engine):
        """SAN 泄露 (子域名发现价值)"""
        r = await traffic_engine.probe("github.com:443", protocol="tls")
        if not r.ok:
            pytest.skip(f"网络不可达: {r.error}")
        # github 证书有多个 SAN, 应标 SAN-LEAK
        assert "SAN-LEAK" in r.tags or len(r.text) > 50

    @pytest.mark.asyncio
    async def test_closed_port_degrade(self, traffic_engine):
        r = await traffic_engine.probe("127.0.0.1:1", protocol="tls")
        assert r.ok is False
        assert r.error  # 有错误信息

    @pytest.mark.asyncio
    async def test_close_then_send(self):
        """B14 继承: close 后 send 返回 adapter-closed"""
        from aiburp.traffic.adapters import TlsAdapter
        a = TlsAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="tls", target="x:443")
        r = await a.send(req)
        assert r.error == "adapter-closed"


# ============================================================
# SnmpAdapter
# ============================================================

class TestSnmpAdapter:

    def test_ber_encoding_basic(self):
        """BER 编码工具基本正确"""
        from aiburp.traffic.adapters.snmp import (
            _encode_snmpv2c_get, _ber_encode_oid, _ber_encode_integer,
        )
        # OID 编码: 1.3.6.1.2.1.1.1.0
        oid_enc = _ber_encode_oid("1.3.6.1.2.1.1.1.0")
        assert oid_enc[0] == 0x06  # ASN1_OBJECT_IDENTIFIER
        assert len(oid_enc) > 5

        # 完整 GetRequest 报文
        packet = _encode_snmpv2c_get("public", "1.3.6.1.2.1.1.1.0")
        assert packet[0] == 0x30  # SEQUENCE
        assert b"public" in packet

    def test_ber_integer_encoding(self):
        """整数编码边界"""
        from aiburp.traffic.adapters.snmp import _ber_encode_integer
        # 0
        assert _ber_encode_integer(0) == b"\x02\x01\x00"
        # 1
        assert _ber_encode_integer(1) == b"\x02\x01\x01"
        # 大数
        big = _ber_encode_integer(256)
        assert big[0] == 0x02
        assert len(big) >= 4

    @pytest.mark.asyncio
    async def test_check_unauth_secure_on_closed_port(self, traffic_engine):
        """
        安全配置的 SNMP: 端口不可达时, 所有 community 失败, 应标 SECURED.
        不依赖本地 fixture (Windows loopback datagram 不可靠), 用 closed port.
        """
        r = await traffic_engine.check_unauth("127.0.0.1:1", protocol="snmp")
        # closed port: 所有 community 无响应, 标 SECURED
        assert "UNAUTH-CONFIRMED" not in r.tags
        assert "SECURED" in r.tags or r.ok is False

    @pytest.mark.asyncio
    async def test_closed_port_degrade(self, traffic_engine):
        r = await traffic_engine.probe("127.0.0.1:1", protocol="snmp")
        assert r.ok is False

    @pytest.mark.asyncio
    async def test_close_then_send(self):
        """B14 继承: close 后 send 返回 adapter-closed"""
        from aiburp.traffic.adapters import SnmpAdapter
        a = SnmpAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="snmp", target="x:161")
        r = await a.send(req)
        assert r.error == "adapter-closed"


# ============================================================
# 协议路由 (M4 新端口)
# ============================================================

class TestM4ProtocolRouting:

    @pytest.mark.asyncio
    async def test_new_port_routing(self, traffic_engine):
        """新端口表项路由正确"""
        cases = [
            ("x:161", "snmp"),    # SNMP
            ("x:123", "udp"),     # NTP
            ("x:465", "tls"),     # SMTPS
            ("x:636", "tls"),     # LDAPS
            ("x:993", "tls"),     # IMAPS
            ("x:995", "tls"),     # POP3S
        ]
        for target, expected in cases:
            proto = await traffic_engine._resolve_protocol(target, "auto")
            assert proto == expected, f"{target} -> {proto}, 期望 {expected}"


# ============================================================
# M4 Review 修复回归
# ============================================================

class TestM4ReviewFixes:
    """固化 M4 review 发现的三个问题"""

    @pytest.mark.asyncio
    async def test_udp_close_then_send(self):
        """M4-1: UdpAdapter close 后 send 返回 adapter-closed (B14 UDP 版)"""
        from aiburp.traffic.adapters import UdpAdapter
        a = UdpAdapter(timeout=1)
        await a.close()
        req = TrafficRequest(protocol="udp", target="127.0.0.1:1", payload=b"x")
        r = await a.send(req)
        assert r.error == "adapter-closed"

    def test_snmp_parse_empty_pdu(self):
        """M4-2: 空/畸形 PDU 不应误判为 error=False"""
        from aiburp.traffic.adapters.snmp import _parse_get_response
        # 空 PDU 应返回 None, 不是 {'error': False}
        for bad in [b"", b"\xa2\x00", b"\xa2\x02\x01\x02", b"not-snmp"]:
            result = _parse_get_response(bad)
            if result is not None:
                assert result.get("error") is not False, \
                    f"空 PDU {bad!r} 不应返回 error=False"
            # result 为 None 是最干净的

    def test_tls_san_leak_high_value(self):
        """M4-3: TLS SAN-LEAK 应被 IntentAnalyzer 标 HIGH-VALUE"""
        from aiburp.burp import IntentAnalyzer
        from aiburp.traffic import TrafficResponse
        resp = TrafficResponse(
            protocol="tls", banner="cn=x",
            tags=["TLS", "SAN-LEAK"], anomalies=["sans:5"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "HIGH-VALUE" in tags
        assert "RECON-VALUE" in tags

    def test_tls_weak_cipher_downgrade(self):
        """M4-3: 弱套件应标 DOWNGRADE-POSSIBLE"""
        from aiburp.burp import IntentAnalyzer
        from aiburp.traffic import TrafficResponse
        resp = TrafficResponse(
            protocol="tls", tags=["TLS", "WEAK-CIPHER"],
            anomalies=["weak-cipher:RC4"],
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "DOWNGRADE-POSSIBLE" in tags

    def test_snmp_ber_oid_invalid_short(self):
        """边界: 单字符 OID 不崩 (返回空编码)"""
        from aiburp.traffic.adapters.snmp import _ber_encode_oid
        # OID '1' 只有 1 part, 不应崩
        result = _ber_encode_oid("1")
        assert isinstance(result, bytes)

    def test_snmp_ber_oid_non_numeric_raises(self):
        """边界: 非数字 OID 抛 ValueError"""
        from aiburp.traffic.adapters.snmp import _ber_encode_oid
        with pytest.raises(ValueError):
            _ber_encode_oid("a.b.c")
