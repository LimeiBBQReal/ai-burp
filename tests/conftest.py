"""
AI-Burp 测试配置 (V3 + V4 traffic layer)

V4 新增 fixture:
    - echo_server:      本地 TCP echo server (无网络依赖, 测成功路径)
    - fake_redis_server: 模拟未授权 Redis (PING+INFO+CONFIG)
    - traffic_engine:   默认 TrafficEngine (本地超时, 不联网)
    - free_port:        随机可用端口 (避免冲突)
"""

import pytest
import asyncio
import socket
import pytest_asyncio

# pytest-asyncio 配置
pytest_plugins = ('pytest_asyncio',)


@pytest.fixture(scope="session")
def event_loop():
    """创建事件循环"""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def httpbin_url():
    """httpbin 测试 URL"""
    return "https://httpbin.org"


@pytest.fixture
def mock_sqli_response():
    """模拟 SQL 错误响应"""
    return "You have an error in your SQL syntax"


# ============================================================
# V4 traffic layer fixtures
# ============================================================

@pytest.fixture
def free_port():
    """获取一个可用的随机端口 (测试结束后释放)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest_asyncio.fixture
async def echo_server(free_port):
    """
    本地 TCP echo server, 模拟有 banner 的服务.
    行为: 先发 SSH banner, 再把客户端数据原样返回 (带 ECHO: 前缀).
    用于测试 TcpAdapter 的成功路径 (不用联网).

    yield: 端口号
    """
    async def handle(reader, writer):
        try:
            # 先发 banner (模拟 SSH)
            writer.write(b'SSH-2.0-OpenSSH_8.9\r\n')
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.write(b'ECHO:' + data)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, '127.0.0.1', free_port)
    try:
        yield free_port
    finally:
        server.close()
        await server.wait_closed()


@pytest_asyncio.fixture
async def fake_redis_server(free_port):
    """
    模拟未授权 Redis server.
    响应: PING -> +PONG, INFO -> 版本信息, CONFIG -> dir, 其它 -> +OK.

    yield: 端口号
    """
    async def handle(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            cmd = data.decode('utf-8', 'replace').upper()
            if 'PING' in cmd:
                writer.write(b'+PONG\r\n')
            elif 'INFO' in cmd:
                writer.write(b'$52\r\nredis_version:7.0.4\r\nredis_mode:standalone\r\nos:Linux\r\n')
            elif 'CONFIG' in cmd:
                writer.write(b'*2\r\n$3\r\ndir\r\n$4\r\n/var\r\n')
            else:
                writer.write(b'+OK\r\n')
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, '127.0.0.1', free_port)
    try:
        yield free_port
    finally:
        server.close()
        await server.wait_closed()


@pytest_asyncio.fixture
async def traffic_engine():
    """
    默认 TrafficEngine (本地超时, 不联网).
    自动 close. 用于大部分 engine 层测试.
    """
    from aiburp.traffic import TrafficEngine
    engine = TrafficEngine(
        http_kwargs={'delay': 0, 'timeout': 5},
        tcp_kwargs={'timeout': 2, 'read_window': 0.4},
        redis_kwargs={'timeout': 2, 'read_window': 0.4},
        dns_kwargs={'timeout': 3},
        udp_kwargs={'timeout': 2},
        tls_kwargs={'timeout': 5},
        snmp_kwargs={'timeout': 2},
    )
    try:
        yield engine
    finally:
        await engine.close()


@pytest_asyncio.fixture
async def udp_echo_server(free_port):
    """
    本地 UDP echo server. 收到数据报后返回 b'ECHO:' + data.
    用于测试 UdpAdapter 成功路径 (不用联网).

    yield: 端口号
    """
    class EchoProtocol(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            try:
                self.transport.sendto(b'ECHO:' + data, addr)
            except Exception:
                pass

    loop = asyncio.get_event_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        EchoProtocol, local_addr=('127.0.0.1', free_port)
    )
    try:
        yield free_port
    finally:
        try:
            transport.close()
        except Exception:
            pass


@pytest_asyncio.fixture
async def fake_snmp_server(free_port):
    """
    模拟未授权 SNMP server (community=public).
    对 SysDescr 请求返回伪造的设备信息. 对其它 community 返回 noSuchObject.

    yield: 端口号
    """
    from aiburp.traffic.adapters.snmp import (
        _encode_snmpv2c_get, _parse_get_response,
        SNMP_GET_RESPONSE, _ber_encode_sequence,
        _ber_encode_integer, _ber_encode_octet_string, _ber_encode_oid,
        _ber_encode_null, OID_SYS_DESCR, ASN1_SEQUENCE,
    )

    SYS_DESCR_VALUE = "Linux Test Router 5.15.0 (Mock)"

    class SnmpProtocol(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            try:
                # 检查 community 是不是 public
                # 简化: 直接看请求包里有没有 'public' 字符串
                if b'public' not in data:
                    # 拒绝 (不响应, 模拟 community 错误)
                    return

                # 构造成功响应 (GetResponse)
                # 复用请求的 request-id
                parsed = _parse_get_response(data)
                # 找请求里的 request_id (在 data 里是第一个 INTEGER after version/community 标记)
                # 简化: 直接用一个固定 request_id
                req_id_bytes = b'\x02\x01\x01'  # INTEGER 1

                # 构造 VarBind: SEQUENCE { OID(OID_SYS_DESCR) OCTET_STRING(value) }
                oid_enc = _ber_encode_oid(OID_SYS_DESCR)
                value_enc = _ber_encode_octet_string(SYS_DESCR_VALUE.encode())
                varbind = _ber_encode_sequence(oid_enc + value_enc)
                varbind_list = _ber_encode_sequence(varbind)

                # PDU body: request-id + error-status(0) + error-index(0) + varbind_list
                err_status = _ber_encode_integer(0)
                err_index = _ber_encode_integer(0)
                pdu_body = req_id_bytes + err_status + err_index + varbind_list
                pdu = bytes([SNMP_GET_RESPONSE]) + bytes([len(pdu_body)]) + pdu_body

                # 外层: version(1) + community(public) + pdu
                from aiburp.traffic.adapters.snmp import (
                    _ber_encode_length,
                )
                version_enc = _ber_encode_integer(1)
                community_enc = _ber_encode_octet_string(b'public')
                msg = _ber_encode_sequence(version_enc + community_enc + pdu)

                self.transport.sendto(msg, addr)
            except Exception:
                pass

    loop = asyncio.get_event_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        SnmpProtocol, local_addr=('127.0.0.1', free_port)
    )
    try:
        yield free_port
    finally:
        try:
            transport.close()
        except Exception:
            pass

