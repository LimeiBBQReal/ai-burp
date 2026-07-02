"""
SNMP 协议适配器 - 内网未授权检测.

SNMP (Simple Network Management Protocol) 默认 UDP 161, 是内网设备管理接口:
    - 默认 community string (public/private) 泄露 = 拿到整张内网拓扑
    - SysDescr/SysName/SysLocation 泄露设备型号 + 部署位置
    - v1/v2c 无加密无认证, community 抓包可破
    - 历史漏洞: SNMP RCE (CVE-2017-6736 思科)、信息泄露等

检测思路:
    - probe(): 用默认 community (public) 发 SNMPv2c GET System 组
    - send(): 自定义 community + OID 查询
    - check_unauth(): 自动尝试常见弱 community (public/private/admin/cisco)

设计:
    - 组合 UdpAdapter (SNMP 是 UDP 协议)
    - 用 BER 编码构造 SNMPv2c GET 请求 (无外部依赖)
    - 解析响应里的 OID 值 (SysDescr/SysName/SysLocation 等)
"""

import asyncio
import struct
from typing import List, Optional, Tuple

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .fingerprints import split_host_port


# ============================================================
# BER 编码常量
# ============================================================

ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OBJECT_IDENTIFIER = 0x06
ASN1_SEQUENCE = 0x30

SNMP_GET_REQUEST = 0xA0       # GetRequest PDU (context-specific, constructed)
SNMP_GET_RESPONSE = 0xA2      # GetResponse PDU

# System 组 OID (1.3.6.1.2.1.1.x)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"      # 设备描述 (型号/系统)
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"  # 厂商 OID
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"     # 启动时间
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"    # 联系人
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"       # 主机名
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"   # 物理位置


# ============================================================
# BER 编码工具
# ============================================================

def _ber_encode_length(length: int) -> bytes:
    """BER 编码长度"""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def _ber_encode_integer(value: int) -> bytes:
    """编码 INTEGER"""
    if value == 0:
        body = b"\x00"
    else:
        body = b""
        v = value
        while v > 0:
            body = bytes([v & 0xFF]) + body
            v >>= 8
        # 处理符号位
        if body[0] & 0x80:
            body = b"\x00" + body
    return bytes([ASN1_INTEGER]) + _ber_encode_length(len(body)) + body


def _ber_encode_octet_string(value: bytes) -> bytes:
    """编码 OCTET STRING"""
    return bytes([ASN1_OCTET_STRING]) + _ber_encode_length(len(value)) + value


def _ber_encode_oid(oid: str) -> bytes:
    """编码 OBJECT IDENTIFIER"""
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        return b""
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            # 多字节编码
            encoded = []
            while p > 0:
                encoded.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(encoded) - 1):
                body += bytes([encoded[i] | 0x80])
            body += bytes([encoded[-1]])
    return bytes([ASN1_OBJECT_IDENTIFIER]) + _ber_encode_length(len(body)) + body


def _ber_encode_null() -> bytes:
    return bytes([ASN1_NULL, 0])


def _ber_encode_sequence(content: bytes) -> bytes:
    return bytes([ASN1_SEQUENCE]) + _ber_encode_length(len(content)) + content


def _encode_snmpv2c_get(community: str, oid: str, request_id: int = 1) -> bytes:
    """
    构造 SNMPv2c GetRequest 报文.

    结构:
        SEQUENCE {
            INTEGER version (1 = v2c)
            OCTET STRING community
            GetRequestPDU {
                INTEGER request-id
                INTEGER error-status (0)
                INTEGER error-index (0)
                SEQUENCE OF VarBind {
                    SEQUENCE {
                        OID name
                        NULL value
                    }
                }
            }
        }
    """
    # Version: 1 = SNMPv2c (0 = v1)
    version = _ber_encode_integer(1)
    comm = _ber_encode_octet_string(community.encode())

    # PDU
    req_id = _ber_encode_integer(request_id)
    err_status = _ber_encode_integer(0)
    err_index = _ber_encode_integer(0)

    # VarBind
    oid_enc = _ber_encode_oid(oid)
    varbind = _ber_encode_sequence(oid_enc + _ber_encode_null())
    varbind_list = _ber_encode_sequence(varbind)

    pdu_body = req_id + err_status + err_index + varbind_list
    pdu = bytes([SNMP_GET_REQUEST]) + _ber_encode_length(len(pdu_body)) + pdu_body

    return _ber_encode_sequence(version + comm + pdu)


def _parse_get_response(data: bytes) -> Optional[dict]:
    """
    解析 GetResponse, 返回 {oid, value, error} 或 None.

    简化解析 - 只提取第一个 VarBind 的 OID 和值.
    畸形/空数据返回 None.
    """
    try:
        if not data or len(data) < 4:
            return None

        result = {"error": False}
        # 跳过外层 SEQUENCE + version + community
        # 找 GetResponse PDU (0xA2)
        idx = data.find(bytes([SNMP_GET_RESPONSE]))
        if idx < 0:
            return None

        # 简化: 直接搜 OID 编码特征, 然后取后面的值
        # OID 编码开头是 06 (ASN1_OBJECT_IDENTIFIER)
        oid_start = data.find(bytes([ASN1_OBJECT_IDENTIFIER]), idx)
        if oid_start < 0:
            return None  # 没有 OID - 不是有效响应

        # 读 OID 长度 + 值 (检查长度字段是否在范围内)
        if oid_start + 1 >= len(data):
            return None
        oid_len = data[oid_start + 1]
        if oid_start + 2 + oid_len > len(data):
            return None  # OID 长度超出数据范围 - 畸形
        oid_value = data[oid_start + 2:oid_start + 2 + oid_len]

        # OID 后面是值 (类型 + 长度 + 内容)
        val_start = oid_start + 2 + oid_len
        if val_start >= len(data):
            return result  # 有 OID 但无值 - 视为 error

        val_type = data[val_start]
        # 错误响应 (noSuchObject = 0x80, noSuchInstance = 0x81, endOfMib = 0x82)
        if val_type in (0x80, 0x81, 0x82):
            result["error"] = True
            result["value"] = ""
            return result

        # 检查值长度字段
        if val_start + 1 >= len(data):
            return result
        val_len = data[val_start + 1]
        if val_start + 2 + val_len > len(data):
            return None  # 值长度超出数据范围 - 畸形
        val_bytes = data[val_start + 2:val_start + 2 + val_len]

        # 根据类型解码值
        if val_type == ASN1_OCTET_STRING:
            try:
                result["value"] = val_bytes.decode("utf-8", "replace")
            except Exception:
                result["value"] = val_bytes.decode("latin-1", "replace")
        elif val_type == ASN1_INTEGER:
            # 大端整数
            value = 0
            for b in val_bytes:
                value = (value << 8) | b
            result["value"] = str(value)
        else:
            result["value"] = val_bytes.hex()

        result["oid"] = _decode_oid(oid_value)
        return result
    except Exception:
        return None


def _decode_oid(encoded: bytes) -> str:
    """把 BER 编码的 OID 解码回点分字符串"""
    if not encoded:
        return ""
    parts = [str(encoded[0] // 40), str(encoded[0] % 40)]
    i = 1
    while i < len(encoded):
        val = 0
        while i < len(encoded):
            b = encoded[i]
            val = (val << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
        parts.append(str(val))
    return ".".join(parts)


# ============================================================
# SnmpAdapter
# ============================================================

# 常见弱 community (按命中率排序)
COMMON_COMMUNITIES = ["public", "private", "cisco", "admin", "default",
                      "monitor", "guest", "manager", "test", "read"]


class SnmpAdapter(ProtocolAdapter):
    """
    SNMP 未授权检测适配器.

    用法:
        async with SnmpAdapter() as s:
            resp = await s.probe("10.0.0.1:161")           # 默认 public 查 SysDescr
            resp = await s.check_unauth("10.0.0.1:161")    # 尝试多个 community
    """

    protocol = "snmp"
    description = "SNMP unauth detection (default community strings)"

    DEFAULT_PORT = 161

    def __init__(self, timeout: float = 3.0, concurrency: int = 10):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活: 用 public community 查 SysDescr.
        - 有响应: SNMP 在线 + community=public 可读 (高危未授权)
        - 无响应: 端口关闭 / community 不对 / 设备不响应
        """
        if self._closed:
            return self._closed_resp(target)

        community = kw.get("community", "public")
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        packet = _encode_snmpv2c_get(community, OID_SYS_DESCR)
        resp = await self._send_snmp(host, port, packet, kw.get("timeout", self.timeout))

        if not resp.ok:
            resp.protocol = "snmp"
            resp.target = target
            return resp

        # 解析响应
        parsed = _parse_get_response(resp.raw)
        tags = ["SNMP"]
        anomalies = []

        if parsed and not parsed.get("error"):
            sys_descr = parsed.get("value", "")
            resp.text = f"SysDescr: {sys_descr}"
            resp.banner = "snmp(public)"
            tags.append("UNAUTH-OK")
            tags.append("HIGH-VALUE")
            anomalies.append("community-public-works")
            anomalies.append("sysdescr-leaked")
        elif parsed and parsed.get("error"):
            # community 不对 (noSuchObject)
            tags.append("AUTH-REQUIRED")
            anomalies.append("community-public-rejected")
            resp.banner = "snmp(secure)"
        else:
            anomalies.append("response-not-parsed")

        resp.protocol = "snmp"
        resp.target = target
        resp.tags = tags
        resp.anomalies = anomalies
        return resp

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """发送 SNMP 查询. req.payload=OID, req.meta.community=community"""
        if self._closed:
            return self._closed_resp(req.target)

        community = req.meta.get("community", "public")
        oid = req.payload or OID_SYS_DESCR
        host, port = split_host_port(req.target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        packet = _encode_snmpv2c_get(community, oid)
        resp = await self._send_snmp(host, port, packet, kw.get("timeout", self.timeout))

        resp.protocol = "snmp"
        resp.target = req.target
        resp.payload = str(oid)
        return resp

    # ============================================================
    #                  check_unauth
    # ============================================================

    async def check_unauth(self, target: str, communities: Optional[List[str]] = None,
                           timeout: Optional[float] = None) -> TrafficResponse:
        """
        一键 SNMP 未授权检测: 尝试多个常见 community.

        命中任一 community = 未授权 (HIGH-VALUE).
        """
        if self._closed:
            return self._closed_resp(target)

        communities = communities or COMMON_COMMUNITIES
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        # 逐个尝试 (避免一次打太多 UDP 包触发限速)
        for comm in communities:
            packet = _encode_snmpv2c_get(comm, OID_SYS_DESCR)
            resp = await self._send_snmp(host, port, packet, t)

            if not resp.ok:
                continue  # 无响应, 试下一个

            parsed = _parse_get_response(resp.raw)
            if parsed and not parsed.get("error"):
                sys_descr = parsed.get("value", "")
                # 命中! 多查几个 OID 拿完整信息
                info_parts = [f"SysDescr: {sys_descr}"]
                for oid, label in [(OID_SYS_NAME, "SysName"),
                                   (OID_SYS_LOCATION, "SysLocation"),
                                   (OID_SYS_CONTACT, "SysContact")]:
                    pkt2 = _encode_snmpv2c_get(comm, oid)
                    r2 = await self._send_snmp(host, port, pkt2, t)
                    if r2.ok:
                        p2 = _parse_get_response(r2.raw)
                        if p2 and not p2.get("error"):
                            info_parts.append(f"{label}: {p2.get('value', '')}")

                return TrafficResponse(
                    protocol="snmp",
                    ok=True,
                    status=1,
                    text="\n".join(info_parts),
                    banner=f"snmp(community={comm})",
                    target=target,
                    tags=["SNMP", "UNAUTH-CONFIRMED", "HIGH-VALUE"],
                    anomalies=[
                        f"community-cracked:{comm}",
                        "unauth-access",
                        "internal-network-exposed",
                        "device-fingerprinted",
                    ],
                )

        # 全部 community 都失败
        return TrafficResponse(
            protocol="snmp",
            ok=True,           # 端口可能有响应 (rejected), 只是没破开 community
            status=0,
            target=target,
            banner="snmp(secure)",
            tags=["SNMP", "SECURED"],
            anomalies=[
                f"tried-{len(communities)}-communities",
                "auth-required",
                "secure-config",
            ],
        )

    # ============================================================
    #                     内部: UDP 收发
    # ============================================================

    async def _send_snmp(self, host: str, port: int, packet: bytes,
                         timeout: float) -> TrafficResponse:
        """发 SNMP UDP 包并收响应"""
        loop = asyncio.get_event_loop()
        start = loop.time()
        queue: asyncio.Queue = asyncio.Queue()

        try:
            transport, _proto = await loop.create_datagram_endpoint(
                lambda: _UdpRecv(queue, host, port),
                remote_addr=(host, port),
            )
        except OSError as e:
            return TrafficResponse(
                protocol="snmp", ok=False, status=0,
                error=f"connect-failed:{type(e).__name__}",
            )

        try:
            transport.sendto(packet)
            try:
                data = await asyncio.wait_for(queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                elapsed = (loop.time() - start) * 1000
                return TrafficResponse(
                    protocol="snmp", ok=False, status=0,
                    error="udp-timeout",
                    time_ms=elapsed,
                )

            elapsed = (loop.time() - start) * 1000
            # 空响应 (ICMP port unreachable 被协议层转成空包) = 端口关闭
            if not data:
                return TrafficResponse(
                    protocol="snmp", ok=False, status=0,
                    target="", error="snmp-no-response",
                    time_ms=elapsed,
                    anomalies=["no-response-may-be-closed"],
                )
            return TrafficResponse(
                protocol="snmp",
                ok=True,
                status=1,
                raw=data,
                length=len(data),
                time_ms=elapsed,
            )
        finally:
            try:
                transport.close()
            except Exception:
                pass

    # ============================================================
    #                       生命周期
    # ============================================================

    def _closed_resp(self, target: str) -> TrafficResponse:
        return TrafficResponse(
            protocol="snmp", ok=False, status=0,
            target=target, error="adapter-closed",
            anomalies=["adapter 已 close"],
        )

    async def close(self):
        if self._closed:
            return
        self._closed = True


# 共用 UDP 接收协议 (内部)
from .udp import _UdpRecvProtocol as _UdpRecv
