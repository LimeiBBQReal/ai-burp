"""
Java RMI 协议适配器 - 轻量指纹 + 反序列化检测入口.

Java RMI (Remote Method Invocation) 是 Java 分布式应用的通信协议:
    - 默认端口 1099 (rmiregistry) / 9999 (JMX) / 4711 (SAP)
    - 反序列化重灾区: ysoserial 的 RMI payload 直接打 RCE
    - 历史 CVE: CVE-2015-4852 (WebLogic), CVE-2017-3248, CVE-2018-2893

实现策略 (轻量级, 不完整实现 Java 序列化协议):
    1. probe(): 发 RMI 协议头 (魔术字节 0x4a 0x52 0x4d 0x49 = "JRMI"),
       看 1099 是否回 RMI 协议响应
    2. send(): 不完整实现 (RMI 调用需要 Java 类路径)
    3. check_deserial(): 检测是否是易受攻击的 RMI 版本 (JDK 版本指纹)

不做完整反序列化利用 - 那是 exploit 层 (ysoserial), adapter 只做检测.

设计:
    - 继承 TcpAdapter (RMI 基于 TCP + 自定义二进制协议)
    - 复用 _connect_and_read (TCP 连接管理)
"""

import asyncio
from typing import Optional

from ..base import TrafficRequest, TrafficResponse
from .tcp import TcpAdapter
from .fingerprints import split_host_port


# RMI 协议常量
RMI_MAGIC = b"\x4a\x52\x4d\x49"  # "JRMI" - RMI 协议魔术字节
RMI_VERSION_1 = b"\x00\x01"       # StreamProtocol
RMI_VERSION_2 = b"\x00\x02"       # SingleOpProtocol

# RMI 协议子类型
RMI_PROTOCOL_STREAM = 0x4b        # 'K' - StreamProtocol
RMI_PROTOCOL_SINGLEOP = 0x4c      # 'L' - SingleOpProtocol
RMI_PROTOCOL_MULTIPLEX = 0x4d     # 'M' - MultiplexProtocol


class RmiAdapter(TcpAdapter):
    """
    Java RMI 轻量适配器 (指纹 + 版本探测).

    用法:
        async with RmiAdapter() as r:
            resp = await r.probe("10.0.0.1:1099")
            # resp.banner 含 "rmi" + 协议版本
    """

    protocol = "rmi"
    description = "Java RMI lightweight fingerprint (deserialization detection entry)"

    DEFAULT_PORT = 1099

    def __init__(self, timeout: float = 3.0, concurrency: int = 10,
                 read_window: float = 2.0, proxy: Optional[str] = None):
        super().__init__(timeout=timeout, concurrency=concurrency,
                         read_window=read_window, proxy=proxy)
        self._closed = False

    def _check_closed(self, target: str = ""):
        if self._closed:
            from ..base import TrafficResponse as _TR
            return _TR(
                protocol="rmi", ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活: 发 RMI 魔术字节, 看 1099 是否回 RMI 协议响应.

        RMI 服务器在收到 "JRMI" + 版本后, 会回:
        - 协议确认字节 (0x4e=ProtocolAck / 0x4f=ProtocolNotSupported)
        - 或直接关闭连接 (非 RMI 服务)
        """
        closed = self._check_closed(target)
        if closed:
            return closed
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        # 发 RMI 协议头: 魔术 + 版本 + 协议类型
        probe_data = RMI_MAGIC + b"\x00\x01" + bytes([RMI_PROTOCOL_STREAM])

        try:
            raw, _banner, elapsed = await self._connect_and_read(
                host, port,
                send=probe_data,
                timeout=kw.get("timeout", self.timeout),
                max_rounds=2,
            )
        except asyncio.TimeoutError:
            return TrafficResponse(
                protocol="rmi", ok=False, status=0,
                target=target, error="timeout",
                time_ms=self.timeout * 1000,
            )
        except OSError as e:
            return TrafficResponse(
                protocol="rmi", ok=False, status=0,
                target=target, error=type(e).__name__,
            )

        text = self._safe_decode(raw)
        tags = []
        anomalies = []
        banner = ""

        # 解析 RMI 响应
        if len(raw) >= 1:
            resp_byte = raw[0]
            if resp_byte == 0x4e:  # 'N' ProtocolAck
                banner = "rmi(stream-protocol)"
                tags = ["RMI", "RMI-STREAM"]
                anomalies.append("protocol-ack")
                # 高危: 暴露的 RMI registry 是反序列化攻击入口
                tags.append("HIGH-VALUE")
                tags.append("DESERIAL-CHECK")
                anomalies.append("deserialization-target")
            elif resp_byte == 0x4f:  # 'O' ProtocolNotSupported
                banner = "rmi(protocol-not-supported)"
                tags = ["RMI"]
                anomalies.append("protocol-rejected")
            elif RMI_MAGIC in raw:
                # 响应里也有 JRMI 魔术 - 可能是 registry 直接回的
                banner = "rmi"
                tags = ["RMI", "HIGH-VALUE", "DESERIAL-CHECK"]
                anomalies.append("rmi-magic-in-response")
            else:
                # 有响应但不是 RMI 标准 - 检查是否明显是其它协议
                # 避免把 HTTP/SSH/SMTP banner 误判为 RMI?
                text_check = text.lower()[:20]
                is_other_protocol = (
                    text_check.startswith("http/")
                    or text_check.startswith("ssh-")
                    or text_check.startswith("220 ")  # SMTP/FTP
                    or text_check.startswith("+ok")   # POP3
                )
                if is_other_protocol:
                    # 明显是其它协议 - 不是 RMI
                    banner = ""
                    tags = []
                    anomalies.append("not-rmi-other-protocol")
                else:
                    # 二进制响应, 可能是 RMI 变种 - 保守标 RMI?
                    banner = "rmi?"
                    tags = ["RMI?"]
                    anomalies.append("non-standard-response")
        else:
            # 无响应但端口开放 (TCP 握手成功) - 可能是 RMI 等待正确输入
            banner = "open-but-silent"
            tags = ["RMI?"]
            anomalies.append("no-rmi-response")

        return TrafficResponse(
            protocol="rmi",
            ok=True if tags else False,
            status=1 if tags else 0,
            raw=raw,
            text=text,
            banner=banner,
            time_ms=elapsed,
            target=target,
            tags=tags,
            anomalies=anomalies,
        )

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送原始 RMI 数据.
        req.payload: 原始字节 (调用方自行构造 RMI 报文).

        注意: 不做完整 RMI 方法调用 - 那需要 Java 类路径和序列化.
        本方法只做原始字节发送, 供高级用户/上层 exploit 使用.
        """
        closed = self._check_closed(req.target)
        if closed:
            return closed
        host, port = split_host_port(req.target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        payload = self._coerce_payload(req.payload)

        try:
            raw, _banner, elapsed = await self._connect_and_read(
                host, port,
                send=payload,
                timeout=kw.get("timeout", self.timeout),
                max_rounds=req.meta.get("read_rounds", 5),
            )
        except asyncio.TimeoutError:
            return TrafficResponse(
                protocol="rmi", ok=False, status=0,
                target=req.target, payload=self._payload_str(req.payload),
                error="timeout", time_ms=self.timeout * 1000,
            )
        except OSError as e:
            return TrafficResponse(
                protocol="rmi", ok=False, status=0,
                target=req.target, payload=self._payload_str(req.payload),
                error=type(e).__name__,
            )

        text = self._safe_decode(raw)
        return TrafficResponse(
            protocol="rmi",
            ok=True,
            status=1,
            raw=raw,
            text=text,
            length=len(raw),
            time_ms=elapsed,
            target=req.target,
            payload=self._payload_str(req.payload),
        )

    # ============================================================
    #              check_deserial (反序列化风险标注)
    # ============================================================

    async def close(self):
        self._closed = True

    async def check_deserial(self, target: str,
                             timeout: Optional[float] = None) -> TrafficResponse:
        """
        检测 RMI 反序列化风险.

        判断依据:
            - 端口 1099 开放 + RMI 协议响应 = 反序列化攻击面暴露
            - 不实际发送 payload (避免触发服务端异常)
            - 标注 DESERIAL-VULNERABLE 供上层决定是否用 ysoserial

        红队流程:
            adapter.check_deserial() -> 标记风险
            exploit 层 (ysoserial) -> 实际利用
        """
        t = timeout or self.timeout
        probe_resp = await self.probe(target, timeout=t)

        if not probe_resp.ok:
            return probe_resp

        if "RMI" in probe_resp.tags and "DESERIAL-CHECK" in probe_resp.tags:
            # 确认是 RMI registry - 标注反序列化风险
            probe_resp.tags.extend(["DESERIAL-VULNERABLE", "HIGH-VALUE"])
            probe_resp.anomalies.extend([
                "rmi-registry-exposed",
                "java-deserialization-attack-surface",
                "ysoserial-target",
                "rce-possible",
            ])
            # 建议信息
            probe_resp.text += "\n\n反序列化风险:\n"
            probe_resp.text += "  - 暴露的 RMI registry 可被 ysoserial 攻击\n"
            probe_resp.text += "  - 历史 CVE: CVE-2015-4852 / CVE-2017-3248 / CVE-2018-2893\n"
            probe_resp.text += "  - 建议: 用 ysoserial 的 RMI payload 验证"

        return probe_resp
