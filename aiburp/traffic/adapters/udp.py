"""
UDP 协议适配器 - 数据报交互.

实现思路:
    1. probe(): 发探测包 (可选) 看是否有响应. UDP 无连接, 端口扫描意义有限 -
       无响应可能是端口关闭, 也可能是服务对探测包不响应. 语义在 anomalies 里明确.
    2. send():  发数据报, 等一个或多个响应包 (带超时).
    3. fuzz():  并发 send 多个 payload.

设计要点:
    - UDP 与 TCP 流式语义不同 (无连接, 无可靠交付), 不能复用 TcpAdapter.
    - 不继承 TcpAdapter, 直接继承 ProtocolAdapter.
    - 严守 review 教训: protocol=self.protocol (多态), _payload_str 避免 repr,
      close 幂等, _closed 标志.
    - UDP "无响应" 不等于 "端口关闭" - 这点在 anomalies 里说明, AI 不应误判.

底层: asyncio.DatagramProtocol + loop.create_datagram_endpoint.
"""

import asyncio
import socket
from typing import List, Optional

from ..base import (
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
)
from .fingerprints import split_host_port, detect_service_by_port


class UdpAdapter(ProtocolAdapter):
    """
    UDP 协议适配器.

    用法:
        adapter = UdpAdapter(timeout=3)
        resp = await adapter.probe("10.0.0.1:161")          # SNMP 端口探活
        req = TrafficRequest(protocol="udp", target="x:53",
                             payload=b"\\x00\\x00...")
        resp = await adapter.send(req)
    """

    protocol = "udp"
    description = "Raw UDP adapter (datagram send/recv)"

    def __init__(
        self,
        timeout: float = 3.0,
        concurrency: int = 20,
        probe_payload: Optional[bytes] = None,
    ):
        """
        Args:
            timeout:       收响应的超时 (秒)
            concurrency:   并发上限
            probe_payload: probe 时主动发送的探测字节 (None = 只 listen 不发, 通常无响应)
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._probe_payload = probe_payload
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False

    def _check_closed(self, target: str = "") -> Optional[TrafficResponse]:
        if self._closed:
            return TrafficResponse(
                protocol=self.protocol, ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        UDP 探活. 发探测包 (可选), 看是否有响应.

        语义注意: UDP 无响应 ≠ 端口关闭. 服务可能只是对探测包不响应.
        - 有响应: 端口肯定开放 (HIGH confidence)
        - 无响应: 端口可能关闭 / 也可能服务对探测包不响应 (LOW confidence)
        """
        closed = self._check_closed(target)
        if closed:
            return closed
        host, port = split_host_port(target)
        port_hint = detect_service_by_port(port) if port else None

        async with self._sem:
            try:
                raw, elapsed = await self._send_and_recv(
                    host, port,
                    send=self._probe_payload,
                    timeout=kw.get("timeout", self.timeout),
                )
            except asyncio.TimeoutError:
                # UDP 超时 - 端口状态未知
                if port_hint:
                    proto, svc = port_hint
                    return TrafficResponse(
                        protocol="udp", ok=False, status=0,
                        target=target, banner=svc,
                        tags=[svc.upper()],
                        error="udp-no-response",
                        anomalies=["no-response-may-be-closed-or-silent"],
                        time_ms=self.timeout * 1000,
                    )
                return TrafficResponse(
                    protocol="udp", ok=False, status=0,
                    target=target, error="udp-no-response",
                    anomalies=["no-response-may-be-closed-or-silent"],
                    time_ms=self.timeout * 1000,
                )
            except OSError as e:
                # 网络不可达 / 主机不可达 / 端口不可达 (ICMP)
                return TrafficResponse(
                    protocol="udp", ok=False, status=0,
                    target=target, error=type(e).__name__,
                    anomalies=[f"{host}:{port} {type(e).__name__}"],
                )

        text = self._safe_decode(raw)
        # UDP 有响应 = 端口开放 (高置信)
        tags = ["UDP"]
        if port_hint:
            tags.append(port_hint[1].upper())

        return TrafficResponse(
            protocol="udp",
            ok=True,
            status=1,            # UDP 约定: 1 = open (有响应)
            raw=raw,
            text=text,
            length=len(raw),
            banner=(port_hint[1] if port_hint else ""),
            time_ms=elapsed,
            target=target,
            tags=tags,
            anomalies=["udp-open-with-response"],
        )

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送 UDP 数据报并收响应.

        req.target: host:port
        req.payload: bytes / str / None
        req.meta.read_rounds: 最多收几个响应包 (UDP 可能有多个, 默认 3)
        """
        closed = self._check_closed(req.target)
        if closed:
            return closed
        host, port = split_host_port(req.target)
        payload = self._coerce_payload(req.payload)
        timeout = kw.get("timeout", self.timeout)

        async with self._sem:
            try:
                raw, elapsed = await self._send_and_recv(
                    host, port, send=payload,
                    timeout=timeout,
                    max_rounds=req.meta.get("read_rounds", 3),
                )
            except asyncio.TimeoutError:
                return TrafficResponse(
                    protocol="udp", ok=False, status=0,
                    target=req.target,
                    payload=self._payload_str(req.payload),
                    error="udp-timeout",
                    time_ms=timeout * 1000,
                    anomalies=["no-response"],
                )
            except OSError as e:
                # ICMP Port Unreachable 在 Windows 上常表现为 ConnectionResetError
                return TrafficResponse(
                    protocol="udp", ok=False, status=0,
                    target=req.target,
                    payload=self._payload_str(req.payload),
                    error=type(e).__name__,
                )

        text = self._safe_decode(raw)
        reflects = bool(payload and payload in raw)

        return TrafficResponse(
            protocol="udp",
            ok=True,
            status=1,
            raw=raw,
            text=text,
            length=len(raw),
            time_ms=elapsed,
            target=req.target,
            payload=self._payload_str(req.payload),
            reflects=reflects,
        )

    # ============================================================
    #                         fuzz
    # ============================================================

    async def fuzz(
        self,
        target: str,
        payloads: List[str],
        marker: str = "§",
        base: Optional[TrafficRequest] = None,
        **kw,
    ) -> List[TrafficResponse]:
        """并发 UDP fuzz - 每个 payload 一个独立数据报"""
        if base is None:
            base = TrafficRequest(protocol="udp", target=target)

        tasks = []
        for p in payloads:
            req = self._inject_into_request(base, p, marker)
            tasks.append(self.send(req, **kw))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        out = []
        for p, r in zip(payloads, results):
            if isinstance(r, Exception):
                out.append(TrafficResponse(
                    protocol=self.protocol, ok=False, error=str(r),
                    target=target, payload=self._payload_str(p),
                ))
            else:
                if r.payload == "":
                    r.payload = self._payload_str(p)
                out.append(r)
        return out

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        """UdpAdapter 无全局 transport (每次 send 创建临时 transport), 只需设标志"""
        self._closed = True

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    # ============================================================
    #                     内部: 数据报收发
    # ============================================================

    async def _send_and_recv(
        self,
        host: str,
        port: int,
        send: Optional[bytes] = None,
        timeout: Optional[float] = None,
        max_rounds: int = 3,
    ) -> tuple:
        """
        发送 UDP 数据报并收集响应.

        Returns: (raw_bytes, elapsed_ms)
        """
        timeout = timeout or self.timeout
        loop = asyncio.get_event_loop()
        start = loop.time()

        # 用 transport + protocol 收数据报
        queue: asyncio.Queue = asyncio.Queue()
        transport = None
        try:
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: _UdpRecvProtocol(queue, host, port),
                remote_addr=(host, port),
            )

            # 发送
            if send:
                transport.sendto(send)

            # 收响应 (最多 max_rounds 个包, 或总超时)
            chunks = []
            deadline = start + timeout
            for _ in range(max_rounds):
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=remaining)
                    if data:
                        chunks.append(data)
                    else:
                        break  # 空包或连接结束信号
                except asyncio.TimeoutError:
                    break

            elapsed = (loop.time() - start) * 1000
            raw = b"".join(chunks)

            # UDP 无响应 = 超时 (不管有没有主动发探测包)
            # probe 用 send=None 时, 仍然期待服务端主动发数据 (被动 banner, UDP 罕见)
            if not chunks:
                raise asyncio.TimeoutError()

            return raw, elapsed

        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    # ============================================================
    #                       工具
    # ============================================================

    @staticmethod
    def _coerce_payload(p) -> Optional[bytes]:
        """统一 payload 为 bytes"""
        if p is None:
            return None
        if isinstance(p, (bytes, bytearray)):
            return bytes(p)
        if isinstance(p, str):
            # 处理 \\x00 字面量 (UDP 二进制常见)
            s = p.replace("\\r\\n", "\r\n").replace("\\n", "\n")
            # 尝试解析 \xHH 转义
            try:
                return s.encode("latin-1").decode("unicode_escape").encode("latin-1")
            except Exception:
                return s.encode("utf-8", "replace")
        return str(p).encode("utf-8", "replace")

    @staticmethod
    def _payload_str(p) -> str:
        """bytes -> 可读字符串 (避免 repr)"""
        if p is None:
            return ""
        if isinstance(p, (bytes, bytearray)):
            try:
                return bytes(p).decode("utf-8")
            except UnicodeDecodeError:
                return bytes(p).decode("latin-1", "replace")
        return str(p)

    @staticmethod
    def _safe_decode(raw: bytes) -> str:
        if not raw:
            return ""
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw.decode("latin-1")
            except Exception:
                return repr(raw)


class _UdpRecvProtocol(asyncio.DatagramProtocol):
    """接收 UDP 响应的内部协议, 把数据塞进 queue"""

    def __init__(self, queue: asyncio.Queue, host: str, port: int):
        self._queue = queue
        self._host = host
        self._port = port

    def datagram_received(self, data: bytes, addr):
        try:
            self._queue.put_nowait(data)
        except Exception:
            pass

    def error_received(self, exc):
        # ICMP Port Unreachable 等会到这里
        # 把异常塞进 queue 让上层判断 (空 bytes 表示出错)
        try:
            self._queue.put_nowait(b"")
        except Exception:
            pass

    def connection_lost(self, exc):
        pass
