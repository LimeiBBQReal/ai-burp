"""
TCP 协议适配器 - 原始字节流交互.

实现思路:
    1. probe(): connect 后读 banner (带超时), 调用 fingerprints 做服务识别
    2. send():  connect -> (可选) 发送 payload -> 读取响应 -> 关闭
    3. fuzz():  并发 send 多个 payload (覆盖基类串行实现)

这是 V4 "ALL-IN-TRAFFIC" 的第一个非 HTTP adapter. Redis/Docker/Kubelet 等
高危未授权服务检测都建立在它之上 (后续 ProtocolAdapter 子类).

设计要点:
    - 每次交互一个新连接 (无状态), 简单可靠; 长连接复用留给子类
    - 读取响应用 "短超时 + 尝试读尽" 策略, 避免阻塞
    - banner 探测支持 "被动读" (有些服务先发 banner, 如 SSH/FTP/SMTP)
      和 "主动发探测包" (如 Redis 发 INFO)
"""

import asyncio
from typing import List, Optional

from ..base import (
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
    ProtocolTimeout,
    ProtocolError,
)
from .fingerprints import (
    split_host_port,
    detect_service_by_port,
    detect_service_by_banner,
)


class TcpAdapter(ProtocolAdapter):
    """
    原始 TCP 协议适配器.

    用法:
        adapter = TcpAdapter()
        resp = await adapter.probe("10.0.0.1:6379")
        print(resp.banner)  # "redis" / "ssh" / ...

        req = TrafficRequest(protocol="tcp", target="10.0.0.1:6379",
                             payload=b"PING\\r\\n")
        resp = await adapter.send(req)
    """

    protocol = "tcp"
    description = "Raw TCP adapter with banner fingerprinting"

    def __init__(
        self,
        timeout: float = 5.0,
        concurrency: int = 20,
        read_window: float = 2.0,
        probe_payload: Optional[bytes] = None,
        proxy: Optional[str] = None,
    ):
        """
        Args:
            timeout:       单次连接/读超时 (秒)
            concurrency:   并发上限
            read_window:   读响应的滚动窗口; 在此时间内无新数据即认为读尽
            probe_payload: probe 时主动发送的探测字节 (None = 纯被动读 banner)
            proxy:         SOCKS5 代理 URL (如 "socks5://127.0.0.1:7890")
                           设置后所有 TCP 连接走代理
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._read_window = read_window
        self._probe_payload = probe_payload
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False
        self._proxy = proxy  # SOCKS5 代理 URL

    def _check_closed(self, target: str = ""):
        """close 后返回明确错误 (子类 RedisAdapter/RmiAdapter 继承此行为)"""
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
        探活 + 指纹.
        - 先按端口推断 (确定性强)
        - 再 connect + 读 banner, 用指纹库二次确认
        """
        closed = self._check_closed(target)
        if closed:
            return closed
        host, port = split_host_port(target)
        # 1. 端口预判
        port_hint = detect_service_by_port(port) if port else None

        # 2. 实际连接 + 读 banner
        try:
            raw, banner, elapsed = await self._connect_and_read(
                host, port,
                send=self._probe_payload,
                timeout=kw.get("timeout", self.timeout),
            )
        except asyncio.TimeoutError:
            # 注意: 不同平台语义不同.
            #   - Linux: connect 被拒会抛 ConnectionRefusedError
            #   - Windows proactor: 连接拒绝常表现为 TimeoutError
            # 因此超时无法精确区分"端口关闭" vs "开放但无响应".
            # 策略: 有端口预判的, 视为开放(无 banner); 否则标记不可达.
            if port_hint:
                proto, svc = port_hint
                return TrafficResponse(
                    protocol="tcp", ok=False, status=0,
                    banner=svc, tags=[svc.upper()],
                    time_ms=self.timeout * 1000,
                    error="timeout-or-closed",
                    anomalies=["no-response-may-be-closed"],
                )
            return TrafficResponse(
                protocol="tcp", ok=False, status=0,
                error="timeout-or-closed",
                anomalies=[f"{host}:{port} no response"],
            )

        except (ConnectionRefusedError, ConnectionResetError) as e:
            return TrafficResponse(
                protocol="tcp", ok=False, status=0,
                error="connection-refused",
                anomalies=[f"{host}:{port} closed ({type(e).__name__})"],
            )

        except OSError as e:
            # 兜底: 网络不可达 / 主机不可达 / 其它 socket 错误
            return TrafficResponse(
                protocol="tcp", ok=False, status=0,
                error=str(e) or type(e).__name__,
                anomalies=[f"{host}:{port} {type(e).__name__}"],
            )

        text = self._safe_decode(raw)

        # 3. 二次指纹
        svc_match = detect_service_by_banner(text) or detect_service_by_banner(banner)
        service = svc_match[0] if svc_match else (port_hint[1] if port_hint else "")
        version = svc_match[1] if svc_match else ""
        attack_value = svc_match[2] if svc_match else ""

        tags = [service.upper()] if service else []
        if attack_value == "high":
            tags.append("HIGH-VALUE")

        # P-1 修复: CDN/ELB/WAF 假阳性防护
        # TCP 握手成功但完全无数据 (空 raw + 空 banner) = 可能是 CDN/ELB 的 SYN+ACK 假象,
        # 不能简单判定为"端口开放". 降级为"疑似开放"并标注警告.
        if not raw and not banner:
            return TrafficResponse(
                protocol="tcp",
                ok=False,                # 不确认开放 (降级)
                status=0,
                target=target,
                time_ms=elapsed,
                tags=[],                 # 不标服务 tag (避免误报 HIGH-VALUE)
                error="syn-ack-but-silent",
                anomalies=[
                    "syn-ack-but-no-data",
                    "may-be-cdn-elb-waf",
                    "real-service-status-unknown",
                ],
            )

        return TrafficResponse(
            protocol="tcp",
            ok=True,
            status=1,               # TCP 约定: 1 = open
            raw=raw,
            text=text,
            banner=(service or "") + (f"/{version}" if version else ""),
            time_ms=elapsed,
            target=target,
            tags=tags,
            anomalies=[] if service else ["unknown-service"],
        )

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送 TCP 数据并读响应.

        req.target: host:port
        req.payload: bytes / str / None
            - None: 仅 connect + 被动读 banner
            - bytes/str: connect -> send -> read
        req.meta.read_rounds: 最多读几轮 (默认 5)
        """
        host, port = split_host_port(req.target)
        payload = self._coerce_payload(req.payload)
        timeout = kw.get("timeout", self.timeout)

        closed = self._check_closed(req.target)
        if closed:
            return closed

        async with self._sem:
            try:
                raw, banner, elapsed = await self._connect_and_read(
                    host, port, send=payload, timeout=timeout,
                    max_rounds=req.meta.get("read_rounds", 5),
                )
            except asyncio.TimeoutError:
                return TrafficResponse(
                    protocol="tcp", ok=False, status=0,
                    target=req.target, payload=self._payload_str(req.payload),
                    error="timeout",
                    time_ms=timeout * 1000,
                )
            except (ConnectionRefusedError, ConnectionResetError) as e:
                return TrafficResponse(
                    protocol="tcp", ok=False, status=0,
                    target=req.target, payload=self._payload_str(req.payload),
                    error=type(e).__name__,
                )
            except OSError as e:
                return TrafficResponse(
                    protocol="tcp", ok=False, status=0,
                    target=req.target, payload=self._payload_str(req.payload),
                    error=str(e),
                )

        text = self._safe_decode(raw)

        # 检测 payload 是否被回显
        reflects = bool(payload and payload in raw)

        resp = TrafficResponse(
            protocol="tcp",
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

        # 若响应还没有服务指纹, 顺手用 banner 文本打一次
        # (req 没有 tags 字段 - tags 是响应侧语义)
        if not resp.tags and text:
            m = detect_service_by_banner(text)
            if m:
                resp.banner = m[0] + (f"/{m[1]}" if m[1] else "")
                resp.tags = [m[0].upper()]

        return resp

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
        """并发 fuzz - 每条 payload 一个独立连接"""
        if base is None:
            base = TrafficRequest(protocol="tcp", target=target)

        tasks = []
        for p in payloads:
            # 直接传 p (保持 bytes/str 原类型), 由 _inject_into_request 内部处理
            req = self._inject_into_request(base, p, marker)
            tasks.append(self.send(req, **kw))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 异常转成 ok=False 的响应, 保持返回长度一致
        out = []
        for p, r in zip(payloads, results):
            if isinstance(r, Exception):
                out.append(TrafficResponse(
                    protocol=self.protocol, ok=False, error=str(r),
                    target=target, payload=self._payload_str(p),
                ))
            else:
                # 成功的 resp.payload 已在 send 里正确设置, 这里补上
                if r.payload == "":
                    r.payload = self._payload_str(p)
                out.append(r)
        return out

    # ============================================================
    #                     生命周期
    # ============================================================

    async def close(self):
        """设 _closed 标志 (子类 RedisAdapter/RmiAdapter 继承)"""
        self._closed = True

    # ============================================================
    #                     内部: 连接 + 读
    # ============================================================

    async def _connect_and_read(
        self,
        host: str,
        port: int,
        send: Optional[bytes] = None,
        timeout: Optional[float] = None,
        max_rounds: int = 5,
    ) -> tuple:
        """
        建立连接, (可选)发送数据, 滚动读取响应.

        Returns: (raw_bytes, banner_str, elapsed_ms)
        """
        timeout = timeout or self.timeout
        start = asyncio.get_event_loop().time()

        # SOCKS5 代理支持: 如果有代理, 通过 socks 建立底层连接
        if self._proxy:
            reader, writer = await self._open_via_proxy(host, port, timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        try:
            banner_bytes = b""

            # 1. 被动读 banner (有些服务先发)
            try:
                first = await asyncio.wait_for(
                    reader.read(1024), timeout=self._read_window
                )
                banner_bytes = first
            except asyncio.TimeoutError:
                pass  # 无被动 banner

            # 2. 主动发送
            all_data = banner_bytes
            if send:
                writer.write(send)
                await writer.drain()
                # 读响应
                window_data = b""
                for _ in range(max_rounds):
                    try:
                        chunk = await asyncio.wait_for(
                            reader.read(4096), timeout=self._read_window
                        )
                        if not chunk:
                            break
                        window_data += chunk
                    except asyncio.TimeoutError:
                        break
                all_data = banner_bytes + window_data
            elif not banner_bytes:
                # 既无被动 banner 又没发送: 至少返回空
                all_data = b""

            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            return all_data, self._safe_decode(banner_bytes)[:256], elapsed

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _open_via_proxy(self, host: str, port: int, timeout: float):
        """
        通过 SOCKS5 代理建立 TCP 连接.

        用 PySocks 创建底层 socket, 再用 asyncio 包装.
        """
        import socks
        from urllib.parse import urlparse

        proxy_parsed = urlparse(self._proxy)
        proxy_type = socks.SOCKS5
        if proxy_parsed.scheme == "socks4":
            proxy_type = socks.SOCKS4
        elif proxy_parsed.scheme in ("http", "https"):
            proxy_type = socks.HTTP

        proxy_host = proxy_parsed.hostname
        proxy_port = proxy_parsed.port or 1080

        # 在线程里建立 SOCKS 连接 (PySocks 是同步的)
        loop = asyncio.get_event_loop()

        def _connect_sync():
            s = socks.socksocket()
            s.set_proxy(proxy_type, proxy_host, proxy_port)
            s.settimeout(timeout)
            s.connect((host, port))
            s.setblocking(False)  # 转异步
            return s

        sock = await asyncio.to_thread(_connect_sync)
        return await asyncio.open_connection(sock=sock)

    # ============================================================
    #                     工具
    # ============================================================

    @staticmethod
    def _payload_str(p) -> str:
        """
        把 payload 转成可读字符串 (供 TrafficResponse.payload 字段).
        bytes -> utf-8 解码 (失败用 latin-1), 避免出现 \"b'...'\" repr.
        None  -> 空串.
        """
        if p is None:
            return ""
        if isinstance(p, (bytes, bytearray)):
            try:
                return bytes(p).decode("utf-8")
            except UnicodeDecodeError:
                return bytes(p).decode("latin-1", "replace")
        return str(p)

    @staticmethod
    def _coerce_payload(p) -> Optional[bytes]:
        """统一 payload 为 bytes"""
        if p is None:
            return None
        if isinstance(p, (bytes, bytearray)):
            return bytes(p)
        if isinstance(p, str):
            # CRLF 处理: 字符串里的 \\r\\n 字面量转真换行
            return p.replace("\\r\\n", "\r\n").replace("\\n", "\n").encode("utf-8", "replace")
        return str(p).encode("utf-8", "replace")

    @staticmethod
    def _safe_decode(raw: bytes) -> str:
        """安全解码, 遇到二进制不崩"""
        if not raw:
            return ""
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            # 混合二进制: 用 latin-1 保住所有字节, 再剔除不可打印
            try:
                return raw.decode("latin-1")
            except Exception:
                return repr(raw)
