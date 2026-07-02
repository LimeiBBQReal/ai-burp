"""
WebSocket 协议适配器.

补全 V3 param_discover 里只提取 ws:// URL 但不能交互的缺口.

用途:
    - 测试 WebSocket 接口的注入 (SQLi/XSS/命令注入 通过 ws 消息)
    - 检测未授权 WebSocket (无 Origin/认证校验)
    - 跨域 WebSocket 劫持 (CSWSH)

依赖: websockets (pip install websockets), 可选库, 缺失时 adapter 不可用.

设计:
    - probe():   连接 + 发握手消息, 看是否接受
    - send():    发任意消息, 收响应
    - fuzz():    对消息内容 marker 替换批量发
    - check_cswsh(): 跨域 WebSocket 劫持检测 (改 Origin)
"""

import asyncio
from typing import List, Optional

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter

try:
    import websockets
    from websockets.exceptions import InvalidHandshake, WebSocketException
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False
    InvalidHandshake = Exception
    WebSocketException = Exception


class WebSocketAdapter(ProtocolAdapter):
    """
    WebSocket 协议适配器.

    用法:
        async with WebSocketAdapter() as ws:
            resp = await ws.probe("ws://target.com/ws")
            resp = await ws.check_cswsh("ws://target.com/ws")
            req = TrafficRequest(protocol="ws", target="ws://target.com/ws",
                                 payload='{"action":"ping"}')
            resp = await ws.send(req)
    """

    protocol = "ws"
    description = "WebSocket adapter (message injection / CSWSH detection)"

    def __init__(self, timeout: float = 5.0, concurrency: int = 5,
                 handshake_only: bool = False):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._handshake_only = handshake_only
        self._sem = asyncio.Semaphore(concurrency)
        self._closed = False

    def _check_closed(self, target: str = ""):
        if self._closed:
            return TrafficResponse(
                protocol="ws", ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    if not _WS_AVAILABLE:
        async def probe(self, target: str, **kw) -> TrafficResponse:
            return TrafficResponse(
                protocol="ws", ok=False, status=0,
                target=target, error="websockets-library-not-installed",
                anomalies=["pip install websockets"],
            )

        async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
            return TrafficResponse(
                protocol="ws", ok=False, status=0,
                target=req.target, error="websockets-library-not-installed",
            )
    else:
        # ============================================================
        #                         probe
        # ============================================================

        async def probe(self, target: str, **kw) -> TrafficResponse:
            """
            探活: 建连 + 发握手消息.

            WebSocket 连接成功 = HTTP Upgrade 101 响应.
            发一条测试消息看服务端是否响应.
            """
            closed = self._check_closed(target)
            if closed:
                return closed
            async with self._sem:
                return await self._do_probe(target, **kw)

        async def _do_probe(self, target: str, **kw) -> TrafficResponse:
            url = self._normalize_url(target)
            headers = kw.get("headers", {})
            start = asyncio.get_event_loop().time()

            try:
                async with websockets.connect(
                    url, additional_headers=headers,
                    open_timeout=self.timeout,
                    close_timeout=1,
                ) as ws:
                    # 连接成功 = 握手通过
                    elapsed = (asyncio.get_event_loop().time() - start) * 1000

                    if self._handshake_only:
                        return TrafficResponse(
                            protocol="ws", ok=True, status=101,
                            banner="websocket",
                            target=target, time_ms=elapsed,
                            tags=["WS", "HANDSHAKE-OK"],
                        )

                    # 发一条 ping 消息探测响应性
                    try:
                        await ws.send("ping")
                        response = await asyncio.wait_for(
                            ws.recv(), timeout=self.timeout
                        )
                        resp_text = response if isinstance(response, str) else str(response)
                        return TrafficResponse(
                            protocol="ws", ok=True, status=101,
                            text=resp_text, banner="websocket",
                            target=target, time_ms=elapsed,
                            tags=["WS", "HANDSHAKE-OK", "RESPONSIVE"],
                            anomalies=[f"echo:{resp_text[:50]}"],
                        )
                    except asyncio.TimeoutError:
                        # 握手成功但无响应 - 仍算在线
                        return TrafficResponse(
                            protocol="ws", ok=True, status=101,
                            banner="websocket",
                            target=target, time_ms=elapsed,
                            tags=["WS", "HANDSHAKE-OK"],
                            anomalies=["no-echo-response"],
                        )

            except InvalidHandshake as e:
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                return TrafficResponse(
                    protocol="ws", ok=False, status=0,
                    target=target, error=f"handshake-failed:{e}",
                    time_ms=elapsed,
                    anomalies=["handshake-rejected"],
                )
            except (WebSocketException, OSError, asyncio.TimeoutError) as e:
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                return TrafficResponse(
                    protocol="ws", ok=False, status=0,
                    target=target, error=type(e).__name__,
                    time_ms=elapsed,
                )

        # ============================================================
        #                          send
        # ============================================================

        async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
            """发送 WebSocket 消息."""
            closed = self._check_closed(req.target)
            if closed:
                return closed
            url = self._normalize_url(req.target)
            headers = req.headers or {}
            msg = req.payload
            if msg is None:
                msg = ""

            async with self._sem:
                start = asyncio.get_event_loop().time()
                try:
                    async with websockets.connect(
                        url, additional_headers=headers,
                        open_timeout=self.timeout,
                        close_timeout=1,
                    ) as ws:
                        await ws.send(msg)
                        # 尝试收响应
                        try:
                            response = await asyncio.wait_for(
                                ws.recv(), timeout=kw.get("timeout", self.timeout)
                            )
                            resp_text = response if isinstance(response, str) else str(response)
                        except asyncio.TimeoutError:
                            resp_text = ""

                        elapsed = (asyncio.get_event_loop().time() - start) * 1000
                        reflects = bool(msg and str(msg) in resp_text)

                        return TrafficResponse(
                            protocol="ws", ok=True, status=101,
                            text=resp_text, length=len(resp_text.encode()),
                            time_ms=elapsed,
                            target=req.target,
                            payload=self._payload_str(msg),
                            reflects=reflects,
                            anomalies=["message-sent"] + (
                                ["response-received"] if resp_text else ["no-response"]
                            ),
                        )
                except (InvalidHandshake, WebSocketException, OSError) as e:
                    elapsed = (asyncio.get_event_loop().time() - start) * 1000
                    return TrafficResponse(
                        protocol="ws", ok=False, status=0,
                        target=req.target, payload=self._payload_str(msg),
                        error=type(e).__name__, time_ms=elapsed,
                    )

        # ============================================================
        #                 check_cswsh (跨域劫持)
        # ============================================================

        async def check_cswsh(self, target: str, evil_origin: str = "http://evil.com",
                              timeout: Optional[float] = None) -> TrafficResponse:
            """
            跨域 WebSocket 劫持检测 (Cross-Site WebSocket Hijacking).

            若服务端不校验 Origin, 攻击者可在恶意页面让受害者浏览器
            (携带 cookie) 连接到该 WebSocket, 窃取数据.

            检测: 用恶意 Origin 建连, 若成功 = 存在 CSWSH.
            """
            url = self._normalize_url(target)
            t = timeout or self.timeout
            start = asyncio.get_event_loop().time()

            try:
                async with websockets.connect(
                    url,
                    additional_headers={"Origin": evil_origin},
                    open_timeout=t, close_timeout=1,
                ) as ws:
                    elapsed = (asyncio.get_event_loop().time() - start) * 1000
                    return TrafficResponse(
                        protocol="ws", ok=True, status=101,
                        target=target, banner="websocket(cswsh-vulnerable)",
                        time_ms=elapsed,
                        tags=["WS", "CSWSH-VULNERABLE", "HIGH-VALUE"],
                        anomalies=["origin-not-checked",
                                   "cross-site-hijack-possible"],
                    )
            except InvalidHandshake:
                # 拒绝恶意 Origin = 安全配置
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                return TrafficResponse(
                    protocol="ws", ok=True, status=1,
                    target=target, banner="websocket(origin-checked)",
                    time_ms=elapsed,
                    tags=["WS", "SECURE"],
                    anomalies=["origin-checked", "cswsh-protected"],
                )
            except (WebSocketException, OSError) as e:
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                return TrafficResponse(
                    protocol="ws", ok=False, status=0,
                    target=target, error=type(e).__name__, time_ms=elapsed,
                )

    # ============================================================
    #                       工具
    # ============================================================

    @staticmethod
    def _normalize_url(target: str) -> str:
        """
        归一化 ws/wss URL.
        ws://, wss://    -> 原样
        http://, https:// -> 转 ws://, wss://
        无 scheme (裸 host) -> 补 ws://
        其它 scheme (ftp/mailto/...) -> 报 ValueError (避免生成 ws://ftp:// 这种错误 URL)
        """
        s = target.strip()
        if s.startswith(("ws://", "wss://")):
            return s
        if s.startswith("http://"):
            return "ws://" + s[7:]
        if s.startswith("https://"):
            return "wss://" + s[8:]
        if "://" in s:
            scheme = s.split("://", 1)[0]
            raise ValueError(
                f"WebSocket 不支持 {scheme}:// scheme, 请用 ws:// 或 wss://"
            )
        # 裸 host, 补 ws://
        return "ws://" + s

    @staticmethod
    def _payload_str(p) -> str:
        if p is None:
            return ""
        if isinstance(p, (bytes, bytearray)):
            return bytes(p).decode("utf-8", "replace")
        return str(p)

    async def close(self):
        self._closed = True  # websockets 连接是 per-call 的, 只需设标志
