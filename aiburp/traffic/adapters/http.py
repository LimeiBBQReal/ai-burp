"""
HTTP/HTTPS 协议适配器.

不重写, 直接包装现有 aiburp.AsyncBurp - 这是"不破坏 V3"红线的关键.

AsyncBurp 已经具备:
    - 异步 httpx 客户端 + stealth 模式
    - IntentAnalyzer 自动打标签
    - SQL/WAF 错误检测 (_detect_error)
    - WAF 拦截识别 (403/406/429)

本 adapter 只做协议归一化: 把 AsyncBurp.Response 字段映射到 TrafficResponse.
"""

import asyncio
from typing import Dict, List, Optional

from ..base import (
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
)
from ...burp import AsyncBurp


class HttpAdapter(ProtocolAdapter):
    """HTTP/HTTPS 协议适配器 - 包装 AsyncBurp"""

    protocol = "http"
    description = "HTTP/HTTPS adapter (wraps AsyncBurp)"

    def __init__(
        self,
        delay: float = 0.5,
        timeout: float = 30.0,
        concurrency: int = 5,
        proxy: Optional[str] = None,
        stealth: bool = False,
        stealth_profile: str = "chrome_120",
    ):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._burp = AsyncBurp(
            delay=delay,
            timeout=timeout,
            concurrency=concurrency,
            proxy=proxy,
            stealth=stealth,
            stealth_profile=stealth_profile,
        )
        self._closed = False

    def _check_closed(self, target: str = ""):
        if self._closed:
            return TrafficResponse(
                protocol="http", ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    # -------- probe --------

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活 + 指纹.
        发 GET / 看状态码 + Server header.
        """
        closed = self._check_closed(target)
        if closed:
            return closed
        url = self._normalize_url(target)
        method = kw.get("method", "GET")
        r = await self._burp.request(method, url)
        return self._convert(r, protocol=self._scheme(url))

    # -------- send --------

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送 HTTP 请求.

        req.payload 约定:
            - dict  -> 当作 query params (GET) 或 json (POST)
            - str   -> 当作 raw body
            - None  -> 空
        req.headers -> HTTP headers
        req.meta 支持:
            - method: HTTP 方法 (默认 GET)
            - params: 显式 query 参数
            - json:   显式 JSON body
            - data:   显式 form body
        """
        method = req.meta.get("method", "GET").upper()
        url = self._normalize_url(req.target)

        closed = self._check_closed(req.target)
        if closed:
            return closed

        params = req.meta.get("params")
        json_body = req.meta.get("json")
        data_body = req.meta.get("data")

        # payload 兜底解析: dict 优先当 params/json, str 当 body
        if req.payload is not None and not (params or json_body or data_body):
            if isinstance(req.payload, dict):
                if method == "GET":
                    params = req.payload
                else:
                    json_body = req.payload
            elif isinstance(req.payload, str):
                data_body = req.payload

        check = kw.pop("check", None)
        r = await self._burp.request(
            method,
            url,
            params=params,
            headers=req.headers or None,
            data=data_body,
            json_data=json_body,
            check=check,
            **kw,
        )
        return self._convert(r, protocol=self._scheme(url), req=req)

    # -------- 高并发 fuzz (覆盖基类的串行实现) --------

    async def fuzz(
        self,
        target: str,
        payloads: List[str],
        marker: str = "§",
        base: Optional[TrafficRequest] = None,
        **kw,
    ) -> List[TrafficResponse]:
        """复用 AsyncBurp 的高并发 fuzz"""
        # 简单路径: target 是 URL 且 payload 直接替换 URL marker
        if base is None:
            results = await self._burp.fuzz(target, payloads, marker=marker)
            return [self._convert(r, protocol=self._scheme(target)) for r in results]

        # 复杂路径: 走基类的 _inject_into_request 逐个 send
        return await super().fuzz(target, payloads, marker=marker, base=base, **kw)

    # -------- 生命周期 --------

    async def close(self):
        if self._closed:
            return
        self._closed = True
        await self._burp.close()

    # ============================================================
    #                     内部工具
    # ============================================================

    @staticmethod
    def _normalize_url(target: str) -> str:
        """target 可能是 host / host:port / URL; 归一化为完整 URL"""
        s = target.strip()
        if s.startswith(("http://", "https://")):
            return s
        # host:port 但没有协议 - 默认 http
        return f"http://{s}"

    @staticmethod
    def _scheme(url: str) -> str:
        """从 URL 取协议标识 (http/https)"""
        if url.startswith("https://"):
            return "https"
        return "http"

    @staticmethod
    def _convert(r, protocol: str = "http", req: Optional[TrafficRequest] = None) -> TrafficResponse:
        """
        AsyncBurp.Response (aiburp.burp.Response) -> TrafficResponse.

        字段一一映射, 旧代码用 .body/.status/.headers 全部保留 (向后兼容).
        """
        return TrafficResponse(
            protocol=protocol,
            ok=r.ok,
            status=r.status,
            time_ms=r.time_ms,
            raw=HttpAdapter._raw_response_bytes(r),
            text=r.body,
            body=r.body,
            length=r.length,
            headers=dict(r.headers) if r.headers else {},
            url=r.url,
            method=r.method,
            error=r.error,
            blocked=r.blocked,
            reflects=r.reflects,
            anomalies=list(r.anomalies) if hasattr(r, "anomalies") else [],
            payload=(req.payload if req and req.payload is not None else r.payload) or "",
            tags=list(r.tags) if hasattr(r, "tags") else [],
        )

    @staticmethod
    def _raw_response_bytes(r) -> bytes:
        raw = getattr(r, "raw", b"") or b""
        if raw:
            return raw

        status = int(getattr(r, "status", 0) or 0)
        headers = dict(getattr(r, "headers", {}) or {})
        body = getattr(r, "body", "") or ""
        if status <= 0 and not headers and not body:
            return b""

        body_bytes = body if isinstance(body, bytes) else str(body).encode("utf-8", "replace")

        status_line = f"HTTP/1.1 {status}\r\n".encode("ascii", "replace")
        header_lines = b"".join(
            f"{name}: {value}\r\n".encode("utf-8", "replace")
            for name, value in headers.items()
        )
        return status_line + header_lines + b"\r\n" + body_bytes
