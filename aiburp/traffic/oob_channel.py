"""
OOB 统一回显通道 (UPM V4).

把 InteractshClient (core/oob.py) 升级为 UPM 风格的回显通道, 让任意协议
adapter 都能用统一的 "生成标记 -> 等 DNS/HTTP/SMTP 回调 -> 判定" 流程,
适配无回显注入场景 (blind SQLi / blind SSRF / blind CMDi).

设计:
    - 不重写 InteractshClient, 用组合方式包装 (向后兼容)
    - async 接口, 与 TrafficEngine 一致
    - 回调协议归一: HTTP/DNS/SMTP 都映射成统一的 OOBCallback

典型流程:
    async with OOBChannel() as oob:
        url = await oob.generate('sqli-test')      # 拿到 xxx.oast.fun
        # 把 url 拼进 payload 发送 (任意协议)
        resp = await engine.send(req_with_oob_url)
        callbacks = await oob.poll('sqli-test', timeout=8)
        if callbacks:
            print('blind 确认! 收到', callbacks[0].protocol, '回调')
"""

import asyncio
from typing import Dict, List, Optional, Tuple

from .base import TrafficResponse


def _get_interactsh_client(server: Optional[str] = None, token: Optional[str] = None):
    """
    延迟导入 aiburp.core.oob.InteractshClient, 避免顶层循环依赖.

    返回已构造的客户端实例 (未注册).
    """
    from ..core.oob import InteractshClient
    return InteractshClient(server=server, token=token)


class OOBChannel:
    """
    UPM 统一 OOB 回显通道.

    包装 aiburp.core.oob.InteractshClient (oast.fun), 提供 async 接口.
    回调按协议 (http/dns/smtp) 归一, 供任意 TrafficRequest 复用.
    """

    def __init__(
        self,
        server: Optional[str] = None,
        token: Optional[str] = None,
        poll_interval: float = 2.0,
    ):
        """
        Args:
            server:        OOB 服务器域名 (默认 oast.fun)
            token:         部分自建服务需要 token
            poll_interval: 轮询间隔 (秒)
        """
        self._client = _get_interactsh_client(server=server, token=token)
        self._poll_interval = poll_interval
        self._markers: Dict[str, str] = {}  # marker -> oob_url
        self._registered = False

    async def register(self) -> str:
        """注册并返回 correlation domain (在 to_thread 中执行同步注册)"""
        url = await asyncio.to_thread(self._client.register)
        self._registered = True
        return url

    async def generate(self, marker: str, protocol: str = "http") -> str:
        """
        为某个标记生成 OOB URL.

        Args:
            marker:   业务标记 (用于后续 check 区分不同 payload)
            protocol: "http" / "https" / "dns" / "raw"
                - http/https: 返回 http(s)://xxx.oast.fun
                - dns:        返回 xxx.oast.fun (用作 DNS 查询名 / DNS Rebinding)
                - raw:        返回 xxx.oast.fun (调用方自行拼接)

        Returns:
            OOB URL
        """
        if not self._registered:
            await self.register()

        # 在 to_thread 中拿 url (InteractshClient 是同步的)
        if protocol == "http":
            url = await asyncio.to_thread(self._client.get_http_url, marker)
        elif protocol == "https":
            url = await asyncio.to_thread(self._client.get_https_url, marker)
        else:
            # dns / raw: 用纯域名 (DNS 查询 / Rebinding 场景)
            url = await asyncio.to_thread(self._client.get_url, marker)

        self._markers[marker] = url
        return url

    async def poll(
        self,
        marker: Optional[str] = None,
        timeout: float = 10.0,
    ) -> List["OOBCallbackUnified"]:
        """
        轮询回调.

        Args:
            marker:  只看特定标记的回调 (None = 全部)
            timeout: 轮询总超时 (秒)

        Returns:
            归一化回调列表 (HTTP/DNS/SMTP 统一字段)
        """
        # InteractshClient.poll 是同步阻塞的, 放到线程
        raw_callbacks = await asyncio.to_thread(
            self._client.poll, timeout=int(timeout), interval=self._poll_interval
        )

        unified = [OOBCallbackUnified.from_raw(c) for c in raw_callbacks]

        if marker:
            m_url = self._markers.get(marker, marker)
            # 精确匹配: marker 是 OOB URL 的最左 label (marker.correlation.server)
            # 用 "marker." 前缀或完整 m_url 匹配, 避免子串误匹配
            # (例如 marker="sqli" 不应命中含 "mysql-injection" 的请求)
            marker_prefix = f"{marker}."
            unified = [
                c for c in unified
                if (marker_prefix in c.raw_request
                    or m_url in c.raw_request
                    or marker_prefix in str(c.extra))
            ]

        return unified

    async def check(self, marker: str, timeout: float = 8.0) -> bool:
        """便捷: 是否收到指定 marker 的回调"""
        callbacks = await self.poll(marker=marker, timeout=timeout)
        return len(callbacks) > 0

    async def wait_first(
        self,
        marker: str,
        timeout: float = 10.0,
    ) -> Optional["OOBCallbackUnified"]:
        """等第一个回调, 超时返回 None"""
        callbacks = await self.poll(marker=marker, timeout=timeout)
        return callbacks[0] if callbacks else None

    # ============================================================
    #                     工具
    # ============================================================

    def markers(self) -> Dict[str, str]:
        """已生成的所有 marker -> url 映射"""
        return dict(self._markers)

    def to_response(
        self,
        callbacks: List["OOBCallbackUnified"],
        target: str = "",
    ) -> TrafficResponse:
        """
        把 OOB 回调转成 TrafficResponse, 让决策层无感消费.

        触发回调 = "reflects via OOB", ok=True 表示确认有漏洞.
        """
        if not callbacks:
            return TrafficResponse(
                protocol="oob", ok=False, status=0,
                target=target, error="no-callback",
            )

        protocols = sorted({c.protocol for c in callbacks})
        return TrafficResponse(
            protocol="oob",
            ok=True,
            status=1,
            reflects=True,                      # OOB 回调 = 外带回显
            target=target,
            text="\n".join(c.summary() for c in callbacks),
            banner=f"{len(callbacks)}callbacks/{','.join(protocols)}",
            tags=["OOB-CONFIRMED", "BLIND-INJECTION"],
            anomalies=[f"got-{p}-callback" for p in protocols],
        )

    async def close(self):
        try:
            await asyncio.to_thread(self._client.deregister)
        except Exception:
            pass
        self._registered = False
        self._markers.clear()

    async def __aenter__(self):
        await self.register()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class OOBCallbackUnified:
    """归一化 OOB 回调 - HTTP/DNS/SMTP 共用统一字段"""

    def __init__(
        self,
        protocol: str,           # http / dns / smtp
        remote_address: str,
        timestamp: str = "",
        raw_request: str = "",
        extra: Optional[Dict] = None,
    ):
        self.protocol = protocol
        self.remote_address = remote_address
        self.timestamp = timestamp
        self.raw_request = raw_request
        self.extra = extra or {}

    @classmethod
    def from_raw(cls, cb) -> "OOBCallbackUnified":
        """从 aiburp.core.oob.OOBCallback 转换"""
        return cls(
            protocol=cb.protocol,
            remote_address=cb.remote_address,
            timestamp=cb.timestamp,
            raw_request=cb.raw_request,
            extra=dict(cb.data) if hasattr(cb, "data") else {},
        )

    def summary(self) -> str:
        return f"[{self.protocol}] {self.remote_address} @ {self.timestamp}"

    def __repr__(self):
        return f"OOBCallback({self.protocol} from {self.remote_address})"
