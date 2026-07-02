"""
Docker daemon 未授权访问适配器.

Docker daemon 暴露 2375 (无 TLS) / 2376 (TLS) 端口时, 若未配置认证:
    - GET /version        -> Docker 版本信息
    - GET /containers/json -> 列出所有容器
    - POST /containers/create + POST /exec -> 容器逃逸/RCE

未授权 Docker = 直接 RCE (创建特权容器挂载宿主机文件系统).

本 adapter 组合 HttpAdapter (Docker API 是 HTTP REST), 加 Docker 特有检测逻辑.
"""

import json as _json
from typing import Optional

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .http import HttpAdapter
from .fingerprints import split_host_port


class DockerAdapter(ProtocolAdapter):
    """
    Docker daemon 未授权检测适配器.

    用法:
        async with DockerAdapter() as d:
            resp = await d.probe("10.0.0.1:2375")
            resp = await d.check_unauth("10.0.0.1:2375")
    """

    protocol = "docker"
    description = "Docker daemon unauth detection (HTTP API)"

    DEFAULT_PORT = 2375

    def __init__(self, timeout: float = 5.0, concurrency: int = 5):
        super().__init__(timeout=timeout, concurrency=concurrency)
        # 组合 HttpAdapter, delay=0 (内网扫描不需要限速)
        self._http = HttpAdapter(delay=0, timeout=timeout, concurrency=concurrency)
        self._closed = False

    def _check_closed(self, target: str = "") -> "Optional[TrafficResponse]":
        """close 后返回明确错误而非泄漏 httpx 异常"""
        if self._closed:
            from ..base import TrafficResponse as _TR
            return _TR(
                protocol="docker", ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """探活: GET /version"""
        closed = self._check_closed(target)
        if closed:
            return closed
        url = self._to_url(target, "/version")
        resp = await self._http.probe(url, **kw)
        resp.protocol = "docker"

        if resp.ok and ("Version" in resp.text or "ApiVersion" in resp.text):
            resp.banner = "docker"
            resp.tags = ["DOCKER", "UNAUTH-OK"]
            resp.anomalies.append("version-leaked")
        elif resp.ok:
            # HTTP 200 但不是 Docker 响应
            resp.anomalies.append("not-docker-api")
        return resp

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """发送任意 Docker API 请求. req.target 是 host:port, payload 是 path."""
        closed = self._check_closed(req.target)
        if closed:
            return closed
        path = req.payload or "/"
        url = self._to_url(req.target, path)
        method = req.meta.get("method", "GET")

        http_req = TrafficRequest(
            protocol="http", target=url,
            payload=req.meta.get("json") if method != "GET" else None,
            headers=req.headers,
            meta={"method": method, "json": req.meta.get("json")},
        )
        resp = await self._http.send(http_req, **kw)
        resp.protocol = "docker"
        resp.target = req.target
        return resp

    # ============================================================
    #                  check_unauth
    # ============================================================

    async def check_unauth(self, target: str, timeout: Optional[float] = None
                           ) -> TrafficResponse:
        """
        一键 Docker 未授权检测.

        流程:
            1. GET /version        -> 确认是 Docker
            2. GET /containers/json -> 列出容器 (确认 API 可用)
            3. GET /info            -> 系统信息 (确认完全未授权)
        """
        t = timeout or self.timeout

        # 1. /version
        ver_resp = await self.probe(target, timeout=t)
        if not ver_resp.ok or "UNAUTH-OK" not in ver_resp.tags:
            return TrafficResponse(
                protocol="docker", ok=False, status=0,
                target=target, error="not-docker-or-unreachable",
                anomalies=ver_resp.anomalies,
            )

        version = ""
        try:
            data = _json.loads(ver_resp.text)
            version = data.get("Version", "")
        except Exception:
            pass

        # 2. /containers/json
        containers_resp = await self.send(
            TrafficRequest(protocol="docker", target=target, payload="/containers/json"),
            timeout=t,
        )
        container_count = 0
        if containers_resp.ok:
            try:
                container_count = len(_json.loads(containers_resp.text))
            except Exception:
                pass

        # 3. /info
        info_resp = await self.send(
            TrafficRequest(protocol="docker", target=target, payload="/info"),
            timeout=t,
        )

        tags = ["DOCKER", "UNAUTH-CONFIRMED", "HIGH-VALUE"]
        anomalies = [
            "unauth-access",
            "version-leaked",
            f"version:{version}" if version else "version:unknown",
        ]
        if container_count > 0:
            anomalies.append(f"containers:{container_count}")
            anomalies.append("containers-visible")
        if info_resp.ok:
            anomalies.append("system-info-leaked")
        # Docker 未授权 = 确定性 RCE (创建特权容器)
        anomalies.append("rce-certain")

        return TrafficResponse(
            protocol="docker",
            ok=True,
            status=200,
            text=ver_resp.text[:1000],
            banner=f"docker/{version}" if version else "docker",
            time_ms=ver_resp.time_ms + containers_resp.time_ms + info_resp.time_ms,
            target=target,
            tags=tags,
            anomalies=anomalies,
        )

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        if self._closed:
            return
        self._closed = True
        await self._http.close()

    # ============================================================
    #                       工具
    # ============================================================

    def _to_url(self, target: str, path: str = "/") -> str:
        """host:port + path -> http://host:port/path"""
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        if not path.startswith("/"):
            path = "/" + path
        return f"http://{host}:{port}{path}"
