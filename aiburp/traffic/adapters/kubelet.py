"""
Kubelet 未授权访问适配器.

Kubelet 是 Kubernetes 节点上的 agent, 默认监听 10250 (HTTPS) / 10255 (HTTP, 只读).
未授权访问 (匿名 webhook 配置错误) 时:
    - GET /pods                  -> 列出节点上所有 Pod (含环境变量/密钥)
    - POST /run/<ns>/<pod>/<c>   -> 在容器内执行命令 = RCE
    - GET /exec/...              -> 获取容器 shell

10255 (cAdvisor) 即使只读也能泄露容器信息. 10250 未授权 = 直接 RCE.

本 adapter 组合 HttpAdapter, 加 Kubelet 检测逻辑.
"""

import json as _json
from typing import Optional

from ..base import TrafficRequest, TrafficResponse, ProtocolAdapter
from .http import HttpAdapter
from .fingerprints import split_host_port


class KubeletAdapter(ProtocolAdapter):
    """
    Kubelet 未授权检测适配器.

    用法:
        async with KubeletAdapter() as k:
            resp = await k.probe("10.0.0.1:10250")
            resp = await k.check_unauth("10.0.0.1:10250")
    """

    protocol = "kubelet"
    description = "Kubelet unauth detection (HTTP API on 10250/10255)"

    DEFAULT_PORT = 10250
    READONLY_PORT = 10255

    def __init__(self, timeout: float = 5.0, concurrency: int = 5):
        """
        Args:
            timeout:     超时 (秒)
            concurrency: 并发

        注: Kubelet 10250 用自签名 HTTPS 证书, HttpAdapter 内部 AsyncBurp
            固定 verify=False (httpx), 所以本 adapter 不暴露 TLS 验证开关 -
            红队场景下必须忽略证书才能访问自签名服务.
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._http = HttpAdapter(delay=0, timeout=timeout, concurrency=concurrency)
        self._closed = False

    def _check_closed(self, target: str = "") -> "Optional[TrafficResponse]":
        if self._closed:
            from ..base import TrafficResponse as _TR
            return _TR(
                protocol="kubelet", ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活: 尝试 /pods.
        Kubelet 10250 是 HTTPS 自签名, httpx verify=False 才能访问.
        """
        closed = self._check_closed(target)
        if closed:
            return closed
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        scheme = "https" if port == self.DEFAULT_PORT else "http"
        url = f"{scheme}://{host}:{port}/pods"

        resp = await self._http.probe(url, **kw)
        resp.protocol = "kubelet"
        resp.target = target

        # Kubelet /pods 返回 JSON, 含 "items" 和 "kind":"PodList"
        if resp.ok and ('"kind":"PodList"' in resp.text
                        or '"items":[' in resp.text
                        or 'kube-proxy' in resp.text):
            resp.banner = "kubelet"
            resp.tags = ["KUBELET", "UNAUTH-OK"]
            resp.anomalies.append("pods-listed")
        elif resp.status == 403:
            # 403 = 有 Kubelet 但需认证 (安全配置)
            resp.banner = "kubelet(auth-required)"
            resp.tags = ["KUBELET", "AUTH-REQUIRED"]
            resp.anomalies.append("auth-required")
        elif resp.status == 401:
            resp.banner = "kubelet(auth-required)"
            resp.tags = ["KUBELET", "AUTH-REQUIRED"]
            resp.anomalies.append("auth-required")
        return resp

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """发送任意 Kubelet API 请求. req.target=host:port, payload=path."""
        closed = self._check_closed(req.target)
        if closed:
            return closed
        host, port = split_host_port(req.target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        scheme = "https" if port == self.DEFAULT_PORT else "http"
        path = req.payload or "/"
        if not path.startswith("/"):
            path = "/" + path
        url = f"{scheme}://{host}:{port}{path}"
        method = req.meta.get("method", "GET")

        http_req = TrafficRequest(
            protocol="http", target=url,
            headers=req.headers,
            meta={"method": method},
        )
        resp = await self._http.send(http_req, **kw)
        resp.protocol = "kubelet"
        resp.target = req.target
        return resp

    # ============================================================
    #                  check_unauth
    # ============================================================

    async def check_unauth(self, target: str, timeout: Optional[float] = None
                           ) -> TrafficResponse:
        """
        一键 Kubelet 未授权检测.

        流程:
            1. GET /pods (10250) -> 确认未授权
            2. 若 10250 需认证, 尝试 10255 (只读端口, 信息泄露)
            3. 检测 /runningpods 或 /metrics (确认可执行命令的可能)
        """
        t = timeout or self.timeout

        # 1. /pods on 10250
        pods_resp = await self.probe(target, timeout=t)
        if "UNAUTH-OK" in pods_resp.tags:
            # 10250 完全未授权 = RCE
            pod_count = 0
            try:
                data = _json.loads(pods_resp.text)
                pod_count = len(data.get("items", []))
            except Exception:
                pass

            tags = ["KUBELET", "UNAUTH-CONFIRMED", "HIGH-VALUE"]
            anomalies = [
                "unauth-access",
                "pods-listed",
                f"pods:{pod_count}",
                "rce-possible",  # POST /run 可以执行命令
                "secrets-may-leak",  # Pod 环境变量含密钥
            ]
            return TrafficResponse(
                protocol="kubelet",
                ok=True,
                status=200,
                text=pods_resp.text[:1500],
                banner="kubelet",
                time_ms=pods_resp.time_ms,
                target=target,
                tags=tags,
                anomalies=anomalies,
            )

        if "AUTH-REQUIRED" in pods_resp.tags:
            # 10250 需认证 - 尝试 10255 只读端口
            host, port = split_host_port(target, self.DEFAULT_PORT)
            readonly_target = f"{host}:{self.READONLY_PORT}"
            ro_resp = await self._probe_readonly(readonly_target, timeout=t)
            if ro_resp.ok and "UNAUTH-OK" in ro_resp.tags:
                return TrafficResponse(
                    protocol="kubelet",
                    ok=True,
                    status=200,
                    text=ro_resp.text[:1000],
                    banner="kubelet(readonly)",
                    target=target,
                    tags=["KUBELET", "READONLY-LEAK", "MEDIUM-VALUE"],
                    anomalies=["readonly-port-open", "info-leak",
                               "no-rce-but-recon"],
                    time_ms=ro_resp.time_ms,
                )
            # 两个端口都安全
            return TrafficResponse(
                protocol="kubelet", ok=True, status=1,
                target=target, banner="kubelet(secure)",
                tags=["KUBELET", "SECURE"],
                anomalies=["auth-required", "secure-config"],
                time_ms=pods_resp.time_ms,
            )

        # 不可达
        return pods_resp

    async def _probe_readonly(self, target: str, timeout: float) -> TrafficResponse:
        """探测 10255 只读端口 (HTTP, /pods)."""
        host, port = split_host_port(target)
        url = f"http://{host}:{port}/pods"
        resp = await self._http.probe(url, timeout=timeout)
        resp.protocol = "kubelet"
        resp.target = target
        if resp.ok and ('"items":[' in resp.text or 'kube-proxy' in resp.text):
            resp.banner = "kubelet(readonly)"
            resp.tags = ["KUBELET", "UNAUTH-OK"]
        return resp

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        if self._closed:
            return
        self._closed = True
        await self._http.close()
