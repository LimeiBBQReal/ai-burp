"""
V3 ↔ V4 桥接层.

让 V3 的同步模块 (DirFuzzer / ParamDiscoverer) 复用 V4 的配置,
但用标准 requests 库 (纯同步, 无 async/loop 问题).

设计:
    - V3 的 DirFuzzer 需要 burp.get() / burp.fuzz() 同步接口
    - V4 的 AsyncBurp 是 async 的, 跨 loop 用会协程泄漏
    - 桥接层用 SimpleBurp (基于 requests) 提供 V3 兼容接口
    - 配置 (timeout/delay/proxy) 从 V4 engine 读取, 保持一致
    - 不共享 httpx 连接池 (async/sync 不互通), 但共享配置

性能权衡:
    独立 requests.Session vs httpx.AsyncClient
    - 短期: 多一个 TCP 连接 (可接受)
    - 长期: V3 模块全部 async 化后可以共享 (未来工作)
"""

import time
import requests as _requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class SimpleResponse:
    """V3 兼容的 Response (Subset of aiburp.Response)"""
    ok: bool = True
    status: int = 0
    length: int = 0
    time_ms: float = 0
    body: str = ""
    headers: dict = None
    url: str = ""
    method: str = "GET"
    error: str = ""
    blocked: bool = False
    reflects: bool = False

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

    @property
    def text(self):
        return self.body


class SimpleBurp:
    """
    V3 兼容的同步 HTTP 客户端 (基于 requests).

    提供 DirFuzzer/ParamDiscoverer 需要的 .get()/.post()/.send() 接口,
    但内部用 requests (纯同步), 避免 AsyncBurp 的跨 loop 协程泄漏.

    用法:
        burp = SimpleBurp(timeout=5, delay=0)
        r = burp.get("http://target.com/")
        print(r.status, r.length)
    """

    def __init__(self, delay: float = 0.0, timeout: float = 10.0,
                 concurrency: int = 5, proxy: str = None):
        self.delay = delay
        self.timeout = timeout
        self._session = _requests.Session()
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
        self._session.verify = False  # 红队场景不校验证书
        # History 兼容 (DirFuzzer/VulnScanner 可能访问)
        self.history = []
        # KB 兼容 (V3 模块可能访问)
        from types import SimpleNamespace
        self.kb = SimpleNamespace(add=lambda *a, **kw: None, get=lambda *a, **kw: [])

    def get(self, url: str, **kw) -> SimpleResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> SimpleResponse:
        return self.request("POST", url, **kw)

    def send(self, method: str, url: str, **kw) -> SimpleResponse:
        return self.request(method, url, **kw)

    def request(self, method: str, url: str, params: Dict = None,
                headers: Dict = None, data: Any = None, json: Dict = None,
                check: str = None, **kw) -> SimpleResponse:
        """发送 HTTP 请求"""
        if self.delay > 0:
            time.sleep(self.delay)

        t0 = time.monotonic()
        try:
            resp = self._session.request(
                method, url,
                params=params, headers=headers,
                data=data, json=json,
                timeout=self.timeout,
                allow_redirects=False,
            )
            elapsed = (time.monotonic() - t0) * 1000
            body = resp.text
            r = SimpleResponse(
                ok=True,
                status=resp.status_code,
                length=len(resp.content),
                time_ms=elapsed,
                body=body,
                headers=dict(resp.headers),
                url=url,
                method=method,
            )
            if check and check in body:
                r.reflects = True
            self.history.append(r)
            return r
        except _requests.exceptions.Timeout:
            return SimpleResponse(ok=False, url=url, method=method,
                                  error="timeout", time_ms=self.timeout * 1000)
        except Exception as e:
            return SimpleResponse(ok=False, url=url, method=method,
                                  error=str(e)[:100])

    def fuzz(self, url: str, payloads: List[str], marker: str = "§") -> List[SimpleResponse]:
        """批量 fuzz (V3 兼容接口)"""
        results = []
        for p in payloads:
            test_url = url.replace(marker, str(p))
            results.append(self.get(test_url, check=str(p)))
        return results

    def close(self):
        self._session.close()


def create_bridge_burp(engine, delay: float = 0.0):
    """
    从 V4 TrafficEngine 创建 V3 兼容的同步 HTTP 客户端.

    用 SimpleBurp (requests) 而非 SyncBurp (async), 避免跨 loop 协程泄漏.
    配置从 V4 engine 读取, 保持一致.
    如果 engine 有 proxy_manager 且已启用, 自动注入代理.

    Args:
        engine: V4 TrafficEngine 实例
        delay:  请求延迟

    Returns:
        SimpleBurp 实例 (V3 兼容接口)
    """
    # 从 V4 读配置
    try:
        http_adapter = engine.adapter("http")
        async_burp = http_adapter._burp
        timeout = getattr(async_burp, "timeout", 10.0)
    except Exception:
        timeout = 10.0

    # 代理支持
    proxy = None
    pm = getattr(engine, "proxy_manager", None)
    if pm and pm.enabled:
        proxy = pm.get_proxy()

    return SimpleBurp(delay=delay, timeout=timeout, proxy=proxy)
