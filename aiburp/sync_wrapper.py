"""
AI-Burp V3 同步包装器

为不熟悉 async/await 的用户提供同步 API
内部使用 asyncio.run() 调用异步方法
"""

import asyncio
from typing import Dict, Any, List, Optional
from .burp import AsyncBurp, AsyncSmartBurp, Response, Decision


# 全局 event loop 管理
_global_loop = None

def _get_or_create_loop():
    """获取或创建全局 event loop"""
    global _global_loop
    if _global_loop is None or _global_loop.is_closed():
        _global_loop = asyncio.new_event_loop()
    return _global_loop


def _run_sync(coro):
    """安全运行协程，复用 event loop"""
    try:
        asyncio.get_running_loop()
        # 在 running loop 的上下文里 (不应该直接调 _run_sync)
        # 用独立线程的 asyncio.run
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        # 没有运行中的 loop - 正常用全局 loop
        pass

    loop = _get_or_create_loop()
    return loop.run_until_complete(coro)


class SyncBurp:
    """
    同步版 AsyncBurp 包装器
    
    用法:
        burp = SyncBurp()
        r = burp.get("https://httpbin.org/get")
        print(r)
        
        results = burp.fuzz("https://target.com?id=§", ["'", '"', "1 OR 1=1"])
        for r in results:
            print(r)
    """
    
    def __init__(
        self,
        project: str = "default",
        delay: float = 0.5,
        timeout: float = 30.0,
        concurrency: int = 5,
        proxy: str = None
    ):
        self.delay = delay
        self._async_burp = AsyncBurp(
            project=project,
            delay=delay,
            timeout=timeout,
            concurrency=concurrency,
            proxy=proxy
        )
    
    def _run(self, coro):
        """运行协程"""
        return _run_sync(coro)
    
    def request(
        self,
        method: str,
        url: str,
        params: Dict = None,
        headers: Dict = None,
        data: Any = None,
        json: Dict = None,
        check: str = None,
        **kwargs
    ) -> Response:
        """发送请求"""
        return self._run(
            self._async_burp.request(
                method, url, params=params, headers=headers,
                data=data, json_data=json, check=check, **kwargs
            )
        )
    
    def send(self, method: str, url: str, **kwargs) -> Response:
        """发送请求 (别名)"""
        return self._run(self._async_burp.send(method, url, **kwargs))
    
    def get(self, url: str, params: Dict = None, **kwargs) -> Response:
        """GET 请求"""
        return self._run(self._async_burp.get(url, params=params, **kwargs))
    
    def post(self, url: str, data=None, json: Dict = None, **kwargs) -> Response:
        """POST 请求"""
        return self._run(self._async_burp.post(url, data=data, json=json, **kwargs))
    
    def fuzz(
        self,
        url: str,
        payloads: List[str],
        marker: str = "§"
    ) -> List[Response]:
        """批量 Fuzz"""
        return self._run(self._async_burp.fuzz(url, payloads, marker))
    
    @property
    def history(self) -> List[Response]:
        """请求历史"""
        return self._async_burp.history
    
    @property
    def kb(self):
        """知识库"""
        return self._async_burp.kb
    
    def close(self):
        """关闭客户端"""
        try:
            self._run(self._async_burp.close())
        except RuntimeError:
            pass  # Event loop 已关闭，忽略
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


class SyncSmartBurp(SyncBurp):
    """
    同步版 AsyncSmartBurp 包装器
    
    用法:
        burp = SyncSmartBurp()
        decision = burp.smart_scan("https://target.com/api", "id", "1")
        print(decision)
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._async_burp = AsyncSmartBurp(**kwargs)
    
    def smart_scan(self, url: str, param: str, value: str) -> Decision:
        """智能扫描"""
        return self._run(self._async_burp.smart_scan(url, param, value))
