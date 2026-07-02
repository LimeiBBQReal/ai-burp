"""
AI-Burp V3 Stealth Module
反检测与指纹伪装

功能:
1. JA3 指纹随机化 (需要 curl_cffi)
2. 浏览器指纹预设
3. 自适应速率限制
"""

import asyncio
import random
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# ============================================================
#                    浏览器指纹预设
# ============================================================

@dataclass
class BrowserProfile:
    """浏览器指纹配置"""
    name: str
    user_agent: str
    headers: Dict[str, str] = field(default_factory=dict)
    ja3_impersonate: str = ""  # curl_cffi impersonate 参数


# 常见浏览器指纹
BROWSER_PROFILES = {
    "chrome_120": BrowserProfile(
        name="Chrome 120 (Windows)",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
        ja3_impersonate="chrome120"
    ),
    "chrome_119": BrowserProfile(
        name="Chrome 119 (Windows)",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        ja3_impersonate="chrome119"
    ),
    "firefox_121": BrowserProfile(
        name="Firefox 121 (Windows)",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        },
        ja3_impersonate="firefox121"
    ),
    "safari_17": BrowserProfile(
        name="Safari 17 (macOS)",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        ja3_impersonate="safari17_0"
    ),
    "edge_120": BrowserProfile(
        name="Edge 120 (Windows)",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        ja3_impersonate="edge120"
    ),
}


# ============================================================
#                 AdaptiveRateLimiter (自适应限速)
# ============================================================

class AdaptiveRateLimiter:
    """
    自适应速率限制器
    
    功能:
    1. 指数退避 (遇到 429/503 时)
    2. 解析 Retry-After 头
    3. 动态调整请求间隔
    """
    
    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        
        self.current_delay = base_delay
        self.consecutive_errors = 0
        self.last_request_time = 0.0
        
        # 统计
        self.total_requests = 0
        self.blocked_requests = 0
    
    async def wait(self):
        """等待适当时间"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.current_delay:
            await asyncio.sleep(self.current_delay - elapsed)
        self.last_request_time = time.time()
        self.total_requests += 1
    
    def on_success(self):
        """请求成功，逐步恢复"""
        self.consecutive_errors = 0
        # 缓慢恢复到基础延迟
        self.current_delay = max(self.base_delay, self.current_delay * 0.9)
    
    def on_rate_limit(self, retry_after: Optional[int] = None):
        """
        遇到速率限制
        
        Args:
            retry_after: Retry-After 头的值 (秒)
        """
        self.consecutive_errors += 1
        self.blocked_requests += 1
        
        if retry_after:
            self.current_delay = min(retry_after, self.max_delay)
        else:
            # 指数退避
            self.current_delay = min(
                self.current_delay * self.backoff_factor,
                self.max_delay
            )
        
        print(f"⚠️ Rate limited! Delay increased to {self.current_delay:.1f}s")
    
    def parse_retry_after(self, headers: Dict[str, str]) -> Optional[int]:
        """解析 Retry-After 头"""
        retry_after = headers.get("Retry-After") or headers.get("retry-after")
        if retry_after:
            try:
                return int(retry_after)
            except ValueError:
                # 可能是日期格式，简单处理
                return 60
        return None
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": self.blocked_requests / max(1, self.total_requests),
            "current_delay": self.current_delay,
        }


# ============================================================
#                    StealthClient (隐身客户端)
# ============================================================

class StealthClient:
    """
    隐身 HTTP 客户端
    
    特性:
    1. JA3 指纹伪装 (需要 curl_cffi)
    2. 浏览器指纹轮换
    3. 自适应速率限制
    
    用法:
        client = StealthClient(profile="chrome_120")
        r = await client.get("https://target.com")
        
        # 随机指纹
        client = StealthClient(profile="random")
    """
    
    def __init__(
        self,
        profile: str = "chrome_120",
        rate_limiter: AdaptiveRateLimiter = None,
        proxy: str = None,
        timeout: float = 30.0
    ):
        self.profile_name = profile
        self.proxy = proxy
        self.timeout = timeout
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter()
        
        # 选择浏览器配置
        if profile == "random":
            self.profile = random.choice(list(BROWSER_PROFILES.values()))
        else:
            self.profile = BROWSER_PROFILES.get(profile, BROWSER_PROFILES["chrome_120"])
        
        # 尝试导入 curl_cffi
        self._curl_available = False
        self._client = None
        self._init_client()
    
    def _init_client(self):
        """初始化 HTTP 客户端"""
        try:
            from curl_cffi.requests import AsyncSession
            self._curl_available = True
            self._client = AsyncSession(
                impersonate=self.profile.ja3_impersonate,
                proxy=self.proxy,
                timeout=self.timeout,
                verify=False
            )
            print(f"🛡️ StealthClient: Using curl_cffi with {self.profile.name} fingerprint")
        except ImportError:
            # 回退到 httpx
            import httpx
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                follow_redirects=False,
                proxy=self.proxy
            )
            print(f"⚠️ StealthClient: curl_cffi not available, using httpx (no JA3 spoofing)")
    
    def _get_headers(self, extra_headers: Dict = None) -> Dict[str, str]:
        """获取请求头"""
        headers = {
            "User-Agent": self.profile.user_agent,
            **self.profile.headers
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Dict = None,
        data: Any = None,
        json: Dict = None,
        **kwargs
    ) -> Dict:
        """
        发送请求
        
        Returns:
            Dict with status, body, headers, time_ms
        """
        await self.rate_limiter.wait()
        
        merged_headers = self._get_headers(headers)
        start = time.time()
        
        try:
            if self._curl_available:
                resp = await self._client.request(
                    method, url,
                    headers=merged_headers,
                    data=data,
                    json=json,
                    **kwargs
                )
                result = {
                    "ok": True,
                    "status": resp.status_code,
                    "body": resp.text,
                    "headers": dict(resp.headers),
                    "time_ms": (time.time() - start) * 1000
                }
            else:
                resp = await self._client.request(
                    method, url,
                    headers=merged_headers,
                    data=data,
                    json=json,
                    **kwargs
                )
                result = {
                    "ok": True,
                    "status": resp.status_code,
                    "body": resp.text,
                    "headers": dict(resp.headers),
                    "time_ms": (time.time() - start) * 1000
                }
            
            # 处理速率限制
            if result["status"] in [429, 503]:
                retry_after = self.rate_limiter.parse_retry_after(result["headers"])
                self.rate_limiter.on_rate_limit(retry_after)
            else:
                self.rate_limiter.on_success()
            
            return result
            
        except Exception as e:
            return {
                "ok": False,
                "status": 0,
                "body": "",
                "headers": {},
                "time_ms": (time.time() - start) * 1000,
                "error": str(e)
            }
    
    async def get(self, url: str, **kwargs) -> Dict:
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Dict:
        return await self.request("POST", url, **kwargs)
    
    def rotate_profile(self):
        """轮换浏览器指纹"""
        profiles = list(BROWSER_PROFILES.values())
        self.profile = random.choice([p for p in profiles if p != self.profile])
        
        if self._curl_available:
            # 重新初始化 curl_cffi session
            self._init_client()
        
        print(f"🔄 Rotated to: {self.profile.name}")
    
    async def close(self):
        """关闭客户端"""
        if self._client:
            if self._curl_available:
                await self._client.close()
            else:
                await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()
