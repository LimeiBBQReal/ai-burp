"""
高性能异步 Fuzzer - 借鉴 ffuf 设计

核心特性:
1. aiohttp 异步并发 (500+ req/s)
2. FUZZ 占位符支持 (URL/Header/Body 任意位置)
3. 智能过滤 (状态码/大小/行数/正则/时间)
4. 自动校准 (识别"正常"响应)
5. 速率限制 (避免打崩目标)

用法:
    fuzzer = AsyncFuzzer()
    results = await fuzzer.fuzz("https://target.com/FUZZ", wordlist)
    
    # 或同步调用
    results = fuzzer.run("https://target.com/FUZZ", wordlist)
"""

import asyncio
import aiohttp
import time
import re
import random
import string
from typing import List, Dict, Set, Optional, Callable, Union
from dataclasses import dataclass, field
from urllib.parse import urlparse
from enum import Enum


class MatchType(Enum):
    """匹配类型"""
    STATUS = "status"      # 状态码
    SIZE = "size"          # 响应大小
    WORDS = "words"        # 单词数
    LINES = "lines"        # 行数
    TIME = "time"          # 响应时间
    REGEX = "regex"        # 正则匹配


@dataclass
class FuzzResult:
    """Fuzz 结果"""
    input: str              # 输入的 payload
    url: str                # 完整 URL
    status: int = 0         # 状态码
    size: int = 0           # 响应大小
    words: int = 0          # 单词数
    lines: int = 0          # 行数
    time: float = 0.0       # 响应时间 (秒)
    redirect: str = ""      # 重定向 URL
    content_type: str = ""  # Content-Type
    error: str = ""         # 错误信息
    matched: bool = True    # 是否匹配 (通过过滤)
    
    def __str__(self):
        if self.error:
            return f"[ERR] {self.input}: {self.error}"
        return f"[{self.status}] {self.input} [{self.size} bytes, {self.words}W, {self.lines}L, {self.time:.2f}s]"


@dataclass
class FuzzConfig:
    """Fuzz 配置"""
    # 并发
    concurrency: int = 100          # 并发数
    rate_limit: int = 0             # 每秒请求数限制 (0=不限制)
    timeout: int = 10               # 超时 (秒)
    
    # 请求
    method: str = "GET"             # HTTP 方法
    headers: Dict[str, str] = field(default_factory=dict)
    data: str = ""                  # POST 数据
    follow_redirects: bool = False  # 跟随重定向
    
    # 匹配器 (保留符合条件的)
    match_status: List[int] = field(default_factory=lambda: [200, 204, 301, 302, 307, 401, 403])
    match_size: Optional[tuple] = None   # (min, max) 或 None
    match_regex: str = ""           # 正则匹配
    
    # 过滤器 (排除符合条件的)
    filter_status: List[int] = field(default_factory=list)
    filter_size: Optional[int] = None    # 精确大小
    filter_size_range: Optional[tuple] = None  # (min, max)
    filter_words: Optional[int] = None   # 精确单词数
    filter_lines: Optional[int] = None   # 精确行数
    filter_regex: str = ""          # 正则过滤
    filter_time: Optional[float] = None  # 响应时间阈值
    
    # 自动校准
    auto_calibrate: bool = True     # 自动校准
    calibrate_random: int = 3       # 校准请求数


class AsyncFuzzer:
    """高性能异步 Fuzzer"""
    
    FUZZ_MARKER = "FUZZ"
    
    def __init__(self, config: FuzzConfig = None):
        self.config = config or FuzzConfig()
        self.results: List[FuzzResult] = []
        self.stats = {
            "total": 0,
            "matched": 0,
            "filtered": 0,
            "errors": 0,
            "start_time": 0,
            "end_time": 0,
        }
        self._calibration = None
        self._semaphore = None
        self._rate_limiter = None
    
    def run(self, url: str, wordlist: Union[List[str], str], 
            method: str = None, headers: Dict = None, data: str = None) -> List[FuzzResult]:
        """
        同步运行 Fuzz
        
        Args:
            url: URL 模板 (包含 FUZZ 占位符)
            wordlist: 字典列表或文件路径
            method: HTTP 方法
            headers: 自定义头
            data: POST 数据
        """
        return asyncio.run(self.fuzz(url, wordlist, method, headers, data))
    
    async def fuzz(self, url: str, wordlist: Union[List[str], str],
                   method: str = None, headers: Dict = None, data: str = None) -> List[FuzzResult]:
        """
        异步 Fuzz
        """
        # 加载字典
        if isinstance(wordlist, str):
            wordlist = self._load_wordlist(wordlist)
        
        if not wordlist:
            return []
        
        # 更新配置
        if method:
            self.config.method = method
        if headers:
            self.config.headers.update(headers)
        if data:
            self.config.data = data
        
        # 初始化
        self.results = []
        self.stats = {
            "total": len(wordlist),
            "matched": 0,
            "filtered": 0,
            "errors": 0,
            "start_time": time.time(),
            "end_time": 0,
        }
        
        self._semaphore = asyncio.Semaphore(self.config.concurrency)
        
        # 速率限制
        if self.config.rate_limit > 0:
            self._rate_limiter = asyncio.Semaphore(self.config.rate_limit)
        
        # SSL 配置
        ssl_context = False  # 忽略 SSL 验证
        
        connector = aiohttp.TCPConnector(
            limit=self.config.concurrency,
            ssl=ssl_context,
            force_close=False,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        ) as session:
            
            # 自动校准
            if self.config.auto_calibrate:
                await self._calibrate(session, url)
            
            # 创建任务
            tasks = [
                self._fuzz_one(session, url, word)
                for word in wordlist
            ]
            
            # 执行
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.stats["end_time"] = time.time()
        
        return [r for r in self.results if r.matched]
    
    async def _fuzz_one(self, session: aiohttp.ClientSession, 
                        url_template: str, word: str) -> FuzzResult:
        """单个 Fuzz 请求"""
        async with self._semaphore:
            # 速率限制
            if self._rate_limiter:
                async with self._rate_limiter:
                    await asyncio.sleep(1.0 / self.config.rate_limit)
            
            # 跳过以.开头的词条（用于子域名扫描时避免编码错误）
            if word.startswith('.') and self.FUZZ_MARKER in url_template:
                # 检查是否是子域名模式 (FUZZ.domain.com)
                if f"{self.FUZZ_MARKER}." in url_template:
                    result = FuzzResult(input=word, url=url_template.replace(self.FUZZ_MARKER, word))
                    result.error = "skipped (invalid subdomain)"
                    result.matched = False
                    self.results.append(result)
                    self.stats["filtered"] += 1
                    return result
            
            # 替换占位符
            url = url_template.replace(self.FUZZ_MARKER, word)
            headers = {k: v.replace(self.FUZZ_MARKER, word) for k, v in self.config.headers.items()}
            data = self.config.data.replace(self.FUZZ_MARKER, word) if self.config.data else None
            
            result = FuzzResult(input=word, url=url)
            
            try:
                start = time.time()
                
                async with session.request(
                    self.config.method,
                    url,
                    headers=headers,
                    data=data,
                    allow_redirects=self.config.follow_redirects,
                    ssl=False
                ) as resp:
                    result.status = resp.status
                    result.content_type = resp.headers.get("Content-Type", "")
                    
                    # 读取响应
                    body = await resp.text(errors='ignore')
                    result.size = len(body)
                    result.words = len(body.split())
                    result.lines = body.count('\n') + 1
                    result.time = time.time() - start
                    
                    # 重定向
                    if resp.history:
                        result.redirect = str(resp.url)
                    
                    # 应用过滤
                    result.matched = self._apply_filters(result, body)
                    
            except asyncio.TimeoutError:
                result.error = "timeout"
                self.stats["errors"] += 1
            except aiohttp.ClientError as e:
                result.error = str(e)[:50]
                self.stats["errors"] += 1
            except Exception as e:
                result.error = str(e)[:50]
                self.stats["errors"] += 1
            
            self.results.append(result)
            
            if result.matched:
                self.stats["matched"] += 1
            else:
                self.stats["filtered"] += 1
            
            return result
    
    async def _calibrate(self, session: aiohttp.ClientSession, url_template: str):
        """自动校准 - 发送随机请求识别"正常"响应"""
        calibration_results = []
        
        for _ in range(self.config.calibrate_random):
            # 生成随机字符串
            random_word = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            url = url_template.replace(self.FUZZ_MARKER, random_word)
            
            try:
                async with session.request(
                    self.config.method, url,
                    allow_redirects=self.config.follow_redirects,
                    ssl=False
                ) as resp:
                    body = await resp.text(errors='ignore')
                    calibration_results.append({
                        "status": resp.status,
                        "size": len(body),
                        "words": len(body.split()),
                        "lines": body.count('\n') + 1,
                    })
            except:
                pass
        
        if calibration_results:
            # 计算基线
            sizes = [r["size"] for r in calibration_results]
            words = [r["words"] for r in calibration_results]
            lines = [r["lines"] for r in calibration_results]
            
            # 如果响应一致，设置过滤器
            if len(set(sizes)) == 1:
                self.config.filter_size = sizes[0]
            if len(set(words)) == 1:
                self.config.filter_words = words[0]
            if len(set(lines)) == 1:
                self.config.filter_lines = lines[0]
            
            self._calibration = {
                "avg_size": sum(sizes) / len(sizes),
                "avg_words": sum(words) / len(words),
                "avg_lines": sum(lines) / len(lines),
            }
    
    def _apply_filters(self, result: FuzzResult, body: str) -> bool:
        """应用过滤器"""
        # 匹配器 (必须满足)
        if self.config.match_status and result.status not in self.config.match_status:
            return False
        
        if self.config.match_size:
            min_size, max_size = self.config.match_size
            if not (min_size <= result.size <= max_size):
                return False
        
        if self.config.match_regex:
            if not re.search(self.config.match_regex, body):
                return False
        
        # 过滤器 (满足则排除)
        if self.config.filter_status and result.status in self.config.filter_status:
            return False
        
        if self.config.filter_size is not None and result.size == self.config.filter_size:
            return False
        
        if self.config.filter_size_range:
            min_size, max_size = self.config.filter_size_range
            if min_size <= result.size <= max_size:
                return False
        
        if self.config.filter_words is not None and result.words == self.config.filter_words:
            return False
        
        if self.config.filter_lines is not None and result.lines == self.config.filter_lines:
            return False
        
        if self.config.filter_regex and re.search(self.config.filter_regex, body):
            return False
        
        if self.config.filter_time and result.time < self.config.filter_time:
            return False
        
        return True
    
    def _load_wordlist(self, path: str) -> List[str]:
        """加载字典"""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except:
            return []
    
    def report(self) -> str:
        """生成报告"""
        duration = self.stats["end_time"] - self.stats["start_time"]
        rps = self.stats["total"] / duration if duration > 0 else 0
        
        lines = [
            "=" * 60,
            "⚡ Fuzz 报告",
            "=" * 60,
            "",
            f"总请求: {self.stats['total']}",
            f"匹配: {self.stats['matched']}",
            f"过滤: {self.stats['filtered']}",
            f"错误: {self.stats['errors']}",
            f"耗时: {duration:.2f}s",
            f"速度: {rps:.1f} req/s",
            "",
        ]
        
        matched = [r for r in self.results if r.matched]
        if matched:
            lines.append("📋 匹配结果:")
            for r in matched[:100]:
                lines.append(f"  {r}")
            if len(matched) > 100:
                lines.append(f"  ... 还有 {len(matched) - 100} 条")
        else:
            lines.append("未找到匹配结果")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)


# ============================================================
# 便捷函数
# ============================================================

def fuzz_dir(url: str, wordlist: str = "quick", concurrency: int = 100,
             extensions: List[str] = None) -> List[FuzzResult]:
    """
    目录爆破
    
    Args:
        url: 目标 URL (自动添加 /FUZZ)
        wordlist: 字典名称或路径
        concurrency: 并发数
        extensions: 扩展名列表
    """
    import os
    
    # 构建 URL
    if not url.endswith("/"):
        url += "/"
    url += "FUZZ"
    
    # 加载字典
    wordlist_path = _get_wordlist_path(wordlist)
    words = []
    
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith('#'):
                words.append(word)
                # 添加扩展名
                if extensions:
                    for ext in extensions:
                        if not ext.startswith('.'):
                            ext = '.' + ext
                        words.append(word + ext)
    
    config = FuzzConfig(
        concurrency=concurrency,
        match_status=[200, 204, 301, 302, 307, 401, 403, 500],
        auto_calibrate=True
    )
    
    fuzzer = AsyncFuzzer(config)
    return fuzzer.run(url, words)


def fuzz_params(url: str, wordlist: str = "params", concurrency: int = 50) -> List[FuzzResult]:
    """
    参数爆破
    
    Args:
        url: 目标 URL (自动添加 ?FUZZ=test)
    """
    if "?" in url:
        url += "&FUZZ=fuzztest123"
    else:
        url += "?FUZZ=fuzztest123"
    
    wordlist_path = _get_wordlist_path(wordlist)
    
    config = FuzzConfig(
        concurrency=concurrency,
        auto_calibrate=True
    )
    
    fuzzer = AsyncFuzzer(config)
    return fuzzer.run(url, wordlist_path)


def fuzz_vhost(domain: str, wordlist: str = "subdomains", 
               concurrency: int = 100) -> List[FuzzResult]:
    """
    VHost/子域名爆破
    
    Args:
        domain: 目标域名
    """
    url = f"https://{domain}/"
    
    wordlist_path = _get_wordlist_path(wordlist)
    
    config = FuzzConfig(
        concurrency=concurrency,
        headers={"Host": f"FUZZ.{domain}"},
        auto_calibrate=True
    )
    
    fuzzer = AsyncFuzzer(config)
    return fuzzer.run(url, wordlist_path)


def _get_wordlist_path(name: str) -> str:
    """获取字典路径"""
    import os
    
    # 如果是文件路径，直接返回
    if os.path.exists(name):
        return name
    
    # 内置字典 - 在 ai-burp/payloads 目录
    # plugins/fuzzer.py -> plugins -> aiburp -> ai-burp
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    wordlist_dir = os.path.join(base_dir, "payloads", "discovery")
    
    builtin = {
        "quick": "dirs_quick.txt",
        "common": "dirs_common.txt",
        "medium": "dirs_medium.txt",
        "large": "dirs_large.txt",
        "asp": "dirs_asp.txt",
        "sensitive": "dirs_sensitive.txt",
        "params": "params_common.txt",
        "subdomains": "subdomains_top1000.txt",
        "subs": "subdomains_top1000.txt",
    }
    
    if name in builtin:
        path = os.path.join(wordlist_dir, builtin[name])
        if os.path.exists(path):
            return path
        # 如果 medium/large 不存在，回退到 common
        if name in ["medium", "large"]:
            fallback = os.path.join(wordlist_dir, "dirs_common.txt")
            if os.path.exists(fallback):
                print(f"⚠️ 字典 {name} 不存在，使用 common 替代")
                return fallback
    
    # 尝试直接在目录中查找
    path = os.path.join(wordlist_dir, name)
    if os.path.exists(path):
        return path
    
    path = os.path.join(wordlist_dir, name + ".txt")
    if os.path.exists(path):
        return path
    
    raise FileNotFoundError(f"字典不存在: {name}")


# ============================================================
# CLI 入口
# ============================================================

if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python fuzzer.py <url_with_FUZZ> <wordlist>")
        print("  python fuzzer.py https://target.com/FUZZ wordlist.txt")
        print("  python fuzzer.py https://target.com/FUZZ quick")
        print("")
        print("内置字典: quick, common, asp, sensitive, params, subdomains")
        sys.exit(1)
    
    url = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else "quick"
    
    print(f"🚀 开始 Fuzz: {url}")
    print(f"📚 字典: {wordlist}")
    print("")
    
    try:
        wordlist_path = _get_wordlist_path(wordlist)
        fuzzer = AsyncFuzzer(FuzzConfig(concurrency=100, auto_calibrate=True))
        results = fuzzer.run(url, wordlist_path)
        print(fuzzer.report())
    except FileNotFoundError as e:
        print(f"❌ {e}")
    except KeyboardInterrupt:
        print("\n⏹️ 已停止")
