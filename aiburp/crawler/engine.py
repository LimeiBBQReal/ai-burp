"""
Crawler Engine — LLM 驱动递归爬虫, 集成 HTML/JS 解析 + 字典定向探测
"""

import asyncio
import time
import hashlib
from urllib.parse import urlparse, urlunparse, urljoin
from typing import List, Optional, Dict, Set, Callable
from dataclasses import dataclass, field

from ..traffic.asset_schema import AssetInventory, AssetItem
from .extractors.html_parser import html_extract
from .extractors.js_extractor import js_extract
from .extractors.sitemap import parse_sitemap, parse_robots
from .llm_driver import llm_analyze_page, llm_analyze_js


@dataclass(order=True)
class CrawlTask:
    priority: int = 10
    url: str = field(default="", compare=False)
    depth: int = field(default=0, compare=False)
    source: str = field(default="seed", compare=False)
    reason: str = field(default="", compare=False)


class CrawlerEngine:
    """爬虫调度引擎"""

    def __init__(
        self,
        base_url: str,
        session=None,
        llm_client=None,
        max_depth: int = 2,
        max_urls: int = 150,
        dict_paths: Optional[List[str]] = None,
        concurrency: int = 10,
        request_delay: float = 0.2,
        proxy_manager=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.llm_client = llm_client
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.dict_paths = dict_paths or []
        self.concurrency = concurrency
        self.request_delay = request_delay
        self.proxy_manager = proxy_manager

        self._queue: List[CrawlTask] = []
        self._visited: Set[str] = set()
        self._fetched_count = 0  # 实际已处理的 URL 数量 (用于预算)
        self._sitemap_pending: List[str] = []  # sitemap URL 延迟处理
        self._sem = asyncio.Semaphore(concurrency)
        self._inventory = AssetInventory(target=self.base_url)

        # 解析 base_url 用于同域判断
        parsed = urlparse(self.base_url)
        self._base_netloc = parsed.netloc
        self._base_scheme = parsed.scheme or "https"

    def _normalize_url(self, url: str) -> str:
        """URL 规范化: 去锚点, 去尾部斜杠 (除根路径), 排序 query"""
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme or self._base_scheme
            netloc = parsed.netloc or self._base_netloc
            path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
            query = parsed.query
            # 排序 query 参数
            if query:
                params = sorted(query.split("&"))
                query = "&".join(params)
            return urlunparse((scheme, netloc, path, parsed.params, query, ""))
        except Exception:
            return url

    def _is_same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self._base_netloc
        except Exception:
            return False

    def _get_content_type(self, resp) -> str:
        ct = (resp.headers.get("Content-Type", "") or "").lower()
        if "text/html" in ct:
            return "html"
        if "javascript" in ct or "application/x-javascript" in ct or "ecmascript" in ct:
            return "js"
        if "application/json" in ct:
            return "json"
        if "text/xml" in ct or "application/xml" in ct:
            return "xml"
        if "text/plain" in ct:
            return "text"
        return "other"

    def _is_js_by_url(self, url: str) -> bool:
        return any(url.lower().endswith(ext) for ext in (".js", ".mjs", ".cjs"))

    def _is_spa_bundle(self, url: str) -> bool:
        lower = url.lower()
        return any(k in lower for k in ("main.", "bundle.", "app.", "vendor.", "chunk-", "index.")) and self._is_js_by_url(url)

    def _should_llm_analyze(self, content: str, source_url: str) -> bool:
        if not self.llm_client:
            return False
        if self._is_spa_bundle(source_url):
            return True
        if len(content) > 5000 and "api" in content.lower():
            return True
        return False

    def enqueue(self, url: str, depth: int = 0, priority: int = 10,
                source: str = "discovered", reason: str = ""):
        norm = self._normalize_url(url)
        if norm in self._visited:
            return

        # sitemap 来源的 URL 延迟到 Phase 6 处理
        if source in ("sitemap", "crawler_sitemap") and priority >= 15:
            if norm not in self._sitemap_pending:
                self._sitemap_pending.append(norm)
            return

        self._visited.add(norm)
        self._queue.append(CrawlTask(
            priority=priority, url=norm, depth=depth,
            source=source, reason=reason,
        ))

    def _drain_sitemaps(self, budget: int):
        """把 sitemap URL 从延迟队列注入主队列 (只在 Phase 6 调用)"""
        if budget <= 0:
            return
        count = 0
        for url in self._sitemap_pending:
            if count >= budget:
                break
            # 检查 URL 是否已被访问过（通过 normalize 后的 URL 判断）
            norm_url = self._normalize_url(url)
            if norm_url not in self._visited:
                self._visited.add(norm_url)
                self._queue.append(CrawlTask(
                    priority=10, url=norm_url, depth=1,
                    source="crawler_sitemap", reason="sitemap deferred",
                ))
                count += 1
        self._sitemap_pending = self._sitemap_pending[count:]

    def _sort_queue(self):
        self._queue.sort(key=lambda t: (-t.priority, t.depth))

    async def _fetch(self, url: str) -> Optional[object]:
        """使用 session 或临时 requests 获取 URL (在 executor 中运行避免阻塞事件循环)"""
        loop = asyncio.get_running_loop()
        self._fetched_count += 1

        if self.session:
            try:
                proxy = None
                if self.proxy_manager:
                    proxy = self.proxy_manager.get_proxy()
                    if proxy:
                        self.session.proxies = {"http": proxy, "https": proxy}
                resp = await loop.run_in_executor(
                    None, lambda: self.session.get(url, timeout=10, allow_redirects=True)
                )
                if self.request_delay > 0:
                    await asyncio.sleep(self.request_delay)
                return resp
            except Exception:
                return None
        else:
            try:
                import requests as _req
                proxies = None
                if self.proxy_manager:
                    p = self.proxy_manager.get_proxy()
                    if p:
                        proxies = {"http": p, "https": p}

                def _do_get():
                    return _req.get(url, timeout=10, allow_redirects=True,
                                    proxies=proxies, verify=False)

                resp = await loop.run_in_executor(None, _do_get)
                if self.request_delay > 0:
                    await asyncio.sleep(self.request_delay)
                return resp
            except Exception:
                return None

    def _add_to_inventory(self, item_type: str, value: str, source: str,
                          confidence: float = 0.8, metadata: dict = None,
                          tags: list = None):
        self._inventory.add(AssetItem(
            type=item_type, value=value, source=source,
            confidence=confidence,
            metadata=metadata or {},
            tags=tags or [],
        ))

    async def _process_html(self, resp, task: CrawlTask):
        """处理 HTML 响应"""
        html = resp.text
        result = html_extract(html, task.url)

        # 发现的新 URL 入队列 (同域)
        for link in result.all_urls:
            if self._is_same_origin(link):
                self.enqueue(link, task.depth + 1, priority=8,
                             source="html_link", reason="from HTML href")

        # JS 文件高优入队列
        for js_url in result.scripts:
            if self._is_same_origin(js_url):
                self.enqueue(js_url, task.depth + 1, priority=15,
                             source="html_script", reason="JS file reference")
            else:
                self.enqueue(js_url, task.depth + 1, priority=5,
                             source="html_script_external", reason="external JS")

        # API 端点从内联 JS 提取
        for api_url in result.api_patterns:
            self._add_to_inventory(
                "url", api_url, "crawler_html_inline_js",
                confidence=0.7, tags=["api_discovered"],
            )

        # 表单 -> 提取 action
        for form in result.forms:
            if form.action and self._is_same_origin(form.action):
                self._add_to_inventory(
                    "url", form.action, "crawler_html_form",
                    confidence=0.8, tags=["form", f"method:{form.method}"],
                    metadata={"inputs": form.inputs, "method": form.method},
                )

        # LLM 深度分析首页 (用 to_thread 避免阻塞事件循环)
        if task.depth == 0 and self.llm_client:
            loop = asyncio.get_running_loop()
            llm_result = await loop.run_in_executor(
                None, llm_analyze_page, html, task.url, self.llm_client
            )
            if llm_result:
                for ep in llm_result.get("endpoints", []):
                    self._add_to_inventory(
                        "url", ep.get("path", ""), "crawler_llm_page",
                        confidence=0.6 if ep.get("confidence") == "medium" else 0.8,
                        tags=["llm_discovered", ep.get("method", "GET")],
                        metadata={"reason": ep.get("reason", "")},
                    )
                for route in llm_result.get("priority_routes", []):
                    abs_route = urljoin(task.url, route)
                    if self._is_same_origin(abs_route):
                        self.enqueue(abs_route, task.depth + 1, priority=16,
                                     source="llm_priority", reason=route)

    async def _process_js(self, js_content: str, task: CrawlTask):
        """处理 JS 响应"""
        result = js_extract(js_content, task.url)

        for ep in result.all_endpoints:
            self._add_to_inventory(
                "url", ep, "crawler_js_extract",
                confidence=0.8, tags=["api_discovered"],
            )

        for ws in result.websocket_urls:
            self._add_to_inventory(
                "url", ws, "crawler_js_ws",
                confidence=0.9, tags=["websocket"],
            )

        # LLM 深度分析 (仅对复杂 JS, 用 to_thread 避免阻塞)
        if self._should_llm_analyze(js_content, task.url):
            loop = asyncio.get_running_loop()
            llm_result = await loop.run_in_executor(
                None, llm_analyze_js, js_content, task.url, self.llm_client
            )
            if llm_result:
                for ep in llm_result.get("endpoints", []):
                    self._add_to_inventory(
                        "url", ep.get("path", ""), "crawler_llm_js",
                        confidence=0.7, tags=["llm_discovered"],
                        metadata={"source": ep.get("source", "")},
                    )

    async def _process_response(self, resp, task: CrawlTask):
        """根据 Content-Type 分发处理"""
        if not resp:
            return

        content_type = self._get_content_type(resp)

        if content_type == "html":
            await self._process_html(resp, task)
        elif content_type == "js" or self._is_js_by_url(task.url):
            await self._process_js(resp.text, task)
        elif content_type == "json":
            self._add_to_inventory(
                "url", task.url, "crawler_json",
                confidence=0.9, tags=["json_endpoint"],
            )
        elif content_type == "xml":
            text = resp.text
            if "<urlset" in text or "<sitemapindex" in text.lower():
                sitemap_urls = parse_sitemap(text, task.url)
                for su in sitemap_urls:
                    if self._is_same_origin(su):
                        self.enqueue(su, task.depth + 1, priority=18,
                                     source="sitemap", reason="from sitemap.xml")
                    self._add_to_inventory(
                        "url", su, "crawler_sitemap",
                        confidence=0.9, tags=["sitemap"],
                    )

    async def _dict_probe(self):
        """字典定向探测 — 对已知路径的子路径递归"""
        discovered_dirs = set()
        for item in self._inventory.items:
            if item.type in ("directory", "url") and "dir" in item.tags:
                discovered_dirs.add(item.value.rstrip("/"))

        if not self.dict_paths:
            return

        for base_dir in discovered_dirs:
            for dict_path in self.dict_paths[:100]:  # 最多 100 条
                test_url = f"{base_dir}{dict_path}"
                self.enqueue(test_url, depth=2, priority=11,
                             source="dict_probe", reason=f"dict:{dict_path}")

        # 对根路径用全量字典
        for dict_path in self.dict_paths[:200]:
            test_url = f"{self.base_url}{dict_path}"
            self.enqueue(test_url, depth=1, priority=12,
                         source="dict_probe_root", reason=f"dict:{dict_path}")

    async def _probe_seed(self):
        """探测种子 URL: robots.txt / sitemap.xml"""
        seeds = [
            f"{self.base_url}/robots.txt",
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            self.base_url,
        ]
        for url in seeds:
            self.enqueue(url, depth=0, priority=20,
                         source="seed", reason="seed probe")

    def _collected_urls_from_sitemap(self) -> int:
        """统计已收集的 sitemap/seed 来源 URL 数量"""
        return sum(
            1 for item in self._inventory.items
            if item.source in ("crawler_sitemap", "seed")
        )

    async def run(self) -> AssetInventory:
        """运行爬虫

        流程:
          Phase 1: 种子探测 (首页 / robots.txt / sitemap.xml)
                    sitemap URL 自动转入 _sitemap_pending, 不占预算
          Phase 2: 首页和 JS 深度处理 (depth 0-1), 最多处理 max_urls // 3 个
          Phase 3: 字典定向探测 (dict_probe), 入队
          Phase 4: 处理字典探测发现的 URL (第二轮), 最多 200 个
          Phase 5: 第三轮扫描 (对已有发现再次探测)
          Phase 6: 把 _sitemap_pending 注入队列并用剩余预算处理
        """
        # Phase 1: 种子探测
        await self._probe_seed()

        # Phase 2: 首页 + JS 深度处理 (depth <= 1)
        primary_budget = max(20, self.max_urls // 3)
        while self._queue and self._fetched_count < primary_budget:
            self._sort_queue()
            task = self._queue.pop(0)
            if task.depth > 1 and self._fetched_count > 5:
                self._queue.insert(0, task)
                break
            if task.depth > self.max_depth:
                continue
            async with self._sem:
                resp = await self._fetch(task.url)
                await self._process_response(resp, task)

        # Phase 3: 字典定向探测
        await self._dict_probe()

        # Phase 4: 处理字典探测入队的新 URL (第二轮)
        second_round_max = min(200, len(self.dict_paths) * 2) if self.dict_paths else 100
        second_round = 0
        while self._queue and second_round < second_round_max and self._fetched_count < self.max_urls:
            self._sort_queue()
            task = self._queue.pop(0)
            async with self._sem:
                resp = await self._fetch(task.url)
                await self._process_response(resp, task)
            second_round += 1

        # Phase 5: 第三轮 — 对非 sitemap 发现再次字典探测
        discovered_new = [
            item.value for item in self._inventory.items
            if item.source not in ("crawler_sitemap", "seed", "sitemap")
            and item.type in ("url", "directory")
        ]
        if discovered_new:
            for url in discovered_new[:20]:
                for dict_path in (self.dict_paths or [])[:30]:
                    test_url = f"{url.rstrip('/')}{dict_path}"
                    if test_url not in self._visited:
                        self.enqueue(test_url, depth=3, priority=4,
                                     source="dict_probe_tertiary", reason=f"3rd:{dict_path}")
            third_round = 0
            while self._queue and third_round < 100 and self._fetched_count < self.max_urls + 100:
                self._sort_queue()
                task = self._queue.pop(0)
                async with self._sem:
                    resp = await self._fetch(task.url)
                    await self._process_response(resp, task)
                third_round += 1

        # Phase 6: 把 sitemap 注入队列并用剩余预算处理
        remaining_budget = self.max_urls + 200 - self._fetched_count
        if remaining_budget > 0:
            self._drain_sitemaps(remaining_budget)
            sitemap_handled = 0
            while self._queue and sitemap_handled < remaining_budget:
                self._sort_queue()
                task = self._queue.pop(0)
                if self._fetched_count > self.max_urls + 200:
                    break
                async with self._sem:
                    resp = await self._fetch(task.url)
                    await self._process_response(resp, task)
                sitemap_handled += 1

        return self._inventory
