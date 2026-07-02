"""LLM 驱动 Crawler: 递归发现 JS API / SPA 路由 / 隐藏接口"""

from .engine import CrawlerEngine, CrawlTask
from .extractors.html_parser import html_extract, HTMLExtractResult
from .extractors.js_extractor import js_extract, JSExtractResult

CRAWLER_VERSION = "1.0.0"

__all__ = [
    "CrawlerEngine",
    "CrawlTask",
    "html_extract",
    "HTMLExtractResult",
    "js_extract",
    "JSExtractResult",
]
