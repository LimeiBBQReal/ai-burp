"""
aiburp/deep_mining/asset_extractor.py
通用资源抽取器 — 从任意 body 抽 endpoint.

支持:
  - JS:     inline + 同源 <script src>
  - CSS:    url(...) 函数 (静态资源, 非动态页面)
  - HTML-like: 嵌入在 PHP/JSP/ASPX 等服务端模板输出里的 HTML
  - 通用:   任意 text/* body 里的 /path 字符串

设计原则:
  - CSS 是静态资源, 不是动态页面
  - PHP/JSP/ASPX 等后端模板输出统一走 BeautifulSoup (不写 PHP 语法解析器)
  - 优先复用 aiburp.crawler.extractors 的成熟实现
"""
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin


_CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)")
_PATH_RE = re.compile(r"""['"\`](/[a-zA-Z0-9_\-./{}?=&%:+]+)['"\`]""")
_HTML_TAGS = ("<!doctype", "<html", "<head", "<body", "<div", "<script", "<form")


def _looks_like_html(body: str) -> bool:
    head = (body or "")[:500].lower().lstrip()
    return head.startswith(_HTML_TAGS)


def _abs_url(href: str, base: str) -> str:
    if not href or href.startswith("#") or href.startswith("javascript:"):
        return ""
    if href.startswith("http://") or href.startswith("https://"):
        return href
    if href.startswith("//"):
        scheme = urlparse(base).scheme or "https"
        return f"{scheme}:{href}"
    if base:
        return urljoin(base, href)
    return href


class AssetExtractor:
    """
    从资源 body 里抽取 endpoint / 资产路径.

    用法:
        ext = AssetExtractor()
        paths = ext.extract(body, content_type="text/html", url="https://x.com/")
    """

    def extract(self, body: str, content_type: str = "",
                url: str = "") -> List[str]:
        """
        根据 content-type 自动选择 extractor.
        返回绝对路径列表 (去重 + 排序).
        """
        if not body:
            return []

        ct = (content_type or "").lower()
        url_lower = (url or "").lower()

        if "css" in ct or url_lower.endswith(".css"):
            paths = self._from_css(body)
        elif "html" in ct or "xml" in ct or _looks_like_html(body):
            paths = self._from_html(body, url)
        elif "javascript" in ct or url_lower.endswith((".js", ".mjs", ".cjs")):
            paths = self._from_js(body, url)
        else:
            paths = self._from_generic(body)

        seen = set()
        out = []
        for p in paths:
            abs_p = _abs_url(p, url) if not p.startswith(("http://", "https://")) else p
            if abs_p and abs_p not in seen:
                seen.add(abs_p)
                out.append(abs_p)
        return out

    def _from_css(self, body: str) -> List[str]:
        """CSS: url(...) 里的路径."""
        return [m.group(1) for m in _CSS_URL_RE.finditer(body or "")]

    def _from_html(self, body: str, base: str) -> List[str]:
        """
        HTML (含 PHP/JSP/ASPX 等服务端模板输出):
        复用 BeautifulSoup, 不写后端语法解析.
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return self._from_generic(body)

        soup = BeautifulSoup(body or "", "html.parser")
        paths = set()
        for tag, attr in [
            ("a", "href"), ("link", "href"), ("script", "src"),
            ("img", "src"), ("iframe", "src"), ("form", "action"),
            ("source", "src"), ("track", "src"),
        ]:
            for el in soup.find_all(tag):
                v = el.get(attr)
                if v and v.startswith("/"):
                    paths.add(v)
        return list(paths)

    def _from_js(self, body: str, base: str) -> List[str]:
        """JS: 优先复用 crawler 的成熟 extractor, 再补正则."""
        try:
            from aiburp.crawler.extractors.js_extractor import js_extract

            r = js_extract(body or "", base)
            return list({u for u in r.all_endpoints if u})
        except Exception:
            return [m.group(1) for m in _PATH_RE.finditer(body or "")]

    def _from_generic(self, body: str) -> List[str]:
        """通用: 任何 body 里的 /path 字符串."""
        return list({m.group(1) for m in _PATH_RE.finditer(body or "")})


def extract_endpoints(body: str, content_type: str = "",
                      url: str = "") -> List[str]:
    """便捷函数: 单次抽取."""
    return AssetExtractor().extract(body, content_type, url)