"""
HTML Parser — 纯标准库正则提取
不依赖 lxml/bs4，零额外安装
"""

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field


@dataclass
class FormInfo:
    action: str = ""
    method: str = "GET"
    inputs: List[str] = field(default_factory=list)


@dataclass
class HTMLExtractResult:
    links: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    meta_refresh: List[str] = field(default_factory=list)
    api_patterns: List[str] = field(default_factory=list)
    json_blocks: List[str] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)
    all_urls: List[str] = field(default_factory=list)


def _abs_url(href: str, base_url: str) -> str:
    if not href or href.startswith('#') or href.startswith('javascript:'):
        return ''
    return urljoin(base_url, href)


def _is_same_domain(url: str, base_url: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(base_url).netloc or not urlparse(url).netloc
    except Exception:
        return False


_SCRIPT_PAT = re.compile(
    r'<script\b[^>]*?\bsrc\s*=\s*["\']\s*([^"\']+)["\']',
    re.IGNORECASE,
)
_LINK_PAT = re.compile(
    r'<link\b[^>]*?\bhref\s*=\s*["\']\s*([^"\']+)["\']',
    re.IGNORECASE,
)
_A_PAT = re.compile(
    r'<a\b[^>]*?\bhref\s*=\s*["\']\s*([^"\']+)["\']',
    re.IGNORECASE,
)
_FORM_PAT = re.compile(
    r'<form\b[^>]*?\baction\s*=\s*["\']\s*([^"\']+)["\']',
    re.IGNORECASE,
)
_FORM_METHOD_PAT = re.compile(
    r'<form\b[^>]*?\bmethod\s*=\s*["\']?\s*(GET|POST|PUT|DELETE|PATCH)\b',
    re.IGNORECASE,
)
_FORM_INPUT_PAT = re.compile(
    r'<input\b[^>]*?\bname\s*=\s*["\']\s*([^"\']+)["\']',
    re.IGNORECASE,
)
_IFRAME_PAT = re.compile(
    r'<iframe\b[^>]*?\bsrc\s*=\s*["\']\s*([^"\']+)["\']',
    re.IGNORECASE,
)
_COMMENT_PAT = re.compile(
    r'<!--(.*?)-->',
    re.DOTALL,
)
_META_REFRESH_PAT = re.compile(
    r'<meta\b[^>]*?\bhttp-equiv\s*=\s*["\']?\s*refresh\s*["\']?[^>]*?\bcontent\s*=\s*["\']?\s*\d+\s*;?\s*url\s*=\s*([^"\'\s>]+)',
    re.IGNORECASE,
)
_NEXT_DATA_PAT = re.compile(
    r'<script\b[^>]*?\bid\s*=\s*["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)
_JSON_BLOCK_PAT = re.compile(
    r'<script\b[^>]*?\btype\s*=\s*["\']application/json["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)
_DATA_ATTR_PAT = re.compile(
    r'data-\w+\s*=\s*["\'](/[\w/{}[\]@!$&()*+,;=.\-?:%#]*|https?://[^"\']+)["\']',
)
_INLINE_JS_API_PAT = re.compile(
    r"""['"](/?(?:api|v\d+|graphql|rest|internal|private|admin|backend)[/\w\-.%]+)['"]""",
    re.IGNORECASE,
)
_COMMENT_URL_PAT = re.compile(
    r'(https?://[^\s<>"\')\]]+|/[a-zA-Z][\w/\-.]*(?:\?[^\s<>"\')\]]*)?(?=[\s<>"\')\]])|(?<=[>\]])\s*/[a-zA-Z][\w/\-]*)',
)
_AJAX_PAT = re.compile(
    r"""['"](/[\w/\-._~%!$&'()*+,;=:@]+(?:\.json|\.xml|\.do|\.action|\.api))['"]""",
    re.IGNORECASE,
)
_PROTO_RELATIVE_PAT = re.compile(
    r'["\']//([^"\']+)["\']',
)


def html_extract(html: str, base_url: str = '') -> HTMLExtractResult:
    result = HTMLExtractResult()

    links = set()
    forms = []
    scripts = []
    iframes = []
    api_patterns = []
    json_blocks = []
    routes = []

    for m in _SCRIPT_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            scripts.append(u)
            links.add(u)

    for m in _LINK_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            links.add(u)

    for m in _A_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u and not u.startswith('#') and not u.startswith('javascript:'):
            links.add(u)

    for m in _FORM_PAT.finditer(html):
        fi = FormInfo()
        fi.action = _abs_url(m.group(1), base_url)
        tag_end = html.find('>', m.start())
        if tag_end > m.start():
            method_m = _FORM_METHOD_PAT.search(html, m.start(), tag_end + 1)
        else:
            method_m = None
        fi.method = method_m.group(1).upper() if method_m else 'GET'
        fi.inputs = [
            inp for inp in _FORM_INPUT_PAT.findall(html, m.end())
            if m.end() < html.find('</form>', m.end())
        ]
        forms.append(fi)
        if fi.action:
            links.add(fi.action)

    for m in _IFRAME_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            iframes.append(u)
            links.add(u)

    comments = _COMMENT_PAT.findall(html)
    for c in comments:
        for u in _COMMENT_URL_PAT.findall(c):
            abs_u = _abs_url(u, base_url)
            if abs_u:
                links.add(abs_u)

    for m in _META_REFRESH_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            links.add(u)

    for m in _NEXT_DATA_PAT.finditer(html):
        content = m.group(1).strip()
        if content:
            json_blocks.append(content)

    for m in _JSON_BLOCK_PAT.finditer(html):
        content = m.group(1).strip()
        if content:
            json_blocks.append(content)

    for m in _DATA_ATTR_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            routes.append(u)
            links.add(u)

    for m in _INLINE_JS_API_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            api_patterns.append(u)
            links.add(u)

    for m in _AJAX_PAT.finditer(html):
        u = _abs_url(m.group(1), base_url)
        if u:
            api_patterns.append(u)
            links.add(u)

    result.links = sorted(links)
    result.forms = forms
    result.scripts = scripts
    result.iframes = iframes
    result.comments = [c.strip() for c in comments if c.strip()]
    result.meta_refresh = [m.group(1) for m in _META_REFRESH_PAT.finditer(html)]
    result.api_patterns = api_patterns
    result.json_blocks = json_blocks
    result.routes = routes
    result.all_urls = sorted(links)
    return result
