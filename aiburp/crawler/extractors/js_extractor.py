"""
JS Extractor — 正则扫描 JS 文件中的 API 端点
分两层: Level 1 正则快速扫描, Level 2 LLM 深度分析
零额外安装依赖
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class JSExtractResult:
    fetch_calls: List[str] = field(default_factory=list)
    xhr_calls: List[str] = field(default_factory=list)
    axios_calls: List[str] = field(default_factory=list)
    ajax_calls: List[str] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    api_paths: List[str] = field(default_factory=list)
    import_urls: List[str] = field(default_factory=list)
    all_endpoints: List[str] = field(default_factory=list)


_FETCH_PAT = re.compile(
    r"""fetch\(['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_XHR_PAT = re.compile(
    r"""\.open\(['"]?(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]?\s*,\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_AXIOS_PAT = re.compile(
    r"""axios\.(?:get|post|put|delete|patch|head|options|request)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_AJAX_PAT = re.compile(
    r"""\$\s*\.\s*ajax\s*\(\s*\{[^}]*?url\s*:\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_AJAX_SHORT_PAT = re.compile(
    r"""url\s*:\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_WEBSOCKET_PAT = re.compile(
    r"""new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_API_PATH_PAT = re.compile(
    r"""['"](/?(?:api|v\d+|graphql|rest|internal|private|admin|backend|service|srv|gw|gateway)[/\w\-._~%!$&'()*+,;=:@]+)['"]""",
    re.IGNORECASE,
)

_IMPORT_PAT = re.compile(
    r"""(?:import\s*\(|require\s*\(|import\s+['"])(['"][^'"]+['"])""",
    re.IGNORECASE,
)

_IMPORT_SIMPLE_PAT = re.compile(
    r"""['"](\.\.?/[\w\-./]+(?:\.\w+)?)['"]""",
)

_ROUTER_PAT = re.compile(
    r"""['"](/[\w\-./*\[\]:]+)['"]""",
)

_ENV_API_PAT = re.compile(
    r"""['"]?(?:VITE_|REACT_APP_|NEXT_PUBLIC_|NUXT_ENV_)?API[_]?(?:URL|ENDPOINT|HOST|BASE|ROOT)?['"]?\s*[:=]\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def js_extract(js_content: str, source_url: str = '') -> JSExtractResult:
    result = JSExtractResult()
    seen = set()

    def _add(container: list, val: str):
        abs_val = _abs_url(val, source_url)
        if abs_val and abs_val not in seen:
            seen.add(abs_val)
            container.append(abs_val)
            result.all_endpoints.append(abs_val)

    for m in _FETCH_PAT.finditer(js_content):
        _add(result.fetch_calls, m.group(1))

    for m in _XHR_PAT.finditer(js_content):
        _add(result.xhr_calls, m.group(1))

    for m in _AXIOS_PAT.finditer(js_content):
        _add(result.axios_calls, m.group(1))

    for m in _AJAX_PAT.finditer(js_content):
        _add(result.ajax_calls, m.group(1))

    for m in _AJAX_SHORT_PAT.finditer(js_content):
        url = m.group(1)
        if not any(u.startswith(url[:20]) for u in seen):
            _add(result.ajax_calls, url)

    for m in _WEBSOCKET_PAT.finditer(js_content):
        _add(result.websocket_urls, m.group(1))

    for m in _API_PATH_PAT.finditer(js_content):
        _add(result.api_paths, m.group(1))

    for m in _IMPORT_PAT.finditer(js_content):
        _add(result.import_urls, m.group(1))

    for m in _IMPORT_SIMPLE_PAT.finditer(js_content):
        _add(result.import_urls, m.group(1))

    for m in _ENV_API_PAT.finditer(js_content):
        _add(result.api_paths, m.group(1))

    # 去重
    result.all_endpoints = sorted(set(result.all_endpoints))
    return result


def _abs_url(href: str, source_url: str) -> Optional[str]:
    if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('data:'):
        return None
    if href.startswith('//'):
        return f'https:{href}'
    if href.startswith('http://') or href.startswith('https://'):
        return href
    if href.startswith('/') and source_url:
        from urllib.parse import urlparse
        parsed = urlparse(source_url)
        return f'{parsed.scheme}://{parsed.netloc}{href}'
    if href.startswith('/'):
        return href
    return href
