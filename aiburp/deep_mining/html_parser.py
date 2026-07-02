"""
aiburp/deep_mining/html_parser.py
HTML 解析 — form / anchor / link / meta / iframe / script.

优先复用 aiburp.crawler.extractors.html_parser (已有成熟实现),
这里只做 thin wrapper + 适配新数据格式.
"""
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class HTMLParseResult:
    forms: List[Dict] = field(default_factory=list)
    anchors: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    meta_refresh: List[str] = field(default_factory=list)
    inline_js_api: List[str] = field(default_factory=list)
    json_blocks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


def parse_html(html: str, base_url: str = "") -> HTMLParseResult:
    """
    解析 HTML 响应, 抽取所有可访问的 endpoint 入口.

    Args:
        html: HTTP 响应的 HTML body
        base_url: 用于把相对路径转成绝对路径

    Returns:
        HTMLParseResult: 表单/链接/脚本等分类列表
    """
    try:
        from aiburp.crawler.extractors.html_parser import html_extract

        raw = html_extract(html, base_url)

        forms = []
        for f in raw.forms:
            forms.append({
                "action": f.action,
                "method": f.method,
                "inputs": list(f.inputs),
                "enctype": "application/x-www-form-urlencoded",
            })

        result = HTMLParseResult(
            forms=forms,
            anchors=sorted({u for u in raw.links
                             if u and not u.endswith((".js", ".css"))}),
            scripts=raw.scripts,
            links=raw.links,
            iframes=raw.iframes,
            meta_refresh=raw.meta_refresh,
            inline_js_api=raw.api_patterns,
            json_blocks=raw.json_blocks,
        )
        return result
    except Exception as e:
        return HTMLParseResult()


def extract_form_endpoints(html: str, base_url: str = "") -> List[Dict]:
    """
    只提取 form 端点 (Phase ④ 发 payload 时直接用).

    Returns:
        [{"url": "https://...", "method": "POST",
          "fields": ["username", "password", "_token"]}, ...]
    """
    res = parse_html(html, base_url)
    out = []
    for f in res.forms:
        if not f.get("action"):
            continue
        out.append({
            "url": f["action"],
            "method": (f.get("method") or "GET").upper(),
            "fields": f.get("inputs") or [],
            "enctype": f.get("enctype", "application/x-www-form-urlencoded"),
        })
    return out