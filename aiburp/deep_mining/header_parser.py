"""
aiburp/deep_mining/header_parser.py
HTTP 响应头解析 — Link / Allow / CORS / Security 头.
"""
import re
from typing import Dict, List, Optional


_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="([^"]+)"', re.IGNORECASE)
_ALLOW_RE = re.compile(r"^Allow$", re.IGNORECASE)
_CORS_RE = re.compile(r"^Access-Control-(Allow-Origin|Allow-Methods|"
                       r"Allow-Headers|Expose-Headers|Max-Age)$",
                       re.IGNORECASE)


def parse_response_headers(headers: Dict[str, str]) -> Dict:
    """
    从响应头抽取侦察线索.

    Returns:
        {
          "links": [{"href": "/page/2", "rel": "next"}, ...],
          "allow": ["GET", "POST"] 或 None,
          "cors": {"origin": "*", "methods": "GET,POST"} 或 None,
          "frame_options": "DENY" 或 None,
          "csp_unsafe": bool,  # 是否有 unsafe-inline / unsafe-eval
          "csp_report_only": bool,
          "powered_by": "PHP/7.4" 或 None,
          "server": "nginx/1.18" 或 None,
        }
    """
    norm = {_norm_key(k): v for k, v in (headers or {}).items()}

    links = []
    link_h = norm.get("link")
    if link_h:
        for m in _LINK_RE.finditer(link_h):
            links.append({"href": m.group(1).strip(), "rel": m.group(2).strip()})

    allow = None
    allow_h = norm.get("allow")
    if allow_h:
        allow = [m.strip().upper() for m in allow_h.split(",") if m.strip()]

    cors = None
    acao = norm.get("access-control-allow-origin")
    if acao:
        cors = {
            "origin": acao,
            "methods": norm.get("access-control-allow-methods", ""),
            "headers": norm.get("access-control-allow-headers", ""),
            "credentials": norm.get("access-control-allow-credentials", ""),
        }

    csp = norm.get("content-security-policy", "")
    csp_ro = norm.get("content-security-policy-report-only", "")
    csp_unsafe = any(tok in (csp + " " + csp_ro)
                     for tok in ("unsafe-inline", "unsafe-eval"))

    return {
        "links": links,
        "allow": allow,
        "cors": cors,
        "frame_options": norm.get("x-frame-options"),
        "csp_unsafe": csp_unsafe,
        "csp_report_only": bool(csp_ro),
        "powered_by": norm.get("x-powered-by"),
        "server": norm.get("server"),
    }


def is_api_endpoint(headers: Dict[str, str]) -> bool:
    """
    启发式判断: 这个响应是否来自 API endpoint.

    信号:
      - Content-Type: application/json / application/xml
      - X-Response-Time 等自定义头
      - 没有 <html> 风格的 body
    """
    norm = {_norm_key(k): v for k, v in (headers or {}).items()}
    ct = norm.get("content-type", "").lower()
    return any(s in ct for s in ("application/json", "application/xml",
                                  "application/graphql"))


def is_spa_hint(headers: Dict[str, str], body: str = "") -> bool:
    """判断是否是 SPA (React/Vue/Webpack)."""
    norm = {_norm_key(k): v for k, v in (headers or {}).items()}
    ct = norm.get("content-type", "").lower()
    body_lower = (body or "")[:2000].lower()
    if "text/html" not in ct:
        return False
    return any(tok in body_lower for tok in (
        "webpack", "chunk-", "__webpack_require__",
        "reactdom", "vue.config", "nuxt",
        "<div id=\"app\"", "<div id=\"root\"",
    ))


def _norm_key(k: str) -> str:
    return k.strip().lower() if k else ""