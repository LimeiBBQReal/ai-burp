"""
aiburp/deep_mining/url_template.py
URL 模板去重 — 纯规则, 不依赖 LLM.

把 /api/users/123/orders/456 转成 /api/users/{N}/orders/{N},
作为 LLM 聚类失效时的 fallback 方案.
"""
import re
from collections import defaultdict
from typing import Dict, List
from urllib.parse import urlparse, parse_qs


_NUM_PAT = re.compile(r"/(\d+)(?=/|$|\?)")
_HEX_PAT = re.compile(r"/([0-9a-f]{8,})(?=/|$|\?)", re.IGNORECASE)
_UUID_PAT = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"(?=/|$|\?)",
    re.IGNORECASE,
)
_SLUG_PAT = re.compile(r"/([a-f0-9]{16,})(?=/|$|\?)", re.IGNORECASE)


def url_to_template(url: str) -> str:
    """
    把具体 URL 变成模板, 用于聚类.

    Examples:
        /api/users/123/orders/456   -> /api/users/{N}/orders/{N}
        /api/users/abc-uuid-...     -> /api/users/{S}
        /catalog/product/28?q=hello -> /catalog/product/{N}?q={Q}
        https://x.com/a/123         -> https://x.com/a/{N}
    """
    try:
        p = urlparse(url)
    except Exception:
        return url

    path = p.path
    path = _UUID_PAT.sub(r"/{S}", path)
    path = _SLUG_PAT.sub(r"/{S}", path)
    path = _HEX_PAT.sub(r"/{H}", path)
    path = _NUM_PAT.sub(r"/{N}", path)

    qs = p.query
    if qs:
        parts = []
        for kv in qs.split("&"):
            if "=" in kv:
                k, _ = kv.split("=", 1)
                parts.append(f"{k}={{Q}}")
            else:
                parts.append(kv)
        qs = "&".join(parts)

    netloc = p.netloc
    scheme = p.scheme

    out = ""
    if scheme:
        out += f"{scheme}://"
    if netloc:
        out += netloc
    out += path
    if qs:
        out += f"?{qs}"
    return out


def cluster_urls(urls: List[str]) -> Dict[str, List[str]]:
    """
    按模板聚类, 返回 {template: [member_url, ...]}.

    同一模板的 URL 默认只测 1 个代表 + 边界值 (id=0, id=-1).
    """
    clusters: Dict[str, List[str]] = defaultdict(list)
    for u in urls:
        t = url_to_template(u)
        clusters[t].append(u)
    return dict(clusters)


def representatives(clusters: Dict[str, List[str]],
                    max_per_cluster: int = 1) -> List[str]:
    """从每个 cluster 取前 N 个代表 URL."""
    reps = []
    for template, members in clusters.items():
        reps.extend(members[:max_per_cluster])
    return reps


def cluster_stats(clusters: Dict[str, List[str]]) -> Dict[str, int]:
    """统计信息: 总数 / 模板数 / 平均每模板成员数."""
    total = sum(len(v) for v in clusters.values())
    n_templates = len(clusters)
    return {
        "total_urls": total,
        "templates": n_templates,
        "avg_per_template": round(total / n_templates, 2) if n_templates else 0,
        "max_per_template": max((len(v) for v in clusters.values()), default=0),
    }