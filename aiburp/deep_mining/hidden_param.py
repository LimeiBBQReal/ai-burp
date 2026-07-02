"""
aiburp/deep_mining/hidden_param.py
隐藏参数推测 — 基于已知参数 + 业务常识.

不调用 LLM, 纯启发式:
  - 参数名相似度 (id → user_id → uid)
  - 业务领域猜测 (debug / admin / source / format)
  - 历史常见隐藏参数列表
"""
import re
from typing import Dict, List


HIDDEN_PARAM_DICT = {
    "general_debug": [
        "debug", "test", "verbose", "source", "internal",
        "trace", "log", "stack", "stacktrace", "errors",
    ],
    "auth_bypass": [
        "admin", "is_admin", "role", "bypass_auth", "skip_auth",
        "elevate", "sudo", "root", "internal_user",
    ],
    "data_expand": [
        "include_deleted", "with_trashed", "show_hidden",
        "expand", "include", "fields", "with_relations",
        "extra_fields", "all_fields",
    ],
    "format_switch": [
        "format", "callback", "jsonp", "_format", "output",
        "render", "view", "template",
    ],
    "ssrf_hint": [
        "url", "uri", "host", "domain", "redirect", "callback",
        "next", "return", "return_url", "feed", "imageurl",
        "source", "target", "dest", "destination",
    ],
    "rate_bypass": [
        "limit", "per_page", "page_size", "count", "max",
    ],
    "id_sibling": [
        "user_id", "uid", "pid", "product_id", "order_id",
        "account_id", "customer_id", "member_id", "org_id",
        "tenant_id", "workspace_id", "team_id",
    ],
}


def infer_hidden_params(url: str, known_params: Dict[str, str]) -> List[Dict]:
    """
    基于已知参数 + URL 推测可能存在的隐藏参数.

    Args:
        url: 目标 URL (用于 path 关键词)
        known_params: 已知的 query 参数 {name: value}

    Returns:
        [{"name": "debug", "value": "1",
          "category": "general_debug", "rationale": "..."}]
    """
    candidates = []
    known_names_lower = {k.lower() for k in known_params.keys()}
    path_lower = url.lower()

    for category, names in HIDDEN_PARAM_DICT.items():
        for name in names:
            if name.lower() in known_names_lower:
                continue
            rationale = _rationale_for(name, category, path_lower, known_params)
            if rationale is None:
                continue
            value = _default_value_for(category, path_lower)
            candidates.append({
                "name": name,
                "value": value,
                "category": category,
                "rationale": rationale,
            })

    return candidates


def _rationale_for(name: str, category: str, path: str,
                    known: Dict[str, str]) -> str:
    """判断是否值得把 name 加进候选 + 给理由."""
    if category == "ssrf_hint":
        if any(k in path for k in ("/api", "/redirect", "/login", "/oauth",
                                    "/sso", "/auth")):
            return (f"路径含 API/重定向相关关键词, 可能存在 SSRF 参数 {name}, "
                    f"测 file:/// 等协议")
        return None

    if category == "auth_bypass":
        if any(k in path for k in ("/api", "/admin", "/internal", "/private")):
            return f"路径涉及 API/管理员, 测 {name}=1 绕过鉴权"
        return None

    if category == "data_expand":
        if any(k in path for k in ("/user", "/order", "/product", "/list",
                                    "/search")):
            return f"路径含列表/搜索/订单, 测 {name}=1 看是否返回隐藏数据"
        return None

    if category == "format_switch":
        if any(k in path for k in ("/api", "/json", "/xml")):
            return f"API 端点, 测 {name}=json/xml 看是否切换输出格式"
        return None

    if category == "id_sibling":
        for known_name in known.keys():
            if known_name.lower() in ("id", "user_id", "uid", "pid"):
                return (f"已知参数 {known_name}, 同类 ID 参数 {name} 可能也存在, "
                        f"测 IDOR")
        return None

    if category == "rate_bypass":
        return f"限速参数 {name}, 测大值绕过限速"

    return f"通用猜测参数 {name}"


def _default_value_for(category: str, path: str) -> str:
    """给个默认值, 优先探测语义信号."""
    if category == "auth_bypass":
        return "1"
    if category == "format_switch":
        return "json" if "/api" in path else "xml"
    if category == "rate_bypass":
        return "10000"
    if category == "data_expand":
        return "1"
    return "1"