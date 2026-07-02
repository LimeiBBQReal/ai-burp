"""递归目录枚举 — 支持多级目录发现 + 状态码分类挖掘.

流程:
  1. 读取 http_fingerprint live_details
  2. 对每个根 URL, 使用 dirs_large 字典递归爆破
  3. 发现有效目录 -> 将其作为子目录种子继续扫描
  4. 遵循 301/302 跳转, 提取 Location 中的路径

状态码处理策略:
  - 200/204: 直接访问, 可递归扫描子路径
  - 301/302/307/308: 跟踪跳转到子目录
  - 401/403: 端点存在,需要认证/授权 (不递归, 记录供后续 auth-bypass 测试)
  - 405: 方法不允许, 可换 POST/PUT/DELETE 重试
  - 400: 参数错误, 说明端点存在, 可 fuzz 参数
  - 500/502/503: 服务器错误, 端点可能存在且可触发漏洞

输出:
  out/dirs.data.enc + out/dirs.key.enc
"""
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from _common import _read_encrypted, write_encrypted, http_get, load_wordlist

MAX_RECURSION_DEPTH = int(os.environ.get("DIR_DEPTH", "2"))
DIR_TIMEOUT = int(os.environ.get("DIR_TIMEOUT", "5"))

# 状态码分类
DIRECTLY_ACCESSIBLE = {200, 204}                 # 可直接访问, 递归子路径
REDIRECT_CODES = {301, 302, 307, 308}            # 跳转, 跟踪
AUTH_REQUIRED = {401, 403}                       # 端点存在, 需认证/授权
METHOD_CHANGE = {405}                            # 方法不允许
CLIENT_ERROR = {400}                             # 参数错误, 可 fuzz
SERVER_ERROR = {500, 502, 503}                   # 服务器错误

# 所有需要记录的状态码
INTERESTING_STATUS = (
    DIRECTLY_ACCESSIBLE
    | REDIRECT_CODES
    | AUTH_REQUIRED
    | METHOD_CHANGE
    | CLIENT_ERROR
    | SERVER_ERROR
)

# 只有这些状态码的结果可作为递归种子
RECURSABLE_STATUS = DIRECTLY_ACCESSIBLE | REDIRECT_CODES


def _classify_status(status: int) -> str:
    """根据状态码返回分类与建议."""
    if status in DIRECTLY_ACCESSIBLE:
        return "accessible"
    if status in REDIRECT_CODES:
        return "redirect"
    if status == 401:
        return "auth_required"
    if status == 403:
        return "forbidden"
    if status == 405:
        return "method_not_allowed"
    if status == 400:
        return "bad_request"
    if status in SERVER_ERROR:
        return "server_error"
    return "other"


def check_path(base: str, path: str = "", timeout: int = DIR_TIMEOUT) -> dict | None:
    # 不重复添加 /
    if path.startswith("/"):
        path = path[1:]
    url = f"{base}/{path}" if path else base
    r = http_get(url, timeout=timeout, allow_redirects=False)
    if not r:
        return None

    status = r.status_code
    if status not in INTERESTING_STATUS:
        return None

    result = {
        "path": path,
        "url": url,
        "status": status,
        "category": _classify_status(status),
        "size": len(r.content) if r.content else 0,
        "location": r.headers.get("Location", r.headers.get("location", "")),
        "content_type": r.headers.get("Content-Type", r.headers.get("content-type", "")),
        "server": r.headers.get("Server", r.headers.get("server", "")),
    }

    # 301/302: 提取相对路径用于递归
    if status in REDIRECT_CODES and result["location"]:
        loc = result["location"].rstrip("/")
        base_stripped = base.rstrip("/")
        if loc.startswith(base_stripped + "/"):
            sub_path = loc[len(base_stripped) + 1:]
            result["sub_dir"] = sub_path
        elif loc.startswith("/"):
            result["sub_dir"] = loc[1:]

    # 根据状态码添加挖掘建议
    if status == 401:
        result["next_steps"] = ["test_common_credentials", "check_401_bypass"]
    elif status == 403:
        result["next_steps"] = ["directory_traversal", "header_bypass", "method_switch"]
    elif status == 405:
        result["next_steps"] = ["retry_with_post", "retry_with_put", "retry_with_delete"]
    elif status == 400:
        result["next_steps"] = ["fuzz_parameters", "check_api_docs"]
    elif status == 500:
        result["next_steps"] = ["check_error_details", "sqli_fuzz", "lfi_test"]

    return result


def scan_base(base: str, wordlist: list[str], max_depth: int) -> list[dict]:
    """单个根 URL 的递归扫描."""
    all_results: list[dict] = []
    scanned_urls: set[str] = set()
    # 每个深度级别的待扫描种子
    seeds: list[tuple[str, int]] = [(base, 0)]  # ( url, current_depth )
    base_stripped = base.rstrip("/")

    while seeds:
        current, depth = seeds.pop(0)
        if depth >= max_depth:
            continue
        if current in scanned_urls:
            continue
        scanned_urls.add(current)

        # 扫描当前级别
        found: list[dict] = []
        with ThreadPoolExecutor(max_workers=30) as ex:
            futs = {ex.submit(check_path, current, path): path for path in wordlist}
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    found.append(r)
                    cat = r.get("category", "?")
                    print(f"  [{r['status']}][{cat}] {r['url']} ({r['size']}B)", file=sys.stderr)

        all_results.extend(found)

        # 将发现的目录作为下一层种子 (只对可直接访问或跳转的)
        if depth + 1 < max_depth:
            for item in found:
                status = item["status"]
                if status in DIRECTLY_ACCESSIBLE:
                    next_url = item["url"].rstrip("/")
                    if next_url not in scanned_urls:
                        seeds.append((next_url, depth + 1))
                elif status in REDIRECT_CODES and item.get("sub_dir"):
                    target = item["location"].rstrip("/")
                    if target.startswith(base_stripped + "/") or target.startswith("/"):
                        if target not in scanned_urls:
                            seeds.append((target, depth + 1))

    return all_results


def main() -> int:
    print("[dir] 读取 http_fingerprint", file=sys.stderr)
    fp = _read_encrypted("live_details")
    target = fp.get("target", "")
    print(f"[dir] 目标: {target}", file=sys.stderr)

    # http_fingerprint schema: {"live_details": {"domain.com": {"root": {...}, ...}}}
    live_details = fp.get("live_details", {})
    live_urls: list[str] = []
    for domain in live_details:
        live_urls.append(f"http://{domain}")
    if not live_urls:
        live_urls = [f"http://{target}"]

    wordlist = load_wordlist("dirs_large")
    if not wordlist:
        wordlist = load_wordlist("dirs")
    if not wordlist:
        print("[FATAL] 未找到 dirs_large 或 dirs wordlist", file=sys.stderr)
        return 1

    print(f"[dir] 字典: {len(wordlist)}, 根 URL: {len(live_urls)}, 最大递归深度: {MAX_RECURSION_DEPTH}",
          file=sys.stderr)

    t0 = time.time()
    all_found: dict[str, list[dict]] = {}
    total = 0
    category_stats: dict[str, int] = {}

    for base in live_urls:
        print(f"\n[dir] 扫描: {base}", file=sys.stderr)
        found = scan_base(base, wordlist, MAX_RECURSION_DEPTH)
        if found:
            all_found[base] = found
            total += len(found)
            # 统计
            for item in found:
                cat = item.get("category", "other")
                category_stats[cat] = category_stats.get(cat, 0) + 1
            print(f"  {base}: {len(found)} 发现", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[dir] 总计 {total} 发现:")
    for cat, cnt in sorted(category_stats.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {cnt}", file=sys.stderr)
    print(f"  耗时: {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("dirs", {
        "target": target,
        "sources": live_urls,
        "wordlist_size": len(wordlist),
        "max_recursion_depth": MAX_RECURSION_DEPTH,
        "total_found": total,
        "category_stats": category_stats,
        "results": all_found,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
