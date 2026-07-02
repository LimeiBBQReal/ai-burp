"""递归深度子域名探测 (depth=N) — 基于已验证子域名进行 DNS 递归爆破.

流程:
  1. 读取 Phase 2a 的 verify_subdomains.data.enc
  2. 取 verified=True 的各级子域名 + 根域名作为种子
  3. 对每个种子, 使用排序后的智能字典递归爆破
  4. 每层进行通配符 IP 过滤 (多层泛解析检测)
  5. 输出 deep_subdomains 含解析 IP

输出:
  out/deep_subdomains.data.enc + out/deep_subdomains.key.enc
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver

from _common import get_target, write_encrypted, load_wordlist, _read_encrypted

WILDCARD_IPS = {"198.18.", "0.0.0.0", "198.51.", "203.0."}
MAX_DEPTH = int(os.environ.get("DEEP_DEPTH", "2"))
BATCH_SIZE = int(os.environ.get("DEEP_BATCH_SIZE", "50"))  # 限制每轮探测的域名数


def _is_wildcard_ip(ip: str | None) -> bool:
    if not ip:
        return True
    for prefix in WILDCARD_IPS:
        if ip.startswith(prefix):
            return True
    return False


def _resolve_ip(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        if answers:
            return answers[0].to_text()
    except Exception:
        return None
    return None


def _get_verified_seeds(data: dict, target: str) -> list[str]:
    """获取所有已验证的子域名作为种子 (不限层级).

    优先级:
      1. dot_count == 2 的二级子域名 (最优)
      2. 更深层级的子域名
      3. 根域名
    """
    verified_domains: list[str] = []
    vd = data.get("verified_subdomains", {})
    for subdomain, info in vd.items():
        if not isinstance(info, dict):
            continue
        if info.get("verified") and subdomain.endswith(target):
            dot_count = subdomain.count(".") - target.count(".")
            verified_domains.append((dot_count, subdomain))
    # 排序: dot_count 升序 (从浅层开始)
    verified_domains.sort(key=lambda x: x[0])
    seeds = [s for _, s in verified_domains]
    if target not in seeds:
        seeds.insert(0, target)
    return seeds


def _prioritize_wordlist(wordlist: list[str], found_patterns: list[str]) -> list[str]:
    """根据已发现模式优先排序字典.

    策略: 如果发现的子域名包含某些前缀模式, 这些前缀排在前面.
    """
    if not found_patterns:
        return wordlist
    priority = []
    remaining = list(wordlist)
    for pattern in found_patterns:
        matching = [w for w in remaining if w.startswith(pattern)]
        priority.extend(matching)
        remaining = [w for w in remaining if not w.startswith(pattern)]
    return priority + remaining


def _scan_wildcard_for_parent(parent: str) -> set[str]:
    """检测特定父域名的泛解析."""
    wc_ips = set()
    for _ in range(2):
        random_sub = str(uuid.uuid4()).replace("-", "")[:10]
        fqdn = f"{random_sub}.{parent}"
        ip = _resolve_ip(fqdn)
        if ip and not _is_wildcard_ip(ip):
            wc_ips.add(ip)
    return wc_ips


def _brute_level(
    parent_domain: str,
    wordlist: list[str],
    scanned: set[str],
    wildcard_ips_for_parent: set[str],
) -> dict[str, str]:
    found: dict[str, str] = {}

    def probe(sub: str) -> tuple[str, str | None]:
        fqdn = f"{sub}.{parent_domain}"
        if fqdn in scanned:
            return fqdn, None
        ip = _resolve_ip(fqdn)
        if ip and not _is_wildcard_ip(ip) and ip not in wildcard_ips_for_parent:
            return fqdn, ip
        return fqdn, None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(probe, sub): sub for sub in wordlist}
        for fut in as_completed(futs):
            fqdn, ip = fut.result()
            if ip:
                found[fqdn] = ip
                scanned.add(fqdn)

    return found


def main() -> int:
    target = get_target()
    print(f"[deep] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    data = _read_encrypted("verify_subdomains")
    if data is None:
        print("[FATAL] 无法读取 verify_subdomains 数据", file=sys.stderr)
        return 1

    seeds = _get_verified_seeds(data, target)
    print(f"[deep] 种子域名: {len(seeds)}", file=sys.stderr)
    for s in seeds[:10]:
        print(f"  种子: {s}", file=sys.stderr)

    wordlist = load_wordlist("subdomains_large") or load_wordlist("subdomains")
    if not wordlist:
        wordlist = ["www", "mail", "api", "admin", "vpn", "cdn", "blog", "dev", "test", "staging"]
    print(f"[deep] 字典: {len(wordlist)} 条", file=sys.stderr)

    all_found: dict[str, str] = {}
    scanned: set[str] = set()

    # 限制每轮扫描的域名数 (避免超时)
    seeds_to_scan = seeds[:BATCH_SIZE]

    for host in seeds_to_scan:
        print(f"\n[deep] 扫描: {host}", file=sys.stderr)

        # 检测该父域名的泛解析
        wc_ips = _scan_wildcard_for_parent(host)
        if wc_ips:
            print(f"  [WARN] {host} 存在泛解析 IPs: {wc_ips}", file=sys.stderr)

        for depth in range(1, MAX_DEPTH + 1):
            if depth == 1:
                targets = [host]
            else:
                # 取上一层发现的域名
                targets = [
                    s for s in all_found
                    if s.endswith(host) and s.count(".") <= host.count(".") + 1
                ]
                targets = [t for t in targets if t not in scanned]

            if not targets:
                continue

            print(f"  depth={depth}, targets={len(targets)}", file=sys.stderr)

            for parent in targets:
                if parent in scanned:
                    continue
                scanned.add(parent)

                # 动态排序字典 (根据已发现模式)
                prefix_patterns = list(set(
                    k.split(".")[0] for k in all_found if k.endswith(host)
                ))
                prioritized_wl = _prioritize_wordlist(wordlist, prefix_patterns[:10])

                found = _brute_level(parent, prioritized_wl, scanned, wc_ips)
                if found:
                    print(f"    {parent}: +{len(found)} (e.g. {list(found.keys())[:3]})", file=sys.stderr)
                    all_found.update(found)

    elapsed = time.time() - t0
    print(f"\n[deep] 深度子域名总数: {len(all_found)}, {elapsed:.1f}s", file=sys.stderr)

    by_parent: dict[str, list[str]] = {}
    for fqdn in all_found:
        parts = fqdn.split(".")
        if len(parts) >= 3:
            parent = ".".join(parts[1:])
            by_parent.setdefault(parent, []).append(fqdn)

    write_encrypted("deep_subdomains", {
        "target": target,
        "subdomains": sorted(all_found.keys()),
        "resolved": all_found,
        "by_parent": {k: sorted(v) for k, v in by_parent.items()},
        "total": len(all_found),
        "max_depth": MAX_DEPTH,
        "seeds_scanned": len(seeds_to_scan),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
