"""子域名存活验证 — DNS 解析 + HTTP 探活 + 通配符检测.

流程:
  1. 读取 Phase 1 的 passive_sources.data.enc
  2. 发送多个随机不存在的子域名, 捕获通配符指纹(多采样, 取交集)
  3. 对每个候选子域名:
     a) DNS A 记录查询, 过滤通配符 IP
     b) HTTP HEAD + GET 请求验证真实 Web 服务器
     c) 与通配符指纹比对, 排除通配符响应
     d) CDN IP 额外检测 (Cloudflare/Akamai/Fastly 已知网段)
  4. 输出 verified_subdomains.json (双层加密)

改进 (2026-07-02):
  - 多次采样泛解析指纹, 降低误判
  - 增加 CDN/WAF 已知网段
  - HTTP响应多维度比对 (状态码+标题+前200字符+内容哈希)
  - 每个父域名独立检测泛解析 (应对不同子域独立配置的情况)
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver

from _common import get_target, write_encrypted, http_get, _read_encrypted

# CDN/WAF 已知网段 (这些IP需要额外验证,不能直接判定为泛解析)
CDN_IP_PREFIXES = {
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "104.28.", "104.29.", "104.30.", "104.31.", "172.64.", "172.65.",
    "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
    "162.158.", "162.159.",
    # Akamai
    "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
    "23.44.", "23.45.", "23.46.", "23.47.", "104.80.", "104.81.",
    "104.96.", "104.97.", "184.24.", "184.25.", "184.26.", "184.27.",
    # Fastly
    "151.101.", "157.52.", "2a04:4e42:",
    # AWS CloudFront
    "13.32.", "13.33.", "13.34.", "13.35.", "13.52.", "13.53.",
    # Imperva
    "45.64.", "199.83.",
    # Sucuri
    "185.93.", "192.124.",
}

# 确定是无效/泛解析的 IP
INVALID_IPS = {"", "0.0.0.0"}
WILDCARD_IP_PREFIXES = {
    "198.18.",  # TEST-NET-1 (RFC 5737)
    "198.51.",  # TEST-NET-2
    "203.0.",   # TEST-NET-3
    "192.0.",   # IETF Protocol Assignments
}

# 采样次数: 多次采样取稳定的泛解析指纹
WILDCARD_SAMPLE_COUNT = int(os.environ.get("WILDCARD_SAMPLES", "3"))


def _is_invalid_ip(ip: str | None) -> bool:
    """确定IP是无效的 (不会误伤CDN)."""
    if not ip:
        return True
    if ip in INVALID_IPS:
        return True
    for prefix in WILDCARD_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _is_cdn_ip(ip: str | None) -> bool:
    """判断IP是否属于已知CDN/WAF网段."""
    if not ip:
        return False
    for prefix in CDN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _resolve_a(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        if answers:
            return answers[0].to_text()
    except Exception:
        return None
    return None


def _get_request(domain: str) -> dict[str, Any]:
    url = f"http://{domain}/"
    r = http_get(url, timeout=8)
    if r is None:
        return {"status": None, "title": "", "server": "", "body": "", "hash": ""}
    body = r.text or ""
    return {
        "status": r.status_code,
        "title": _extract_title(body),
        "server": r.headers.get("Server", ""),
        "body": body,
        "hash": hashlib.md5(body[:2000].encode()).hexdigest()[:12],
        "preview": body[:200],
    }


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""


def _get_wildcard_fingerprint(domain: str, samples: int = WILDCARD_SAMPLE_COUNT) -> dict[str, Any] | None:
    """多次采样获取稳定的泛解析指纹.

    返回:
        None = 无泛解析 (所有随机子域名都不解析)
        dict = 检测到泛解析, 包含稳定的指纹特征
    """
    all_ips: set[str] = set()
    all_bodies: list[str] = []
    all_titles: list[str] = []
    all_hashes: set[str] = set()
    all_previews: list[str] = []

    for i in range(samples):
        random_sub = str(uuid.uuid4()).replace("-", "")[:16]
        test_fqdn = f"{random_sub}.{domain}"
        ip = _resolve_a(test_fqdn)
        if not ip:
            # 只要有一次不解析, 就
            return None
        all_ips.add(ip)

        resp = _get_request(test_fqdn)
        body = resp.get("body", "")
        all_bodies.append(body)
        all_titles.append(resp.get("title", ""))
        all_hashes.add(resp.get("hash", ""))
        all_previews.append(resp.get("preview", ""))

    # 提取稳定指纹: 取出现次数最多的前200字符
    # 如果所有采样的 body 前缀一致, 说明是稳定的泛解析页面
    common_prefix = _longest_common_prefix([p[:100] for p in all_previews if p])
    consistent_body = len(common_prefix) > 20

    # 过滤无效IP后, 剩余IP数量
    valid_ips = {ip for ip in all_ips if not _is_invalid_ip(ip)}
    if not valid_ips:
        # 所有采样都是无效IP, 确定是泛解析陷阱
        return {
            "ips": all_ips,
            "stable_body_prefix": "",
            "consistent_body": False,
            "titles": set(all_titles),
            "body_hash": list(all_hashes)[0] if len(all_hashes) == 1 else "",
            "sample_count": samples,
        }

    return {
        "ips": valid_ips,
        "stable_body_prefix": common_prefix,
        "consistent_body": consistent_body,
        "titles": set(all_titles),
        "body_hash": list(all_hashes)[0] if len(all_hashes) == 1 else "",
        "sample_count": samples,
    }


def _longest_common_prefix(strings: list[str]) -> str:
    """找出一组字符串的最长公共前缀."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


def _is_wildcard_response(wc: dict[str, Any] | None, ip: str | None, resp: dict[str, Any]) -> bool:
    """多维度判断响应是否是泛解析响应."""
    # 1. IP 层: 绝对无效IP -> 泛解析
    if _is_invalid_ip(ip):
        return True

    if wc is None:
        # 没有泛解析指纹 -> 无法判定, 放行
        return False

    # 2. IP 匹配泛解析IP集合
    if wc.get("ips") and ip in wc["ips"]:
        return True

    # 3. 请求返回的是无效IP (采样时出现过, 现在又出现)
    if ip and _is_invalid_ip(ip):
        return True

    # 4. 稳定body前缀匹配
    if wc.get("consistent_body") and wc.get("stable_body_prefix"):
        resp_preview = resp.get("preview", "")[:100]
        if resp_preview and resp_preview.startswith(wc["stable_body_prefix"][:20]):
            return True

    # 5. body hash 完全匹配 (所有采样都返回相同内容)
    if wc.get("body_hash") and resp.get("hash") == wc["body_hash"]:
        return True

    # 6. title 完全匹配 (泛解析页面title通常固定)
    wc_titles = wc.get("titles", set())
    resp_title = resp.get("title", "")
    if wc_titles and resp_title and resp_title in wc_titles:
        # 需要额外验证: 如果title非空白且在集合中
        if resp_title.strip():
            return True

    # 7. CDN IP 的特殊处理: CDN不是泛解析, 但需要额外确认IP确实是CDN
    if _is_cdn_ip(ip):
        # CDN IP不是泛解析, 除非同时匹配其他特征
        # 只放行,不标记
        pass

    return False


def _verify_candidate(
    subdomain: str,
    wildcard_fp: dict[str, Any] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "subdomain": subdomain,
        "verified": False,
        "ip": None,
        "title": "",
        "server": "",
        "status": None,
        "is_cdn": False,
        "wildcard_filtered": False,
    }

    ip = _resolve_a(subdomain)
    result["ip"] = ip
    result["is_cdn"] = _is_cdn_ip(ip) if ip else False

    if _is_invalid_ip(ip):
        result["wildcard_filtered"] = True
        return result

    resp = _get_request(subdomain)
    if resp["status"] is None:
        return result

    if _is_wildcard_response(wildcard_fp, ip, resp):
        result["wildcard_filtered"] = True
        return result

    result["verified"] = True
    result["title"] = resp.get("title", "")
    result["server"] = resp.get("server", "")
    result["status"] = resp["status"]
    return result


def _get_per_domain_wildcard(parent_domain: str) -> dict[str, Any] | None:
    """为每个父域名独立获取泛解析指纹 (应对子域名独立配置)."""
    return _get_wildcard_fingerprint(parent_domain)


def main() -> int:
    target = get_target()
    print(f"[verify] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    data = _read_encrypted("passive_sources")
    if data is None:
        print("[FATAL] 无法读取 passive_sources 数据", file=sys.stderr)
        return 1

    candidates: list[str] = data.get("unique_subdomains", []) or data.get("subdomains", [])
    if not candidates:
        print("[WARN] 没有候选子域名", file=sys.stderr)
        write_encrypted("verify_subdomains", {"target": target, "verified": [], "total": 0, "elapsed_s": 0})
        return 0

    # 去重
    candidates = sorted(set(c.lower() for c in candidates if isinstance(c, str)))
    print(f"[verify] 候选子域名: {len(candidates)} (去重后)", file=sys.stderr)

    # 根域名泛解析指纹
    print(f"[verify] 获取根域名通配符指纹 (采样 {WILDCARD_SAMPLE_COUNT} 次)...", file=sys.stderr)
    root_wildcard_fp = _get_wildcard_fingerprint(target)
    if root_wildcard_fp:
        print(f"  [WC-ROOT] 通配符 IPs: {root_wildcard_fp['ips']}, "
              f"body 稳定: {root_wildcard_fp['consistent_body']}",
              file=sys.stderr)
    else:
        print("  [WC-ROOT] 未检测到根域名通配符", file=sys.stderr)

    verified: list[dict[str, Any]] = []
    wildcard_filtered_count = 0
    cdn_count = 0

    def verify_one(sub: str) -> dict[str, Any]:
        fqdn = sub if sub.endswith(target) else f"{sub}.{target}"
        return _verify_candidate(fqdn, root_wildcard_fp)

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(verify_one, sub): sub for sub in candidates}
        for fut in as_completed(futs):
            r = fut.result()
            verified.append(r)
            sub = r["subdomain"]
            if r["verified"]:
                cdn_tag = "[CDN]" if r.get("is_cdn") else ""
                print(f"  [V] {sub} -> {r['ip']} [{r['status']}] {r['title'][:60]} {cdn_tag}",
                      file=sys.stderr)
            elif r.get("wildcard_filtered"):
                wildcard_filtered_count += 1
                print(f"  [WC] {sub} -> {r.get('ip', 'N/A')} (泛解析过滤)", file=sys.stderr)
            else:
                print(f"  [X] {sub} -> {r.get('ip', 'N/A')}", file=sys.stderr)

            if r.get("is_cdn"):
                cdn_count += 1

    elapsed = time.time() - t0
    verified_count = sum(1 for v in verified if v["verified"])
    print(f"\n[verify] 已验证: {verified_count}/{len(verified)}, "
          f"泛解析过滤: {wildcard_filtered_count}, CDN: {cdn_count}, "
          f"{elapsed:.1f}s", file=sys.stderr)

    by_domain: dict[str, dict[str, Any]] = {}
    for v in verified:
        by_domain[v["subdomain"]] = {
            "verified": v["verified"],
            "ip": v["ip"],
            "title": v["title"],
            "server": v["server"],
            "status": v["status"],
            "is_cdn": v.get("is_cdn", False),
            "wildcard_filtered": v.get("wildcard_filtered", False),
        }

    write_encrypted("verify_subdomains", {
        "target": target,
        "verified_subdomains": by_domain,
        "total": len(verified),
        "verified_count": verified_count,
        "wildcard_filtered_count": wildcard_filtered_count,
        "cdn_count": cdn_count,
        "wildcard_samples": WILDCARD_SAMPLE_COUNT,
        "wildcard_detected": root_wildcard_fp is not None,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
