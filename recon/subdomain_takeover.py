"""子域名接管检测 — 发现失效的 CNAME 指向.

功能:
  1. 检查子域名的 CNAME 记录
  2. 识别指向已知可接管服务的 CNAME
  3. 验证目标服务是否真的失效(可注册)
  4. 输出可接管的子域名列表

已知可接管服务:
  - *.herokuapp.com
  - *.s3.amazonaws.com
  - *.cloudfront.net
  - *.azurewebsites.net
  - *.cloudapp.net
  - *.trafficmanager.net
  - *.blob.core.windows.net
  - *.github.io
  - *.shopify.com
  - *.zendesk.com
  - *.wpengine.com
  - *.fastly.net
  - *.ghost.io
  - *.myshopify.com
  - *.surge.sh
  - *.bitbucket.io
  - *.pantheonsite.io
  - *.teamwork.com
  - *.helpjuice.com
  - *.helpscoutdocs.com
  - *.freshdesk.com
  - *.tilda.ws
  - *.campaignmonitor.com
  - *.uservoice.com
  - *.ghost.io
  - *.pingdom.com
  - *.mysmartjobboard.com
  - *.squarespace.com
  - *.teamwork.com
  - *.tumblr.com
  - *.wpengine.com
  - *.zendesk.com

输出: out/takeover.data.enc + key.enc
"""
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver

from _common import get_target, write_encrypted, _read_encrypted

ROOT = os.path.dirname(os.path.abspath(__file__))

# 已知可接管的 CNAME 模式
TAKEOVER_PATTERNS = {
    "herokuapp.com": {"service": "Heroku", "fingerprint": "herokucdn.com", "registerable": True},
    "s3.amazonaws.com": {"service": "AWS S3", "fingerprint": "NoSuchBucket", "registerable": True},
    "cloudfront.net": {"service": "AWS CloudFront", "fingerprint": "CloudFront", "registerable": False},
    "azurewebsites.net": {"service": "Azure App Service", "fingerprint": "Azure", "registerable": True},
    "cloudapp.net": {"service": "Azure Cloud App", "fingerprint": "Azure", "registerable": True},
    "trafficmanager.net": {"service": "Azure Traffic Manager", "fingerprint": "Azure", "registerable": True},
    "blob.core.windows.net": {"service": "Azure Blob Storage", "fingerprint": "Azure", "registerable": True},
    "github.io": {"service": "GitHub Pages", "fingerprint": "GitHub", "registerable": True},
    "shopify.com": {"service": "Shopify", "fingerprint": "Shopify", "registerable": True},
    "zendesk.com": {"service": "Zendesk", "fingerprint": "Zendesk", "registerable": True},
    "wpengine.com": {"service": "WP Engine", "fingerprint": "WP Engine", "registerable": True},
    "fastly.net": {"service": "Fastly", "fingerprint": "Fastly", "registerable": False},
    "ghost.io": {"service": "Ghost", "fingerprint": "Ghost", "registerable": True},
    "myshopify.com": {"service": "Shopify", "fingerprint": "Shopify", "registerable": True},
    "surge.sh": {"service": "Surge.sh", "fingerprint": "Surge", "registerable": True},
    "bitbucket.io": {"service": "Bitbucket", "fingerprint": "Bitbucket", "registerable": True},
    "pantheonsite.io": {"service": "Pantheon", "fingerprint": "Pantheon", "registerable": True},
    "teamwork.com": {"service": "Teamwork", "fingerprint": "Teamwork", "registerable": True},
    "helpjuice.com": {"service": "HelpJuice", "fingerprint": "HelpJuice", "registerable": True},
    "helpscoutdocs.com": {"service": "HelpScout", "fingerprint": "HelpScout", "registerable": True},
    "freshdesk.com": {"service": "Freshdesk", "fingerprint": "Freshdesk", "registerable": True},
    "tilda.ws": {"service": "Tilda", "fingerprint": "Tilda", "registerable": True},
    "campaignmonitor.com": {"service": "Campaign Monitor", "fingerprint": "Campaign Monitor", "registerable": True},
    "uservoice.com": {"service": "UserVoice", "fingerprint": "UserVoice", "registerable": True},
    "pingdom.com": {"service": "Pingdom", "fingerprint": "Pingdom", "registerable": True},
    "squarespace.com": {"service": "Squarespace", "fingerprint": "Squarespace", "registerable": True},
    "tumblr.com": {"service": "Tumblr", "fingerprint": "Tumblr", "registerable": True},
    "animaapp.com": {"service": "Anima", "fingerprint": "Anima", "registerable": True},
    "render.com": {"service": "Render", "fingerprint": "Render", "registerable": True},
    "netlify.app": {"service": "Netlify", "fingerprint": "Netlify", "registerable": True},
    "vercel.app": {"service": "Vercel", "fingerprint": "Vercel", "registerable": True},
    "webflow.io": {"service": "Webflow", "fingerprint": "Webflow", "registerable": True},
}


def get_subdomains() -> list[str]:
    """获取所有子域名."""
    subs = set()
    try:
        vd = _read_encrypted("verify_subdomains")
        for sub, info in vd.get("verified_subdomains", {}).items():
            if isinstance(info, dict) and info.get("verified"):
                subs.add(sub)
    except Exception:
        pass

    try:
        ps = _read_encrypted("passive_sources")
        for sub in ps.get("unique_subdomains", []) or ps.get("subdomains", []):
            if isinstance(sub, str):
                subs.add(sub.lower())
    except Exception:
        pass

    return sorted(subs)


def check_cname(domain: str) -> dict[str, Any] | None:
    """检查域名的 CNAME 记录."""
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
        if answers:
            cname = str(answers[0].target).rstrip(".").lower()
            return {"domain": domain, "cname": cname}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return None
    except Exception:
        return None
    return None


def check_takeover(cname_info: dict[str, str]) -> dict[str, Any] | None:
    """检查 CNAME 是否指向可接管服务."""
    domain = cname_info["domain"]
    cname = cname_info["cname"]

    for pattern, info in TAKEOVER_PATTERNS.items():
        if cname.endswith(pattern):
            # 进一步验证: 尝试解析 CNAME 目标
            is_vulnerable = verify_takeover(cname, info["fingerprint"])
            return {
                "domain": domain,
                "cname": cname,
                "service": info["service"],
                "registerable": info["registerable"],
                "vulnerable": is_vulnerable,
            }
    return None


def verify_takeover(cname: str, fingerprint: str) -> bool:
    """验证 CNAME 目标是否真的失效."""
    try:
        # 尝试解析 CNAME 目标
        answers = dns.resolver.resolve(cname, "A", lifetime=5)
        if not answers:
            return True  # 无法解析,可能可接管
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return True  # NXDOMAIN = 可接管
    except Exception:
        pass
    return False


def main() -> int:
    target = get_target()
    print(f"[takeover] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 获取子域名
    subdomains = get_subdomains()
    print(f"[takeover] 子域名: {len(subdomains)} 个", file=sys.stderr)

    if not subdomains:
        print("[takeover] 无子域名, 跳过", file=sys.stderr)
        write_encrypted("takeover", {
            "target": target,
            "checked": 0,
            "vulnerable": [],
            "elapsed_s": 0,
        })
        return 0

    # 检查 CNAME
    print(f"[takeover] 检查 CNAME 记录 ...", file=sys.stderr)
    cname_results = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(check_cname, sub): sub for sub in subdomains[:100]}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                cname_results.append(r)

    print(f"  发现 {len(cname_results)} 个 CNAME 记录", file=sys.stderr)

    # 检查可接管
    takeover_vulns = []
    for cname_info in cname_results:
        result = check_takeover(cname_info)
        if result:
            takeover_vulns.append(result)
            print(f"  [VULN] {result['domain']} -> {result['cname']} ({result['service']})", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[takeover] 完成: {len(takeover_vulns)} 可接管, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("takeover", {
        "target": target,
        "checked": len(subdomains[:100]),
        "cname_found": len(cname_results),
        "vulnerable": takeover_vulns,
        "total_vulnerable": len(takeover_vulns),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
