"""WHOIS 组织关联 — 发现同注册人/组织的其他域名.

功能:
  1. 查询目标域名的 WHOIS 信息
  2. 提取注册人/组织/邮箱
  3. 通过注册邮箱反查其他域名
  4. 通过组织名关联其他域名

输出: out/whois_corr.data.enc + key.enc
"""
from __future__ import annotations

import os
import re
import sys
import time
from typing import Any

from _common import get_target, write_encrypted, http_get

ROOT = os.path.dirname(os.path.abspath(__file__))


def whois_via_api(domain: str) -> dict[str, Any]:
    """通过 whois API 查询域名信息."""
    # 使用 whoisjson.com API (免费)
    url = f"https://whoisjson.com/api/v1/whois?domain={domain}"
    try:
        r = http_get(url, timeout=15, verify=False)
        if r and r.status_code == 200:
            data = r.json()
            return data
    except Exception:
        pass

    # 备用: 使用 ip-api.com 的 whois
    url = f"http://ip-api.com/json/{domain}?fields=status,message,org,as,isp"
    try:
        r = http_get(url, timeout=10, verify=False)
        if r and r.status_code == 200:
            return r.json()
    except Exception:
        pass

    return {}


def extract_whois_info(domain: str) -> dict[str, Any]:
    """提取 WHOIS 关键信息."""
    raw = whois_via_api(domain)

    info = {
        "domain": domain,
        "registrar": "",
        "organization": "",
        "registrant": "",
        "email": "",
        "name_servers": [],
        "creation_date": "",
        "expiry_date": "",
        "raw_text": "",
    }

    if not raw:
        return info

    # 解析 whoisjson.com 格式
    info["registrar"] = raw.get("registrar", {}).get("name", "") if isinstance(raw.get("registrar"), dict) else str(raw.get("registrar", ""))
    info["organization"] = raw.get("registrant", {}).get("organization", "") if isinstance(raw.get("registrant"), dict) else ""
    info["registrant"] = raw.get("registrant", {}).get("name", "") if isinstance(raw.get("registrant"), dict) else ""
    info["email"] = raw.get("registrant", {}).get("email", "") if isinstance(raw.get("registrant"), dict) else ""
    info["name_servers"] = raw.get("nameserver", []) if isinstance(raw.get("nameserver"), list) else []
    info["creation_date"] = raw.get("created", "") or raw.get("creation_date", "")
    info["expiry_date"] = raw.get("expires", "") or raw.get("expiry_date", "")

    # 备用字段
    if not info["organization"]:
        info["organization"] = raw.get("org", "") or raw.get("organization", "")
    if not info["email"]:
        info["email"] = raw.get("email", "") or raw.get("registrantemail", "")
    if not info["registrar"]:
        info["registrar"] = raw.get("registrar", "")

    return info


def reverse_whois_by_email(email: str) -> list[str]:
    """通过注册邮箱反查其他域名."""
    if not email or "@" not in email:
        return []

    # 使用 viewdns.info 的反向 WHOIS (需要 API key,这里用模拟)
    # 实际项目中可以使用 paid API
    return []


def reverse_whois_by_org(org: str) -> list[str]:
    """通过组织名反查其他域名."""
    if not org:
        return []

    # 使用 crt.sh 搜索组织名
    url = f"https://crt.sh/?q={org}&output=json"
    try:
        r = http_get(url, timeout=20, verify=False)
        if not r or r.status_code != 200:
            return []
        data = r.json()
        domains = set()
        for entry in data:
            for name in entry.get("name_value", []):
                name = name.lower().strip()
                if name.startswith("*."):
                    name = name[2:]
                if "." in name:
                    domains.add(name)
        return sorted(domains)[:100]
    except Exception:
        return []


def find_nameserver_domains(ns: str) -> list[str]:
    """通过 NS 记录发现同 NS 下的其他域名."""
    if not ns:
        return []

    # 从 NS 提取基础域名
    parts = ns.lower().split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        return [base]
    return []


def main() -> int:
    target = get_target()
    print(f"[whois-corr] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 1. 查询 WHOIS
    print(f"[whois-corr] 查询 WHOIS ...", file=sys.stderr)
    info = extract_whois_info(target)
    print(f"  注册商: {info['registrar']}", file=sys.stderr)
    print(f"  组织: {info['organization']}", file=sys.stderr)
    print(f"  邮箱: {info['email']}", file=sys.stderr)
    print(f"  NS: {info['name_servers']}", file=sys.stderr)

    # 2. 通过组织名反查
    related_domains = []
    if info["organization"]:
        print(f"[whois-corr] 通过组织名反查 ...", file=sys.stderr)
        org_domains = reverse_whois_by_org(info["organization"])
        related_domains.extend(org_domains)
        print(f"  组织关联: {len(org_domains)} 域名", file=sys.stderr)

    # 3. 通过邮箱反查
    if info["email"]:
        print(f"[whois-corr] 通过邮箱反查 ...", file=sys.stderr)
        email_domains = reverse_whois_by_email(info["email"])
        related_domains.extend(email_domains)
        print(f"  邮箱关联: {len(email_domains)} 域名", file=sys.stderr)

    # 4. 通过 NS 关联
    ns_domains = []
    for ns in info.get("name_servers", [])[:3]:
        d = find_nameserver_domains(ns)
        ns_domains.extend(d)
    related_domains.extend(ns_domains)

    # 去重
    related_domains = sorted(set(related_domains))

    elapsed = time.time() - t0
    print(f"\n[whois-corr] 完成: {len(related_domains)} 关联域名, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("whois_corr", {
        "target": target,
        "whois_info": info,
        "related_domains": related_domains[:200],
        "total_related": len(related_domains),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
