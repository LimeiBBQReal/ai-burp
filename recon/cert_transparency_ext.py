"""证书透明度扩展 — 发现与目标共享证书的域名.

功能:
  1. 从 crt.sh 查询目标域名的所有证书
  2. 从证书中提取所有域名 (SAN + CN)
  3. 发现组织关联域名 (同一证书/同一组织)
  4. 提取子域名模式

输出: out/cert_ext.data.enc + key.enc
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from _common import get_target, write_encrypted, http_get

ROOT = os.path.dirname(os.path.abspath(__file__))


def crt_sh_subdomains(target: str) -> list[str]:
    """从 crt.sh 查询子域名."""
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        r = http_get(url, timeout=30, verify=False)
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
        return sorted(domains)
    except Exception:
        return []


def crt_sh_organization(target: str) -> list[dict]:
    """从 crt.sh 查询组织信息."""
    url = f"https://crt.sh/?q={target}&output=json"
    try:
        r = http_get(url, timeout=30, verify=False)
        if not r or r.status_code != 200:
            return []
        data = r.json()
        orgs = {}
        for entry in data:
            issuer = entry.get("issuer_name", "")
            # 提取组织名
            org_match = _extract_org(issuer)
            if org_match:
                if org_match not in orgs:
                    orgs[org_match] = {"count": 0, "issuers": set()}
                orgs[org_match]["count"] += 1
                orgs[org_match]["issuers"].add(issuer)

        # 转换 set 为 list 以便 JSON 序列化
        result = []
        for org, info in sorted(orgs.items(), key=lambda x: x[1]["count"], reverse=True):
            result.append({
                "organization": org,
                "count": info["count"],
                "issuers": list(info["issuers"])[:5],
            })
        return result
    except Exception:
        return []


def _extract_org(issuer: str) -> str:
    """从证书颁发者提取组织名."""
    import re
    # 匹配 O= 字段
    m = re.search(r'O=([^,]+)', issuer)
    if m:
        return m.group(1).strip().strip('"')
    # 匹配 CN= 字段
    m = re.search(r'CN=([^,]+)', issuer)
    if m:
        return m.group(1).strip().strip('"')
    return ""


def find_related_by_cert(target: str, all_domains: list[str]) -> dict[str, list[str]]:
    """根据证书信息发现关联域名."""
    related: dict[str, list[str]] = {
        "same_tld": [],
        "similar_name": [],
        "third_level": [],
    }

    target_parts = target.rsplit(".", 1)
    target_name = target_parts[0] if len(target_parts) > 1 else target
    target_tld = target_parts[1] if len(target_parts) > 1 else ""

    for d in all_domains:
        if d == target:
            continue
        d_parts = d.rsplit(".", 1)
        d_name = d_parts[0] if len(d_parts) > 1 else d
        d_tld = d_parts[1] if len(d_parts) > 1 else ""

        # 同一 TLD
        if d_tld == target_tld and d != target:
            related["same_tld"].append(d)

        # 相似名称
        if target_name in d_name or d_name in target_name:
            related["similar_name"].append(d)

        # 三级子域名
        if d.endswith(f".{target}") and d.count(".") >= 2:
            related["third_level"].append(d)

    return related


def main() -> int:
    target = get_target()
    print(f"[cert-ext] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 1. 查询 crt.sh 获取所有子域名
    print(f"[cert-ext] 查询 crt.sh ...", file=sys.stderr)
    all_domains = crt_sh_subdomains(target)
    print(f"  发现 {len(all_domains)} 个域名", file=sys.stderr)

    # 2. 查询组织信息
    print(f"[cert-ext] 提取组织信息 ...", file=sys.stderr)
    orgs = crt_sh_organization(target)
    print(f"  组织: {len(orgs)} 个", file=sys.stderr)
    for org in orgs[:5]:
        print(f"    {org['organization']}: {org['count']} 张证书", file=sys.stderr)

    # 3. 发现关联域名
    related = find_related_by_cert(target, all_domains)

    elapsed = time.time() - t0
    print(f"\n[cert-ext] 完成: {len(all_domains)} 域名, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("cert_ext", {
        "target": target,
        "all_domains": all_domains[:500],  # 限制数量
        "total_domains": len(all_domains),
        "organizations": orgs,
        "related": {k: v[:100] for k, v in related.items()},
        "related_counts": {k: len(v) for k, v in related.items()},
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
