"""ASN/IP 段归属查询 — 发现组织关联的 IP 段.

功能:
  1. 查询目标 IP 的 ASN 信息
  2. 获取 ASN 关联的 IP 段
  3. 查询组织名下的所有 IP 段
  4. 发现同组织的其他资产

输出: out/asn_lookup.data.enc + key.enc
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from _common import get_target, write_encrypted, http_get, _read_encrypted

ROOT = os.path.dirname(os.path.abspath(__file__))


def ipinfo_lookup(ip: str) -> dict[str, Any]:
    """通过 ipinfo.io 查询 IP 信息."""
    url = f"https://ipinfo.io/{ip}/json"
    try:
        r = http_get(url, timeout=10, verify=False)
        if r and r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def bgpview_asn_lookup(asn: str) -> dict[str, Any]:
    """通过 BGPView 查询 ASN 信息."""
    url = f"https://api.bgpview.io/asn/{asn.replace('AS', '')}"
    try:
        r = http_get(url, timeout=15, verify=False)
        if r and r.status_code == 200:
            data = r.json()
            return data.get("data", {})
    except Exception:
        pass
    return {}


def get_target_ips() -> list[str]:
    """从验证结果中获取目标 IP 列表."""
    ips = set()
    try:
        vd = _read_encrypted("verify_subdomains")
        for sub, info in vd.get("verified_subdomains", {}).items():
            if isinstance(info, dict) and info.get("ip"):
                ip = info["ip"]
                if not _is_private_ip(ip):
                    ips.add(ip)
    except Exception:
        pass
    return list(ips)


def _is_private_ip(ip: str) -> bool:
    """检查是否是私有/保留地址."""
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    if octets[0] == 198 and octets[1] in (18, 19):
        return True
    if octets[0] == 100 and 64 <= octets[1] <= 127:
        return True
    return False


def main() -> int:
    target = get_target()
    print(f"[asn-lookup] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 获取目标 IP
    ips = get_target_ips()
    print(f"[asn-lookup] 目标 IP: {len(ips)} 个", file=sys.stderr)

    if not ips:
        print("[asn-lookup] 无有效 IP, 跳过", file=sys.stderr)
        write_encrypted("asn_lookup", {
            "target": target,
            "asns": [],
            "ip_ranges": [],
            "elapsed_s": 0,
        })
        return 0

    # 查询每个 IP 的 ASN
    asns: dict[str, dict] = {}
    ip_ranges: list[str] = []

    for ip in ips[:5]:  # 限制查询数量
        print(f"[asn-lookup] 查询 {ip} ...", file=sys.stderr)
        info = ipinfo_lookup(ip)

        if info:
            asn = info.get("asn", "") or info.get("org", "").split()[0] if info.get("org") else ""
            org = info.get("org", "")

            if asn and asn not in asns:
                asns[asn] = {
                    "asn": asn,
                    "organization": org,
                    "ips": [ip],
                    "country": info.get("country", ""),
                }
                print(f"  ASN: {asn}, 组织: {org}", file=sys.stderr)

                # 查询 ASN 的 IP 段
                if asn.startswith("AS"):
                    bgp_info = bgpview_asn_lookup(asn)
                    prefixes = bgp_info.get("prefixes", [])
                    for prefix in prefixes[:10]:
                        p = prefix.get("prefix", "")
                        if p:
                            ip_ranges.append(p)
                    print(f"  IP 段: {len(prefixes)} 个", file=sys.stderr)
            else:
                if asn in asns:
                    asns[asn]["ips"].append(ip)

        time.sleep(0.5)

    elapsed = time.time() - t0
    print(f"\n[asn-lookup] 完成: {len(asns)} ASN, {len(ip_ranges)} IP 段, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("asn_lookup", {
        "target": target,
        "asns": list(asns.values()),
        "ip_ranges": ip_ranges[:50],
        "total_ranges": len(ip_ranges),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
