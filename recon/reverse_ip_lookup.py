"""反向 IP 查找 — 发现同 IP 上的其他域名.

功能:
  1. 查询目标 IP 上的其他域名 (Reverse IP / Domain)
  2. 支持多个 API: hackertarget, viewdns, aizhan
  3. 过滤出与目标组织相关的域名

输出: out/reverse_ip.data.enc + key.enc
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from _common import get_target, write_encrypted, http_get, _read_encrypted

ROOT = os.path.dirname(os.path.abspath(__file__))


def hackertarget_reverse_ip(ip: str) -> list[str]:
    """使用 hackertarget.com API 查询反向 IP."""
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        r = http_get(url, timeout=15, verify=False)
        if not r or r.status_code != 200:
            return []
        text = r.text.strip()
        if "error" in text.lower() or "api count" in text.lower():
            return []
        domains = [d.strip().lower() for d in text.split("\n") if d.strip() and "." in d]
        return domains
    except Exception:
        return []


def viewdns_reverse_ip(ip: str) -> list[str]:
    """使用 viewdns.info API 查询反向 IP."""
    url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey=demo&output=json"
    try:
        r = http_get(url, timeout=15, verify=False)
        if not r or r.status_code != 200:
            return []
        data = r.json()
        domains = []
        for item in data.get("response", {}).get("domains", []):
            name = item.get("name", "").lower()
            if name and "." in name:
                domains.append(name)
        return domains
    except Exception:
        return []


def crt_sh_same_ip(ip: str) -> list[str]:
    """通过 crt.sh 查询同一 IP 上的证书域名."""
    url = f"https://crt.sh/?q={ip}&output=json"
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
        return list(domains)
    except Exception:
        return []


def get_target_ips() -> list[str]:
    """从验证结果中获取目标 IP 列表."""
    ips = []
    try:
        vd = _read_encrypted("verify_subdomains")
        for sub, info in vd.get("verified_subdomains", {}).items():
            if isinstance(info, dict) and info.get("ip"):
                ip = info["ip"]
                # 过滤 TEST-NET 和私有地址
                if not _is_private_ip(ip):
                    ips.append(ip)
    except Exception:
        pass

    # 也尝试从 ports 获取
    try:
        pd = _read_encrypted("ports")
        for ip in pd.get("open_ports", {}):
            if not _is_private_ip(ip) and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return ips


def _is_private_ip(ip: str) -> bool:
    """检查是否是私有/保留地址."""
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    octets = [int(p) for p in parts]
    # 10.0.0.0/8
    if octets[0] == 10:
        return True
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return True
    # 127.0.0.0/8
    if octets[0] == 127:
        return True
    # 169.254.0.0/16
    if octets[0] == 169 and octets[1] == 254:
        return True
    # 198.18.0.0/15 (TEST-NET)
    if octets[0] == 198 and octets[1] in (18, 19):
        return True
    # 100.64.0.0/10
    if octets[0] == 100 and 64 <= octets[1] <= 127:
        return True
    return False


def main() -> int:
    target = get_target()
    print(f"[reverse-ip] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 获取目标 IP
    ips = get_target_ips()
    print(f"[reverse-ip] 目标 IP: {len(ips)} 个", file=sys.stderr)

    if not ips:
        print("[reverse-ip] 无有效 IP, 跳过", file=sys.stderr)
        write_encrypted("reverse_ip", {
            "target": target,
            "ips_checked": 0,
            "found_domains": [],
            "elapsed_s": 0,
        })
        return 0

    all_domains: dict[str, list[str]] = {}  # ip -> domains
    total_found = 0

    for ip in ips[:10]:  # 限制查询 IP 数量
        print(f"[reverse-ip] 查询 {ip} ...", file=sys.stderr)
        domains = set()

        # 方法 1: hackertarget
        d1 = hackertarget_reverse_ip(ip)
        domains.update(d1)
        print(f"  hackertarget: {len(d1)} 域名", file=sys.stderr)

        # 方法 2: crt.sh (证书透明度)
        d2 = crt_sh_same_ip(ip)
        domains.update(d2)
        print(f"  crt.sh: {len(d2)} 域名", file=sys.stderr)

        # 过滤: 只保留与目标组织相关的域名
        related = _filter_related(domains, target)
        if related:
            all_domains[ip] = sorted(related)
            total_found += len(related)
            print(f"  关联域名: {len(related)} 个", file=sys.stderr)

        time.sleep(1)  # 避免 API 限流

    elapsed = time.time() - t0
    print(f"\n[reverse-ip] 总计: {total_found} 关联域名, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("reverse_ip", {
        "target": target,
        "ips_checked": len(ips[:10]),
        "found_domains": all_domains,
        "total_found": total_found,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


def _filter_related(domains: set[str], target: str) -> set[str]:
    """过滤出与目标组织相关的域名."""
    related = set()
    target_base = target.split(".")[0]  # e.g., "cartmanager" from "cartmanager.net"

    for d in domains:
        # 包含目标域名
        if target in d:
            related.add(d)
            continue
        # 包含目标基础名称
        if target_base in d.lower():
            related.add(d)
            continue
        # 同一 TLD 下的相似域名
        parts = d.rsplit(".", 1)
        if len(parts) == 2:
            name = parts[0]
            # 相似度检查 (简单包含)
            if target_base in name or name in target_base:
                related.add(d)

    return related


if __name__ == "__main__":
    sys.exit(main())
