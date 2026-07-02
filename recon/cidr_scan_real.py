"""C 段真实扫描 — 扫描目标 IP 的 C 段(同网段)发现存活主机.

功能:
  1. 从目标 IP 提取 C 段 (x.x.x.0/24)
  2. 扫描 C 段内存活主机 (常见 Web 端口)
  3. 对存活主机做反向 IP 查找
  4. 过滤 TEST-NET/私有地址

输出: out/cidr_real.data.enc + key.enc
"""
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from _common import get_target, write_encrypted, http_get, _read_encrypted

ROOT = os.path.dirname(os.path.abspath(__file__))

# 常见 Web 端口
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 7001, 8081, 8880, 9090]


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

    try:
        pd = _read_encrypted("ports")
        for ip in pd.get("open_ports", {}):
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
    # 198.18.0.0/15 (TEST-NET-1)
    if octets[0] == 198 and octets[1] in (18, 19):
        return True
    # 100.64.0.0/10
    if octets[0] == 100 and 64 <= octets[1] <= 127:
        return True
    # 224.0.0.0/4 (组播)
    if octets[0] >= 224:
        return True
    return False


def _get_c_class(ip: str) -> str | None:
    """从 IP 提取 C 段."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def scan_port(ip: str, port: int, timeout: float = 2.0) -> dict | None:
    """扫描单个端口."""
    url = f"http://{ip}:{port}/" if port == 80 else f"http://{ip}:{port}/"
    if port == 443 or port == 8443:
        url = f"https://{ip}:{port}/"

    try:
        r = http_get(url, timeout=timeout, verify=False)
        if r and r.status_code < 500:
            return {
                "ip": ip,
                "port": port,
                "status": r.status_code,
                "server": r.headers.get("Server", ""),
                "title": _extract_title(r.text or ""),
            }
    except Exception:
        pass
    return None


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def scan_c_class(c_base: str, max_hosts: int = 20) -> list[dict]:
    """扫描 C 段内的存活主机."""
    results = []
    ips_to_scan = [f"{c_base}.{i}" for i in range(1, min(max_hosts + 1, 255))]

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {}
        for ip in ips_to_scan:
            for port in WEB_PORTS[:4]:  # 只扫前 4 个常用端口
                futs[ex.submit(scan_port, ip, port, 1.5)] = (ip, port)

        for fut in as_completed(futs):
            r = fut.result()
            if r:
                results.append(r)

    return results


def main() -> int:
    target = get_target()
    print(f"[cidr-real] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 获取目标 IP
    ips = get_target_ips()
    print(f"[cidr-real] 目标 IP: {len(ips)} 个", file=sys.stderr)

    if not ips:
        print("[cidr-real] 无有效 IP, 跳过", file=sys.stderr)
        write_encrypted("cidr_real", {
            "target": target,
            "c_classes_scanned": 0,
            "alive_hosts": [],
            "elapsed_s": 0,
        })
        return 0

    # 提取 C 段
    c_classes = set()
    for ip in ips:
        c = _get_c_class(ip)
        if c:
            c_classes.add(c)

    print(f"[cidr-real] C 段: {len(c_classes)} 个", file=sys.stderr)

    all_alive = []
    for c_base in sorted(c_classes)[:3]:  # 限制扫描 C 段数量
        print(f"[cidr-real] 扫描 {c_base}.0/24 ...", file=sys.stderr)
        alive = scan_c_class(c_base, max_hosts=20)
        all_alive.extend(alive)
        print(f"  存活: {len(alive)} 个", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[cidr-real] 总计: {len(all_alive)} 存活主机, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("cidr_real", {
        "target": target,
        "c_classes_scanned": len(c_classes)[:3],
        "alive_hosts": all_alive,
        "total_alive": len(all_alive),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
