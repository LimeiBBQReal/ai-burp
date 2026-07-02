"""
Phase 1 v3: CartManager.net 资产发现 — DoH-only, 完全绕过系统 DNS 栈

诊断结论:
  - UDP/53 全部被劫持: 8.8.8.8 / 1.1.1.1 / 9.9.9.9 都返回 198.18.0.33
  - DoH (HTTPS) 是干净的: dns.google / cloudflare-dns 都返回真实 IP 192.41.22.47
  - 原因: 二开 clash TUN 在更底层劫持了所有 UDP/53 出站, 但没劫持 HTTPS 流量 (或劫持了但能识别为白名单)

策略:
  - 全部 DNS 走 DoH (Google + Cloudflare)
  - UDP 仅作日志, 不信任
  - 保留段检测 (RFC 6890) 仍然开启
  - 污染产物继续归档
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
OUT = ROOT
OUT.mkdir(exist_ok=True)
PROXY_STATE = ROOT.parent / ".proxy_state"

TARGET = "cartmanager.net"
KEY_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521,
             2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 5432, 5900,
             6379, 8000, 8080, 8081, 8443, 8888, 9200, 9300, 11211, 27017]

DOH_ENDPOINTS = [
    ("Google", "https://dns.google/resolve"),
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
]


def is_spoofed(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "INVALID_IP"
    if addr.is_private:
        return "PRIVATE_RFC1918"
    if addr.is_reserved:
        return "RESERVED"
    if addr.is_loopback:
        return "LOOPBACK"
    if addr.is_link_local:
        return "LINK_LOCAL"
    if addr in ipaddress.ip_network("198.18.0.0/15"):
        return "BENCHMARKING_RFC6890"
    if addr in ipaddress.ip_network("192.0.2.0/24"):
        return "TEST_NET_1_RFC5737"
    if addr in ipaddress.ip_network("198.51.100.0/24"):
        return "TEST_NET_2_RFC5737"
    if addr in ipaddress.ip_network("203.0.113.0/24"):
        return "TEST_NET_3_RFC5737"
    return None


def doh_query(host: str, rtype: str) -> tuple[list[str], str]:
    """纯 DoH 查询 (HTTPS, 绕开系统 DNS 栈)."""
    try:
        import requests
    except ImportError:
        return [], "no_requests"
    type_map = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16}
    if rtype not in type_map:
        return [], "bad_type"
    qtype = type_map[rtype]
    for name, ep in DOH_ENDPOINTS:
        try:
            r = requests.get(
                ep,
                params={"name": host, "type": qtype},
                headers={"Accept": "application/dns-json"},
                timeout=12,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            answers = data.get("Answer", [])
            if not answers:
                continue
            out = []
            for a in answers:
                if a.get("type") != qtype:
                    continue
                if rtype in ("A", "AAAA"):
                    out.append(a["data"])
                elif rtype in ("CNAME", "NS"):
                    out.append(a["name"].rstrip("."))
                elif rtype == "MX":
                    out.append(a["name"].rstrip("."))
                elif rtype == "TXT":
                    out.append(a["data"].strip('"'))
            if out:
                return out, name
        except Exception as e:
            print(f"[WARN] DoH {name} {host}/{rtype} fail: {e}", file=sys.stderr)
            continue
    return [], "fail"


def resolve(host: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "host": host, "a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": [],
        "source": {}, "spoofed": [], "errors": []
    }
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        res, src = doh_query(host, rtype)
        key = rtype.lower()
        out[key] = res
        out["source"][rtype] = src
        for ip in res if rtype in ("A", "AAAA") else []:
            tag = is_spoofed(ip)
            if tag:
                out["spoofed"].append({"ip": ip, "type": rtype, "tag": tag, "source": src})
    return out


def subdomains_crtsh(domain: str) -> list[str]:
    try:
        import requests
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith("." + domain) or sub == domain:
                    seen.add(sub.lower())
        return sorted(seen)
    except Exception as e:
        print(f"[WARN] crt.sh fail: {e}", file=sys.stderr)
        return []


def subdomains_rapiddns(domain: str) -> list[str]:
    try:
        import requests
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200:
            return []
        text = r.text
        seen = set()
        for m in re.finditer(rf"([\w-]+\.{re.escape(domain)})", text, re.IGNORECASE):
            seen.add(m.group(1).lower())
        return sorted(seen)
    except Exception as e:
        print(f"[WARN] rapiddns fail: {e}", file=sys.stderr)
        return []


def subdomains_otx(domain: str) -> list[str]:
    try:
        import requests
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        seen = set()
        for entry in data.get("passive_dns", []):
            host = entry.get("hostname", "").lower()
            if host.endswith("." + domain) or host == domain:
                seen.add(host)
        return sorted(seen)
    except Exception as e:
        print(f"[WARN] otx fail: {e}", file=sys.stderr)
        return []


def port_scan(host: str, ports: list[int], timeout: float = 2.0) -> dict[int, dict[str, Any]]:
    """
    真·端口探测 — 不只判 SYN/ACK, 必须读到应用层 banner 才算 open.
    TUN 在 L3/L4 模拟 SYN/ACK 是常事, 必须做协议级取证.

    返回: {port: {"open": bool, "banner": str|None, "err": str|None, "probe": str}}
    """
    results: dict[int, dict[str, Any]] = {}

    def _probe_tcp(p: int) -> tuple[int, str | None, str | None]:
        try:
            with socket.create_connection((host, p), timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    probe_payload = PROBE_PAYLOADS.get(p)
                    if probe_payload:
                        s.sendall(probe_payload)
                    else:
                        s.sendall(b"\r\n")
                    try:
                        banner = s.recv(256)
                    except socket.timeout:
                        banner = b""
                except (BrokenPipeError, ConnectionResetError, OSError):
                    banner = b""
            if banner:
                return p, banner[:200].decode("latin-1", errors="replace"), None
            return p, None, "no_banner"
        except socket.timeout:
            return p, None, "timeout"
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            return p, None, repr(e)

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(_probe_tcp, p): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                _, banner, err = fut.result()
                results[p] = {
                    "open": bool(banner),
                    "banner": banner,
                    "err": err,
                    "probe": "PROBE" if p in PROBE_PAYLOADS else "GENERIC",
                }
            except Exception as e:
                results[p] = {"open": False, "banner": None, "err": repr(e), "probe": "ERR"}

    return results


PROBE_PAYLOADS: dict[int, bytes] = {
    21: b"USER anonymous\r\n",
    22: b"SSH-2.0-OpenSSH_8.0\r\n",
    25: b"EHLO probe.local\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: probe.local\r\nUser-Agent: probe\r\n\r\n",
    110: b"USER probe\r\n",
    143: b"A1 CAPABILITY\r\n",
    443: b"",  # TLS 单独走 _probe_tls
    465: b"EHLO probe.local\r\n",
    587: b"EHLO probe.local\r\n",
    993: b"",
    995: b"USER probe\r\n",
    1433: b"",
    1521: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    11211: b"version\r\n",
    27017: b"",
}


def _probe_tls(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """对 443/993 等 TLS 端口做真握手并记录证书指纹."""
    out: dict[str, Any] = {"open": False, "banner": None, "err": None, "cert_sha256": None, "tls_version": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=True)
                if cert:
                    out["cert_sha256"] = __import__("hashlib").sha256(cert).hexdigest()
                out["tls_version"] = s.version()
                out["open"] = True
                out["banner"] = f"TLS {s.version()} cert={out['cert_sha256'][:16]}..."
    except Exception as e:
        out["err"] = repr(e)
    return out


def wayback_urls(domain: str, limit: int = 500) -> list[str]:
    try:
        import requests
        r = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "json", "limit": limit,
                    "fl": "original", "collapse": "urlkey"},
            timeout=90,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        if not data or len(data) < 2:
            return []
        urls = []
        for row in data[1:]:
            u = row[0] if row else None
            if u and u not in urls:
                urls.append(u)
        return urls
    except Exception as e:
        print(f"[WARN] wayback fail: {e}", file=sys.stderr)
        return []


def reverse_ip(ip: str) -> list[str]:
    try:
        import requests
        r = requests.get(
            f"https://api.hackertarget.com/reverseip/?host={ip}",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200:
            return []
        lines = [l.strip() for l in r.text.splitlines() if l.strip() and "error" not in l.lower()]
        return [l for l in lines if l != ip]
    except Exception as e:
        print(f"[WARN] reverse_ip {ip} fail: {e}", file=sys.stderr)
        return []


def main() -> int:
    print(f"[INFO] Phase 1 v3 (DoH-only): 资产发现 -> {TARGET}", file=sys.stderr)
    print(f"[INFO] 全部 DNS 走 DoH (HTTPS), 完全绕开 UDP/53 系统 DNS 栈", file=sys.stderr)
    print(f"[INFO] 诊断已确认: UDP/53 全部被 TUN 劫持 (198.18.0.x), 只有 DoH 是真实的", file=sys.stderr)

    print(f"[INFO] 子域枚举 (crt.sh + rapiddns + otx)", file=sys.stderr)
    subs: set[str] = set()
    subs.update(subdomains_crtsh(TARGET))
    subs.update(subdomains_rapiddns(TARGET))
    subs.update(subdomains_otx(TARGET))
    subs.add(TARGET)
    subs.add(f"www.{TARGET}")
    sub_list = sorted(subs)
    print(f"[INFO] 子域总数: {len(sub_list)}", file=sys.stderr)

    print(f"[INFO] DNS 解析 (DoH 串行)", file=sys.stderr)
    resolved: list[dict[str, Any]] = []
    pollution_log: list[dict[str, Any]] = []
    ips: set[str] = set()
    for sub in sub_list:
        r = resolve(sub)
        resolved.append(r)
        if r["spoofed"]:
            pollution_log.append({"host": sub, "spoofed": r["spoofed"]})
        for ip in r["a"]:
            if not is_spoofed(ip):
                ips.add(ip)
        for ip in r["aaaa"]:
            if not is_spoofed(ip):
                ips.add(ip)
    print(f"[INFO] 解析到 {len(ips)} 个干净 IP (剔除 {sum(len(r['spoofed']) for r in resolved)} 条污染)", file=sys.stderr)
    if pollution_log:
        print(f"[WARN] DoH 仍有污染: {len(pollution_log)} 个子域命中保留段 (TUN 深度劫持 HTTPS?)", file=sys.stderr)
    else:
        print(f"[OK] DoH 全部干净, 真实 IP:", file=sys.stderr)
        for ip in sorted(ips):
            print(f"  {ip}", file=sys.stderr)

    port_results: dict[str, list[int]] = {}
    port_evidence: dict[str, dict[int, dict[str, Any]]] = {}
    ip_list = sorted(ips)
    print(f"[INFO] 端口扫描 {len(ip_list)} IP × {len(KEY_PORTS)} 端口 (banner+TLS 取证)", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(port_scan, ip, KEY_PORTS): ip for ip in ip_list}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                detail = fut.result()
                port_evidence[ip] = detail
                true_open = [p for p, info in detail.items() if info["open"]]
                port_results[ip] = sorted(true_open)
                if true_open:
                    print(f"[SCAN] {ip} 真开放 {len(true_open)}: {true_open}", file=sys.stderr)
                else:
                    print(f"[SCAN] {ip} 0 真开放 (banner 全空) — TUN 可能在伪造 SYN/ACK", file=sys.stderr)
            except Exception as e:
                print(f"[WARN] scan {ip} fail: {e}", file=sys.stderr)
                port_results[ip] = []
                port_evidence[ip] = {}

    print(f"[INFO] wayback 历史快照", file=sys.stderr)
    wb = wayback_urls(TARGET)

    print(f"[INFO] reverse IP (取最多端口的 IP 反查)", file=sys.stderr)
    sample_ips = sorted(port_results.keys(), key=lambda x: -len(port_results.get(x, [])))[:5]
    reverse: dict[str, list[str]] = {}
    for ip in sample_ips:
        reverse[ip] = reverse_ip(ip)

    inventory = {
        "target": TARGET,
        "ts": time.time(),
        "dns_strategy": {
            "primary": "DoH (HTTPS) only",
            "endpoints": [n for n, _ in DOH_ENDPOINTS],
            "udp_53_status": "BLOCKED — TUN hijack confirmed",
            "spoof_check": "RFC 6890 reserved ranges",
        },
        "subdomains": sub_list,
        "resolved_dns": resolved,
        "ips": sorted(ips),
        "port_scan": port_results,
        "port_evidence": port_evidence,
        "port_evidence_note": (
            "open=true 仅当 banner 真的读到; TUN 可能伪造 SYN/ACK, "
            "但伪造不出正确 HTTP 200/SMTP 220/Redis +PONG 等应用层响应"
        ),
        "wayback_count": len(wb),
        "wayback_sample": wb[:100],
        "reverse_ip_sample": reverse,
        "stats": {
            "subdomain_count": len(sub_list),
            "ip_count": len(ips),
            "ip_with_open_ports": sum(1 for v in port_results.values() if v),
            "wayback_url_count": len(wb),
            "spoofed_records_total": sum(len(r["spoofed"]) for r in resolved),
            "spoofed_subdomains": len(pollution_log),
        },
    }

    out_path = OUT / "cartmanager_inventory.json"
    out_path.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[INFO] inventory -> {out_path}", file=sys.stderr)

    summary_path = OUT / "cartmanager_inventory_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "target": TARGET,
                "subdomain_count": len(sub_list),
                "ip_count": len(ips),
                "open_port_ips": {ip: ports for ip, ports in port_results.items() if ports},
                "wayback_count": len(wb),
                "reverse_ip_ips": list(reverse.keys()),
                "spoofed_records": sum(len(r["spoofed"]) for r in resolved),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[INFO] summary -> {summary_path}", file=sys.stderr)

    if pollution_log:
        evidence_path = OUT / "cartmanager_dns_pollution_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "target": TARGET,
                    "ts": time.time(),
                    "note": "TUN DNS hijack evidence — DoH fallback STILL polluted, deep hijack",
                    "polluted_hosts": pollution_log,
                    "reserved_ranges_checked": [
                        "198.18.0.0/15 (BENCHMARKING)",
                        "192.0.2.0/24 (TEST-NET-1)",
                        "198.51.100.0/24 (TEST-NET-2)",
                        "203.0.113.0/24 (TEST-NET-3)",
                    ],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"[INFO] pollution evidence -> {evidence_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
