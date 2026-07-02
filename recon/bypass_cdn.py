"""CDN real IP detection - bypass CDN to find real server addr.

Phase 1: Read DNS records
Phase 2: Detect CDN via headers and known IP ranges
Phase 3: Multiple bypass methods if CDN detected
Phase 4: Verify candidate IPs
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dns.resolver
import dns.query
import dns.zone

from _common import get_target, write_encrypted, http_get, _read_encrypted

CDN_RANGES: list[ipaddress.ip_network] = []
ROOT = Path(__file__).resolve().parent


def _load_cdn_ranges() -> list[ipaddress.ip_network]:
    ranges: list[ipaddress.ip_network] = []
    path = ROOT / "cdn-ranges.txt"
    if not path.exists():
        print(f"  [WARN] cdn-ranges.txt not found", file=sys.stderr)
        return ranges
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ranges.append(ipaddress.ip_network(line, strict=False))
        except ValueError as e:
            print(f"  [WARN] invalid CIDR: {line} ({e})", file=sys.stderr)
    print(f"  [CDN] loaded {len(ranges)} ranges", file=sys.stderr)
    return ranges


CDN_RANGES = _load_cdn_ranges()


def _is_cdn_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in CDN_RANGES:
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False


def _detect_cdn_from_headers(headers: dict[str, str]) -> list[str]:
    detected: list[str] = []
    h = {k.lower(): v for k, v in headers.items()}
    if "server" in h:
        s = h["server"].lower()
        if "cloudflare" in s:
            detected.append("Cloudflare")
        elif "akamai" in s or "akamaighost" in s:
            detected.append("Akamai")
        elif "fastly" in s:
            detected.append("Fastly")
        elif "cloudfront" in s or "amazons3" in s:
            detected.append("CloudFront")
        elif "sucuri" in s:
            detected.append("Sucuri")
    via = h.get("via", "")
    if "cloudflare" in via.lower() and "Cloudflare" not in detected:
        detected.append("Cloudflare")
    if "akamai" in via.lower() and "Akamai" not in detected:
        detected.append("Akamai")
    x_cache = h.get("x-cache", "")
    if "cloudflare" in x_cache.lower() and "Cloudflare" not in detected:
        detected.append("Cloudflare")
    if "cf-ray" in h and "Cloudflare" not in detected:
        detected.append("Cloudflare")
    if "x-akamai-request-id" in h and "Akamai" not in detected:
        detected.append("Akamai")
    if "x-amz-cf-id" in h and "CloudFront" not in detected:
        detected.append("CloudFront")
    if "x-sucuri-id" in h and "Sucuri" not in detected:
        detected.append("Sucuri")
    return list(set(detected))


def _fetch_history_ips(domain: str) -> set[str]:
    ips: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return ips
    try:
        entries = r.json()
        for entry in entries:
            for field in ("ip_address",):
                ip_val = entry.get(field, "")
                if ip_val:
                    try:
                        ipaddress.ip_address(ip_val)
                        ips.add(ip_val)
                    except ValueError:
                        pass
    except Exception as e:
        print(f"  [crt.sh history] error: {e}", file=sys.stderr)
    return ips


def _fetch_mx_same_subnet(domain: str) -> set[str]:
    ips: set[str] = set()
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
        for mx in mx_hosts[:3]:
            try:
                mx_answers = dns.resolver.resolve(mx, "A", lifetime=5)
                mx_ip = str(mx_answers[0].address)
                parts = mx_ip.split(".")
                base = ".".join(parts[:3])
                for i in range(1, 255):
                    ips.add(f"{base}.{i}")
            except Exception:
                continue
    except Exception:
        pass
    return ips


def _try_axfr(domain: str, ns_servers: list[str]) -> list[str]:
    results: list[str] = []
    for ns in ns_servers[:3]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5, lifetime=10))
            for name, node in zone.nodes.items():
                str_name = str(name)
                if str_name == "@":
                    continue
                fqdn = f"{str_name}.{domain}" if str_name else domain
                results.append(fqdn)
        except Exception:
            continue
    return results


def _ssl_cert_hostname(domain: str) -> set[str]:
    hosts: set[str] = set()
    for port in (443, 8443, 4433):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        for entry in cert.get("subjectAltName", []):
                            if entry[0] == "DNS":
                                hosts.add(entry[1])
        except Exception:
            continue
    return hosts


def _scan_http_title(ip: str) -> dict[str, Any]:
    result: dict[str, Any] = {"ip": ip, "status": None, "title": "", "server": ""}
    for port in (80, 443, 8080, 8443):
        try:
            scheme = "https" if port in (443, 8443) else "http"
            r = http_get(f"{scheme}://{ip}", timeout=5)
            if r and r.status_code:
                result["status"] = r.status_code
                result["server"] = r.headers.get("Server", "")
                result["port"] = port
                result["scheme"] = scheme
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.IGNORECASE | re.DOTALL)
                if m:
                    result["title"] = m.group(1).strip()[:200]
                break
        except Exception:
            continue
    return result


def main() -> int:
    target = get_target()
    t0 = time.time()
    print(f"[bypass_cdn] target: {target}", file=sys.stderr)

    dns_data = None
    try:
        dns_data = _read_encrypted("dns_authoritative")
    except SystemExit:
        dns_data = None
    cdn_ips: set[str] = set()
    real_ips: set[str] = set()
    candidate_ips: set[str] = set()

    if dns_data:
        records = dns_data.get("records", {}).get(target, [])
        for rec in records:
            if rec.get("type") == "A" and rec.get("value"):
                ip_str = rec["value"]
                if _is_cdn_ip(ip_str):
                    cdn_ips.add(ip_str)
                else:
                    real_ips.add(ip_str)

    cdn_headers: list[str] = []
    r = http_get(f"https://{target}", timeout=10)
    if r:
        cdn_headers = _detect_cdn_from_headers(dict(r.headers))

    if not cdn_ips and not cdn_headers:
        write_encrypted("cdn_bypass", {
            "target": target,
            "cdn_detected": False,
            "cdn_ips": sorted(cdn_ips),
            "cdn_providers": cdn_headers,
            "real_ips": sorted(real_ips),
            "candidate_ips": sorted(real_ips | candidate_ips),
            "elapsed_s": round(time.time() - t0, 1),
        })
        return 0

    history_ips = _fetch_history_ips(target)
    for ip in sorted(history_ips):
        if not _is_cdn_ip(ip):
            candidate_ips.add(ip)

    cert_hosts = _ssl_cert_hostname(target)
    for host in sorted(cert_hosts):
        try:
            a = dns.resolver.resolve(host, "A", lifetime=3)
            for rr in a:
                ip_str = str(rr)
                if not _is_cdn_ip(ip_str):
                    candidate_ips.add(ip_str)
        except Exception:
            continue

    subnet_ips = _fetch_mx_same_subnet(target)
    for ip in subnet_ips:
        if not _is_cdn_ip(ip):
            candidate_ips.add(ip)

    ns_servers = []
    if dns_data:
        for rec in dns_data.get("records", {}).get(target, []):
            if rec.get("type") == "NS":
                ns_servers.append(rec["value"])
    axfr_results = _try_axfr(target, ns_servers)
    for fqdn in axfr_results:
        try:
            a = dns.resolver.resolve(fqdn, "A", lifetime=3)
            for rr in a:
                ip_str = str(rr)
                if not _is_cdn_ip(ip_str):
                    candidate_ips.add(ip_str)
        except Exception:
            continue

    verified: list[dict[str, Any]] = []

    def verify(ip_str: str) -> dict[str, Any]:
        return _scan_http_title(ip_str)

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(verify, ip): ip for ip in candidate_ips}
        for fut in as_completed(futs):
            r = fut.result()
            if r["status"] is not None:
                verified.append(r)

    elapsed = time.time() - t0
    write_encrypted("cdn_bypass", {
        "target": target,
        "cdn_detected": True,
        "cdn_ips": sorted(cdn_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "cdn_providers": cdn_headers,
        "real_ips": sorted(real_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "candidate_ips": sorted(candidate_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "verified_live": verified,
        "history_ip_count": len(history_ips),
        "cert_host_count": len(cert_hosts),
        "axfr_count": len(axfr_results),
        "methods_used": ["crt.sh_history", "ssl_cert_san", "mx_subnet", "axfr"],
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
