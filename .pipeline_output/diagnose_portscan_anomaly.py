"""
诊断: 两个 IP (192.41.22.32, 192.41.22.47) 同时返回 33 个相同开放端口
—— 是脚本 bug (硬编码), 还是 TUN 在 TCP 层做了劫持?
"""
from __future__ import annotations
import socket
import ssl
import ipaddress
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IPS = ["192.41.22.32", "192.41.22.47"]
PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521,
         2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 5432, 5900, 6379,
         8000, 8080, 8081, 8443, 8888, 9200, 9300, 11211, 27017]


def check_ipaddr(ip: str) -> dict:
    a = ipaddress.ip_address(ip)
    return {
        "ip": ip,
        "is_global": a.is_global,
        "is_private": a.is_private,
        "is_reserved": a.is_reserved,
        "is_loopback": a.is_loopback,
        "is_multicast": a.is_multicast,
        "is_unspecified": a.is_unspecified,
    }


def check_reverse_dns(ip: str, timeout: float = 5.0) -> dict:
    out = {"ip": ip, "ok": False, "hostname": None, "aliases": [], "err": None}
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        h, a, _ = socket.gethostbyaddr(ip)
        out["ok"] = True
        out["hostname"] = h
        out["aliases"] = a
    except Exception as e:
        out["err"] = repr(e)
    finally:
        socket.setdefaulttimeout(old)
    return out


def check_https_root(ip: str, timeout: float = 8.0) -> dict:
    out = {"ip": ip, "https": {}, "http": {}, "err": None}
    for scheme, port in (("https", 443), ("http", 80)):
        try:
            r = requests.get(
                f"{scheme}://{ip}:{port}/",
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"Host": "cartmanager.net", "User-Agent": "Mozilla/5.0"},
            )
            out[scheme] = {
                "status": r.status_code,
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
                "location": r.headers.get("Location"),
                "content_type": r.headers.get("Content-Type"),
                "body_sha256": __import__("hashlib").sha256(r.content).hexdigest()[:16],
                "body_len": len(r.content),
                "body_head": r.text[:200].replace("\n", " "),
            }
        except Exception as e:
            out[scheme] = {"err": repr(e)}
    return out


def check_tcp_diff(ip_a: str, ip_b: str, port: int = 80, timeout: float = 4.0) -> dict:
    """在两 IP 同端口上分别抓 SYN 后的 banner, 看是否真不同主机"""
    out = {}
    for ip in (ip_a, ip_b):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: cartmanager.net\r\n\r\n")
                except Exception:
                    pass
                try:
                    banner = s.recv(256)
                except Exception:
                    banner = b""
                out[ip] = banner[:200].decode("latin-1", errors="replace")
        except Exception as e:
            out[ip] = f"ERR {e!r}"
    return out


def check_ssl_cert(ip: str, port: int = 443, timeout: float = 6.0) -> dict:
    out = {"ip": ip}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                cert = s.getpeercert(binary_form=True)
                der = cert
                import hashlib
                out["sha256"] = hashlib.sha256(der).hexdigest()
                out["subject_alt_name"] = "(cert verify off)"
    except Exception as e:
        out["err"] = repr(e)
    return out


def main():
    print("=" * 72)
    print("[1] ipaddress 标记")
    for ip in IPS:
        print(json.dumps(check_ipaddr(ip), ensure_ascii=False, indent=2))

    print("\n" + "=" * 72)
    print("[2] 反向 DNS")
    for ip in IPS:
        print(json.dumps(check_reverse_dns(ip), ensure_ascii=False, indent=2))

    print("\n" + "=" * 72)
    print("[3] HTTP(S) 根请求, Host=cartmanager.net")
    for ip in IPS:
        print(json.dumps(check_https_root(ip), ensure_ascii=False, indent=2))

    print("\n" + "=" * 72)
    print("[4] 80 端口 HEAD 报文比对")
    print(json.dumps(check_tcp_diff(IPS[0], IPS[1], 80), ensure_ascii=False, indent=2))

    print("\n" + "=" * 72)
    print("[5] 443 证书指纹")
    for ip in IPS:
        print(json.dumps(check_ssl_cert(ip, 443), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
