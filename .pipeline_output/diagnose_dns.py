"""
diagnose_dns.py — 诊断当前环境的 DNS 劫持状况

输出:
  - 系统默认 DNS 解析 cartmanager.net
  - 8.8.8.8 解析
  - 1.1.1.1 解析
  - 9.9.9.9 解析
  - DoH 解析 (Google + Cloudflare)
  - 结论
"""
import json
import socket
import subprocess
import sys


def nslookup(server: str, host: str) -> str:
    try:
        r = subprocess.run(
            ["nslookup", host, server],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout
    except Exception as e:
        return f"FAIL: {e}"


def getent(host: str) -> str:
    try:
        r = subprocess.run(
            ["getent", "hosts", host],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout or "(empty)"
    except Exception as e:
        return f"FAIL: {e}"


def doh_google(host: str) -> str:
    try:
        import requests
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=10,
        )
        return r.text
    except Exception as e:
        return f"FAIL: {e}"


def doh_cloudflare(host: str) -> str:
    try:
        import requests
        r = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=10,
        )
        return r.text
    except Exception as e:
        return f"FAIL: {e}"


def udp_dnspython(host: str, ns: str) -> str:
    try:
        import dns.resolver
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ns]
        r.timeout = 5
        r.lifetime = 8
        answers = r.resolve(host, "A")
        return ", ".join(str(a.address) for a in answers)
    except Exception as e:
        return f"FAIL: {type(e).__name__}: {str(e)[:100]}"


def main():
    host = "cartmanager.net"
    print("=" * 60)
    print(f"DNS 诊断 -> {host}")
    print("=" * 60)

    print("\n[1] 系统默认 (getent/socket):")
    try:
        sys_ip = socket.gethostbyname(host)
        print(f"  socket.gethostbyname: {sys_ip}")
    except Exception as e:
        print(f"  socket FAIL: {e}")
    print(f"  getent hosts: {getent(host).strip()}")

    print("\n[2] nslookup (走系统 stack, 但显式 server):")
    for ns in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
        print(f"  --- {ns} ---")
        out = nslookup(ns, host)
        for line in out.splitlines():
            print(f"    {line}")

    print("\n[3] dnspython UDP/53 直连 (完全绕开系统 stack):")
    for ns in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
        print(f"  {ns} -> {udp_dnspython(host, ns)}")

    print("\n[4] DoH (HTTPS, 完全绕开 UDP/53):")
    print(f"  dns.google     -> {doh_google(host)[:200]}")
    print(f"  cloudflare     -> {doh_cloudflare(host)[:200]}")

    print("\n[5] 结论判定:")
    import requests
    try:
        ip_doh = []
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=10,
        )
        for a in r.json().get("Answer", []):
            if a.get("type") == 1:
                ip_doh.append(a["data"])
        print(f"  DoH 真实 IP: {ip_doh}")
    except Exception as e:
        print(f"  DoH FAIL: {e}")


if __name__ == "__main__":
    main()
