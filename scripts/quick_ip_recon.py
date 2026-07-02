"""快速 IP 侦察脚本 - 针对单个 IP 地址."""
from __future__ import annotations

import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# 添加 recon 目录到路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "recon"))
from _common import http_get

TARGET_IP = "142.171.54.2"
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 8888, 9000, 9200, 11211, 27017, 6379, 5432]
COMMON_PATHS = [
    "/", "/admin", "/login", "/api", "/api/v1", "/api/v2", "/swagger", "/docs",
    "/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/administrator",
    "/phpmyadmin", "/mysql", "/console", "/dashboard", "/panel", "/cpanel",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config", "/server-status",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/debug", "/trace", "/metrics", "/health", "/info", "/status",
    "/api/docs", "/api/swagger", "/openapi.json", "/graphql",
    "/v1", "/v2", "/v3", "/version", "/config", "/setup", "/install",
    "/backup", "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/db", "/database", "/data", "/files", "/uploads", "/media",
    "/static", "/assets", "/css", "/js", "/images", "/img",
    "/test", "/dev", "/staging", "/demo", "/beta", "/alpha",
    "/user", "/users", "/account", "/accounts", "/profile", "/auth",
    "/oauth", "/sso", "/register", "/signup", "/forgot-password",
    "/admin/login", "/admin/dashboard", "/admin/users", "/admin/config",
    "/wp-json", "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/server-info", "/server-status", "/phpinfo.php", "/info.php",
    "/.well-known/security.txt", "/security.txt", "/humans.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/favicon.ico",
    "/apple-touch-icon.png", "/manifest.json", "/browserconfig.xml",
    "/.DS_Store", "/Thumbs.db", "/web.sitemap", "/sitemap",
    "/.svn/entries", "/.svn/wc.db", "/.git/HEAD", "/.git/index",
    "/.gitignore", "/.gitattributes", "/.gitmodules", "/.git/config",
    "/.git/description", "/.git/hooks", "/.git/info", "/.git/objects",
    "/.git/refs", "/.git/logs", "/.git/FETCH_HEAD", "/.git/ORIG_HEAD",
]


def reverse_ip_lookup(ip: str) -> list[str]:
    """反向 IP 查找 - 查找同一 IP 上的其他域名."""
    print(f"\n[1/3] 反向 IP 查找: {ip}")
    domains = set()

    # 方法 1: hackertarget
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        r = http_get(url, timeout=15, verify=False)
        if r and r.status_code == 200:
            text = r.text.strip()
            if "error" not in text.lower() and "api count" not in text.lower():
                for line in text.split("\n"):
                    line = line.strip()
                    if line and "." in line:
                        domains.add(line.lower())
        print(f"  hackertarget: {len(domains)} 个域名")
    except Exception as e:
        print(f"  hackertarget 错误: {e}")

    # 方法 2: viewdns
    try:
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey=demo&output=json"
        r = http_get(url, timeout=15, verify=False)
        if r and r.status_code == 200:
            data = r.json()
            for d in data.get("response", {}).get("domains", []):
                domains.add(d["name"].lower())
        print(f"  viewdns: {len(domains)} 个域名 (累计)")
    except Exception as e:
        print(f"  viewdns 错误: {e}")

    return sorted(domains)


def scan_ports(ip: str, ports: list[int]) -> dict[int, str]:
    """扫描端口."""
    print(f"\n[2/3] 端口扫描: {ip} ({len(ports)} 个端口)")
    open_ports: dict[int, str] = {}

    def probe_port(port: int) -> tuple[int, str | None]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # 尝试获取 banner
                try:
                    sock.settimeout(1)
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:100]
                except Exception:
                    banner = ""
                sock.close()
                return port, banner
            sock.close()
        except Exception:
            pass
        return port, None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(probe_port, p): p for p in ports}
        for fut in as_completed(futures):
            port, banner = fut.result()
            if banner is not None:
                open_ports[port] = banner
                print(f"  [OPEN] Port {port}: {banner[:50]}...")

    return open_ports


def dir_brute_force(ip: str, paths: list[str]) -> list[dict]:
    """目录爆破."""
    print(f"\n[3/3] 目录爆破: http://{ip}/ ({len(paths)} 个路径)")
    found: list[dict] = []

    def probe_path(path: str) -> dict | None:
        url = f"http://{ip}{path}"
        try:
            r = http_get(url, timeout=5, verify=False, allow_redirects=False)
            if r and r.status_code < 404:
                return {
                    "path": path,
                    "status": r.status_code,
                    "length": len(r.content),
                    "title": _extract_title(r.text) if r.text else "",
                    "content_type": r.headers.get("Content-Type", ""),
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(probe_path, p): p for p in paths}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found.append(result)
                print(f"  [FOUND] {result['path']} -> {result['status']} ({result['length']} bytes)")

    return found


def _extract_title(html: str) -> str:
    """从 HTML 中提取 title."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def main():
    print("=" * 60)
    print(f"快速 IP 侦察 - 目标: {TARGET_IP}")
    print("=" * 60)

    t0 = time.time()

    # 1. 反向 IP 查找
    domains = reverse_ip_lookup(TARGET_IP)

    # 2. 端口扫描
    open_ports = scan_ports(TARGET_IP, COMMON_PORTS)

    # 3. 目录爆破
    found_paths = dir_brute_force(TARGET_IP, COMMON_PATHS)

    elapsed = time.time() - t0

    # 输出结果
    print("\n" + "=" * 60)
    print("侦察结果汇总")
    print("=" * 60)

    print(f"\n[反向 IP 查找] 发现 {len(domains)} 个域名:")
    for d in domains[:20]:
        print(f"  - {d}")
    if len(domains) > 20:
        print(f"  ... 还有 {len(domains) - 20} 个")

    print(f"\n[端口扫描] 发现 {len(open_ports)} 个开放端口:")
    for port, banner in sorted(open_ports.items()):
        service = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
                   8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt",
                   3000: "Dev", 5000: "Dev", 8000: "HTTP-Alt", 9000: "HTTP-Alt",
                   9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
                   6379: "Redis", 5432: "PostgreSQL"}.get(port, "Unknown")
        print(f"  - {port}/{service}: {banner[:50]}..." if banner else f"  - {port}/{service}")

    print(f"\n[目录爆破] 发现 {len(found_paths)} 个路径:")
    for item in sorted(found_paths, key=lambda x: x["status"]):
        print(f"  - {item['path']} -> {item['status']} ({item['length']} bytes) {item['title']}")

    print(f"\n总耗时: {elapsed:.1f} 秒")

    # 保存结果
    output = {
        "target": TARGET_IP,
        "domains": domains,
        "open_ports": {str(k): v for k, v in open_ports.items()},
        "found_paths": found_paths,
        "elapsed_s": round(elapsed, 1),
    }
    out_path = Path(__file__).resolve().parent / "ip_recon_result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n结果已保存: {out_path}")


if __name__ == "__main__":
    main()
