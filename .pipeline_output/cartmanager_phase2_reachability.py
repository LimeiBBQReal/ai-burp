"""
Phase 2 — Reachability + 指纹 + 敏感文件穷举 (穷举模式, 监理)
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent
OUT = ROOT

INVENTORY = json.loads((OUT / "cartmanager_inventory.json").read_text(encoding="utf-8"))

PROXY_POOL = OUT.parent / ".proxy_state" / "cartmanager_proxy_pool.json"
PROXY_POOL_LIVE = OUT.parent / ".proxy_state" / "cartmanager_proxy_pool_live.json"
PROXY_STATE_DIR = OUT.parent / ".proxy_state"

TARGET = INVENTORY["target"]
SUBDOMAINS: list[str] = INVENTORY["subdomains"]
TRUE_OPEN_IPS: list[str] = [ip for ip, ports in INVENTORY["port_scan"].items() if ports]

HOSTS_TO_TRY: list[str] = sorted({TARGET, f"www.{TARGET}", *SUBDOMAINS})

SENSITIVE_PATHS: list[str] = [
    "/",
    "/index.html", "/index.php", "/index.asp",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap_index.xml.gz",
    "/.env", "/.env.bak", "/.env.local", "/.env.production", "/.env.example",
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/", "/.bzr/",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php",
    "/api/", "/api/v1/", "/api/v2/",
    "/v1/", "/v2/", "/v3/",
    "/swagger/", "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/health", "/healthz", "/status", "/ping",
    "/graphql", "/graphiql",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/web.config", "/WEB-INF/web.xml", "/crossdomain.xml",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/db.sql",
    "/config.php", "/config.php.bak", "/wp-config.php", "/wp-config.php.bak",
    "/configuration.php", "/configuration.php.bak",
    "/.htaccess", "/.htpasswd",
    "/cgi-bin/", "/cgi-bin/test-cgi",
    "/manager/", "/manager/html",
    "/console/", "/console/login",
    "/phpmyadmin/", "/pma/", "/myadmin/", "/mysql/",
    "/jenkins/", "/nexus/", "/gitlab/",
    "/.well-known/", "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/acme-challenge/",
    "/favicon.ico",
    "/crossdomain.xml",
    "/readme.md", "/README.md", "/CHANGELOG.md",
    "/humans.txt", "/security.txt",
    "/passwords.txt", "/password.txt", "/creds.txt",
    "/id_rsa", "/id_rsa.pub", "/ssh_key", "/.ssh/id_rsa",
    "/.DS_Store", "/Thumbs.db",
    "/wp-json/", "/wp-json/wp/v2/users",
    "/xmlrpc.php",
    "/elmah.axd", "/trace.axd", "/errorlog",
    "/server-status?auto", "/server-info?auto",
]

IP_PORT_PAIR: list[tuple[str, int]] = [(ip, 80) for ip in TRUE_OPEN_IPS]
for ip in TRUE_OPEN_IPS:
    IP_PORT_PAIR.append((ip, 443))

SENSITIVE_TOTAL = len(SENSITIVE_PATHS) * len(HOSTS_TO_TRY) * len(IP_PORT_PAIR)
print(f"[INFO] Phase 2 — reachability + 指纹 + 敏感文件穷举", file=sys.stderr)
print(f"[INFO] target={TARGET}", file=sys.stderr)
print(f"[INFO] true_open_ips={TRUE_OPEN_IPS}", file=sys.stderr)
print(f"[INFO] hosts_to_try={len(HOSTS_TO_TRY)}", file=sys.stderr)
print(f"[INFO] sensitive_paths={len(SENSITIVE_PATHS)}", file=sys.stderr)
print(f"[INFO] ip:port={len(IP_PORT_PAIR)} ({IP_PORT_PAIR})", file=sys.stderr)
print(f"[INFO] 理论请求数: {SENSITIVE_TOTAL}", file=sys.stderr)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "curl/8.0.1",
    "BurpSuite/2024 (https://portswigger.net)",
    "sqlmap/1.7",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]


def load_proxies() -> list[dict[str, Any]]:
    """从 Phase 0 池里挑 alive 代理, 没有就 None (直连)."""
    if not PROXY_STATE_DIR.exists():
        return []
    cands = []
    for fn in ("cartmanager_proxy_pool.json", "cartmanager_proxy_pool_live.json", "alive.yaml"):
        p = PROXY_STATE_DIR / fn
        if not p.exists():
            continue
        try:
            if fn.endswith(".json"):
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    cands.extend([x for x in data if isinstance(x, dict) and (x.get("alive") or x.get("status") == "alive")])
                elif isinstance(data, dict):
                    pool = data.get("alive") or data.get("proxies") or data
                    if isinstance(pool, list):
                        cands.extend([x for x in pool if isinstance(x, dict)])
        except Exception:
            pass
    out = []
    for c in cands:
        scheme = c.get("scheme") or c.get("protocol") or "http"
        host = c.get("host") or c.get("ip")
        port = c.get("port")
        if not (host and port):
            continue
        out.append({"scheme": scheme, "host": host, "port": int(port),
                    "user": c.get("user"), "pwd": c.get("password") or c.get("pwd")})
    return out[:50]


PROXIES = load_proxies()
print(f"[INFO] alive proxy candidates loaded: {len(PROXIES)}", file=sys.stderr)


def build_proxy_dict(p: dict[str, Any] | None) -> dict[str, str] | None:
    if not p:
        return None
    auth = ""
    if p.get("user"):
        auth = f"{p['user']}:{p.get('pwd','')}@"
    return {p["scheme"]: f"{p['scheme']}://{auth}{p['host']}:{p['port']}"}


def head_root(ip: str, port: int, host: str, ua: str, proxy: dict[str, Any] | None) -> dict[str, Any]:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = requests.get(
            url, timeout=8, verify=False, allow_redirects=True,
            headers={"Host": host, "User-Agent": ua,
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.9",
                     "Connection": "close"},
            proxies=build_proxy_dict(proxy),
        )
        body = r.content
        body_sha = hashlib.sha256(body).hexdigest()[:16]
        return {
            "ip": ip, "port": port, "host": host, "ua": ua,
            "status": r.status_code,
            "server": r.headers.get("Server"),
            "powered_by": r.headers.get("X-Powered-By"),
            "location": r.headers.get("Location"),
            "content_type": r.headers.get("Content-Type"),
            "content_length": r.headers.get("Content-Length"),
            "cookies": dict(r.headers).get("Set-Cookie", ""),
            "strict_transport": r.headers.get("Strict-Transport-Security"),
            "csp": r.headers.get("Content-Security-Policy"),
            "x_frame": r.headers.get("X-Frame-Options"),
            "body_sha256": body_sha,
            "body_len": len(body),
            "body_head": r.text[:500].replace("\n", " | "),
            "final_url": r.url,
            "history": [h.status_code for h in r.history],
        }
    except Exception as e:
        return {"ip": ip, "port": port, "host": host, "ua": ua, "err": repr(e)[:200]}


def probe_path(ip: str, port: int, host: str, path: str, ua: str, proxy: dict[str, Any] | None) -> dict[str, Any]:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}{path}"
    t0 = time.time()
    try:
        r = requests.request(
            "GET", url, timeout=6, verify=False, allow_redirects=False,
            headers={"Host": host, "User-Agent": ua,
                     "Accept": "*/*", "Connection": "close"},
            proxies=build_proxy_dict(proxy),
        )
        body = r.content
        body_sha = hashlib.sha256(body).hexdigest()[:16]
        interesting = (
            r.status_code not in (404, 403, 400) or
            len(body) > 0 and r.status_code != 404
        )
        return {
            "ip": ip, "port": port, "host": host, "path": path, "ua": ua,
            "status": r.status_code,
            "content_type": r.headers.get("Content-Type"),
            "server": r.headers.get("Server"),
            "body_len": len(body),
            "body_sha256": body_sha,
            "body_head": (r.text[:200].replace("\n", " | ") if body and len(body) < 5000 else ""),
            "interesting": bool(interesting),
            "latency_ms": int((time.time() - t0) * 1000),
        }
    except requests.exceptions.Timeout:
        return {"ip": ip, "port": port, "host": host, "path": path, "ua": ua, "err": "timeout"}
    except Exception as e:
        return {"ip": ip, "port": port, "host": host, "path": path, "ua": ua, "err": repr(e)[:160]}


def main():
    proxy = PROXIES[0] if PROXIES else None
    if proxy:
        print(f"[INFO] using proxy: {proxy['scheme']}://{proxy['host']}:{proxy['port']}", file=sys.stderr)
    else:
        print(f"[WARN] no alive proxy, 直连 (受 TUN 劫持, 仅 192.41.22.47:80 可达)", file=sys.stderr)

    print(f"\n=== STAGE A: HEAD / 跨 host × ua × ip:port ===", file=sys.stderr)
    root_matrix: list[dict[str, Any]] = []
    futs = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        for ip, port in IP_PORT_PAIR:
            for host in HOSTS_TO_TRY:
                for ua in USER_AGENTS[:4]:
                    futs[ex.submit(head_root, ip, port, host, ua, proxy)] = (ip, port, host, ua)
        done = 0
        for fut in as_completed(futs):
            res = fut.result()
            root_matrix.append(res)
            done += 1
            if done % 50 == 0:
                print(f"[A] {done}/{len(futs)}", file=sys.stderr)

    interesting_roots = [r for r in root_matrix if r.get("status") and r.get("status") not in (403, 404, 0)]
    print(f"[A] root_matrix total={len(root_matrix)}, interesting={len(interesting_roots)}", file=sys.stderr)
    for r in interesting_roots[:30]:
        st = r.get("status")
        sv = r.get("server")
        bl = r.get("body_len")
        host = r.get("host")
        sha = r.get("body_sha256")
        head = (r.get("body_head") or "")[:100].replace("\n", " ")
        print(f"  [{st}] host={host} ip={r.get('ip')} ua={r.get('ua')[:20]} sv={sv} len={bl} sha={sha} head={head}", file=sys.stderr)

    print(f"\n=== STAGE B: 敏感路径穷举 ===", file=sys.stderr)
    path_matrix: list[dict[str, Any]] = []
    futs = {}
    with ThreadPoolExecutor(max_workers=30) as ex:
        for ip, port in IP_PORT_PAIR:
            for host in HOSTS_TO_TRY:
                for path in SENSITIVE_PATHS:
                    ua = USER_AGENTS[0]
                    futs[ex.submit(probe_path, ip, port, host, path, ua, proxy)] = (ip, port, host, path)
        done = 0
        for fut in as_completed(futs):
            res = fut.result()
            path_matrix.append(res)
            done += 1
            if done % 200 == 0:
                print(f"[B] {done}/{len(futs)}", file=sys.stderr)

    interesting_paths = sorted(
        [r for r in path_matrix if r.get("interesting") and not r.get("err")],
        key=lambda x: (x.get("ip", ""), x.get("port", 0), x.get("host", ""), x.get("status", 0)),
    )
    print(f"[B] path_matrix total={len(path_matrix)}, interesting={len(interesting_paths)}", file=sys.stderr)
    for r in interesting_paths[:80]:
        st = r.get("status")
        print(f"  [{st}] {r.get('host')}:{r.get('port')} {r.get('path'):<35} len={r.get('body_len'):>6} sha={r.get('body_sha256')[:10]} head={(r.get('body_head') or '')[:80]!r}", file=sys.stderr)

    print(f"\n=== STAGE C: 分类汇总 ===", file=sys.stderr)
    by_ip_host = {}
    for r in path_matrix:
        if r.get("err"):
            continue
        if r.get("status") in (404, 0):
            continue
        key = (r["ip"], r["host"])
        by_ip_host.setdefault(key, []).append(r)
    for key, items in by_ip_host.items():
        print(f"  ip={key[0]} host={key[1]}: {len(items)} non-404 paths", file=sys.stderr)
        seen_codes = {}
        for r in items[:30]:
            seen_codes.setdefault(r["status"], []).append(r["path"])
        for st, paths in seen_codes.items():
            print(f"    [{st}] x{len(paths)}: {paths[:5]}{' ...' if len(paths) > 5 else ''}", file=sys.stderr)

    out_data = {
        "target": TARGET,
        "ts": time.time(),
        "true_open_ips": TRUE_OPEN_IPS,
        "ip_port_pair": [list(x) for x in IP_PORT_PAIR],
        "hosts_tried": len(HOSTS_TO_TRY),
        "paths_tried": len(SENSITIVE_PATHS),
        "proxy_used": proxy,
        "ua_count": len(USER_AGENTS),
        "root_matrix": root_matrix,
        "path_matrix": path_matrix,
        "interesting_roots": interesting_roots,
        "interesting_paths": interesting_paths,
        "summary_by_ip_host": {
            f"{k[0]}|{k[1]}": [{"status": r["status"], "path": r["path"], "len": r.get("body_len"), "sha": r.get("body_sha256")} for r in v]
            for k, v in by_ip_host.items()
        },
    }

    (OUT / "cartmanager_phase2_reachability.json").write_text(
        json.dumps(out_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n[INFO] phase2 -> {OUT / 'cartmanager_phase2_reachability.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
