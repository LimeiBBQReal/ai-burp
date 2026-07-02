"""
Phase 2.1 — 深抓 /admin/ + /.svn/entries + 其他异常响应
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent
OUT = ROOT

INVENTORY = json.loads((OUT / "cartmanager_inventory.json").read_text(encoding="utf-8"))
TARGET = INVENTORY["target"]
SUBDOMAINS: list[str] = INVENTORY["subdomains"]
TRUE_OPEN_IPS: list[str] = [ip for ip, ports in INVENTORY["port_scan"].items() if ports]

HOSTS: list[str] = sorted({TARGET, f"www.{TARGET}", *SUBDOMAINS})

DEPTH_PATHS: list[str] = [
    "/admin/", "/admin", "/admin/index.php", "/admin/index.html", "/admin/login",
    "/admin/login.php", "/admin/admin.php", "/admin/dashboard", "/admin/home",
    "/admin/config.php", "/admin/users", "/admin/settings",
    "/wp-admin/", "/wp-login.php",
    "/administrator/", "/user/login", "/login", "/login.php",
    "/.svn/", "/.svn/entries", "/.svn/wc.db", "/.svn/format",
    "/.git/HEAD", "/.git/config", "/.git/index", "/.git/description",
    "/.git/refs/heads/master", "/.git/logs/HEAD",
    "/.env", "/.env.bak", "/.env.local", "/.env.production", "/.env.example",
    "/backup.sql", "/dump.sql", "/db.sql",
    "/crossdomain.xml", "/elmah.axd",
    "/server-info", "/server-info?auto",
    "/phpinfo.php", "/info.php", "/test.php",
    "/cgi-bin/", "/cgi-bin/test-cgi",
    "/manager/", "/manager/html", "/phpmyadmin/", "/pma/",
    "/api/", "/api/v1/", "/api/v2/", "/swagger/", "/swagger.json",
    "/actuator/", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/heapdump",
    "/.well-known/", "/.well-known/security.txt", "/.well-known/openid-configuration",
]

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
IP = TRUE_OPEN_IPS[0]
print(f"[INFO] IP={IP} hosts={len(HOSTS)} paths={len(DEPTH_PATHS)}", file=sys.stderr)


def head_full(ip: str, host: str, path: str) -> dict[str, Any]:
    url = f"http://{ip}{path}"
    try:
        s = requests.Session()
        s.headers.update({
            "Host": host, "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Connection": "close",
            "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
        })
        r = s.get(url, timeout=10, verify=False, allow_redirects=True)
        out = {
            "ip": ip, "host": host, "path": path, "url": url,
            "status": r.status_code,
            "history": [h.status_code for h in r.history],
            "final_url": r.url,
            "server": r.headers.get("Server"),
            "powered_by": r.headers.get("X-Powered-By"),
            "content_type": r.headers.get("Content-Type"),
            "content_length": r.headers.get("Content-Length"),
            "location": r.headers.get("Location"),
            "cookies": r.headers.get("Set-Cookie"),
            "x_frame": r.headers.get("X-Frame-Options"),
            "csp": r.headers.get("Content-Security-Policy"),
            "hsts": r.headers.get("Strict-Transport-Security"),
            "body_len": len(r.content),
            "body_sha256": __import__("hashlib").sha256(r.content).hexdigest()[:16],
            "body_text": r.text,
        }
        return out
    except Exception as e:
        return {"ip": ip, "host": host, "path": path, "url": url, "err": repr(e)[:200]}


def main():
    out_data = []
    interesting = []
    for host in HOSTS:
        for path in DEPTH_PATHS:
            r = head_full(IP, host, path)
            out_data.append(r)
            if r.get("status") and r.get("status") not in (404, 0):
                interesting.append(r)
                body_head = (r.get("body_text") or "")[:200].replace("\n", " | ")
                print(f"[{r.get('status')}] {host}{path} len={r.get('body_len')} sv={r.get('server')} loc={r.get('location')} head={body_head!r}", file=sys.stderr)

    (OUT / "cartmanager_phase2_depth.json").write_text(
        json.dumps(out_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n[INFO] interesting_count={len(interesting)} total={len(out_data)}", file=sys.stderr)
    print(f"[INFO] phase2_depth -> {OUT / 'cartmanager_phase2_depth.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
