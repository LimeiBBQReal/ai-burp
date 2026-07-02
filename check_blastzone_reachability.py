"""
Step 1: 检查 blastzone 报告里所有资产可达性
- 不止 bzhost1.com, 包括 webmail.blastzone.org / bzhost1.blastzone.org / www.ashleywestmark.com / 216.215.30.39 等
- 直连 + 代理 各测一次
"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import requests
import urllib3
urllib3.disable_warnings()

OUT = Path(".pipeline_output")
OUT.mkdir(exist_ok=True)

# 从 blastzone v4 报告抽取的目标
TARGETS = [
    "http://bzhost1.com",
    "http://bzhost1.com/phpmyadmin",
    "http://bzhost1.com/wp-login.php",
    "http://www.bzhost1.com",
    "https://www.bzhost1.com",
    "http://webmail.blastzone.org",
    "https://webmail.blastzone.org",
    "http://webmail.blastzone.org/?_task=login",
    "http://bzhost1.blastzone.org",
    "http://bzhost1.blastzone.org/phpmyadmin",
    "http://www.ashleywestmark.com",
    "https://www.ashleywestmark.com",
    "http://www.ashleywestmark.com/wp-login.php",
    "http://ashleywestmark.com",
    "http://216.215.30.39",
    "https://216.215.30.39",
    "http://blastzone.org",
    "http://www.blastzone.org",
    "http://bouncehouses.com",
    "https://bouncehouses.com",
]

PROXY = "http://3.211.120.181:443"
PROXIES = {"http": PROXY, "https": PROXY}
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def probe(url, proxy=None, timeout=8):
    try:
        kwargs = dict(timeout=timeout, allow_redirects=True, verify=False,
                     headers=HEADERS)
        if proxy:
            kwargs["proxies"] = proxy
        r = requests.get(url, **kwargs)
        return r.status_code, len(r.content), r.headers.get("Server", ""), r.headers.get("Location", "")
    except Exception as e:
        return "ERR", 0, str(e)[:60], ""


print(f"{'TARGET':45s} {'DIRECT':>12s} {'PROXY':>12s}")
print("-" * 80)
results = []
for url in TARGETS:
    d_code, d_len, d_srv, d_loc = probe(url, proxy=None)
    p_code, p_len, p_srv, p_loc = probe(url, proxy=PROXIES)
    d_str = f"{d_code}/{d_len}B"
    p_str = f"{p_code}/{p_len}B"
    print(f"{url[:43]:45s} {d_str:>12s} {p_str:>12s}")
    results.append({
        "url": url,
        "direct": {"status": d_code, "length": d_len, "server": d_srv, "location": d_loc},
        "proxy": {"status": p_code, "length": p_len, "server": p_srv, "location": p_loc},
    })
    time.sleep(0.3)

import json
with open(OUT / "blastzone_reachability.json", "w") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print("\n写入 -> .pipeline_output/blastzone_reachability.json")

# 总结: 哪些资产可达
print("\n[+] 可达资产 (200/301/302/403):")
for r in results:
    for mode in ("direct", "proxy"):
        m = r[mode]
        if isinstance(m["status"], int) and m["status"] in (200, 301, 302, 303, 307, 401, 403):
            print(f"  [{mode:6s}] {r['url']:50s} {m['status']} {m['length']:>6}B")
