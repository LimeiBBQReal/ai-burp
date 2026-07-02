"""
aiburp/proxy/verify_fresh.py
新拉代理 → 同时验证 fershop.net 和 blastzone.in (用户指定)
按延迟+匿名度排序, 导出 alive + 高优 yaml

输出:
  .proxy_state/fresh_proxy_pool.json   完整结构化结果
  aiburp/proxy/yaml/alive.yaml         mihomo yaml
"""
import os
import json
import time
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = r"E:\CursorDEV\CKFinder\ai-burp"
HTTP_FILE = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw\http_proxies.txt"
SOCKS5_FILE = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw\socks5_proxies.txt"
OUT_DIR = r"E:\CodexDEV\qwen2API\proxy\yaml\proxy_raw"
ALIVE_DIR = os.path.join(ROOT, ".proxy_state")
os.makedirs(ALIVE_DIR, exist_ok=True)

# === 用户指定: 同时验证 fershop.net + blastzone.in ===
PROBE_HOSTS = [
    ("fershop.net", 443, "https"),
    ("blastzone.in", 443, "https"),
]
WORKERS = 50
TIMEOUT = 8

REAL_IP_CHECK = "https://api.ipify.org?format=json"

# 上次记录的真实 IP (用作 anonymous 判定参照)
LAST_REAL_IP = None
try:
    with open(os.path.join(ALIVE_DIR, "proxy_pool.json"), "r", encoding="utf-8") as f:
        LAST_REAL_IP = json.load(f).get("real_ip")
except Exception:
    pass


def get_real_ip():
    """直接连, 不走代理, 拿真实出口 IP."""
    try:
        r = requests.get(REAL_IP_CHECK, timeout=TIMEOUT)
        return r.json().get("ip")
    except Exception:
        return None


def probe_with_proxy(proxy_str, proxy_type, host, port, scheme):
    """通过指定代理访问 host:port, 返回 (ok, latency_ms, eip)."""
    if proxy_type == "socks5":
        proxy_url = f"socks5h://{proxy_str}"
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        proxy_url = f"http://{proxy_str}"
        proxies = {"http": proxy_url, "https": proxy_url}

    t0 = time.time()
    try:
        # 简单 GET 一次, 用 HEAD 减少流量
        r = requests.get(
            f"{scheme}://{host}/",
            proxies=proxies, timeout=TIMEOUT, allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        )
        latency = int((time.time() - t0) * 1000)
        # 任何响应都算通, 包括 200/301/302/403/404 (能握手 + 收包就行)
        if r.status_code:
            return True, latency, None
    except Exception as e:
        return False, 0, str(e)[:80]
    return False, 0, "no_response"


def eip_for(proxy_str, proxy_type):
    """单独拿一次出口 IP, 用 fershop.net 作为外部测速点."""
    if proxy_type == "socks5":
        proxy_url = f"socks5h://{proxy_str}"
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        proxy_url = f"http://{proxy_str}"
        proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get(REAL_IP_CHECK, proxies=proxies, timeout=TIMEOUT)
        return r.json().get("ip")
    except Exception:
        return None


def test_proxy_full(proxy_str, proxy_type):
    """
    对单个代理:
      1. 同时验证 fershop.net 和 blastzone.in
      2. 通过 ipify 拿出口 IP, 跟 real_ip 比对 → 判定 anonymous
    """
    results = {}
    for host, port, scheme in PROBE_HOSTS:
        ok, lat, err = probe_with_proxy(proxy_str, proxy_type, host, port, scheme)
        results[host] = {"ok": ok, "ms": lat, "err": err}
    # 两边都通才算 alive
    alive = all(r["ok"] for r in results.values())
    avg_ms = sum(r["ms"] for r in results.values()) // len(results)
    return {
        "proxy": f"{proxy_type}://{proxy_str}",
        "type": proxy_type,
        "alive": alive,
        "avg_ms": avg_ms,
        "results": results,
    }


def main():
    real_ip = get_real_ip()
    print(f"[*] 真实出口 IP: {real_ip}")
    print(f"[*] 上次真实 IP: {LAST_REAL_IP}")

    http_list = []
    if os.path.isfile(HTTP_FILE):
        with open(HTTP_FILE) as f:
            http_list = [l.strip() for l in f if l.strip()]
    socks5_list = []
    if os.path.isfile(SOCKS5_FILE):
        with open(SOCKS5_FILE) as f:
            socks5_list = [l.strip() for l in f if l.strip()]
    print(f"[*] 待验证: HTTP={len(http_list)}, SOCKS5={len(socks5_list)}")

    proxies_to_test = [(p, "http") for p in http_list] + [(p, "socks5") for p in socks5_list]
    print(f"[*] {WORKERS} 并发, 超时 {TIMEOUT}s/host")

    alive_results = []
    tested = 0
    t_start = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [
            pool.submit(test_proxy_full, p, t) for p, t in proxies_to_test
        ]
        for f in as_completed(futures):
            tested += 1
            r = f.result()
            if r["alive"]:
                alive_results.append(r)
            if tested % 1000 == 0:
                elapsed = time.time() - t_start
                rate = tested / elapsed if elapsed > 0 else 0
                eta = (len(proxies_to_test) - tested) / rate if rate > 0 else 0
                print(f"  [{tested}/{len(proxies_to_test)}] alive={len(alive_results)}  "
                      f"elapsed={elapsed:.0f}s  ETA={eta:.0f}s")

    print(f"\n[*] 存活 (能同时访问两个目标): {len(alive_results)}/{len(proxies_to_test)}")

    # === 抽样 eip, 判 anonymous ===
    # 为了速度, 只对 top-100 最低延迟的拿 eip
    alive_results.sort(key=lambda x: x["avg_ms"])
    top = alive_results[:120]
    print(f"[*] 对 top {len(top)} 最低延迟代理拿出口 IP 判匿名")

    anonymous_pool = []
    for r in top:
        proxy_str = r["proxy"].split("://", 1)[1]
        eip = eip_for(proxy_str, r["type"])
        r["eip"] = eip
        is_anon = bool(eip) and (eip != real_ip) and (eip != LAST_REAL_IP)
        r["anonymous"] = is_anon
        if is_anon:
            anonymous_pool.append(r)

    print(f"[*] 匿名 (出口 IP != 真实): {len(anonymous_pool)}")

    # === 写出 ===
    pool_out = os.path.join(ALIVE_DIR, "fresh_proxy_pool.json")
    with open(pool_out, "w", encoding="utf-8") as f:
        json.dump({
            "real_ip": real_ip,
            "timestamp": time.time(),
            "probe_hosts": [{"host": h, "port": p, "scheme": s} for h, p, s in PROBE_HOSTS],
            "total_tested": len(proxies_to_test),
            "alive_count": len(alive_results),
            "anonymous_count": len(anonymous_pool),
            "alive": alive_results,
            "anonymous": anonymous_pool,
        }, f, ensure_ascii=False, indent=2)
    print(f"[+] {pool_out}")

    # === 写 mihomo yaml ===
    import yaml
    proxies_cfg = []
    for i, r in enumerate(anonymous_pool[:60]):
        server, port = r["proxy"].split("://", 1)[1].split(":")
        proxies_cfg.append({
            "name": f"{r['type']}_{i:03d}_{r['avg_ms']}ms",
            "type": r["type"],
            "server": server,
            "port": int(port),
        })
    yaml_out = os.path.join(ALIVE_DIR, "alive.yaml")
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "global",
        "log-level": "warning",
        "ipv6": False,
        "dns": {"enable": True, "ipv6": False, "nameserver": ["223.5.5.5", "8.8.8.8"]},
        "proxies": proxies_cfg,
        "proxy-groups": [{
            "name": "GLOBAL", "type": "select",
            "proxies": [p["name"] for p in proxies_cfg] + ["DIRECT"],
        }],
        "rules": ["MATCH,GLOBAL"],
    }
    with open(yaml_out, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
    print(f"[+] mihomo yaml: {yaml_out} ({len(proxies_cfg)} 节点)")

    elapsed = time.time() - t_start
    print(f"\n[*] 用时 {elapsed:.0f}s, 存活 {len(alive_results)}, 匿名 {len(anonymous_pool)}")
    return alive_results, anonymous_pool


if __name__ == "__main__":
    main()