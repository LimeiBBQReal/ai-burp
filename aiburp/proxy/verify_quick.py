"""
aiburp/proxy/verify_quick.py
快速代理拉取+验证 — 只拉 1 个源 (mmpx12 via ghfast 镜像), 单目标检查, 60 并发
预计 5-10 分钟内出结果
"""
import os
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = r"E:\CursorDEV\CKFinder\ai-burp"
ALIVE_DIR = os.path.join(ROOT, ".proxy_state")
os.makedirs(ALIVE_DIR, exist_ok=True)

# === 只拉 1 个稳定源 (mmpx12 via ghfast 镜像, 经验上最稳) ===
SOURCES = [
    ("http", "https://ghfast.top/https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt"),
    ("socks5", "https://ghfast.top/https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"),
]

# === 同时验证 2 个目标域 ===
TARGETS = [
    ("fershop.net", 443, "https"),
    ("blastzone.in", 443, "https"),
]

WORKERS = 60
TIMEOUT = 5
REAL_IP_CHECK = "https://api.ipify.org?format=json"


def fetch(url, timeout=20):
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200 and len(r.text) > 30:
            return r.text
    except Exception:
        pass
    return None


def parse_lines(text):
    out = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace(",", ":").replace("\t", ":").split(":")
        if len(parts) >= 2:
            ip, port = parts[0].strip(), parts[1].strip()
            if all(c in "0123456789." for c in ip) and port.isdigit():
                out.append(f"{ip}:{port}")
    return out


def probe(proxy_str, ptype, host, port, scheme):
    if ptype == "socks5":
        proxy_url = f"socks5h://{proxy_str}"
    else:
        proxy_url = f"http://{proxy_str}"
    proxies = {"http": proxy_url, "https": proxy_url}
    t0 = time.time()
    try:
        r = requests.get(
            f"{scheme}://{host}/",
            proxies=proxies, timeout=TIMEOUT, allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        )
        return r.status_code, int((time.time() - t0) * 1000)
    except Exception:
        return 0, 0


def eip_for(proxy_str, ptype):
    if ptype == "socks5":
        proxy_url = f"socks5h://{proxy_str}"
    else:
        proxy_url = f"http://{proxy_str}"
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get(REAL_IP_CHECK, proxies=proxies, timeout=TIMEOUT)
        return r.json().get("ip")
    except Exception:
        return None


def main():
    print("[1] 拉取代理 (mmpx12 via ghfast 镜像)...")
    http_set, socks5_set = set(), set()
    for ptype, url in SOURCES:
        text = fetch(url)
        if text:
            proxies = parse_lines(text)
            if ptype == "socks5":
                socks5_set.update(proxies)
            else:
                http_set.update(proxies)
            print(f"  ✓ {ptype}: {len(proxies)} 个")
        else:
            print(f"  ✗ {ptype} 拉取失败")

    candidates = [(p, "http") for p in http_set] + [(p, "socks5") for p in socks5_set]
    print(f"\n[*] 总计 {len(candidates)} 个待验证 (60 并发, 超时 {TIMEOUT}s)")

    real_ip = None
    try:
        real_ip = requests.get(REAL_IP_CHECK, timeout=8).json().get("ip")
    except Exception:
        pass
    print(f"[*] 真实出口 IP: {real_ip}")

    alive = []
    tested = 0
    t0 = time.time()

    def test_one(p, pt):
        results = {}
        for h, port, s in TARGETS:
            st, ms = probe(p, pt, h, port, s)
            results[h] = (st, ms)
        # 双目标都通才算 alive
        f_ok, f_ms = results[TARGETS[0][0]]
        b_ok, b_ms = results[TARGETS[1][0]]
        avg_ms = (f_ms + b_ms) // 2
        ok = bool(f_ok) and bool(b_ok)
        return {
            "proxy": f"{pt}://{p}",
            "type": pt,
            "alive": ok,
            "fershop_status": f_ok, "fershop_ms": f_ms,
            "blastzone_status": b_ok, "blastzone_ms": b_ms,
            "avg_ms": avg_ms,
        }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(test_one, p, pt) for p, pt in candidates]
        for f in as_completed(futs):
            tested += 1
            r = f.result()
            if r["alive"]:
                alive.append(r)
            if tested % 500 == 0:
                el = time.time() - t0
                rate = tested / el if el > 0 else 0
                eta = (len(candidates) - tested) / rate if rate > 0 else 0
                print(f"  [{tested}/{len(candidates)}] alive={len(alive)} "
                      f"el={el:.0f}s ETA={eta:.0f}s")

    print(f"\n[*] 双目标都通: {len(alive)}/{len(candidates)}")
    alive.sort(key=lambda x: x["avg_ms"])

    # === top-100 拿 eip 判匿名 ===
    print(f"[*] 对 top-100 拿出口 IP 判匿名")
    anonymous_pool = []
    for r in alive[:100]:
        ps = r["proxy"].split("://", 1)[1]
        eip = eip_for(ps, r["type"])
        r["eip"] = eip
        is_anon = bool(eip) and eip != real_ip
        r["anonymous"] = is_anon
        if is_anon:
            anonymous_pool.append(r)

    print(f"[*] 匿名: {len(anonymous_pool)}")

    # === 写出 ===
    pool_out = os.path.join(ALIVE_DIR, "fresh_proxy_pool_quick.json")
    with open(pool_out, "w", encoding="utf-8") as f:
        json.dump({
            "real_ip": real_ip,
            "timestamp": time.time(),
            "targets": [{"host": h, "port": p, "scheme": s} for h, p, s in TARGETS],
            "total_tested": len(candidates),
            "alive_count": len(alive),
            "anonymous_count": len(anonymous_pool),
            "alive": alive,
            "anonymous": anonymous_pool,
        }, f, ensure_ascii=False, indent=2)
    print(f"[+] {pool_out}")

    # === mihomo yaml ===
    import yaml
    proxies_cfg = []
    for i, r in enumerate(anonymous_pool[:50]):
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

    el = time.time() - t0
    print(f"\n[*] 用时 {el:.0f}s, 双目标都通 {len(alive)}, 匿名 {len(anonymous_pool)}")


if __name__ == "__main__":
    main()