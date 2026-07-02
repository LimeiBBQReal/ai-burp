"""
aiburp/proxy/verify_fresh_v2.py
更宽松的代理拉取+验证 — 接受"单目标能通", fallback 兼容任一目标域
"""
import os
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = r"E:\CursorDEV\CKFinder\ai-burp"
ALIVE_DIR = os.path.join(ROOT, ".proxy_state")
os.makedirs(ALIVE_DIR, exist_ok=True)

# === 候选代理源 (比 proxy_sources.json 更宽) ===
EXTRA_SOURCES = [
    # 直接 GitHub 代理列表 (多个项目)
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/extra/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/extra/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXY_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXY_LIST/master/socks5.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies-List/main/http.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies-List/main/socks5.txt",
    # API 端点
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=yes",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all&ssl=yes",
    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/http.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/socks5.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/vakhov/socks5-proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/dpang0/socks5-proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/iptotal/main/http.txt",
    "https://raw.githubusercontent.com/iptotal/main/socks5.txt",
    # openproxy.space / spys.me
    "https://openproxy.space/list/http",
    "https://raw.githubusercontent.com/spys-one/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/spys-one/proxy-list/main/socks5.txt",
]

# === 候选验证目标 ===
PRIMARY_HOSTS = [
    ("fershop.net", 443, "https"),
    ("blastzone.in", 443, "https"),
]
FALLBACK_HOST = ("1.1.1.1", 443, "https")

WORKERS = 60
TIMEOUT = 6
REAL_IP_CHECK = "https://api.ipify.org?format=json"


def fetch(url, timeout=15):
    """带镜像的下载."""
    urls = [url]
    if "raw.githubusercontent.com" in url:
        path = url.split("raw.githubusercontent.com/", 1)[1]
        urls.append(f"https://ghfast.top/https://raw.githubusercontent.com/{path}")
    for u in urls:
        try:
            r = requests.get(u, timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and len(r.text) > 30:
                return r.text
        except Exception:
            pass
    return None


def parse_lines(text):
    """宽容解析 ip:port (支持 ip,port / ip:port:user:pass)."""
    out = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 兼容 CSV
        for sep in [",", ";", "\t"]:
            if sep in line and line.count(":") < 2:
                line = line.replace(sep, ":")
                break
        parts = line.split(":")
        if len(parts) >= 2:
            ip, port = parts[0].strip(), parts[1].strip()
            # 简单 IP 校验
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
    except Exception as e:
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
    print("[1] 拉取额外代理源...")
    http_set, socks5_set = set(), set()
    for url in EXTRA_SOURCES:
        text = fetch(url, timeout=12)
        if not text:
            print(f"  ✗ {url[:60]}")
            continue
        proxies = parse_lines(text)
        if "socks5" in url:
            socks5_set.update(proxies)
            print(f"  ✓ socks5 {len(proxies):>4} 个  {url[:60]}")
        else:
            http_set.update(proxies)
            print(f"  ✓ http   {len(proxies):>4} 个  {url[:60]}")

    print(f"\n[*] 候选: HTTP={len(http_set)}, SOCKS5={len(socks5_set)}")

    real_ip = None
    try:
        real_ip = requests.get(REAL_IP_CHECK, timeout=8).json().get("ip")
    except Exception:
        pass
    print(f"[*] 真实 IP: {real_ip}")

    # === 验证 (宽松: 主目标或 fallback 任一能通即可) ===
    candidates = [(p, "http") for p in http_set] + [(p, "socks5") for p in socks5_set]
    print(f"[*] {WORKERS} 并发验证, 主目标 fershop/blastzone, fallback 1.1.1.1")
    print(f"[*] 超时 {TIMEOUT}s, 总计 {len(candidates)} 个")

    alive = []
    tested = 0
    t0 = time.time()

    def test_one(p, pt):
        # 主目标 (任一通即可)
        best_status = 0
        best_ms = 99999
        primary_ok = False
        primary_ms = 99999
        primary_host = ""
        for h, port, s in PRIMARY_HOSTS:
            st, ms = probe(p, pt, h, port, s)
            if st and st != 0:
                primary_ok = True
                primary_ms = min(primary_ms, ms)
                primary_host = h
                if best_ms > ms:
                    best_ms = ms
                    best_status = st
        # fallback (1.1.1.1)
        fb_st, fb_ms = probe(p, pt, FALLBACK_HOST[0], FALLBACK_HOST[1], FALLBACK_HOST[2])
        return {
            "proxy": f"{pt}://{p}",
            "type": pt,
            "primary_ok": primary_ok,
            "primary_host": primary_host,
            "primary_ms": primary_ms,
            "fallback_status": fb_st,
            "fallback_ms": fb_ms,
        }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(test_one, p, pt) for p, pt in candidates]
        for f in as_completed(futs):
            tested += 1
            r = f.result()
            # 接受 primary_ok OR (fallback 状态码非 0 且 < 500)
            if r["primary_ok"] or (r["fallback_status"] and r["fallback_status"] < 500):
                alive.append(r)
            if tested % 2000 == 0:
                el = time.time() - t0
                rate = tested / el if el > 0 else 0
                eta = (len(candidates) - tested) / rate if rate > 0 else 0
                print(f"  [{tested}/{len(candidates)}] alive={len(alive)} "
                      f"el={el:.0f}s ETA={eta:.0f}s")

    print(f"\n[*] 存活: {len(alive)}/{len(candidates)}")
    # 按延迟排序
    alive.sort(key=lambda x: x["primary_ms"] if x["primary_ms"] < 99999 else x["fallback_ms"])

    # === top-150 拿 eip 判匿名 ===
    print(f"[*] 对 top-150 拿出口 IP 判匿名")
    anonymous_pool = []
    for r in alive[:150]:
        ps = r["proxy"].split("://", 1)[1]
        eip = eip_for(ps, r["type"])
        r["eip"] = eip
        is_anon = bool(eip) and eip != real_ip
        r["anonymous"] = is_anon
        if is_anon:
            anonymous_pool.append(r)

    print(f"[*] 匿名: {len(anonymous_pool)}")

    # === 写出 ===
    pool_out = os.path.join(ALIVE_DIR, "fresh_proxy_pool_v2.json")
    with open(pool_out, "w", encoding="utf-8") as f:
        json.dump({
            "real_ip": real_ip,
            "timestamp": time.time(),
            "primary_hosts": [{"host": h, "port": p, "scheme": s} for h, p, s in PRIMARY_HOSTS],
            "fallback_host": {"host": FALLBACK_HOST[0], "port": FALLBACK_HOST[1]},
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
            "name": f"{r['type']}_{i:03d}_{r.get('primary_ms', r.get('fallback_ms', 0))}ms",
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
    print(f"\n[*] 用时 {el:.0f}s, 存活 {len(alive)}, 匿名 {len(anonymous_pool)}")


if __name__ == "__main__":
    main()