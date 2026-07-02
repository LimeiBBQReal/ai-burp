"""
批量验证代理 IP: 直接测能否访问 dola.com (不只是存活, 还要过 DOLA TLS)
用 curl_cffi + Chrome 指纹 (和实际使用一致)
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from curl_cffi import requests

HTTP_FILE = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw\http_proxies.txt"
SOCKS5_FILE = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw\socks5_proxies.txt"
OUT_DIR = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw"
DOLA_URL = "https://www.dola.com/"
WORKERS = 30
TIMEOUT = 10


def test_proxy(proxy_str, proxy_type="http"):
    """测试单个代理能否访问 dola.com, 返回 (proxy_str, ok, latency_ms)"""
    if proxy_type == "socks5":
        proxy_url = f"socks5://{proxy_str}"
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        proxy_url = f"http://{proxy_str}"
        proxies = {"http": proxy_url, "https": proxy_url}
    t0 = time.time()
    try:
        r = requests.get(DOLA_URL, proxies=proxies, impersonate="chrome131",
                        timeout=TIMEOUT, allow_redirects=False)
        latency = int((time.time() - t0) * 1000)
        # 200 或 301/302 都算通过 (dola.com 可能重定向)
        if r.status_code in (200, 301, 302, 303):
            return (proxy_str, proxy_type, True, latency)
    except:
        pass
    return (proxy_str, proxy_type, False, 0)


def main():
    # 读代理列表
    http_proxies = []
    if os.path.isfile(HTTP_FILE):
        with open(HTTP_FILE) as f:
            http_proxies = [l.strip() for l in f if l.strip()]
    socks5_proxies = []
    if os.path.isfile(SOCKS5_FILE):
        with open(SOCKS5_FILE) as f:
            socks5_proxies = [l.strip() for l in f if l.strip()]

    total = len(http_proxies) + len(socks5_proxies)
    print(f"[*] 验证 {total} 个代理 (HTTP:{len(http_proxies)} + SOCKS5:{len(socks5_proxies)})")
    print(f"[*] {WORKERS} 并发, 每个超时 {TIMEOUT}s\n")

    alive_http = []
    alive_socks5 = []
    tested = 0
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        for p in http_proxies:
            futures.append(pool.submit(test_proxy, p, "http"))
        for p in socks5_proxies:
            futures.append(pool.submit(test_proxy, p, "socks5"))

        for f in as_completed(futures):
            tested += 1
            proxy_str, ptype, ok, latency = f.result()
            if ok:
                if ptype == "socks5":
                    alive_socks5.append((proxy_str, latency))
                else:
                    alive_http.append((proxy_str, latency))
            if tested % 500 == 0:
                elapsed = time.time() - t_start
                rate = tested / elapsed if elapsed > 0 else 0
                eta = (total - tested) / rate if rate > 0 else 0
                print(f"  [{tested}/{total}] alive={len(alive_http)+len(alive_socks5)}  "
                      f"elapsed={elapsed:.0f}s  ETA={eta:.0f}s")

    elapsed = time.time() - t_start
    total_alive = len(alive_http) + len(alive_socks5)
    print(f"\n[*] 验证完成 ({elapsed:.0f}s)")
    print(f"    HTTP 存活: {len(alive_http)}/{len(http_proxies)}")
    print(f"    SOCKS5 存活: {len(alive_socks5)}/{len(socks5_proxies)}")

    # 按延迟排序
    alive_http.sort(key=lambda x: x[1])
    alive_socks5.sort(key=lambda x: x[1])

    # 写出
    http_out = os.path.join(OUT_DIR, "http_alive.txt")
    with open(http_out, "w") as f:
        for p, lat in alive_http:
            f.write(f"{p}\n")
    socks5_out = os.path.join(OUT_DIR, "socks5_alive.txt")
    with open(socks5_out, "w") as f:
        for p, lat in alive_socks5:
            f.write(f"{p}\n")

    # 生成 mihomo yaml (存活代理 → Clash 格式)
    yaml_out = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_alive.yaml"
    proxies_cfg = []
    for i, (p, lat) in enumerate(alive_http[:200]):  # 最多 200 个
        proxies_cfg.append({"name": f"http_{i:03d}_{lat}ms", "type": "http",
                           "server": p.split(":")[0], "port": int(p.split(":")[1])})
    for i, (p, lat) in enumerate(alive_socks5[:200]):
        proxies_cfg.append({"name": f"socks5_{i:03d}_{lat}ms", "type": "socks5",
                           "server": p.split(":")[0], "port": int(p.split(":")[1])})

    import yaml
    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "global",
        "log-level": "warning", "ipv6": False,
        "dns": {"enable": True, "ipv6": False, "nameserver": ["223.5.5.5", "8.8.8.8"]},
        "proxies": proxies_cfg,
        "proxy-groups": [{"name": "GLOBAL", "type": "select",
                          "proxies": [p["name"] for p in proxies_cfg] + ["DIRECT"]}],
        "rules": ["MATCH,GLOBAL"],
    }
    with open(yaml_out, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    print(f"\n[+] 存活 HTTP: {http_out}")
    print(f"[+] 存活 SOCKS5: {socks5_out}")
    print(f"[+] mihomo YAML: {yaml_out} ({len(proxies_cfg)} 节点)")
    print(f"\n前 10 快速 HTTP 代理:")
    for p, lat in alive_http[:10]:
        print(f"  {p:25} {lat}ms")
    return 0


if __name__ == "__main__":
    exit(main())
