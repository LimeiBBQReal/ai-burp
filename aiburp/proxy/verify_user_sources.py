"""
aiburp/proxy/verify_user_sources.py
按用户提供的新代理源 (extra_sources.json) 拉取 + 验证
目标: fershop.net + blastzone.in (按 user 要求)
"""
import os
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = r"E:\CursorDEV\CKFinder\ai-burp"
ALIVE_DIR = os.path.join(ROOT, ".proxy_state")
os.makedirs(ALIVE_DIR, exist_ok=True)

EXTRA_SRC = os.path.join(ROOT, "aiburp/proxy/extra_sources.json")
TARGETS = [
    ("fershop.net", 443, "https"),
    ("blastzone.in", 443, "https"),
]
WORKERS = 60
TIMEOUT = 6
REAL_IP_CHECK = "https://api.ipify.org?format=json"


def fetch(url, timeout=20, use_mirror=True):
    """带 ghfast 镜像."""
    urls = [url]
    if use_mirror and "raw.githubusercontent.com" in url:
        path = url.split("raw.githubusercontent.com/", 1)[1]
        urls.insert(0, f"https://ghfast.top/https://raw.githubusercontent.com/{path}")
    for u in urls:
        try:
            r = requests.get(u, timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and len(r.text) > 20:
                return r.text
        except Exception:
            pass
    return None


def parse_text_format(text, default_type):
    """
    解析 ip:port 列表 (多种格式)
    - 纯 ip:port (ProxyScraper / ProxyScrape)
    - ip:port:user:pass (含认证)
    - 表格行 / Markdown 行 (proxifly)
    """
    out = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 过滤 Markdown 表格分隔符
        if line.startswith("|") and set(line.replace("|", "").replace(":", "").replace(" ", "")) <= {"-"}:
            continue
        # 去掉 Markdown 表格行的前导 |
        if line.startswith("|"):
            parts = [p.strip() for p in line.split("|") if p.strip()]
            # proxifly 格式: | ip | port | | | https | | | | | | | | |
            # 取前两个非空数字/数字.数字作为 ip + port
            ip = parts[0] if parts else ""
            port = parts[1] if len(parts) > 1 else ""
            if ip and port:
                line = f"{ip}:{port}"
        # 兼容 CSV / Tab
        for sep in [",", ";", "\t"]:
            if sep in line and line.count(":") < 2:
                line = line.replace(sep, ":")
                break
        parts = line.split(":")
        if len(parts) >= 2:
            ip, port = parts[0].strip(), parts[1].strip()
            if all(c in "0123456789." for c in ip) and port.isdigit():
                out.append({
                    "addr": f"{ip}:{port}",
                    "type": default_type,
                    "auth": f"{parts[2]}:{parts[3]}" if len(parts) >= 4 and parts[2] else None,
                })
    return out


def parse_html_page(html):
    """
    从 HTML 页面抓 ip:port 模式
    用于 vxiaov / wrfree 这种 GitHub repo page
    """
    import re
    # ip:port 模式 (端口 1-65535)
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s](\d{2,5})")
    out = []
    for m in pattern.finditer(html):
        ip, port = m.group(1), m.group(2)
        if 1 <= int(port) <= 65535:
            out.append({
                "addr": f"{ip}:{port}",
                "type": "http",  # 默认
                "auth": None,
            })
    return out


def parse_repo_via_api(repo):
    """
    用 GitHub API 列出 repo 内所有 .txt 文件内容
    """
    out = []
    api_url = f"https://api.github.com/repos/{repo}/contents"
    # 用 ghfast 镜像
    api_urls = [api_url,
                f"https://ghfast.top/https://{api_url.split('https://', 1)[1]}"]
    for u in api_urls:
        try:
            r = requests.get(u, timeout=15, headers={"User-Agent": "Mozilla/5.0",
                                                    "Accept": "application/vnd.github+json"})
            if r.status_code == 200:
                items = r.json()
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not item.get("name", "").endswith((".txt", ".list")):
                        continue
                    dl = item.get("download_url")
                    if not dl:
                        continue
                    text = fetch(dl, timeout=15, use_mirror=True)
                    if text:
                        # 看文件名猜类型
                        n = item["name"].lower()
                        if "socks5" in n:
                            ptype = "socks5"
                        elif "socks4" in n:
                            ptype = "socks4"
                        elif "http" in n:
                            ptype = "http"
                        else:
                            ptype = "mixed"
                        out.extend(parse_text_format(text, ptype))
                return out
        except Exception:
            pass
    return out


def probe(addr, auth, ptype, host, port, scheme):
    if ptype == "socks5":
        if auth:
            proxy_url = f"socks5h://{auth}@{addr}"
        else:
            proxy_url = f"socks5h://{addr}"
    else:
        if auth:
            proxy_url = f"http://{auth}@{addr}"
        else:
            proxy_url = f"http://{addr}"
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


def eip_for(addr, auth, ptype):
    if ptype == "socks5":
        proxy_url = f"socks5h://{auth}@{addr}" if auth else f"socks5h://{addr}"
    else:
        proxy_url = f"http://{auth}@{addr}" if auth else f"http://{addr}"
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get(REAL_IP_CHECK, proxies=proxies, timeout=TIMEOUT)
        return r.json().get("ip")
    except Exception:
        return None


def main():
    with open(EXTRA_SRC, "r", encoding="utf-8") as f:
        cfg = json.load(f)["extra_sources"]

    print("[1] 拉取用户提供的代理源...")
    all_proxies = []
    for src in cfg:
        name = src["name"]
        url = src["url"]
        ptype = src.get("type", "http")
        fmt = src.get("format", "ip:port")
        print(f"  -> {name} ({ptype}, {fmt})")

        if fmt == "page":
            # repo HTML page
            repo_path = url.replace("https://github.com/", "").strip("/")
            proxies = parse_repo_via_api(repo_path)
        else:
            text = fetch(url, timeout=20, use_mirror=True)
            if not text:
                print(f"     ✗ 拉取失败")
                continue
            actual_type = ptype if ptype != "mixed" else "http"
            proxies = parse_text_format(text, actual_type)
            if ptype == "mixed":
                # 启发式: 端口在 socks 常见范围 (1080, 9050, 9150) → socks5
                for p in proxies:
                    port = int(p["addr"].split(":")[1])
                    if port in (1080, 9050, 9150, 10808):
                        p["type"] = "socks5"

        print(f"     ✓ 解析 {len(proxies)} 个")
        for p in proxies:
            p["source"] = name
        all_proxies.extend(proxies)

    print(f"\n[*] 总计候选: {len(all_proxies)} 个")

    # 去重
    seen = set()
    unique = []
    for p in all_proxies:
        k = (p["addr"], p["type"])
        if k not in seen:
            seen.add(k)
            unique.append(p)
    print(f"[*] 去重后: {len(unique)} 个")

    real_ip = None
    try:
        real_ip = requests.get(REAL_IP_CHECK, timeout=8).json().get("ip")
    except Exception:
        pass
    print(f"[*] 真实出口 IP: {real_ip}")

    # === 验证 ===
    print(f"[*] {WORKERS} 并发, 超时 {TIMEOUT}s")
    alive = []
    tested = 0
    t0 = time.time()

    def test_one(p):
        results = {}
        for h, port, s in TARGETS:
            st, ms = probe(p["addr"], p.get("auth"), p["type"], h, port, s)
            results[h] = (st, ms)
        f_ok, f_ms = results[TARGETS[0][0]]
        b_ok, b_ms = results[TARGETS[1][0]]
        # 任一目标通即可
        ok = bool(f_ok) or bool(b_ok)
        avg_ms = ((f_ms or 9999) + (b_ms or 9999)) // 2
        return {
            **p,
            "alive": ok,
            "fershop_status": f_ok, "fershop_ms": f_ms,
            "blastzone_status": b_ok, "blastzone_ms": b_ms,
            "avg_ms": avg_ms,
        }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(test_one, p) for p in unique]
        for f in as_completed(futs):
            tested += 1
            r = f.result()
            if r["alive"]:
                alive.append(r)
            if tested % 500 == 0:
                el = time.time() - t0
                rate = tested / el if el > 0 else 0
                eta = (len(unique) - tested) / rate if rate > 0 else 0
                print(f"  [{tested}/{len(unique)}] alive={len(alive)} "
                      f"el={el:.0f}s ETA={eta:.0f}s")

    print(f"\n[*] 存活: {len(alive)}/{len(unique)}")
    alive.sort(key=lambda x: x["avg_ms"])

    # === top-100 eip 匿名判定 ===
    print(f"[*] 对 top-100 拿出口 IP 判匿名")
    anonymous = []
    for r in alive[:100]:
        eip = eip_for(r["addr"], r.get("auth"), r["type"])
        r["eip"] = eip
        is_anon = bool(eip) and eip != real_ip
        r["anonymous"] = is_anon
        if is_anon:
            anonymous.append(r)

    print(f"[*] 匿名: {len(anonymous)}")

    # === 按 source 统计 ===
    by_source = {}
    for r in alive:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    print(f"\n[*] 各源存活数:")
    for s, c in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    {s}: {c}")

    # 双目标都通的(最严格)
    dual_ok = [r for r in alive if r["fershop_status"] and r["blastzone_status"]]
    print(f"[*] 双目标都通: {len(dual_ok)}")
    fershop_only = [r for r in alive if r["fershop_status"] and not r["blastzone_status"]]
    blastzone_only = [r for r in alive if r["blastzone_status"] and not r["fershop_status"]]
    print(f"[*] fershop 单独通: {len(fershop_only)}")
    print(f"[*] blastzone 单独通: {len(blastzone_only)}")

    # === 写出 ===
    pool_out = os.path.join(ALIVE_DIR, "user_sources_proxy_pool.json")
    with open(pool_out, "w", encoding="utf-8") as f:
        json.dump({
            "real_ip": real_ip,
            "timestamp": time.time(),
            "targets": [{"host": h, "port": p, "scheme": s} for h, p, s in TARGETS],
            "total_candidates": len(unique),
            "alive_count": len(alive),
            "anonymous_count": len(anonymous),
            "dual_ok_count": len(dual_ok),
            "fershop_only": len(fershop_only),
            "blastzone_only": len(blastzone_only),
            "by_source": by_source,
            "alive": alive,
            "anonymous": anonymous,
            "dual_ok": dual_ok,
        }, f, ensure_ascii=False, indent=2)
    print(f"\n[+] {pool_out}")

    # === mihomo yaml (用 dual_ok 优先, 不够再补 anonymous) ===
    import yaml
    pool_for_yaml = dual_ok if len(dual_ok) >= 20 else (dual_ok + anonymous)[:50]
    proxies_cfg = []
    for i, r in enumerate(pool_for_yaml):
        server, port = r["addr"].split(":")
        cfg_item = {
            "name": f"{r['type']}_{i:03d}_{r['avg_ms']}ms",
            "type": r["type"],
            "server": server,
            "port": int(port),
        }
        if r.get("auth"):
            cfg_item["username"] = r["auth"].split(":")[0]
            cfg_item["password"] = r["auth"].split(":")[1]
        proxies_cfg.append(cfg_item)
    yaml_out = os.path.join(ALIVE_DIR, "alive.yaml")
    yaml_cfg = {
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
        yaml.dump(yaml_cfg, f, allow_unicode=True, sort_keys=False)
    print(f"[+] mihomo yaml: {yaml_out} ({len(proxies_cfg)} 节点)")

    el = time.time() - t0
    print(f"\n[*] 用时 {el:.0f}s")
    print(f"[*] 总候选: {len(unique)}, 存活: {len(alive)}, 匿名: {len(anonymous)}")
    print(f"[*] 双目标都通: {len(dual_ok)}")


if __name__ == "__main__":
    main()