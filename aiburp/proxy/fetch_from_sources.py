"""
从 proxy_sources.json 批量采集高质量代理 IP
重点: tier1 快速验证源 (HTTP/SOCKS5 纯代理列表)
"""
import json
import os
import time
import requests

SOURCES_FILE = r"F:\CodexDEV\qwen2API\proxy\proxy_sources.json"
OUT_DIR = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw"
os.makedirs(OUT_DIR, exist_ok=True)


def fetch(url, timeout=15):
    """带镜像的下载"""
    urls = [url]
    if "raw.githubusercontent.com" in url:
        path = url.split("raw.githubusercontent.com/", 1)[1]
        urls.append(f"https://ghfast.top/https://raw.githubusercontent.com/{path}")
        urls.append(f"https://fastly.jsdelivr.net/gh/{path.replace('/master/', '@master/').replace('/main/', '@main/')}")
    for u in urls:
        try:
            r = requests.get(u, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and len(r.text) > 50:
                return r.text
        except:
            pass
    return None


def parse_proxy_list(text):
    """解析 ip:port 代理列表 (每行一个)"""
    proxies = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            parts = line.split(":")
            if len(parts) >= 2:
                ip = parts[0].strip()
                port = parts[1].strip()
                if port.isdigit():
                    proxies.append(f"{ip}:{port}")
    return proxies


def parse_csv_http(text):
    """解析 CSV 格式代理列表 (ip,port,country,...)"""
    proxies = []
    for line in text.strip().split("\n"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(",")
        if len(parts) >= 2 and parts[1].strip().isdigit():
            proxies.append(f"{parts[0].strip()}:{parts[1].strip()}")
    return proxies


def main():
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)

    all_http_proxies = set()
    all_socks5_proxies = set()
    results = {}

    # === tier1: 快速验证源 ===
    print("="*60)
    print("Tier 1: 快速验证源 (HTTP/SOCKS5 纯代理)")
    print("="*60)
    for src in config.get("tier1_fast_verify", {}).get("sources", []):
        name = src["name"]
        url = src["url"]
        fmt = src.get("format", "http_txt")
        print(f"\n[{name}] {url[:70]}...")
        text = fetch(url)
        if not text:
            print(f"  ✗ 下载失败")
            results[name] = 0
            continue
        if fmt == "csv_http":
            proxies = parse_csv_http(text)
        else:
            proxies = parse_proxy_list(text)
        print(f"  ✓ {len(proxies)} 个代理")
        results[name] = len(proxies)
        if "socks5" in name:
            all_socks5_proxies.update(proxies)
        else:
            all_http_proxies.update(proxies)

    # === tier3: API 源 ===
    print(f"\n{'='*60}")
    print("Tier 3: API 源")
    print("="*60)
    for src in config.get("tier3_api_pool", {}).get("sources", []):
        name = src["name"]
        url = src["url"]
        fmt = src.get("format", "txt")
        print(f"\n[{name}] {url[:70]}...")
        text = fetch(url)
        if not text:
            print(f"  ✗ 下载失败")
            results[name] = 0
            continue
        if fmt == "json":
            try:
                data = json.loads(text)
                items = data.get("data", [])
                proxies = [f"{d['ip']}:{d['port']}" for d in items if "ip" in d and "port" in d]
            except:
                proxies = []
        elif fmt == "http_txt":
            proxies = parse_proxy_list(text)
        else:
            proxies = parse_proxy_list(text)
        print(f"  ✓ {len(proxies)} 个代理")
        results[name] = len(proxies)
        if "socks5" in name:
            all_socks5_proxies.update(proxies)
        else:
            all_http_proxies.update(proxies)

    # === 汇总 + 写出 ===
    print(f"\n{'='*60}")
    print("汇总")
    print("="*60)
    print(f"HTTP 代理: {len(all_http_proxies)} 个 (去重)")
    print(f"SOCKS5 代理: {len(all_socks5_proxies)} 个 (去重)")

    # 写纯文本列表
    http_file = os.path.join(OUT_DIR, "http_proxies.txt")
    with open(http_file, "w") as f:
        f.write("\n".join(sorted(all_http_proxies)))
    print(f"\n[+] HTTP: {http_file}")

    socks5_file = os.path.join(OUT_DIR, "socks5_proxies.txt")
    with open(socks5_file, "w") as f:
        f.write("\n".join(sorted(all_socks5_proxies)))
    print(f"[+] SOCKS5: {socks5_file}")

    # 各源统计
    print(f"\n各源统计:")
    for name, count in sorted(results.items(), key=lambda x: -x[1]):
        print(f"  {name:25} {count:>6} 个")

    total = len(all_http_proxies) + len(all_socks5_proxies)
    print(f"\n总计: {total} 个代理 IP")
    return 0


if __name__ == "__main__":
    exit(main())
