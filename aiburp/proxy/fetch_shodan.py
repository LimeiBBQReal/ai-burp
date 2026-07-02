"""
Shodan 代理采集 — 从 Shodan 搜索高匿代理

Shodan 能搜到 GitHub 免费列表里没有的代理:
  - 搜索特定端口 (3128, 8080, 1080 等)
  - 按国家/ISP 过滤
  - 按 HTTP 响应头确认是代理

用法:
  cd proxy
  python fetch_shodan.py                    # 默认采集 1000 个
  python fetch_shodan.py --limit 5000       # 采集 5000 个
  python fetch_shodan.py --country US,SG    # 按国家
  python fetch_shodan.py --port 3128,8080   # 按端口

需要: .env 文件里的 SHODAN_API_KEY
"""
import os
import sys
import json
import time
import requests
from typing import List

# 加载 .env
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_FILE = os.path.join(_PARENT, ".env")
if os.path.isfile(_ENV_FILE):
    with open(_ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_BASE = "https://api.shodan.io"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yaml", "proxy_raw")


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def search_shodan(query: str, limit: int = 1000, facets: str = None) -> List[dict]:
    """
    Shodan search API
    返回 [{ip, port, country, org, ...}, ...]
    """
    if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_api_key_here":
        log("[!] SHODAN_API_KEY 未配置, 请在 .env 文件填入")
        log("    获取: https://www.shodan.io/ → My Account → API Key")
        return []

    results = []
    page = 1
    page_size = 100

    while len(results) < limit:
        params = {
            "key": SHODAN_API_KEY,
            "query": query,
            "page": page,
        }
        log(f"  Shodan API page {page} (query: {query[:50]}...)")

        try:
            r = requests.get(f"{SHODAN_BASE}/shodan/host/search",
                           params=params, timeout=30)
            if r.status_code == 200:
                data = r.json()
                matches = data.get("matches", [])
                if not matches:
                    log(f"    无更多结果")
                    break
                for m in matches:
                    results.append({
                        "ip": m.get("ip_str", ""),
                        "port": m.get("port", 0),
                        "country": m.get("location", {}).get("country_code", ""),
                        "org": m.get("org", ""),
                        "os": m.get("os", ""),
                    })
                log(f"    +{len(matches)} (总计 {len(results)})")
                # Shodan 限速: 1 req/sec (免费版)
                time.sleep(1.5)
                page += 1
            elif r.status_code == 429:
                log(f"    限速! 等待 5s...")
                time.sleep(5)
                continue
            elif r.status_code == 403:
                log(f"    API Key 无效或额度用完")
                break
            else:
                log(f"    HTTP {r.status_code}: {r.text[:100]}")
                break
        except Exception as e:
            log(f"    异常: {type(e).__name__}: {str(e)[:60]}")
            time.sleep(3)

    return results[:limit]


def build_query(ports: str = None, countries: str = None, proxy_type: str = "http") -> str:
    """构造 Shodan 搜索 query (简化语法, 避免嵌套 OR 导致 500)"""
    parts = []

    # 端口: 单端口 (Shodan 不支持嵌套 OR)
    if ports:
        # 多端口时只用第一个 (主脚本会分端口轮询)
        p = ports.split(",")[0].strip()
        parts.append(f"port:{p}")
    else:
        if proxy_type == "http":
            parts.append("port:3128")
        elif proxy_type == "socks5":
            parts.append("port:1080")

    # 国家: 单国家
    if countries:
        c = countries.split(",")[0].strip()
        parts.append(f"country:{c}")

    # 代理产品标识
    if proxy_type == "http":
        parts.append("product:Squid")
    elif proxy_type == "socks5":
        parts.append('"Socks5"')

    return " ".join(parts)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Shodan 代理采集")
    ap.add_argument("--limit", type=int, default=1000, help="采集数量 (默认 1000)")
    ap.add_argument("--port", default=None, help="端口 (逗号分隔, 如 3128,8080)")
    ap.add_argument("--country", default=None, help="国家代码 (如 US,SG,KR)")
    ap.add_argument("--type", choices=["http", "socks5"], default="http", help="代理类型")
    args = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)

    # 分端口/国家轮询 (Shodan 不支持嵌套 OR, 每次单端口单国家)
    port_list = args.port.split(",") if args.port else (["3128","8080","8888","3129"] if args.type == "http" else ["1080","1081","9050"])
    country_list = args.country.split(",") if args.country else ["US","KR","SG","JP","DE","NL","GB","FR","TW","HK"]
    per_query = max(100, args.limit // (len(port_list) * min(3, len(country_list))))

    log(f"[*] Shodan 代理采集")
    log(f"    类型: {args.type}")
    log(f"    端口: {port_list}")
    log(f"    国家: {country_list}")
    log(f"    总目标: {args.limit}")
    log(f"    每轮: {per_query}")

    all_results = []
    used_countries = set()
    for port in port_list:
        for country in country_list:
            if len(all_results) >= args.limit:
                break
            query = build_query(ports=port, countries=country, proxy_type=args.type)
            log(f"\n  [{port} / {country}] {query[:60]}...")
            results = search_shodan(query, limit=per_query)
            all_results.extend(results)
            used_countries.add(country)
            log(f"    累计: {len(all_results)}")
            time.sleep(1)
        if len(all_results) >= args.limit:
            break

    results = all_results[:args.limit]
    if not results:
        log("[!] 无结果")
        return 1

    # 去重
    seen = set()
    unique = []
    for r in results:
        key = f"{r['ip']}:{r['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)

    log(f"\n[*] 采集完成: {len(unique)} 个唯一代理 (去重前 {len(results)})")

    # 按国家统计
    by_country = {}
    for r in unique:
        c = r.get("country", "??")
        by_country[c] = by_country.get(c, 0) + 1
    log("[*] 国家分布:")
    for c, n in sorted(by_country.items(), key=lambda x: -x[1])[:10]:
        log(f"    {c}: {n}")

    # 写纯文本 (ip:port)
    txt_file = os.path.join(OUT_DIR, f"shodan_{args.type}.txt")
    with open(txt_file, "w") as f:
        for r in unique:
            f.write(f"{r['ip']}:{r['port']}\n")
    log(f"\n[+] {txt_file} ({len(unique)} 个)")

    # 写 JSON (含元数据)
    json_file = os.path.join(OUT_DIR, f"shodan_{args.type}.json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=2)
    log(f"[+] {json_file}")

    # 合并到已有代理列表
    existing_file = os.path.join(OUT_DIR, f"http_proxies.txt" if args.type == "http" else "socks5_proxies.txt")
    if os.path.isfile(existing_file):
        with open(existing_file) as f:
            existing = set(l.strip() for l in f if l.strip())
        new = [f"{r['ip']}:{r['port']}" for r in unique if f"{r['ip']}:{r['port']}" not in existing]
        if new:
            with open(existing_file, "a") as f:
                f.write("\n" + "\n".join(new))
            log(f"[+] 合并到 {existing_file} (+{len(new)} 新增)")
        else:
            log(f"[*] 无新增 (全部已存在)")

    log(f"\n[*] 下一步: python verify_proxies.py  (验证存活)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
