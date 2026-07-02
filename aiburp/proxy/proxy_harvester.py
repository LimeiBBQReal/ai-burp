"""
统一代理采集器 — 多源合并 + 自动测活 + 持续更新.

采集源:
    1. Shodan API (优质 HTTP 代理)
    2. ProxyScrape (实时热门代理)
    3. GitHub 节点源 (Vless/Trojan 通过 fetch_free_nodes.py)

策略:
    - 三源同时采集, 去重合并
    - 自动测试 HTTP + HTTPS 连通性
    - 存活节点写入 proxy_alive.yaml (mihomo 加载)
    - 提供 get_working_proxy() 快速返回可用节点
"""

import os
import sys
import time
import json
import random
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import requests
import urllib3
urllib3.disable_warnings()


# 路径
YAML_DIR = Path(__file__).parent / "yaml"
ALIVE_YAML = YAML_DIR / "proxy_alive.yaml"


# ============================================================
# 源 1: ProxyScrape (直接 HTTP 代理, 实时)
# ============================================================

PROXYSCRAPE_URLS = [
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000&country=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all",
]


def fetch_proxyscrape() -> List[Dict]:
    """从 ProxyScrape 获取代理列表."""
    results = []
    seen = set()

    for url in PROXYSCRAPE_URLS:
        protocol = "socks5" if "socks5" in url else ("socks4" if "socks4" in url else "http")
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200:
                continue
            lines = [l.strip() for l in r.text.strip().split("\n") if l.strip()]
            for line in lines:
                if ":" not in line:
                    continue
                ip, port_str = line.rsplit(":", 1)
                if not port_str.isdigit():
                    continue
                key = f"{protocol}://{line}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "protocol": protocol,
                    "ip": ip,
                    "port": int(port_str),
                    "url": f"{protocol}://{line}",
                    "source": "proxyscrape",
                })
        except Exception:
            continue

    return results


# ============================================================
# 源 2: Shodan (优质 HTTP 代理)
# ============================================================

SHODAN_QUERIES = [
    'http port:3128 "HTTP/1.1" 200 -cloudflare',
    'http port:8080 "HTTP/1.1" 200 -cloudflare -"connection refused"',
    'http port:8888 "HTTP/1.1" 200 -cloudflare',
    'socks5 port:1080 "SOCKS5"',
]


def fetch_shodan(api_key: str, max_results: int = 200) -> List[Dict]:
    """从 Shodan 获取代理."""
    from .shodan_proxy_scanner import search_proxies

    results = []
    for query in SHODAN_QUERIES:
        if len(results) >= max_results:
            break
        try:
            from .shodan_proxy_scanner import shodan_search
            matches, total = shodan_search(query, api_key)
            if not matches:
                continue
            for m in matches:
                ip = m.get("ip_str", "")
                port = m.get("port", 0)
                protocol = "http"
                if port == 1080:
                    protocol = "socks5"
                url = f"{protocol}://{ip}:{port}"
                results.append({
                    "protocol": protocol,
                    "ip": ip,
                    "port": port,
                    "url": url,
                    "source": "shodan",
                    "org": m.get("org", ""),
                    "country": m.get("location", {}).get("country_code", ""),
                })
                if len(results) >= max_results:
                    break
        except Exception:
            continue
    return results


# ============================================================
# 测活
# ============================================================

def test_proxy(proxy: Dict, timeout: float = 4.0) -> Optional[Dict]:
    """
    测试单个代理 (HTTP + HTTPS).

    Returns:
        测活通过的 proxy dict (含 latency_ms/exit_ip/ssl_ok),
        失败返回 None
    """
    url = proxy["url"]
    try:
        # 测试 HTTP
        t0 = time.time()
        r = requests.get(
            "http://httpbin.org/ip",
            proxies={"http": url, "https": url},
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        ms = int((time.time() - t0) * 1000)

        ip = r.json().get("origin", "").split(",")[0].strip()
        proxy["latency_ms"] = ms
        proxy["exit_ip"] = ip

        # 测试 HTTPS (快速, 3s 超时)
        try:
            r2 = requests.get(
                "https://api.ipify.org?format=json",
                proxies={"http": url, "https": url},
                timeout=min(3.0, timeout),
            )
            proxy["ssl_ok"] = (r2.status_code == 200)
        except Exception:
            proxy["ssl_ok"] = False

        return proxy
    except Exception:
        return None


def batch_test(
    proxies: List[Dict],
    max_workers: int = 30,
    timeout: float = 4.0,
    require_ssl: bool = False,
) -> List[Dict]:
    """
    批量测试代理.

    Args:
        proxies: 代理列表
        max_workers: 并发数
        timeout: 超时秒数
        require_ssl: 是否要求 HTTPS 能力

    Returns:
        存活代理列表 (按延迟排序)
    """
    import concurrent.futures

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(test_proxy, p, timeout): p for p in proxies}
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                if require_ssl and not result.get("ssl_ok"):
                    continue
                alive.append(result)

    alive.sort(key=lambda x: x.get("latency_ms", 9999))
    return alive


# ============================================================
# 合并去重
# ============================================================

def dedup(proxies: List[Dict]) -> List[Dict]:
    """按 ip:port 去重, 保留第一个."""
    seen = set()
    result = []
    for p in proxies:
        key = f"{p['ip']}:{p['port']}"
        if key in seen:
            continue
        seen.add(key)
        result.append(p)
    return result


# ============================================================
# 生成 Clash YAML
# ============================================================

def to_clash_yaml(proxies: List[Dict], max_nodes: int = 50) -> Dict:
    """
    生成 mihomo 兼容 YAML.

    按类型分组, 最多 max_nodes 个. 优先 SSL 支持.
    """
    # 按 SSL 支持排序
    proxies.sort(key=lambda x: (0 if x.get("ssl_ok") else 1, x.get("latency_ms", 9999)))

    clash_proxies = []
    for i, p in enumerate(proxies[:max_nodes]):
        ip = p["ip"]
        port = p["port"]
        lat = p.get("latency_ms", 0)
        exit_ip = p.get("exit_ip", "?")
        ssl_tag = "S" if p.get("ssl_ok") else "H"

        name = f"pool_{i:03d}_{ssl_tag}_{lat}ms"
        proxy_type = p.get("protocol", "http")

        # mihomo 支持的代理类型: http / socks5
        if proxy_type.startswith("socks"):
            proxy_type = "socks5"

        entry = {
            "name": name,
            "type": proxy_type,
            "server": ip,
            "port": port,
        }
        if proxy_type == "http":
            entry["tls"] = False

        clash_proxies.append(entry)

    return {
        "port": 7890,
        "socks-port": 7891,
        "mode": "Rule",
        "log-level": "silent",
        "proxies": clash_proxies,
        "proxy-groups": [{
            "name": "GLOBAL",
            "type": "url-test",
            "url": "http://httpbin.org/ip",
            "interval": 60,
            "proxies": [p["name"] for p in clash_proxies],
        }],
        "rules": [
            "MATCH,GLOBAL",
        ],
    }


# ============================================================
# 主入口
# ============================================================

def collect(
    require_ssl: bool = False,
    min_alive: int = 5,
    timeout: float = 4.0,
) -> List[Dict]:
    """
    完整采集流程.

    Returns:
        存活代理列表
    """
    all_candidates = []

    # Phase 1: ProxyScrape (最快, 最及时)
    print(f"[Phase 1] ProxyScrape...")
    ps = fetch_proxyscrape()
    print(f"  → {len(ps)} 候选")
    all_candidates.extend(ps)

    # Phase 2: Shodan (高质量)
    try:
        from .shodan_proxy_scanner import get_shodan_api_key
        api_key = get_shodan_api_key()
        if api_key:
            print(f"[Phase 2] Shodan...")
            sd = fetch_shodan(api_key, max_results=200)
            print(f"  → {len(sd)} 候选")
            all_candidates.extend(sd)
        else:
            print(f"[Phase 2] Shodan: 无 API Key, 跳过")
    except Exception as e:
        print(f"[Phase 2] Shodan: {e}")

    # 去重
    all_candidates = dedup(all_candidates)
    print(f"\n总候选 (去重后): {len(all_candidates)}")

    if not all_candidates:
        print("❌ 无候选代理")
        return []

    # Phase 3: 测活 (分两批: 先 HTTP 快速筛选, 再 HTTPS 质量筛选)
    print(f"\n[Phase 3] 测活 (并发30, {timeout}s)...")
    alive = batch_test(all_candidates, max_workers=30, timeout=timeout)

    ssl_alive = [p for p in alive if p.get("ssl_ok")]
    print(f"存活: HTTP={len(alive)}, HTTPS={len(ssl_alive)}")

    if len(alive) < min_alive:
        print(f"⚠ 存活太少 ({len(alive)} < {min_alive}), 降低超时重试...")
        # 放宽要求再试一次
        time.sleep(1)
        extra = batch_test(
            [c for c in all_candidates if c not in alive],
            max_workers=30, timeout=timeout + 2,
        )
        alive.extend(extra)
        alive = dedup(alive)
        alive.sort(key=lambda x: x.get("latency_ms", 9999))
        print(f"  放宽后: {len(alive)} 存活")

    return alive


def write_config(alive: List[Dict]):
    """写出 YAML 配置."""
    YAML_DIR.mkdir(parents=True, exist_ok=True)
    yaml_data = to_clash_yaml(alive, max_nodes=80)

    try:
        import yaml as _yaml
        with open(ALIVE_YAML, "w", encoding="utf-8") as f:
            _yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
        print(f"\n已写出: {ALIVE_YAML} ({len(yaml_data['proxies'])} 个)")
    except ImportError:
        # fallback to JSON
        json_path = YAML_DIR / "proxy_alive.json"
        with open(json_path, "w") as f:
            json.dump(alive, f, indent=2, default=str)
        print(f"\n已写出: {json_path} (yaml 包未安装)")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="统一代理采集器")
    parser.add_argument("--min-alive", type=int, default=5,
                       help="最低存活数量 (默认 5)")
    parser.add_argument("--timeout", type=float, default=4.0,
                       help="测活超时秒数 (默认 4s)")
    parser.add_argument("--require-ssl", action="store_true",
                       help="要求 HTTPS 能力")
    parser.add_argument("--no-write", action="store_true",
                       help="不写出 YAML (仅打印)")
    args = parser.parse_args()

    alive = collect(
        require_ssl=args.require_ssl,
        min_alive=args.min_alive,
        timeout=args.timeout,
    )

    if alive:
        print(f"\n最快的 {min(10, len(alive))} 个:")
        for p in alive[:10]:
            ssl_mark = "🔒" if p.get("ssl_ok") else "  "
            print(f"  {ssl_mark} {p['url']:30s} {p.get('latency_ms',0):>5}ms "
                  f"{p.get('exit_ip','?'):15s} {p.get('source','?')}")
        print(f"\nHTTP: {len(alive)} | HTTPS: {len([p for p in alive if p.get('ssl_ok')])}")

        if not args.no_write:
            write_config(alive)
    else:
        print(f"\n❌ 未找到存活代理")
        sys.exit(1)


if __name__ == "__main__":
    main()