"""
Shodan API 代理扫描器 — 用 Shodan 搜索高质量 HTTP/SOCKS5 代理.

搜索策略:
    1. 过滤条件: port:80,1080,8080,3128,8081 "HTTP" 且 非 "anonymous" 非 "transparent"
    2. 排除已知坏 IP 段
    3. 测试存活后输出 YAML

用法:
    python -m aiburp.proxy.shodan_proxy_scanner --count 50
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


# ============================================================
# Shodan 搜索
# ============================================================

SHODAN_API_BASE = "https://api.shodan.io"

# 代理搜索 query
PROXY_QUERIES = [
    # HTTP 代理 (透明/匿名)
    'http port:8080 "HTTP/1.1" 200 country:US -cloudflare -"connection refused"',
    'http port:3128 "HTTP/1.1" 200 -"Privoxy" -cloudflare',
    'http port:80 "HTTP/1.1" 200 -cloudflare -"connection refused"',
    'http port:8888 "HTTP/1.1" 200 -cloudflare',
    
    # SOCKS5 代理
    'socks5 port:1080 "SOCKS5"',
    'socks5 port:1080 "METHOD"',

    # HTTPS 代理 (CONNECT)
    'https port:443 "HTTP/1.1" 200 method:CONNECT',
]

# 排除的 IP 段 (内网/保留/已知低质量)
EXCLUDED_CIDRS = [
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.', '127.', '0.', '169.254.',
]


def get_shodan_api_key() -> Optional[str]:
    """从环境变量获取 Shodan API Key"""
    # 从 .env 文件加载
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path)
        except ImportError:
            pass
    # 从环境变量获取
    key = os.getenv("SHODAN_API_KEY", "")
    return key if key and len(key) > 10 else None


def shodan_search(query: str, api_key: str, page: int = 1) -> List[Dict]:
    """
    执行 Shodan 搜索.

    Returns:
        [{ip, port, org, country, hostnames}, ...]
    """
    url = f"{SHODAN_API_BASE}/shodan/host/search"
    params = {
        "key": api_key,
        "query": query,
        "page": page,
        "facets": {},
    }
    try:
        r = requests.get(url, params=params, timeout=15)
        if r.status_code == 200:
            data = r.json()
            matches = data.get("matches", [])
            total = data.get("total", 0)
            return matches, total
        elif r.status_code == 401:
            print(f"  ⚠ Shodan API Key 无效")
            return [], 0
        elif r.status_code == 403:
            print(f"  ⚠ Shodan 配额不足")
            return [], 0
        else:
            return [], 0
    except Exception as e:
        return [], 0


def search_proxies(api_key: str, max_results: int = 200) -> List[Dict]:
    """
    搜索代理服务器.

    Args:
        api_key: Shodan API Key
        max_results: 最大结果数

    Returns:
        [{ip, port, url}, ...]
    """
    results = []
    seen = set()

    for query in PROXY_QUERIES:
        if len(results) >= max_results:
            break

        print(f"  搜索: {query[:60]}...", end=" ", flush=True)
        matches, total = shodan_search(query, api_key)
        if not matches:
            print(f"0 结果")
            continue

        # 去重 + 过滤
        for m in matches:
            ip = m.get("ip_str", "")
            port = m.get("port", 0)

            # 排除内网/保留 IP
            if any(ip.startswith(c) for c in EXCLUDED_CIDRS):
                continue

            key = f"{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)

            protocol = _guess_protocol(port)
            if protocol == "http":
                url = f"http://{ip}:{port}"
            elif protocol == "socks5":
                url = f"socks5://{ip}:{port}"
            else:
                url = f"http://{ip}:{port}"

            results.append({
                "ip": ip,
                "port": port,
                "url": url,
                "protocol": protocol,
                "org": m.get("org", ""),
                "country": m.get("location", {}).get("country_code", ""),
                "hostnames": m.get("hostnames", []),
            })

            if len(results) >= max_results:
                break

        print(f"{len(matches)} 结果, 收集 {len(results)}")

        # Shodan API 有速率限制, 稍等
        time.sleep(1.5)

    return results


def _guess_protocol(port: int) -> str:
    """根据端口猜测代理协议."""
    if port in (1080, 10808):
        return "socks5"
    return "http"


# ============================================================
# 存活测试
# ============================================================

def test_proxy_liveness(proxy: Dict, timeout: int = 5) -> bool:
    """
    测试单个代理是否存活.

    Args:
        proxy: {"url": "...", "protocol": "..."}
        timeout: 超时秒数

    Returns:
        True 如果代理存活
    """
    url = proxy["url"]
    try:
        t0 = time.time()
        r = requests.get(
            "http://httpbin.org/ip",
            proxies={"http": url, "https": url},
            timeout=timeout,
        )
        ms = int((time.time() - t0) * 1000)
        if r.status_code == 200:
            ip = r.json().get("origin", "").split(",")[0].strip()
            proxy["latency_ms"] = ms
            proxy["exit_ip"] = ip
            return True
    except Exception:
        pass
    return False


def test_batch_liveness(
    proxies: List[Dict],
    max_workers: int = 20,
    timeout: int = 4,
) -> List[Dict]:
    """
    批量测试代理存活.

    Returns:
        存活代理列表 (已排序, 按延迟)
    """
    import concurrent.futures

    alive = []

    def test(p):
        if test_proxy_liveness(p, timeout=timeout):
            return p
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for i, result in enumerate(pool.map(test, proxies)):
            if result:
                alive.append(result)
            if (i + 1) % 20 == 0 or i == len(proxies) - 1:
                pass  # silent progress

    alive.sort(key=lambda x: x.get("latency_ms", 9999))
    return alive


# ============================================================
# 生成 Clash YAML
# ============================================================

def to_clash_yaml(proxies: List[Dict]) -> Dict:
    """
    将存活代理列表转换为 Clash YAML 配置.

    Returns:
        可直接 dump 为 YAML 的 dict
    """
    clash_proxies = []
    for i, p in enumerate(proxies[:100]):  # 最多 100 个, 避免 config 太大
        url = p["url"]
        ip = p["ip"]
        port = p["port"]
        lat = p.get("latency_ms", 0)
        exit_ip = p.get("exit_ip", "?")

        clash_proxies.append({
            "name": f"shodan_{i:03d}_{lat}ms_{exit_ip}",
            "type": "http",
            "server": ip,
            "port": port,
        })

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
            "interval": 120,
            "proxies": [p["name"] for p in clash_proxies],
        }],
        "rules": [
            "MATCH,GLOBAL",
        ],
    }


# ============================================================
# 主入口
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Shodan 代理扫描器")
    parser.add_argument("--count", type=int, default=80,
                       help="目标代理数量 (默认 80)")
    parser.add_argument("--timeout", type=int, default=4,
                       help="测活超时秒数 (默认 4)")
    parser.add_argument("--output", type=str,
                       default="yaml/shodan_proxies.yaml",
                       help="输出 YAML 路径 (默认 yaml/shodan_proxies.yaml)")
    args = parser.parse_args()

    # 1. 获取 Shodan API Key
    api_key = get_shodan_api_key()
    if not api_key:
        print("❌ 未找到 SHODAN_API_KEY (检查 .env 或环境变量)")
        sys.exit(1)
    print("✅ Shodan API Key 已加载")

    # 2. 搜索代理
    print(f"\n搜索代理 (目标 {args.count} 个)...")
    candidates = search_proxies(api_key, max_results=args.count * 3)
    print(f"搜索到 {len(candidates)} 个候选代理")

    if not candidates:
        print("❌ 未找到候选代理")
        sys.exit(1)

    # 3. 测活
    print(f"\n测试存活 ({len(candidates)} 个, 并发20, {args.timeout}s 超时)...")
    alive = test_batch_liveness(candidates, max_workers=20, timeout=args.timeout)
    print(f"存活: {len(alive)}/{len(candidates)}")

    if not alive:
        print("❌ 无存活代理")
        out_dir = Path(__file__).parent / "yaml"
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / "shodan_proxies.yaml"
        with open(output_path, "w") as f:
            json.dump({"error": "no_alive_proxies"}, f)
        print(f"已写出空结果: {output_path}")
        sys.exit(1)

    # 4. 输出结果
    print(f"\n最快 {min(10, len(alive))} 个:")
    for p in alive[:10]:
        print(f"  {p['url']:25s} {p.get('latency_ms',0):>5}ms "
              f"{p.get('exit_ip','?'):15s} {p.get('country','?')} {p.get('org','')[:30]}")

    # 5. 生成 YAML
    yaml_data = to_clash_yaml(alive)

    try:
        import yaml as _yaml
        out_dir = Path(__file__).parent / "yaml"
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / args.output.split("/")[-1]
        with open(output_path, "w", encoding="utf-8") as f:
            _yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
        print(f"\n已写出 YAML: {output_path} ({len(alive)} 个代理)")
    except ImportError:
        print("⚠ yaml 包未安装, 输出 JSON")
        out_dir = Path(__file__).parent / "yaml"
        output_path = out_dir / args.output.replace(".yaml", ".json")
        with open(output_path, "w") as f:
            json.dump(alive, f, indent=2)
        print(f"已写出 JSON: {output_path}")

    # 6. 清理: 旧 shodan_proxies.yaml 隔代保留
    print("✅ 完成")


if __name__ == "__main__":
    main()