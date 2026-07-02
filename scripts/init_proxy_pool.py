"""
代理池初始化脚本 — 测活 + 加载 + OpSec 验证.

用法:
    python scripts/init_proxy_pool.py

输出:
    - 从 YAML/TXT 文件中读取候选代理
    - 测活 → 筛除非透明代理
    - 加载到 ProxyManager
    - 验证 OpSec (真实IP ≠ 代理出口IP)
    - 返回代理 URL
"""

import os
import sys
import time
import json
import threading
import queue
import logging
from typing import List, Tuple, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ============================================================
# 步骤 1: 读取候选代理
# ============================================================

def load_candidates() -> List[str]:
    """从 YAML + TXT 文件读取代理候选."""
    import yaml

    candidates = []
    seen = set()

    yaml_files = [
        "aiburp/proxy/yaml/proxy_alive.yaml",
        "aiburp/proxy/yaml/dola_capable_proxies.yaml",
        "aiburp/proxy/yaml/shodan_proxies.yaml",
    ]
    for fp in yaml_files:
        if not os.path.exists(fp):
            continue
        with open(fp) as f:
            data = yaml.safe_load(f)
            raw = data.get("proxies", []) if isinstance(data, dict) else []
        for p in raw:
            ptype = p.get("type", "http").lower()
            host = p.get("server", "")
            port = p.get("port", 8080)
            if host and port:
                url = f"http://{host}:{port}"
                if url not in seen:
                    seen.add(url)
                    candidates.append(url)

    txt_path = "aiburp/proxy/yaml/proxy_raw/http_alive.txt"
    if os.path.exists(txt_path):
        with open(txt_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    url = line if line.startswith("http") else f"http://{line}"
                    if url not in seen:
                        seen.add(url)
                        candidates.append(url)

    logger.info(f"读取到 {len(candidates)} 个候选代理")
    return candidates


# ============================================================
# 步骤 2: 测活 + 筛非透明
# ============================================================

def test_liveness(proxies: List[str], max_threads: int = 30,
                  timeout: float = 8) -> List[Tuple[str, int, str]]:
    """
    并发测活.

    Returns: [(url, latency_ms, exit_ip), ...]
    只保留非透明代理 (出口IP ≠ 代理IP).
    """
    results = []
    q = queue.Queue()
    lock = threading.Lock()

    for p in proxies:
        q.put(p)

    def worker():
        while True:
            try:
                url = q.get_nowait()
            except queue.Empty:
                break
            try:
                import requests
                t0 = time.time()
                r = requests.get(
                    "http://httpbin.org/ip",
                    proxies={"http": url, "https": url},
                    timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                elapsed_ms = round((time.time() - t0) * 1000)
                exit_ip = r.json().get("origin", "")

                # 检查是否非透明: exit_ip 不包含代理 IP
                proxy_ip = url.split("/")[2].split(":")[0]
                is_transparent = proxy_ip in exit_ip

                # 检查是否泄露真实 IP (本次固定)
                real_check = requests.get(
                    "http://httpbin.org/ip",
                    timeout=5,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                real_ip = real_check.json().get("origin", "")
                leaks_real = real_ip in exit_ip

                if not is_transparent and not leaks_real:
                    with lock:
                        results.append((url, elapsed_ms, exit_ip))
                elif leaks_real:
                    logger.warning(f"  泄露真实IP: {url} → exit={exit_ip}")
                else:
                    logger.debug(f"  透明代理: {url} → exit={exit_ip}")
            except Exception:
                pass

    threads = [threading.Thread(target=worker) for _ in range(max_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    results.sort(key=lambda x: x[1])  # 按延迟排序
    logger.info(f"测活完成: {len(results)} 个非透明代理存活 / {len(proxies)} 候选")
    return results


# ============================================================
# 步骤 3: 加载到 ProxyManager + OpSec 验证
# ============================================================

def load_and_verify(alive: List[Tuple[str, int, str]],
                    required_min: int = 5) -> Optional[str]:
    """
    加载到 ProxyManager 并验证 OpSec.

    Returns: 代理 URL (如果验证通过), 否则 None
    """
    if len(alive) < required_min:
        logger.error(f"存活代理不足 ({len(alive)} < {required_min}), 无法继续")
        return None

    try:
        from aiburp.proxy_manager import ProxyManager

        pm = ProxyManager()
        proxy_urls = [url for url, ms, ip in alive]
        pm.add_proxies(proxy_urls)
        logger.info(f"已加载 {len(proxy_urls)} 个代理到 ProxyManager")

        # 获取一个代理
        proxy = pm.get_proxy()
        if not proxy:
            logger.error("ProxyManager.get_proxy() 返回 None")
            return None

        logger.info(f"获取代理: {proxy}")

        # OpSec 验证: 出口 IP ≠ 真实 IP
        import requests
        # 真实 IP
        real_resp = requests.get(
            "http://httpbin.org/ip",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        real_ip = real_resp.json().get("origin", "")
        logger.info(f"真实 IP: {real_ip}")

        # 代理出口 IP
        proxy_resp = requests.get(
            "http://httpbin.org/ip",
            proxies={"http": proxy, "https": proxy},
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        exit_ip = proxy_resp.json().get("origin", "")
        logger.info(f"代理出口 IP: {exit_ip}")

        if exit_ip == real_ip:
            logger.error(f"⛔ OpSec 失败: 出口IP={exit_ip} 等于真实IP={real_ip}")
            return None

        logger.info(f"✅ OpSec 通过: 出口IP={exit_ip} ≠ 真实IP={real_ip}")
        return proxy

    except Exception as e:
        logger.error(f"加载失败: {e}")
        return None


# ============================================================
# 主流程
# ============================================================

def main() -> Optional[str]:
    print("=" * 55)
    print("  🔒 Proxy 初始化 — 测活 → 加载 → OpSec 验证")
    print("=" * 55)

    # Step 1: 读取候选
    candidates = load_candidates()
    if not candidates:
        logger.error("无候选代理")
        return None

    # Step 2: 测活
    logger.info(f"测活 {len(candidates)} 个候选...")
    alive = test_liveness(candidates)
    if len(alive) < 5:
        logger.warning(f"仅 {len(alive)} 个存活, 尝试从 proxyscrape 补充...")
        try:
            from aiburp.proxy.proxy_harvester import collect
            harvested = collect(min_alive=5, timeout=4)
            logger.info(f"补充采集: {len(harvested)} 个")
            # 对采集的再次测活
            extra = test_liveness(harvested)
            alive.extend(extra)
            alive.sort(key=lambda x: x[1])
        except Exception as e:
            logger.warning(f"补充采集失败: {e}")

    if len(alive) < 5:
        logger.error(f"最终存活代理不足 ({len(alive)}), 无法继续")
        return None

    logger.info(f"Top 5: {[u for u, ms, ip in alive[:5]]}")
    logger.info(f"出口 IP 列表: {[ip for u, ms, ip in alive[:10]]}")

    # Step 3: 加载 + 验证
    proxy = load_and_verify(alive)
    if proxy:
        print(f"\n{'='*55}")
        print(f"  代理就绪: {proxy}")
        print(f"  存活节点: {len(alive)}")
        print(f"{'='*55}")
    return proxy


if __name__ == "__main__":
    proxy = main()
    if proxy:
        # 输出 JSON 供后续脚本消费
        output = {
            "proxy": proxy,
            "status": "ready",
            "timestamp": time.time(),
        }
        os.makedirs(".proxy_state", exist_ok=True)
        with open(".proxy_state/active_proxy.json", "w") as f:
            json.dump(output, f)
        print(f"\n代理已持久化到 .proxy_state/active_proxy.json")
        print(f"后续脚本可用: python -c \"import json; print(json.load(open('.proxy_state/active_proxy.json'))['proxy'])\"")