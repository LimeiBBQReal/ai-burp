"""
快速测活脚本: 用 mini_clash 加载 free_nodes_merged.yaml,
并发测试节点的 TCP 连通性 (connectivity check, 不做 DOLA 探测).

策略:
  1. 启动 mini_clash 加载全部节点
  2. 随机抽样 + 多线程并发测延迟
  3. 筛选出 delay > 0 的存活节点
  4. 导出存活节点为 yaml/free_nodes_alive.yaml

输出: yaml/free_nodes_alive.yaml + 终端报告
"""
import sys
import time
import yaml
import json
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from mini_clash import MiniClash
from typing import List, Dict

SRC_YAML = r"F:\CodexDEV\qwen2API\proxy\yaml\free_nodes_merged.yaml"
OUT_YAML = r"F:\CodexDEV\qwen2API\proxy\yaml\free_nodes_alive.yaml"

# 最多抽样测活的节点数 (19493 全测太慢, 随机抽样)
MAX_SAMPLE = 800
# 并发线程数
WORKERS = 30


def test_one_delay(mc_url: str, name: str, timeout_ms: int = 5000) -> tuple:
    """测单个节点延迟，返回 (name, delay_ms)"""
    try:
        encoded = requests.utils.quote(name, safe="")
        url = f"{mc_url}/proxies/{encoded}/delay?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout={timeout_ms}"
        r = requests.get(url, timeout=timeout_ms / 1000 + 3)
        if r.status_code == 200:
            delay = r.json().get("delay", -1)
            return (name, delay)
    except Exception:
        pass
    return (name, -1)


def test_all_delay(mc: MiniClash, nodes: List[Dict], timeout_ms: int = 5000) -> Dict[str, int]:
    """并发测活"""
    names = [n["name"] for n in nodes]
    total = len(names)
    print(f"\n[*] 并发测活 {total} 个节点 (workers={WORKERS}, timeout={timeout_ms}ms)...\n")

    results = {}
    alive = 0
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(test_one_delay, mc._base_url, name, timeout_ms): name
            for name in names
        }
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            name, delay = future.result()
            results[name] = delay
            if delay > 0:
                alive += 1
            if done_count % 100 == 0 or done_count == total:
                elapsed = time.time() - t0
                rate = done_count / elapsed if elapsed > 0 else 0
                eta = (total - done_count) / rate if rate > 0 else 0
                print(f"  [{done_count}/{total}] alive={alive}  elapsed={elapsed:.0f}s  ETA={eta:.0f}s")

    elapsed = time.time() - t0
    print(f"\n[*] 测活完成 ({elapsed:.0f}s)")
    print(f"    存活: {alive}/{total}")
    return results


def main():
    with open(SRC_YAML, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    all_proxies = cfg.get("proxies", []) or []

    total = len(all_proxies)
    print(f"[*] 原始节点: {total} 个")

    # 随机抽样
    if total > MAX_SAMPLE:
        sample = random.sample(all_proxies, MAX_SAMPLE)
        print(f"[*] 随机抽样: {MAX_SAMPLE} 个 (共 {total})")
    else:
        sample = all_proxies
        print(f"[*] 全量测活: {total} 个")

    # 临时写一个只含抽样节点的 yaml 给 mini_clash 用
    sample_cfg = dict(cfg)
    sample_cfg["proxies"] = sample
    sample_cfg["proxy-groups"] = [
        {
            "name": "GLOBAL",
            "type": "select",
            "proxies": [p["name"] for p in sample] + ["DIRECT"],
        }
    ]
    import tempfile, os
    tmp_yaml = os.path.join(tempfile.gettempdir(), "free_nodes_sample.yaml")
    with open(tmp_yaml, "w", encoding="utf-8") as f:
        yaml.dump(sample_cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    mc = MiniClash(config_path=tmp_yaml)
    if not mc.start(timeout=30):
        print("[!] mini_clash 启动失败")
        return 1

    try:
        results = test_all_delay(mc, sample, timeout_ms=5000)

        # 筛选存活节点
        alive_names = {name for name, delay in results.items() if delay > 0}
        alive_proxies = [p for p in all_proxies if p.get("name") in alive_names]

        # 按延迟排序
        delay_map = {name: delay for name, delay in results.items() if delay > 0}
        alive_proxies.sort(key=lambda p: delay_map.get(p.get("name", ""), 99999))

        print(f"\n[*] 存活节点: {len(alive_proxies)} 个 (抽样 {len(sample)} 中)")
        if alive_proxies:
            print(f"    最快: {alive_proxies[0].get('name')} ({delay_map.get(alive_proxies[0].get('name',''), 0)}ms)")
            print(f"    最慢: {alive_proxies[-1].get('name')} ({delay_map.get(alive_proxies[-1].get('name',''), 0)}ms)")

        # 导出
        out_cfg = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "global",
            "log-level": "warning",
            "ipv6": False,
            "dns": {
                "enable": True,
                "ipv6": False,
                "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"],
            },
            "proxies": alive_proxies,
            "proxy-groups": [
                {
                    "name": "GLOBAL",
                    "type": "select",
                    "proxies": [p["name"] for p in alive_proxies] + ["DIRECT"],
                }
            ],
            "rules": ["MATCH,GLOBAL"],
        }

        with open(OUT_YAML, "w", encoding="utf-8") as f:
            yaml.dump(out_cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        print(f"[+] 已写出: {OUT_YAML}")
        print(f"    {len(alive_proxies)} 个存活节点")

        # 打印类型分布
        by_type = {}
        for p in alive_proxies:
            t = p.get("type", "?")
            by_type[t] = by_type.get(t, 0) + 1
        print(f"\n[*] 存活节点类型分布:")
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"    {t}: {c}")

        return 0
    finally:
        mc.stop()


if __name__ == "__main__":
    sys.exit(main())
