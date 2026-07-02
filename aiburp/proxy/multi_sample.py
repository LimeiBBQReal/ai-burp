"""
多轮随机抽样测活，累积存活节点，合并写出 yaml/free_nodes_alive_all.yaml

每轮抽样 800 个，跑 N 轮，去重合并。
"""
import sys
import time
import yaml
import json
import random
import requests
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from mini_clash import MiniClash

SRC_YAML = r"F:\CodexDEV\qwen2API\proxy\yaml\free_nodes_merged.yaml"
OUT_YAML = r"F:\CodexDEV\qwen2API\proxy\yaml\free_nodes_alive_all.yaml"
SAMPLE_PER_ROUND = 800
WORKERS = 30
TIMEOUT_MS = 5000
ROUNDS = 8


def test_one(mc_url, name, timeout_ms=5000):
    try:
        encoded = requests.utils.quote(name, safe="")
        url = f"{mc_url}/proxies/{encoded}/delay?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout={timeout_ms}"
        r = requests.get(url, timeout=timeout_ms/1000+3)
        if r.status_code == 200:
            return (name, r.json().get("delay", -1))
    except: pass
    return (name, -1)


def run_round(mc, nodes, round_num):
    names = [n["name"] for n in nodes]
    total = len(names)
    alive = {}
    t0 = time.time()
    print(f"\n[轮次 {round_num}] 测活 {total} 个节点 (workers={WORKERS})...")

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(test_one, mc._base_url, n, TIMEOUT_MS): n for n in names}
        done = 0
        for f in as_completed(futures):
            done += 1
            name, delay = f.result()
            if delay > 0:
                alive[name] = delay
            if done % 200 == 0 or done == total:
                print(f"  [{done}/{total}] alive={len(alive)}")

    elapsed = time.time() - t0
    print(f"[轮次 {round_num}] 完成 ({elapsed:.0f}s) 存活={len(alive)}")
    return alive


def main():
    with open(SRC_YAML, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    all_proxies = cfg.get("proxies", []) or []
    total = len(all_proxies)
    print(f"[*] 总节点: {total}")

    all_alive_names = {}
    tested_names = set()

    for round_num in range(1, ROUNDS + 1):
        # 从还没测过的节点中抽样
        untested = [p for p in all_proxies if p.get("name") not in tested_names]
        if not untested:
            print(f"\n[*] 所有节点已测完，停止")
            break
        sample_size = min(SAMPLE_PER_ROUND, len(untested))
        sample = random.sample(untested, sample_size)
        for p in sample:
            tested_names.add(p.get("name", ""))

        # 写临时 yaml
        sample_cfg = dict(cfg)
        sample_cfg["proxies"] = sample
        sample_cfg["proxy-groups"] = [{"name": "GLOBAL", "type": "select",
                                       "proxies": [p["name"] for p in sample] + ["DIRECT"]}]
        tmp = os.path.join(tempfile.gettempdir(), f"sample_r{round_num}.yaml")
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.dump(sample_cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        mc = MiniClash(config_path=tmp)
        if not mc.start(timeout=30):
            print(f"[!] 轮次 {round_num} mini_clash 启动失败")
            continue
        try:
            alive = run_round(mc, sample, round_num)
            all_alive_names.update(alive)
        finally:
            mc.stop()

        print(f"  累计存活: {len(all_alive_names)}")

    # 合并所有存活节点
    alive_set = set(all_alive_names.keys())
    alive_proxies = [p for p in all_proxies if p.get("name") in alive_set]
    alive_proxies.sort(key=lambda p: all_alive_names.get(p.get("name",""), 99999))

    print(f"\n[*] 总计测试: {len(tested_names)} 节点")
    print(f"[*] 总计存活: {len(alive_proxies)} 节点")

    out_cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "global",
        "log-level": "warning", "ipv6": False,
        "dns": {"enable": True, "ipv6": False, "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"]},
        "proxies": alive_proxies,
        "proxy-groups": [{"name": "GLOBAL", "type": "select",
                          "proxies": [p["name"] for p in alive_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,GLOBAL"],
    }
    with open(OUT_YAML, "w", encoding="utf-8") as f:
        yaml.dump(out_cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    print(f"[+] 已写出: {OUT_YAML}")

    by_type = {}
    for p in alive_proxies:
        t = p.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
    print(f"\n[*] 存活节点类型:")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
