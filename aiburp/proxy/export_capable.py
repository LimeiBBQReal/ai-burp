"""
从 dola_capability.json 读取 CAPABLE 节点名,
从 yaml/verified_all.yaml 中筛出对应 proxy 配置,
生成只含 CAPABLE 节点的精简 yaml (供 DOLA 脚本直接用).

输出: yaml/dola_capable.yaml
"""
import json
import yaml

SRC_YAML = r"F:\CodexDEV\qwen2API\proxy\yaml\verified_all.yaml"
RESULT_JSON = r"F:\CodexDEV\qwen2API\dola_capability.json"
OUT_YAML = r"F:\CodexDEV\qwen2API\proxy\yaml\dola_capable.yaml"


def main():
    # 1. 读探测结果, 取 CAPABLE 节点名
    with open(RESULT_JSON, "r", encoding="utf-8") as f:
        results = json.load(f)
    capable_names = [r["node"] for r in results if r["status"] in ("CAPABLE", "CAPABLE+")]
    capable_set = set(capable_names)
    print(f"[*] CAPABLE 节点 {len(capable_names)} 个")

    # 2. 读原 yaml, 筛 proxies
    with open(SRC_YAML, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    all_proxies = cfg.get("proxies", []) or []
    capable_proxies = [p for p in all_proxies if p.get("name") in capable_set]

    # 诊断: 哪些 CAPABLE 节点名在 yaml 里没匹配到
    matched = {p["name"] for p in capable_proxies}
    missing = capable_set - matched
    if missing:
        print(f"[!] 警告: {len(missing)} 个 CAPABLE 节点在 yaml 中未找到配置:")
        for n in missing:
            print(f"      - {n}")

    print(f"[*] 匹配到 proxy 配置 {len(capable_proxies)} 个")

    # 3. 生成精简 yaml (保留最小必要字段, mini_clash 友好)
    out = {
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
        "proxies": capable_proxies,
        "proxy-groups": [
            {
                "name": "GLOBAL",
                "type": "select",
                "proxies": [p["name"] for p in capable_proxies] + ["DIRECT"],
            }
        ],
        "rules": ["MATCH,GLOBAL"],
    }

    with open(OUT_YAML, "w", encoding="utf-8") as f:
        yaml.dump(out, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    print(f"[+] 已写出: {OUT_YAML}")
    print(f"    {len(capable_proxies)} 个 CAPABLE proxy 节点")
    print(f"\n[*] 节点列表:")
    for p in capable_proxies:
        print(f"    {p.get('name'):<48} ({p.get('type')}, {p.get('server')}:{p.get('port')})")


if __name__ == "__main__":
    main()
