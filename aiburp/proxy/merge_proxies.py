"""合并新 CAPABLE 代理到 dola_capable.yaml"""
import yaml

with open("proxy/yaml/dola_capable_proxies.yaml") as f:
    new_proxies = yaml.safe_load(f).get("proxies", [])

with open("proxy/yaml/dola_capable.yaml") as f:
    existing = yaml.safe_load(f)
existing_proxies = existing.get("proxies", [])

seen = set()
merged = []
for p in existing_proxies + new_proxies:
    key = f'{p.get("server","")}:{p.get("port",0)}'
    if key not in seen:
        seen.add(key)
        merged.append(p)

print(f"现有: {len(existing_proxies)} 节点")
print(f"新增: {len(new_proxies)} 节点")
print(f"合并去重: {len(merged)} 节点")

cfg = dict(existing)
cfg["proxies"] = merged
cfg["proxy-groups"] = [{"name": "GLOBAL", "type": "select",
                        "proxies": [p["name"] for p in merged] + ["DIRECT"]}]
with open("proxy/yaml/dola_capable.yaml", "w", encoding="utf-8") as f:
    yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

by_type = {}
for p in merged:
    t = p.get("type", "?")
    by_type[t] = by_type.get(t, 0) + 1
print(f"\n协议分布: {by_type}")
print(f"\n[+] yaml/dola_capable.yaml 已更新 ({len(merged)} 节点)")
