import json
from pathlib import Path

p = Path(__file__).parent / "cartmanager_inventory.json"
d = json.loads(p.read_text(encoding="utf-8"))

print(f"target: {d.get('target')}")
print(f"IPs ({len(d['ips'])}): {d['ips']}")
print(f"subdomains ({len(d['subdomains'])}):")
for s in d['subdomains']:
    print(f"  - {s}")

print(f"\nwayback count: {d['wayback_count']}")
print(f"wayback sample (first 8):")
for u in d['wayback_sample'][:8]:
    print(f"  - {u}")

print(f"\nport_scan (truth table):")
for ip, ports in d['port_scan'].items():
    print(f"  {ip}: {ports}")

print(f"\nport_evidence detail:")
for ip, ports in d['port_evidence'].items():
    print(f"\n  ===== {ip} =====")
    for pp, info in ports.items():
        flag = "OPEN" if info['open'] else "x"
        b = (info['banner'] or '')[:80].replace('\n', ' | ')
        e = (info['err'] or '')[:60]
        probe = info['probe']
        print(f"    [{flag}] {pp:>5}  probe={probe:<7}  err={e}  banner={b!r}")

print(f"\nreverse_ip_sample:")
for ip, hosts in d['reverse_ip_sample'].items():
    print(f"  {ip} -> {len(hosts)} hosts: {hosts[:10]}")
