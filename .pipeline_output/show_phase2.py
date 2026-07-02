"""Show Phase 2 findings."""
import json
from collections import Counter, defaultdict
from pathlib import Path

p = Path(__file__).parent / "cartmanager_phase2_reachability.json"
d = json.loads(p.read_text(encoding="utf-8"))

print(f"target: {d['target']}")
print(f"true_open_ips: {d['true_open_ips']}")
print(f"ip:port: {d['ip_port_pair']}")
print(f"hosts_tried: {d['hosts_tried']}")
print(f"paths_tried: {d['paths_tried']}")
print(f"proxy_used: {d['proxy_used']}")
print()

print("=" * 72)
print(f"STAGE A — root_matrix: total={len(d['root_matrix'])} interesting={len(d['interesting_roots'])}")
print("=" * 72)
for r in d['interesting_roots'][:50]:
    st = r.get('status')
    host = r.get('host')
    ip = r.get('ip')
    port = r.get('port')
    sv = r.get('server')
    bl = r.get('body_len')
    sha = r.get('body_sha256')
    loc = r.get('location')
    head = (r.get('body_head') or '')[:90].replace('\n', ' | ')
    print(f"  [{st}] {host} @ {ip}:{port} sv={sv} loc={loc} len={bl} sha={sha} head={head!r}")

print()
print("=" * 72)
print(f"STAGE B — path_matrix: total={len(d['path_matrix'])} interesting={len(d['interesting_paths'])}")
print("=" * 72)
for r in d['interesting_paths'][:80]:
    st = r.get('status')
    host = r.get('host')
    ip = r.get('ip')
    port = r.get('port')
    path = r.get('path')
    bl = r.get('body_len')
    sha = r.get('body_sha256', '')[:10]
    ct = r.get('content_type', '')
    sv = r.get('server', '')
    head = (r.get('body_head') or '')[:80].replace('\n', ' ')
    print(f"  [{st}] {host}:{port}{path:<35} sv={sv:<10} ct={ct:<25} len={bl:>6} sha={sha} head={head!r}")

print()
print("=" * 72)
print("STAGE C — summary by ip|host (non-404)")
print("=" * 72)
for key, items in d['summary_by_ip_host'].items():
    print(f"\n  ip|host: {key}  ({len(items)} paths)")
    code_counter = Counter(x['status'] for x in items)
    for code, count in sorted(code_counter.items()):
        paths = [x['path'] for x in items if x['status'] == code]
        print(f"    [{code}] x{count}: {paths[:8]}{' ...' if len(paths) > 8 else ''}")
        for x in items:
            if x['status'] == code and x['len'] and x['len'] > 0:
                print(f"      -> {x['path']:<35} len={x['len']} sha={(x.get('sha') or '')[:10]}")
