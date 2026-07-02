"""Phase 1: C-Section Scan for 142.171.54.0/24."""
from __future__ import annotations
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "recon"))

CIDR = "142.171.54"
PORTS = [21, 22, 80, 443, 3306, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 9200, 11211, 27017, 6379, 5432]

def probe(ip_suffix):
    ip = f"{CIDR}.{ip_suffix}"
    open_ports = []
    for port in PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return (ip, open_ports) if open_ports else None

print("=" * 60)
print("  Phase 1: C-Section Scan (142.171.54.0/24)")
print("=" * 60)

t0 = time.time()
alive = {}
with ThreadPoolExecutor(max_workers=100) as ex:
    futs = {ex.submit(probe, i): i for i in range(1, 255)}
    for fut in as_completed(futs):
        r = fut.result()
        if r:
            ip, ports = r
            alive[ip] = ports
            print(f"  [ALIVE] {ip}: {ports}")

elapsed = time.time() - t0
print(f"\n  Total alive: {len(alive)} hosts")
print(f"  Time: {elapsed:.1f}s")

# Save
out = {"target": "142.171.54.0/24", "alive_hosts": alive, "elapsed_s": round(elapsed, 1)}
Path("scripts/c_section_result.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print("  Saved: scripts/c_section_result.json")
