"""Check subdomain levels and CDN status."""
import sys, os, base64
sys.path.insert(0, r"E:\CursorDEV\CKFinder\ai-burp\recon")
os.chdir(r"E:\CursorDEV\CKFinder\ai-burp\recon")

from cryptography.hazmat.primitives import serialization as ser
from _common import _read_encrypted

priv_pem = open('test_private.pem', 'rb').read()
pk = ser.load_pem_private_key(priv_pem, password=None)
pub_b64 = base64.b64encode(pk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)).decode()
priv_b64 = base64.b64encode(priv_pem).decode()
os.environ["RECON_RSA_PUBLIC"] = pub_b64
os.environ["RECON_RSA_PRIVATE"] = priv_b64

vd = _read_encrypted("verify_subdomains")
target = "cartmanager.net"

l1 = []  # e.g., www.cartmanager.net
l2 = []  # e.g., api.www.cartmanager.net
l3 = []  # deeper

for sub, info in vd.get("verified_subdomains", {}).items():
    if not isinstance(info, dict):
        continue
    parts = sub.split(".")
    level = len(parts) - len(target.split("."))
    
    ip = info.get("ip", "")
    is_cdn = info.get("is_cdn", False)
    is_testnet = ip.startswith("198.18.") or ip.startswith("198.51.") or ip.startswith("203.0.")
    
    entry = (sub, ip, is_cdn, is_testnet)
    
    if level == 1:
        l1.append(entry)
    elif level == 2:
        l2.append(entry)
    else:
        l3.append(entry)

print(f"=== Subdomain Levels ===")
print(f"L1 (二级域名, e.g., www.{target}): {len(l1)}")
print(f"L2 (三级域名, e.g., api.www.{target}): {len(l2)}")
print(f"L3+ (更深层级): {len(l3)}")
print()

def show_stats(data, label):
    if not data:
        print(f"{label}: 无")
        return
    cdn = sum(1 for _, _, c, _ in data if c)
    testnet = sum(1 for _, _, _, t in data if t)
    real = len(data) - cdn - testnet
    print(f"{label}: 总计 {len(data)}, CDN={cdn}, TEST-NET={testnet}, 真实IP={real}")
    for sub, ip, is_cdn, is_testnet in data[:5]:
        tag = "[TEST-NET]" if is_testnet else ("[CDN]" if is_cdn else "[REAL]")
        print(f"  {sub} -> {ip} {tag}")

show_stats(l1, "L1 (二级)")
print()
show_stats(l2, "L2 (三级)")
print()
show_stats(l3, "L3+ (深层)")
