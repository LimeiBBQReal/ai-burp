"""Check L2 subdomain discovery results."""
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

sd = _read_encrypted("subdomains")
target = "cartmanager.net"

print(f"=== subdomain_enum 结果 ===")
print(f"总数: {sd.get('total', 'N/A')}")
print(f"DNS 爆破: {sd.get('dns_brute_found', 'N/A')}")
print(f"crt.sh: {sd.get('crtsh_found', 'N/A')}")
print(f"subfinder: {sd.get('subfinder_found', 'N/A')}")
print(f"L2 爆破: {sd.get('l2_brute_found', 'N/A')}")

subs = sd.get("unique_subdomains", [])
l1 = []
l2 = []
l3 = []

for s in subs:
    parts = s.split(".")
    level = len(parts) - len(target.split("."))

    if level == 1:
        l1.append(s)
    elif level == 2:
        l2.append(s)
    elif level >= 3:
        l3.append(s)

print(f"\n=== 子域名层级分布 ===")
print(f"L1 (二级): {len(l1)}")
print(f"L2 (三级): {len(l2)}")
print(f"L3+ (深层): {len(l3)}")

if l2:
    print(f"\n=== L2 三级子域名 (前20) ===")
    for s in l2[:20]:
        ip = sd.get("resolved", {}).get(s, "N/A")
        print(f"  {s} -> {ip}")

if l3:
    print(f"\n=== L3+ 深层子域名 (前20) ===")
    for s in l3[:20]:
        ip = sd.get("resolved", {}).get(s, "N/A")
        print(f"  {s} -> {ip}")
