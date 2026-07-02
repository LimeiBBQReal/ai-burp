"""Check DNS resolution for all subdomains."""
import sys, os, json, base64, subprocess
sys.path.insert(0, r"E:\CursorDEV\CKFinder\ai-burp\recon")
os.chdir(r"E:\CursorDEV\CKFinder\ai-burp\recon")

from cryptography.hazmat.primitives import serialization as ser
from _common import _read_encrypted

# Set up keys
priv_pem = open('test_private.pem', 'rb').read()
pk = ser.load_pem_private_key(priv_pem, password=None)
pub_b64 = base64.b64encode(pk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)).decode()
priv_b64 = base64.b64encode(priv_pem).decode()
os.environ["RECON_RSA_PUBLIC"] = pub_b64
os.environ["RECON_RSA_PRIVATE"] = priv_b64

# Get subdomains
vd = _read_encrypted("verify_subdomains")
subs = []
for sub, info in vd.get("verified_subdomains", {}).items():
    if isinstance(info, dict):
        subs.append((sub, info.get("ip", ""), info.get("verified", False), info.get("is_cdn", False)))

print(f"Total subdomains: {len(subs)}")
print()

# Count by type
cdn_count = 0
real_ip_count = 0
no_ip_count = 0
test_net_count = 0

for sub, ip, verified, is_cdn in subs:
    if not ip:
        no_ip_count += 1
    elif ip.startswith("198.18.") or ip.startswith("198.51.") or ip.startswith("203.0."):
        test_net_count += 1
    elif is_cdn:
        cdn_count += 1
    else:
        real_ip_count += 1

print(f"=== Summary ===")
print(f"  CDN (Cloudflare etc): {cdn_count}")
print(f"  TEST-NET (198.18.x.x): {test_net_count}")
print(f"  Real IP: {real_ip_count}")
print(f"  No IP: {no_ip_count}")
print()

# Show samples
print("=== CDN subdomains (sample) ===")
for sub, ip, v, c in subs[:10]:
    if c:
        print(f"  {sub} -> {ip} [CDN]")

print()
print("=== TEST-NET subdomains (sample) ===")
for sub, ip, v, c in subs[:10]:
    if ip.startswith("198.18."):
        print(f"  {sub} -> {ip}")

print()
print("=== Real IP subdomains (if any) ===")
for sub, ip, v, c in subs:
    if ip and not c and not ip.startswith("198.18.") and not ip.startswith("198.51.") and not ip.startswith("203.0."):
        print(f"  {sub} -> {ip}")
