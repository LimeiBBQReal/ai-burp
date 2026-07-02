"""Check Phase 4 output files - direct key load."""
import sys, os, json, base64
sys.path.insert(0, r"E:\CursorDEV\CKFinder\ai-burp\recon")
os.chdir(r"E:\CursorDEV\CKFinder\ai-burp\recon")

from cryptography.hazmat.primitives import serialization as ser
from _common import _read_encrypted, write_encrypted

# Set up keys from PEM
priv_pem = open('test_private.pem', 'rb').read()
pk = ser.load_pem_private_key(priv_pem, password=None)
pub_b64 = base64.b64encode(pk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)).decode()
priv_b64 = base64.b64encode(priv_pem).decode()
os.environ["RECON_RSA_PUBLIC"] = pub_b64
os.environ["RECON_RSA_PRIVATE"] = priv_b64

print(f"Keys loaded from test_private.pem")
print()

for name in ['reverse_ip', 'cidr_real', 'cert_ext', 'whois_corr', 'asn_lookup', 'takeover']:
    try:
        data = _read_encrypted(name)
        print(f"=== {name} ===")
        # Show key fields
        if name == "reverse_ip":
            print(f"  IPs checked: {data.get('ips_checked', 0)}")
            print(f"  Total found: {data.get('total_found', 0)}")
            found = data.get('found_domains', {})
            if found:
                for ip, domains in list(found.items())[:3]:
                    print(f"    {ip}: {domains[:3]}")
        elif name == "cidr_real":
            print(f"  C-classes scanned: {data.get('c_classes_scanned', 0)}")
            print(f"  Alive hosts: {data.get('total_alive', 0)}")
            hosts = data.get('alive_hosts', [])
            if hosts:
                for h in hosts[:5]:
                    print(f"    {h.get('ip')}:{h.get('port')} - {h.get('title', '')[:50]}")
        elif name == "cert_ext":
            print(f"  Total domains: {data.get('total_domains', 0)}")
            print(f"  Related: {data.get('related_counts', {})}")
            orgs = data.get('organizations', [])
            if orgs:
                print(f"  Organizations: {[o.get('organization') for o in orgs[:3]]}")
        elif name == "whois_corr":
            print(f"  Related domains: {data.get('total_related', 0)}")
            whois = data.get('whois_info', {})
            print(f"  Registrar: {whois.get('registrar', '')}")
            print(f"  Org: {whois.get('organization', '')}")
            print(f"  Email: {whois.get('email', '')}")
        elif name == "asn_lookup":
            print(f"  ASNs: {len(data.get('asns', []))}")
            print(f"  IP ranges: {data.get('total_ranges', 0)}")
            for asn in data.get('asns', [])[:3]:
                print(f"    {asn.get('asn')}: {asn.get('organization', '')}")
        elif name == "takeover":
            print(f"  Checked: {data.get('checked', 0)}")
            print(f"  Vulnerable: {data.get('total_vulnerable', 0)}")
            vulns = data.get('vulnerable', [])
            if vulns:
                for v in vulns[:5]:
                    print(f"    {v.get('domain')} -> {v.get('cname')} ({v.get('service')})")
        print()
    except Exception as e:
        print(f"{name}: ERROR - {e}")
        print()
