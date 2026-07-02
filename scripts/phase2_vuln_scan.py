"""Phase 2: Vulnerability Scan - DB unauth, SSL cert, FTP anon."""
from __future__ import annotations
import json
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "recon"))
from _common import http_get

TARGET = "142.171.54.2"
RESULTS = {}

def section(t):
    print(f"\n{'='*60}\n  {t}\n{'='*60}")

# 1. Database Unauth Detection
def check_redis():
    section("Redis Unauth Check (port 6379)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, 6379))
        s.send(b"INFO\r\n")
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        if "redis_version" in resp:
            print("  [VULN] Redis: UNAUTHORIZED ACCESS!")
            # Extract version
            for line in resp.split("\r\n"):
                if "redis_version" in line:
                    print(f"  {line}")
            return {"status": "VULN", "info": resp[:500]}
    except Exception as e:
        print(f"  Redis: {e}")
    return {"status": "SAFE"}

def check_mongodb():
    section("MongoDB Unauth Check (port 27017)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, 27017))
        # isMaster command
        payload = b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        s.send(payload)
        resp = s.recv(4096)
        s.close()
        if b"maxBsonObjectSize" in resp or b"ismaster" in resp:
            print("  [VULN] MongoDB: UNAUTHORIZED ACCESS!")
            return {"status": "VULN", "info": resp[:200].hex()}
    except Exception as e:
        print(f"  MongoDB: {e}")
    return {"status": "SAFE"}

def check_mysql():
    section("MySQL Unauth Check (port 3306)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, 3306))
        # MySQL greeting
        resp = s.recv(1024)
        s.close()
        if len(resp) > 5 and resp[4] == 0x0a:  # Protocol 10 = MySQL
            version = resp[5:resp.index(b"\x00", 5)].decode("utf-8", errors="ignore")
            print(f"  [INFO] MySQL version: {version}")
            # Check if we can try auth
            return {"status": "OPEN", "version": version}
    except Exception as e:
        print(f"  MySQL: {e}")
    return {"status": "SAFE"}

def check_ftp_anon():
    section("FTP Anonymous Check (port 21)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, 21))
        banner = s.recv(1024).decode("utf-8", errors="ignore")
        print(f"  Banner: {banner.strip()}")
        s.send(b"USER anonymous\r\n")
        resp = s.recv(1024).decode("utf-8", errors="ignore")
        print(f"  USER anonymous: {resp.strip()}")
        if "200" in resp or "331" in resp or "230" in resp:
            s.send(b"PASS anonymous@\r\n")
            resp2 = s.recv(1024).decode("utf-8", errors="ignore")
            print(f"  PASS: {resp2.strip()}")
            if "230" in resp2:
                print("  [VULN] FTP: Anonymous login allowed!")
                s.send(b"LIST\r\n")
                resp3 = s.recv(4096).decode("utf-8", errors="ignore")
                print(f"  LIST: {resp3[:200]}")
                s.close()
                return {"status": "VULN", "info": resp3[:500]}
        s.close()
    except Exception as e:
        print(f"  FTP: {e}")
    return {"status": "SAFE"}

def check_ssl():
    section(f"SSL Cert Analysis ({TARGET}:443)")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((TARGET, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=TARGET) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    san = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]
                    print(f"  Subject: {subj}")
                    print(f"  Issuer: {issuer}")
                    print(f"  Valid: {cert.get('notBefore')} -> {cert.get('notAfter')}")
                    print(f"  SAN: {san}")
                    return {"subject": subj, "issuer": issuer, "san": san}
    except Exception as e:
        print(f"  SSL Error: {e}")
    return {}

def check_elasticsearch():
    section("Elasticsearch Check (port 9200)")
    try:
        r = http_get(f"http://{TARGET}:9200/", timeout=5, verify=False)
        if r and r.status_code == 200:
            data = r.json()
            print(f"  [VULN] Elasticsearch: UNAUTHORIZED ACCESS!")
            print(f"  Name: {data.get('name')}")
            print(f"  Cluster: {data.get('cluster_name')}")
            print(f"  Version: {data.get('version', {}).get('number')}")
            return {"status": "VULN", "info": data}
    except Exception as e:
        print(f"  ES: {e}")
    return {"status": "SAFE"}

def check_memcached():
    section("Memcached Check (port 11211)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, 11211))
        s.send(b"stats\r\n")
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        if "STAT" in resp:
            print("  [VULN] Memcached: UNAUTHORIZED ACCESS!")
            print(f"  Info: {resp[:200]}")
            return {"status": "VULN", "info": resp[:500]}
    except Exception as e:
        print(f"  Memcached: {e}")
    return {"status": "SAFE"}

def check_postgresql():
    section("PostgreSQL Check (port 5432)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, 5432))
        # SSL request
        s.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        resp = s.recv(1024)
        s.close()
        if resp and resp[0:1] == b"S":
            print("  [INFO] PostgreSQL: SSL required (may need auth)")
            return {"status": "SSL_REQ"}
        elif resp and resp[0:1] == b"N":
            print("  [INFO] PostgreSQL: No SSL")
            return {"status": "OPEN"}
    except Exception as e:
        print(f"  PostgreSQL: {e}")
    return {"status": "SAFE"}

def main():
    print("=" * 60)
    print(f"  Phase 2: Vulnerability Scan - {TARGET}")
    print("=" * 60)
    t0 = time.time()

    RESULTS["redis"] = check_redis()
    RESULTS["mongodb"] = check_mongodb()
    RESULTS["mysql"] = check_mysql()
    RESULTS["ftp"] = check_ftp_anon()
    RESULTS["ssl"] = check_ssl()
    RESULTS["elasticsearch"] = check_elasticsearch()
    RESULTS["memcached"] = check_memcached()
    RESULTS["postgresql"] = check_postgresql()

    elapsed = time.time() - t0
    RESULTS["elapsed_s"] = round(elapsed, 1)

    # Summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    vulns = [k for k, v in RESULTS.items() if isinstance(v, dict) and v.get("status") == "VULN"]
    print(f"  Vulnerabilities found: {len(vulns)}")
    for v in vulns:
        print(f"    - {v.upper()}")
    print(f"  Time: {elapsed:.1f}s")

    Path("scripts/vuln_result.json").write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")
    print("  Saved: scripts/vuln_result.json")

if __name__ == "__main__":
    main()
