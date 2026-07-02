"""Phase 3: Web Service Scan - HTTP based detection."""
from __future__ import annotations
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "recon"))
from _common import http_get

TARGET = "142.171.54.2"
RESULTS = {}

def section(t):
    print(f"\n{'='*60}\n  {t}\n{'='*60}")

def scan_web_port(port, proto="http"):
    """Scan a web service on a specific port."""
    url = f"{proto}://{TARGET}:{port}/"
    try:
        r = http_get(url, timeout=8, verify=False, allow_redirects=True)
        if r:
            title = ""
            import re
            m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.IGNORECASE)
            if m:
                title = m.group(1).strip()
            server = r.headers.get("Server", "")
            powered = r.headers.get("X-Powered-By", "")
            print(f"  [{port}] {r.status_code} {r.url}")
            print(f"       Server: {server}")
            print(f"       X-Powered-By: {powered}")
            print(f"       Title: {title}")
            print(f"       Size: {len(r.content)} bytes")
            return {
                "port": port,
                "status": r.status_code,
                "server": server,
                "powered_by": powered,
                "title": title,
                "size": len(r.content),
                "url": r.url,
            }
    except Exception as e:
        print(f"  [{port}] Error: {e}")
    return None

def check_robots():
    """Check robots.txt content."""
    section("robots.txt Content")
    try:
        r = http_get(f"http://{TARGET}/robots.txt", timeout=5, verify=False)
        if r and r.status_code == 200:
            print(f"  Content:\n{r.text}")
            return r.text
    except Exception as e:
        print(f"  Error: {e}")
    return ""

def check_sitemap():
    """Check sitemap.xml."""
    section("sitemap.xml")
    try:
        r = http_get(f"http://{TARGET}/sitemap.xml", timeout=5, verify=False)
        if r and r.status_code == 200:
            print(f"  Size: {len(r.content)} bytes")
            print(f"  Content (first 500): {r.text[:500]}")
            return r.text[:1000]
    except Exception as e:
        print(f"  Error: {e}")
    return ""

def check_security_txt():
    """Check security.txt."""
    section("security.txt")
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = http_get(f"http://{TARGET}{path}", timeout=5, verify=False)
            if r and r.status_code == 200:
                print(f"  Found at {path}:")
                print(f"  {r.text[:500]}")
                return r.text
        except Exception as e:
            print(f"  {path}: {e}")
    return ""

def check_hsphere():
    """Check Parallels H-Sphere specific paths."""
    section("Parallels H-Sphere Detection")
    paths = [
        "/hsphere/", "/hsphere/admin/", "/hsphere/user/",
        "/cpanel/", "/control/", "/panel/",
        "/admin/", "/admin/login", "/admin/login.php",
        "/login", "/login.php", "/auth/",
        "/pma/", "/phpmyadmin/", "/mysql/",
        "/webmail/", "/roundcube/", "/squirrelmail/",
        "/cp/", "/controlpanel/", "/manager/",
    ]
    found = []
    for path in paths:
        try:
            r = http_get(f"http://{TARGET}{path}", timeout=5, verify=False, allow_redirects=False)
            if r and r.status_code < 404:
                print(f"  [{r.status_code}] {path}")
                found.append({"path": path, "status": r.status_code, "size": len(r.content)})
        except:
            pass
    return found

def check_cidr_web():
    """Check a few other IPs in C-section for web services."""
    section("C-Section Web Scan (sample)")
    results = []
    # Check a few interesting IPs
    for last_octet in [1, 3, 7, 10, 50, 100, 150, 200, 254]:
        ip = f"142.171.54.{last_octet}"
        try:
            r = http_get(f"http://{ip}/", timeout=3, verify=False, allow_redirects=False)
            if r and r.status_code < 404:
                import re
                title = ""
                m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.IGNORECASE)
                if m:
                    title = m.group(1).strip()
                server = r.headers.get("Server", "")
                print(f"  {ip}: [{r.status_code}] {title} ({server})")
                results.append({"ip": ip, "status": r.status_code, "title": title, "server": server})
        except:
            pass
    return results

def main():
    print("=" * 60)
    print(f"  Phase 3: Web Service Scan - {TARGET}")
    print("=" * 60)
    t0 = time.time()

    # Main target web ports
    section("Main Target - Web Ports")
    web_ports = [80, 443, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 9000]
    web_results = []
    for port in web_ports:
        r = scan_web_port(port, "http")
        if r:
            web_results.append(r)
    RESULTS["web_ports"] = web_results

    # Content discovery
    RESULTS["robots_txt"] = check_robots()
    RESULTS["sitemap"] = check_sitemap()
    RESULTS["security_txt"] = check_security_txt()
    RESULTS["hsphere_paths"] = check_hsphere()
    RESULTS["c_section_web"] = check_cidr_web()

    elapsed = time.time() - t0
    RESULTS["elapsed_s"] = round(elapsed, 1)

    # Summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Web services found: {len(RESULTS['web_ports'])}")
    print(f"  H-Sphere paths found: {len(RESULTS['hsphere_paths'])}")
    print(f"  C-section web hosts: {len(RESULTS['c_section_web'])}")
    print(f"  Time: {elapsed:.1f}s")

    Path("scripts/web_result.json").write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")
    print("  Saved: scripts/web_result.json")

if __name__ == "__main__":
    main()
