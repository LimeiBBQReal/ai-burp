"""Full recon pipeline runner — all modules in correct dependency order."""
import os, sys, subprocess, base64, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa

SCRIPT_DIR = Path(r"E:\CursorDEV\CKFinder\ai-burp\recon")
KEY_PATH = SCRIPT_DIR / "test_private.pem"
OUT_DIR = SCRIPT_DIR / "out"
LOG_DIR = SCRIPT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
os.chdir(str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

# RSA key setup
if not KEY_PATH.exists():
    pk = rsa.generate_private_key(65537, 2048)
    KEY_PATH.write_bytes(pk.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
pk = ser.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
priv_pem = KEY_PATH.read_bytes()
pub_b64 = base64.b64encode(pk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)).decode()
priv_b64 = base64.b64encode(priv_pem).decode()
os.environ["RECON_RSA_PUBLIC"] = pub_b64
os.environ["RECON_RSA_PRIVATE"] = priv_b64
os.environ["TARGET"] = "cartmanager.net"
os.environ["RECON_SSL_VERIFY"] = "0"
os.environ["DEEP_DEPTH"] = "1"
print("[SETUP] RSA ready, TARGET=cartmanager.net, DEEP_DEPTH=1, SSL=off")

def run_script(name, timeout=120):
    log_path = LOG_DIR / (name.replace('.', '_') + '.log')
    with open(log_path, "w", encoding="utf-8") as fh:
        t0 = time.time()
        try:
            r = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / name)],
                cwd=str(SCRIPT_DIR), env=os.environ.copy(),
                stdout=fh, stderr=subprocess.STDOUT, timeout=timeout)
            print(f"  exit={r.returncode}, {time.time()-t0:.1f}s  log={log_path.name}")
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT {time.time()-t0:.1f}s  log={log_path.name}")
            return False

pipeline_start = time.time()

PIPELINE = [
    ("subdomain_enum.py", "Phase 2b", 180),
    ("bypass_cdn.py",     "Phase 2b", 60),
    ("deep_subdomain.py", "Phase 2 deep", 300),
    ("url_collect.py",    "Phase 3", 180),
    ("js_extract.py",     "Phase 3", 120),
    ("param_brute.py",    "Phase 3", 300),
]

results = []
for script_name, phase, timeout in PIPELINE:
    print(f"\n{'#'*70}")
    print(f"# {phase}: {script_name} (timeout={timeout}s)")
    print(f"{'#'*70}")
    ok = run_script(script_name, timeout=timeout)
    results.append((script_name, ok))

# Summary
print(f"\n{'='*70}")
print("OUTPUT FILES SUMMARY")
print(f"{'='*70}")
for f in sorted(OUT_DIR.glob("*.data.enc")):
    st = f.stat()
    tag = "NEW" if st.st_mtime > pipeline_start else "OLD"
    print(f"  [{tag:3s}] {f.name:40s} {st.st_size:>8} bytes  {time.ctime(st.st_mtime)}")

print(f"\n{'='*70}")
print("PIPELINE RESULTS")
print(f"{'='*70}")
for script_name, ok in results:
    tag = "OK" if ok else "FAIL"
    print(f"  [{tag:4s}] {script_name}")
passed = sum(1 for _, ok in results if ok)
print(f"\n{passed}/{len(results)} scripts succeeded")
