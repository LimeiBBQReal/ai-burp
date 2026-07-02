"""Full Recon Pipeline v2 — 运行改进后的完整采集流程.

包含所有新模块:
  - experience_engine (经验引擎)
  - js_sign_reverse (JS 签名识别)
  - js_ast_analyzer (JS AST 深度分析)
  - waf_bypass (WAF 绕过)
  - field_journal (经验沉淀)
"""
import os
import sys
import subprocess
import base64
import time
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
os.environ["DEEP_DEPTH"] = "2"
os.environ["MAX_ROUNDS"] = "2"
os.environ["CONVERGE_ROUNDS"] = "2"
os.environ["SCRIPT_TIMEOUT"] = "300"
os.environ["WILDCARD_SAMPLES"] = "3"
os.environ["DEEP_BATCH_SIZE"] = "30"
os.environ["PORT_TIMEOUT"] = "1.5"
os.environ["DIR_TIMEOUT"] = "5"
os.environ["DIR_DEPTH"] = "2"
os.environ["WAF_BYPASS_LIMIT"] = "20"
os.environ["PARAM_MAX_URLS"] = "20"
os.environ["PARAM_MAX_REQUESTS"] = "2000"
print("[SETUP] RSA ready")
print(f"  TARGET=cartmanager.net")
print(f"  DEEP_DEPTH=2, MAX_ROUNDS=1, WILDCARD_SAMPLES=3")
print(f"  DEEP_BATCH_SIZE=30, PORT_TIMEOUT=1.5, DIR_DEPTH=2")

pipeline_start = time.time()

# Run the orchestrator (which now includes all modules)
log_path = LOG_DIR / "orchestrator_v2.log"
with open(log_path, "w", encoding="utf-8") as fh:
    print(f"\n{'='*70}")
    print(f"Running Recon Orchestrator v2 (all modules)")
    print(f"{'='*70}")
    t0 = time.time()
    try:
        r = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "recon_orchestrator.py")],
            cwd=str(SCRIPT_DIR), env=os.environ.copy(),
            stdout=fh, stderr=subprocess.STDOUT, timeout=3600)
        elapsed = time.time() - t0
        print(f"\n  exit={r.returncode}, {elapsed:.1f}s ({elapsed/60:.1f}min)")
        print(f"  log={log_path.name}")
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT after {time.time()-t0:.1f}s")

# Summary
print(f"\n{'='*70}")
print("OUTPUT FILES SUMMARY")
print(f"{'='*70}")
for f in sorted(OUT_DIR.glob("*.data.enc")):
    st = f.stat()
    tag = "NEW" if st.st_mtime > pipeline_start else "OLD"
    print(f"  [{tag:3s}] {f.name:40s} {st.st_size:>8} bytes  {time.ctime(st.st_mtime)}")

# Check field-journal
journal_dir = SCRIPT_DIR / "field-journal"
if journal_dir.exists():
    print(f"\n{'='*70}")
    print("FIELD JOURNAL")
    print(f"{'='*70}")
    for jf in sorted(journal_dir.glob("*.md")):
        st = jf.stat()
        tag = "NEW" if st.st_mtime > pipeline_start else "OLD"
        print(f"  [{tag:3s}] {jf.name} ({st.st_size} bytes)")

print(f"\nTotal time: {time.time()-pipeline_start:.1f}s")
