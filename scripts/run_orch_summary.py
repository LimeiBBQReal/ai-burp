"""Run orchestrator in aggregation-only mode — just summarize existing .enc files."""
import os, sys, subprocess, base64, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization as ser

SCRIPT_DIR = Path(r"E:\CursorDEV\CKFinder\ai-burp\recon")
KEY_PATH = SCRIPT_DIR / "test_private.pem"
os.chdir(str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

if not KEY_PATH.exists():
    sys.exit(1)
pk = ser.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
pub_b64 = base64.b64encode(pk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)).decode()
priv_b64 = base64.b64encode(KEY_PATH.read_bytes()).decode()
os.environ["RECON_RSA_PUBLIC"] = pub_b64
os.environ["RECON_RSA_PRIVATE"] = priv_b64
os.environ["TARGET"] = "cartmanager.net"
os.environ["RECON_SSL_VERIFY"] = "0"
os.environ["DEEP_DEPTH"] = "1"
os.environ["MAX_ROUNDS"] = "1"
os.environ["CONVERGE_ROUNDS"] = "1"
# All phases — only collecting from existing files (no script execution)
os.environ["RUN_PHASE1"] = "0"
os.environ["RUN_PHASE2"] = "0"
os.environ["RUN_PHASE3"] = "0"

t0 = time.time()
r = subprocess.run([sys.executable, "recon_orchestrator.py"],
                   cwd=str(SCRIPT_DIR), env=os.environ.copy(), timeout=60)
print(f"Orchestrator exit={r.returncode}, elapsed={time.time()-t0:.1f}s")
