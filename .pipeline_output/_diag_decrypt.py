#!/usr/bin/env python3
"""诊断: 解密 http.enc 看 raw 内容."""
import hashlib
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ROOT = Path(__file__).resolve().parent.parent
ALIVE = ROOT / "cloud-proxy-pool" / "alive"


def _derive_key(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()[:32]


def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    iv = blob[:16]
    ct = blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    pad = pt[-1]
    return pt[:-pad]


key_str = os.environ.get("PROXY_AES_KEY") or "ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5"
key = _derive_key(key_str)

for name in ("http.enc", "socks5.enc", "meta.enc"):
    blob = (ALIVE / name).read_bytes()
    pt = aes_decrypt(blob, key)
    print(f"--- {name} (raw first 200 bytes) ---")
    print(pt[:200])
    print(f"  len = {len(pt)}")
    if name == "meta.enc":
        print(f"  as utf-8: {pt.decode('utf-8', errors='replace')[:500]}")
    print()
