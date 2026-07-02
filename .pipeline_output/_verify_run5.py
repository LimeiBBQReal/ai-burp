#!/usr/bin/env python3
"""解密 refresh #5: meta.enc 是 JSON, http.enc / socks5.enc 是纯文本 ip:port 一行一个."""
import hashlib
import json
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


def main() -> int:
    key_str = os.environ.get("PROXY_AES_KEY") or "ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5"
    key = _derive_key(key_str)

    meta_blob = (ALIVE / "meta.enc").read_bytes()
    meta = json.loads(aes_decrypt(meta_blob, key).decode("utf-8"))

    http_blob = (ALIVE / "http.enc").read_bytes()
    http_lines = aes_decrypt(http_blob, key).decode("utf-8").strip().split("\n")
    socks5_blob = (ALIVE / "socks5.enc").read_bytes()
    socks5_lines = aes_decrypt(socks5_blob, key).decode("utf-8").strip().split("\n")

    print("=" * 64)
    print("REFRESH #5 统计")
    print("=" * 64)
    print(f"  updated_at      : {meta.get('updated_at')}")
    print(f"  total_tested    : {meta.get('total_tested')}")
    print(f"  alive_http      : {meta.get('alive_http')}")
    print(f"  alive_socks5    : {meta.get('alive_socks5')}")
    print(f"  alive_total     : {meta.get('alive_total')}")
    print(f"  hit_rate        : {meta.get('hit_rate')}")
    print(f"  avg_latency_ms  : {meta.get('avg_latency_ms')}")
    print(f"  sources         : {meta.get('sources')}")
    print(f"  http.enc 行数   : {len(http_lines)}")
    print(f"  socks5.enc 行数 : {len(socks5_lines)}")
    print()
    print("--- source_stats ---")
    for s in meta.get("source_stats", []):
        print(f"  {s.get('name'):24s}  fetched={s.get('fetched', 0):5d}  "
              f"alive={s.get('alive', 0):4d}  errors={s.get('errors', 0):5d}  "
              f"hit_rate={s.get('hit_rate', 0)}")
    print()
    print("--- http 前 5 条 ---")
    for line in http_lines[:5]:
        print(f"  {line}")
    print("--- socks5 前 5 条 ---")
    for line in socks5_lines[:5]:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
