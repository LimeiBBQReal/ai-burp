#!/usr/bin/env python3
"""refresh #4 完整报告 — 拉取 + 解密 + 源级统计."""
import os
import sys
import urllib.request
import hashlib
import json
import requests

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


REPO_BASE = "https://raw.githubusercontent.com/LimeiBBQReal/proxy-pool/main/alive"


def fetch_decrypt(path):
    url = f"{REPO_BASE}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    blob = urllib.request.urlopen(req, timeout=15).read()
    key_str = os.environ["PROXY_AES_KEY"]
    key_bytes = hashlib.sha256(key_str.encode()).digest()[:32]
    iv = blob[:16]
    ct = blob[16:]
    c = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    pt = d.update(ct) + d.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(pt) + unpadder.finalize()).decode("utf-8")


def main():
    print("=" * 70)
    print("refresh #4 完整报告")
    print("=" * 70)

    print("\n[1/3] 解密 meta.enc ...")
    meta = json.loads(fetch_decrypt("meta.enc"))
    print(f"  运行时间:   {meta['updated_at']}")
    print(f"  总采集数:   {meta['total_tested']}")
    print(f"  HTTP 活:    {meta['alive_http']}")
    print(f"  SOCKS5 活:  {meta['alive_socks5']}")
    print(f"  测活成功率: {meta['hit_rate']}")
    print(f"  平均延迟:   {meta['avg_latency_ms']} ms")

    print("\n[2/3] 各代理源详细统计:")
    print(f"{'代理源':<25} {'采集':>6} {'活':>6} {'错(超时)':>8} {'成功率':>8}")
    print("-" * 70)
    total_f = total_a = total_e = 0
    for s in meta.get("source_stats", []):
        n = s["name"]
        f, a, e = s["fetched"], s["alive"], s["errors"]
        total_f += f
        total_a += a
        total_e += e
        rate = s["hit_rate"]
        print(f"{n:<25} {f:>6} {a:>6} {e:>8} {rate:>8}")
    print("-" * 70)
    overall = f"{total_a / total_f * 100:.1f}%" if total_f else "-"
    print(f"{'合计':<25} {total_f:>6} {total_a:>6} {total_e:>8} {overall:>8}")

    print("\n[3/3] .enc 文件大小 + 解密后明文条目数:")
    for fname in ("http.enc", "socks5.enc"):
        blob = requests.get(f"{REPO_BASE}/{fname}", timeout=15).content
        plain = fetch_decrypt(fname)
        lines = [l for l in plain.splitlines() if l.strip()]
        print(f"  {fname:<14} blob {len(blob):>6} B   →   解密后 {len(lines)} 条")

    # 抽样 5 条 HTTP + 5 条 SOCKS5
    print("\n[抽样] 明文前 5 条:")
    http_plain = fetch_decrypt("http.enc")
    socks5_plain = fetch_decrypt("socks5.enc")
    http_lines = [l for l in http_plain.splitlines() if l.strip()]
    socks5_lines = [l for l in socks5_plain.splitlines() if l.strip()]
    print("  HTTP 样例:")
    for l in http_lines[:5]:
        print(f"    {l}")
    print("  SOCKS5 样例:")
    for l in socks5_lines[:5]:
        print(f"    {l}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()