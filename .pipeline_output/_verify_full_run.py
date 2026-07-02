#!/usr/bin/env python3
"""
汇总本次 workflow 运行结果：
1. 从 raw.githubusercontent.com 拉 alive/*.enc
2. AES-256-CBC 解密
3. 统计 HTTP / SOCKS5 活代理数量
4. 拉 meta.enc 里的 source_stats 字段，统计每个代理源采集数 / 测活成功率
5. 输出表格报告
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


REPO_OWNER = "LimeiBBQReal"
REPO_NAME = "proxy-pool"
BRANCH = "main"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/alive"


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 17:
        raise ValueError("ciphertext too short")
    iv = blob[:16]
    ct = blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    if 1 <= pad <= 16:
        pt = pt[:-pad]
    return pt


def fetch_and_decrypt(path: str, key: bytes) -> bytes | None:
    url = f"{RAW_BASE}/{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status != 200:
                print(f"  [FAIL] {path}: HTTP {r.status}")
                return None
            blob = r.read()
    except urllib.error.HTTPError as e:
        print(f"  [FAIL] {path}: HTTP {e.code}")
        return None
    except Exception as e:
        print(f"  [FAIL] {path}: {e}")
        return None
    try:
        return aes_decrypt(key, blob)
    except Exception as e:
        print(f"  [FAIL] decrypt {path}: {e}")
        return None


def main():
    key_env = os.environ.get("PROXY_AES_KEY", "")
    if not key_env:
        print("ERROR: PROXY_AES_KEY 环境变量未设置")
        sys.exit(1)
    key = key_env.encode("utf-8")
    if len(key) != 32:
        print(f"ERROR: PROXY_AES_KEY 长度 {len(key)} != 32")
        sys.exit(1)

    print("=" * 60)
    print(f"仓库: https://github.com/{REPO_OWNER}/{REPO_NAME}")
    print(f"分支: {BRANCH}")
    print("=" * 60)

    # HTTP 代理
    print("\n[1/3] 拉取 alive/http.enc ...")
    http_pt = fetch_and_decrypt("http.enc", key)
    if http_pt is None:
        print("  [SKIP] HTTP 跳过")
        http_lines = []
    else:
        http_lines = [ln.decode("utf-8", "ignore").strip() for ln in http_pt.splitlines() if ln.strip()]
        print(f"  [OK] 解密成功: {len(http_lines)} 条 HTTP 活代理")

    # SOCKS5 代理
    print("\n[2/3] 拉取 alive/socks5.enc ...")
    socks_pt = fetch_and_decrypt("socks5.enc", key)
    if socks_pt is None:
        print("  [SKIP] SOCKS5 跳过")
        socks_lines = []
    else:
        socks_lines = [ln.decode("utf-8", "ignore").strip() for ln in socks_pt.splitlines() if ln.strip()]
        print(f"  [OK] 解密成功: {len(socks_lines)} 条 SOCKS5 活代理")

    # 元信息（含 source_stats）
    print("\n[3/3] 拉取 alive/meta.enc ...")
    meta_pt = fetch_and_decrypt("meta.enc", key)
    if meta_pt is None:
        print("  [SKIP] meta 跳过")
        meta = {}
    else:
        try:
            meta = json.loads(meta_pt.decode("utf-8"))
        except Exception as e:
            print(f"  [WARN] meta JSON 解析失败: {e}")
            meta = {}

    # ===== 汇总 =====
    print("\n" + "=" * 60)
    print("汇总报告")
    print("=" * 60)

    run_time = meta.get("generated_at", "未知")
    print(f"运行时间: {run_time} UTC")
    print(f"HTTP 活代理:  {len(http_lines)} 条")
    print(f"SOCKS5 活代理: {len(socks_lines)} 条")
    print(f"总活代理:     {len(http_lines) + len(socks_lines)} 条")

    # 来源统计
    sources = meta.get("sources", [])
    if sources:
        print("\n各代理源采集与测活结果:")
        print(f"{'代理源':<30} {'采集':>8} {'测活成功':>8} {'成功率':>8}")
        print("-" * 60)
        total_fetched = 0
        total_alive = 0
        for s in sources:
            name = s.get("name", "?")
            fetched = s.get("fetched", 0)
            alive = s.get("alive", 0)
            total_fetched += fetched
            total_alive += alive
            rate = f"{alive / fetched * 100:.1f}%" if fetched > 0 else "-"
            print(f"{name:<30} {fetched:>8} {alive:>8} {rate:>8}")
        print("-" * 60)
        print(f"{'合计':<30} {total_fetched:>8} {total_alive:>8} "
              f"{total_alive / total_fetched * 100:.1f}%")
        print(f"\n总采集 → 总测活成功: {total_fetched} → {total_alive}")
        print(f"整体测活成功率: {total_alive / total_fetched * 100:.1f}%")
    else:
        print("\n(meta.json 中未找到 sources 字段, 跳过来源统计)")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()