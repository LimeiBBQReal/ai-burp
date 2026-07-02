"""云端采集结果本地解密器.

用法 (放在你本地电脑, 不上传到 GitHub 仓库):

    # 1. 首次使用: 生成 RSA 密钥对 (用户操作, 见 README)
    #    openssl genrsa -out ~/.recon/recon_private.pem 2048
    #    openssl rsa -in ~/.recon/recon_private.pem -pubout -out ~/.recon/recon_public.pem
    #    base64 -w0 ~/.recon/recon_public.pem > ~/.recon/recon_public_b64.txt
    #
    # 2. 把 recon_public_b64.txt 内容粘贴到 GitHub Secret RECON_RSA_PUBLIC
    #    仓库跑完 workflow 后 commit 回 *.data.enc + *.key.enc
    #
    # 3. 本地解密:

    python -m aiburp.recon_decoder --repo LimeiBBQReal/ai-burp-recon --task subdomain
    python -m aiburp.recon_decoder --repo LimeiBBQReal/ai-burp-recon --task dns --out ./decrypted/

工作机制:
    1. 从 GitHub raw 拉取 out/<task>.data.enc + out/<task>.key.enc
    2. 用 RSA 私钥解密 .key.enc 得到 AES-256 key
    3. 用 AES-256-CBC 解密 .data.enc (前 16 字节是 IV)
    4. 输出明文 JSON / 文本到本地
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import requests

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
except ImportError:
    print("[FATAL] 缺少 cryptography 库, 请先: pip install cryptography", file=sys.stderr)
    sys.exit(1)


DEFAULT_REPO = "LimeiBBQReal/ai-burp-recon"
DEFAULT_BRANCH = "main"
DEFAULT_OUT_DIR = "recon_out"
DEFAULT_KEY_DIR = os.path.expanduser("~/.recon")
DEFAULT_KEY_FILE = os.path.join(DEFAULT_KEY_DIR, "recon_private.pem")


def _fetch(url: str) -> bytes | None:
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.content
        print(f"  [WARN] {url} → HTTP {r.status_code}", file=sys.stderr)
    except Exception as e:
        print(f"  [ERR] {url}: {e}", file=sys.stderr)
    return None


def _decrypt_data(data_enc: bytes, key_enc: bytes, private_pem: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_pem, password=None)
    aes_key = priv.decrypt(
        key_enc,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(aes_key) != 32:
        raise ValueError(f"AES key 长度异常: {len(aes_key)} (期望 32)")
    iv = data_enc[:16]
    ct = data_enc[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _decrypt_with_aes_key(data_enc: bytes, aes_key: bytes) -> bytes:
    iv = data_enc[:16]
    ct = data_enc[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _try_parse(plaintext: bytes) -> tuple[str, str]:
    """尝试解析为 JSON / 文本, 返回 (format, content)."""
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return ("binary", plaintext.hex())
    try:
        obj = json.loads(text)
        return ("json", json.dumps(obj, ensure_ascii=False, indent=2))
    except json.JSONDecodeError:
        return ("text", text)


def decode_one(
    repo: str,
    branch: str,
    task: str,
    private_pem: bytes,
    out_dir: Path,
) -> Path | None:
    base = f"https://raw.githubusercontent.com/{repo}/{branch}/recon/out"
    data_url = f"{base}/{task}.data.enc"
    key_url = f"{base}/{task}.key.enc"

    print(f"\n[+] 解密任务: {task}")
    print(f"    data: {data_url}")
    print(f"    key:  {key_url}")

    data_enc = _fetch(data_url)
    key_enc = _fetch(key_url)
    if data_enc is None or key_enc is None:
        print(f"  [FAIL] 拉取失败, 跳过", file=sys.stderr)
        return None

    try:
        plaintext = _decrypt_data(data_enc, key_enc, private_pem)
    except Exception as e:
        print(f"  [ERR] 解密失败: {e}", file=sys.stderr)
        return None

    fmt, content = _try_parse(plaintext)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{task}.{ 'json' if fmt == 'json' else 'txt'}"
    out_path.write_text(content, encoding="utf-8")
    print(f"  → 解密成功 [{fmt}] {len(plaintext)} 字节 → {out_path}")
    return out_path


def decode_all(repo: str, branch: str, tasks: list[str], private_pem: bytes, out_dir: Path) -> int:
    ok = 0
    for t in tasks:
        if decode_one(repo, branch, t, private_pem, out_dir):
            ok += 1
    return ok


def main():
    ap = argparse.ArgumentParser(description="云端采集结果本地解密器")
    ap.add_argument("--repo", default=os.environ.get("RECON_REPO", DEFAULT_REPO),
                    help=f"GitHub 仓库 (默认 {DEFAULT_REPO})")
    ap.add_argument("--branch", default=DEFAULT_BRANCH, help=f"分支 (默认 {DEFAULT_BRANCH})")
    ap.add_argument("--task", help="单个任务名, 如 subdomain / dns / ports")
    ap.add_argument("--tasks", help="逗号分隔多个任务")
    ap.add_argument("--list", action="store_true", help="列出 GitHub 上所有 .enc 文件")
    ap.add_argument("--key", default=DEFAULT_KEY_FILE, help=f"RSA 私钥路径 (默认 {DEFAULT_KEY_FILE})")
    ap.add_argument("--out", default=DEFAULT_OUT_DIR, help=f"明文输出目录 (默认 {DEFAULT_OUT_DIR})")
    args = ap.parse_args()

    if not os.path.exists(args.key):
        print(f"[FATAL] 找不到 RSA 私钥: {args.key}", file=sys.stderr)
        print("        生成方式: openssl genrsa -out ~/.recon/recon_private.pem 2048", file=sys.stderr)
        sys.exit(1)
    private_pem = Path(args.key).read_bytes()

    out_dir = Path(args.out).resolve()

    if args.list:
        api = f"https://api.github.com/repos/{args.repo}/contents/recon/out?ref={args.branch}"
        try:
            r = requests.get(api, timeout=15)
            for item in r.json():
                if item.get("name", "").endswith(".enc"):
                    print(item["name"])
        except Exception as e:
            print(f"[ERR] 列举失败: {e}", file=sys.stderr)
        return

    tasks = []
    if args.task:
        tasks.append(args.task)
    if args.tasks:
        tasks.extend(t.strip() for t in args.tasks.split(",") if t.strip())
    if not tasks:
        ap.error("必须指定 --task 或 --tasks 或 --list")

    ok = decode_all(args.repo, args.branch, tasks, private_pem, out_dir)
    print(f"\n[+] 完成: {ok}/{len(tasks)} 个任务解密成功 → {out_dir}")


if __name__ == "__main__":
    main()