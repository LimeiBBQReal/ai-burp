"""通过 GitHub API 创建仓库 + 配置 Secrets + 推送代码."""
import base64, json, os, subprocess, sys, tempfile
from pathlib import Path
import requests

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
RECON_DIR = r"e:\CursorDEV\CKFinder\ai-burp\recon"

# 公钥 base64 (之前生成的)
PUB_B64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1UVdkUEdCdkpGOGZTMWRpSjFaaAozRVI0STUyVnJqQXp0c0dwUmVKZmhSSzI0K1AyMmZiQTBCa1pET044cHViWnptRG9ERW9RMHpjdjMyRmNpayt6CnBESzNQUmh1Nm4vTW5WYU45WktXZUl6SStkTHdsM1A0bGxoZ0ZTN2Y5NmpEMFpVZ2JsVElYK1JRMWRnQzIrTTkKY3hqY2JNRWc3Z292cVhjcFIvd3Nmd0EzVzdiYTVYUFc1RWV0SnB0SlQ0ZWFhR09uMlAzaFF5MzZNL1F0MW5MKwpra2k3aDUreHpSbnBDZHRwb0RTaU80ODhkTTZYc3FIeUwyWm1Va0FKazJ3K1BtSGZENUZKUEJxOVNPazBJWkxVCjhiaWNEM0dyZ3NJdEVhRm9QL2FFckZpWE9VeENnVmFCNWZtTHpqMkN6S0o5cXhJQ2ZWN0pPMGp3RUx3d01uN3IKYXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def gh(url, method="GET", body=None):
    r = requests.request(method, url, headers=HEADERS, json=body, timeout=15)
    print(f"  {method} {url} → {r.status_code}")
    if r.status_code >= 400:
        print(f"    ERR: {r.text[:200]}")
    return r


def encrypt_secret(public_key_b64, secret_value):
    """用 GitHub 的 public key + libsodium 加密 secret."""
    try:
        from nacl.bindings import crypto_box_seal
    except ImportError:
        # 尝试用 cryptography 模拟 (但 pyNaCl 更标准)
        print("  [*] 安装 pynacl...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pynacl", "-q"], check=True)
        from nacl.bindings import crypto_box_seal

    import nacl.encoding
    pub_key = nacl.encoding.Base64Encoder.decode(public_key_b64)
    sealed = crypto_box_seal(secret_value.encode("utf-8"), pub_key)
    return nacl.encoding.Base64Encoder.encode(sealed).decode("ascii")


def main():
    print("=== 1. 创建仓库 ===")
    r = gh("https://api.github.com/repos/LimeiBBQReal/ai-burp-recon")
    if r.status_code == 200:
        print("  仓库已存在, 跳过")
    else:
        r = gh("https://api.github.com/user/repos", "POST", {
            "name": REPO, "private": False, "auto_init": False,
            "description": "Cloud recon collector with AES+RSA two-layer encryption"
        })
        if r.status_code == 201:
            print(f"  创建成功: {r.json()['html_url']}")
        else:
            print("  [FATAL] 创建仓库失败")
            sys.exit(1)

    print("\n=== 2. 获取 public key ===")
    r = gh(f"https://api.github.com/repos/{OWNER}/{REPO}/actions/secrets/public-key")
    pk = r.json()
    key_id = pk["key_id"]
    key_b64 = pk["key"]
    print(f"  key_id: {key_id}")

    print("\n=== 3. 配置 Secret: PROXY_AES_KEY ===")
    encrypted = encrypt_secret(key_b64, "ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5")
    gh(f"https://api.github.com/repos/{OWNER}/{REPO}/actions/secrets/PROXY_AES_KEY", "PUT", {
        "encrypted_value": encrypted, "key_id": key_id
    })

    print("\n=== 4. 配置 Secret: RECON_RSA_PUBLIC ===")
    encrypted2 = encrypt_secret(key_b64, PUB_B64)
    gh(f"https://api.github.com/repos/{OWNER}/{REPO}/actions/secrets/RECON_RSA_PUBLIC", "PUT", {
        "encrypted_value": encrypted2, "key_id": key_id
    })

    print("\n=== 5. 推送代码 ===")
    if not os.path.exists(RECON_DIR):
        print(f"  [FATAL] 找不到目录: {RECON_DIR}")
        sys.exit(1)

    # 用 git 推
    os.chdir(RECON_DIR)
    remote_url = f"https://{OWNER}:{TOKEN}@github.com/{OWNER}/{REPO}.git"

    # 检查是否已经是 git repo
    r = subprocess.run(["git", "status"], capture_output=True, text=True)
    if r.returncode != 0:
        subprocess.run(["git", "init"], check=True)
        subprocess.run(["git", "branch", "-M", "main"], check=True)

    # 移除已有 remote (如果有)
    subprocess.run(["git", "remote", "remove", "origin"], capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", remote_url], check=True)

    # add + commit + push
    subprocess.run(["git", "add", "."], check=True)
    r = subprocess.run(["git", "diff", "--cached", "--quiet"], capture_output=True)
    if r.returncode == 0:
        print("  没有变更, 跳过 commit")
    else:
        subprocess.run(["git", "commit", "-m", "init: recon cloud collector with two-layer encryption"], check=True)

    print("  Push 中...")
    r = subprocess.run(["git", "push", "-u", "origin", "main", "--force"], capture_output=True, text=True)
    if r.returncode == 0:
        print("  Push 成功!")
    else:
        print(f"  Push 失败: {r.stderr[:500]}")
        print("  可能原因: repo 已有冲突, 尝试 --force 后重试")

    print("\n=== 完成! ===")
    print(f"仓库: https://github.com/{OWNER}/{REPO}")
    print(f"Actions: https://github.com/{OWNER}/{REPO}/actions")


if __name__ == "__main__":
    main()