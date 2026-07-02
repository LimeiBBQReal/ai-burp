"""配置 PAT_TOKEN secret 到 GitHub 仓库, 用于 workflow push 提交 .enc 文件."""
import base64, json, subprocess, sys
import requests

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Step 1: 获取 public key
print("=== 获取 public key ===")
r = requests.get(f"https://api.github.com/repos/{OWNER}/{REPO}/actions/secrets/public-key", headers=HEADERS, timeout=15)
pk = r.json()
key_id = pk["key_id"]
print(f"  key_id: {key_id}")

# Step 2: 加密 PAT_TOKEN (和 workflow 中要用的一致)
try:
    from nacl.bindings import crypto_box_seal
except ImportError:
    print("  [*] 安装 pynacl...")
    subprocess.run([sys.executable, "-m", "pip", "install", "pynacl", "-q"], check=True)
    from nacl.bindings import crypto_box_seal

import nacl.encoding
pub_key = nacl.encoding.Base64Encoder.decode(pk["key"])
encrypted = crypto_box_seal(TOKEN.encode("utf-8"), pub_key)
encrypted_b64 = nacl.encoding.Base64Encoder.encode(encrypted).decode("ascii")

print(f"\n=== 设置 Secret: PAT_TOKEN ===")
r = requests.put(
    f"https://api.github.com/repos/{OWNER}/{REPO}/actions/secrets/PAT_TOKEN",
    headers=HEADERS,
    json={"encrypted_value": encrypted_b64, "key_id": key_id},
    timeout=15,
)
if r.status_code == 201 or r.status_code == 204:
    print("  PAT_TOKEN secret 设置成功!")
else:
    print(f"  ERR: {r.status_code} {r.text[:200]}")

print("\n=== 完成! ===")
print("现在 GitHub Actions workflow 提交 .enc 文件时将使用你的 PAT_TOKEN 进行 git push")
