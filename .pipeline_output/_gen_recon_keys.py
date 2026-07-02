"""Windows one-click RSA keypair + base64 public key (openssl replacement).

Generates:
    C:\\Users\\<you>\\.recon\\recon_private.pem   private key (local only, never commit)
    C:\\Users\\<you>\\.recon\\recon_public.pem    public key (PEM)
    C:\\Users\\<you>\\.recon\\recon_public_b64.txt base64 of public key (paste into GitHub Secret)
"""
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = Path(os.path.expanduser("~/.recon"))
KEY_DIR.mkdir(parents=True, exist_ok=True)
PRIV_PATH = KEY_DIR / "recon_private.pem"
PUB_PATH = KEY_DIR / "recon_public.pem"
PUB_B64_PATH = KEY_DIR / "recon_public_b64.txt"

if PRIV_PATH.exists() and PUB_PATH.exists():
    print(f"[!] 已存在密钥对, 不覆盖: {PRIV_PATH}")
    print(f"    如需重新生成, 先删除该文件再跑.")
else:
    print(f"[*] 生成 RSA-2048 密钥对 ...")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIV_PATH.write_bytes(priv_pem)
    PUB_PATH.write_bytes(pub_pem)
    print(f"[+] 私钥 → {PRIV_PATH} ({len(priv_pem)} 字节)")
    print(f"[+] 公钥 → {PUB_PATH} ({len(pub_pem)} 字节)")

pub_b64 = base64.b64encode(PUB_PATH.read_bytes()).decode("ascii")
PUB_B64_PATH.write_text(pub_b64, encoding="ascii")

print()
print("=" * 60)
print("GitHub Secret RECON_RSA_PUBLIC 的值 (复制下面整行):")
print("=" * 60)
print(pub_b64)
print("=" * 60)
print(f"\n[*] 也已写入 {PUB_B64_PATH}")
print()
print("下一步:")
print("  1. 打开 https://github.com/LimeiBBQReal/ai-burp-recon/settings/secrets/actions")
print("  2. New repository secret")
print("     Name:  RECON_RSA_PUBLIC")
print("     Value: 上面那行 base64")
print("  3. 再加一个: PROXY_AES_KEY = ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5")
print()
print(f"[!] 私钥 {PRIV_PATH} 只在这台电脑, 别上传.")