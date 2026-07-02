"""端到端自检: 生成临时 RSA + AES, 加密, 解密, 比对."""
import base64, hashlib, json, os, sys, tempfile
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. 生成 RSA 2048
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
print(f"[1] RSA-2048 生成 OK ({len(pub_pem)} 字节 PEM)")

# 2. 派生 AES key
raw_key = "ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5"
aes_key = hashlib.sha256(raw_key.encode("utf-8")).digest()[:32]
print(f"[2] AES-256 key 派生 OK ({len(aes_key)} 字节)")

# 3. 加密
plaintext = json.dumps({"target": "example.com", "subdomains": ["a.example.com", "b.example.com"]}, indent=2)
iv = os.urandom(16)
padder = sym_padding.PKCS7(128).padder()
padded = padder.update(plaintext.encode()) + padder.finalize()
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
data_enc = iv + ct
print(f"[3] AES 加密 OK ({len(data_enc)} 字节 ciphertext)")

# 4. RSA 加密 AES key
key_enc = pub.encrypt(
    aes_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print(f"[4] RSA-OAEP 加密 AES key OK ({len(key_enc)} 字节)")

# 5. 解密 AES key
aes_key_dec = priv.decrypt(
    key_enc,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
assert aes_key_dec == aes_key, "RSA 解密后 key 不一致"
print(f"[5] RSA 解密 key 一致性 OK")

# 6. 解密数据
iv2 = data_enc[:16]
ct2 = data_enc[16:]
cipher2 = Cipher(algorithms.AES(aes_key_dec), modes.CBC(iv2))
padded2 = cipher2.decryptor().update(ct2) + cipher2.decryptor().finalize()
unpadder = sym_padding.PKCS7(128).unpadder()
plaintext_dec = (unpadder.update(padded2) + unpadder.finalize()).decode("utf-8")
assert plaintext_dec == plaintext, "AES 解密后 plaintext 不一致"
print(f"[6] AES 解密 plaintext 一致性 OK")

# 7. 跑一遍 recon_decoder 的核心逻辑
sys.path.insert(0, r"e:\CursorDEV\CKFinder\ai-burp\aiburp")
from recon_decoder import _decrypt_data

priv2 = serialization.load_pem_private_key(priv_pem, password=None)
plaintext_final = _decrypt_data(data_enc, key_enc, priv_pem).decode("utf-8")
assert plaintext_final == plaintext, "recon_decoder._decrypt_data 不一致"
print(f"[7] recon_decoder._decrypt_data 调用 OK")

# 8. 跑一遍 _common 的核心逻辑 (需要 monkey-patch 环境变量)
os.environ["PROXY_AES_KEY"] = raw_key
os.environ["RECON_RSA_PUBLIC"] = base64.b64encode(pub_pem).decode("ascii")
sys.path.insert(0, r"e:\CursorDEV\CKFinder\ai-burp\recon")
from _common import write_encrypted, aes_encrypt, rsa_encrypt_key
from pathlib import Path

data_path, key_path = write_encrypted("test_task", {"hello": "world"})
print(f"[8] _common.write_encrypted OK: {data_path.name} + {key_path.name}")

# 用 recon_decoder 解 _common 生成的密文
data_enc2 = data_path.read_bytes()
key_enc2 = key_path.read_bytes()
plaintext_v2 = _decrypt_data(data_enc2, key_enc2, priv_pem).decode("utf-8")
obj = json.loads(plaintext_v2)
assert obj == {"hello": "world"}, f"recon 解密结果不匹配: {obj}"
print(f"[9] _common → recon_decoder 端到端 OK: {obj}")

# 清理
data_path.unlink(missing_ok=True)
key_path.unlink(missing_ok=True)

print("\n========== 自检全部通过 ==========")
print(f"PROXY_AES_KEY (env):    {raw_key}")
print(f"RECON_RSA_PUBLIC (env): {os.environ['RECON_RSA_PUBLIC'][:60]}...")