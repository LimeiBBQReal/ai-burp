"""
Recon Pipeline V3 - 加密模块

加密方案:
1. API Keys: 仅通过 GitHub Secrets 传递，不写入任何文件
2. 扫描结果: AES-256 加密后保存
3. 密钥管理: RSA 公钥加密 AES 密钥

文件结构:
- test_public.pem  - RSA 公钥 (可公开，用于加密)
- test_private.pem - RSA 私钥 (仅本地，用于解密)
- *.data.enc       - AES 加密的数据文件
- *.key.enc        - RSA 加密的 AES 密钥
"""
import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Optional, Union

# 尝试导入加密库
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# 默认密钥路径
DEFAULT_PUBLIC_KEY = "test_public.pem"
DEFAULT_PRIVATE_KEY = "test_private.pem"


class CryptoManager:
    """
    加密管理器

    负责:
    - AES-256 数据加密/解密
    - RSA 密钥加密/解密
    - 文件加密存储
    """

    def __init__(self, public_key_path: str = None, private_key_path: str = None):
        self.public_key_path = Path(public_key_path or DEFAULT_PUBLIC_KEY)
        self.private_key_path = Path(private_key_path or DEFAULT_PRIVATE_KEY)
        self._public_key = None
        self._private_key = None

    @property
    def has_cryptography(self) -> bool:
        return HAS_CRYPTO

    # ==================== 密钥加载 ====================

    def load_public_key(self):
        """加载 RSA 公钥"""
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"公钥文件不存在: {self.public_key_path}")

        with open(self.public_key_path, 'rb') as f:
            self._public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    def load_private_key(self):
        """加载 RSA 私钥"""
        if not self.private_key_path.exists():
            raise FileNotFoundError(f"私钥文件不存在: {self.private_key_path}")

        with open(self.private_key_path, 'rb') as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    # ==================== AES 加密 ====================

    def generate_aes_key(self) -> bytes:
        """生成 256-bit AES 密钥"""
        return os.urandom(32)  # 256 bits

    def aes_encrypt(self, data: bytes, key: bytes) -> tuple:
        """
        AES-256-CBC 加密

        Returns: (ciphertext, iv)
        """
        iv = os.urandom(16)

        # PKCS7 填充
        pad_len = 16 - (len(data) % 16)
        padded = data + bytes([pad_len] * pad_len)

        cipher = Cipher(
            algorithms.AES(key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return ciphertext, iv

    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-256-CBC 解密"""
        cipher = Cipher(
            algorithms.AES(key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # 去除 PKCS7 填充
        pad_len = padded[-1]
        return padded[:-pad_len]

    # ==================== RSA 加密 ====================

    def rsa_encrypt(self, data: bytes) -> bytes:
        """RSA-OAEP 加密"""
        if not self._public_key:
            self.load_public_key()

        return self._public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, ciphertext: bytes) -> bytes:
        """RSA-OAEP 解密"""
        if not self._private_key:
            self.load_private_key()

        return self._private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # ==================== 文件加密存储 ====================

    def encrypt_file(self, data: Union[dict, str, bytes],
                     output_path: str) -> tuple:
        """
        加密数据到文件

        Args:
            data: 要加密的数据
            output_path: 输出文件路径

        Returns:
            (data_file, key_file) 路径元组
        """
        # 序列化数据
        if isinstance(data, dict):
            plaintext = json.dumps(data, ensure_ascii=False).encode('utf-8')
        elif isinstance(data, str):
            plaintext = data.encode('utf-8')
        else:
            plaintext = data

        # 生成 AES 密钥并加密数据
        aes_key = self.generate_aes_key()
        ciphertext, iv = self.aes_encrypt(plaintext, aes_key)

        # RSA 加密 AES 密钥
        encrypted_key = self.rsa_encrypt(aes_key)

        # 保存加密数据
        data_file = Path(output_path).with_suffix('.data.enc')
        key_file = Path(output_path).with_suffix('.key.enc')

        # 数据文件格式: IV (16 bytes) + ciphertext
        with open(data_file, 'wb') as f:
            f.write(iv + ciphertext)

        # 密钥文件: base64 编码的加密密钥
        with open(key_file, 'wb') as f:
            f.write(base64.b64encode(encrypted_key))

        return str(data_file), str(key_file)

    def decrypt_file(self, data_path: str, key_path: str) -> dict:
        """
        解密文件

        Args:
            data_path: 加密数据文件路径
            key_path: 加密密钥文件路径

        Returns:
            解密后的数据 (dict)
        """
        # 读取加密密钥
        with open(key_path, 'rb') as f:
            encrypted_key = base64.b64decode(f.read())

        # RSA 解密 AES 密钥
        aes_key = self.rsa_decrypt(encrypted_key)

        # 读取加密数据
        with open(data_path, 'rb') as f:
            data = f.read()

        iv = data[:16]
        ciphertext = data[16:]

        # AES 解密
        plaintext = self.aes_decrypt(ciphertext, aes_key, iv)

        return json.loads(plaintext.decode('utf-8'))

    # ==================== 便捷方法 ====================

    def encrypt_and_save(self, data: dict, name: str,
                         output_dir: str = "recon/out") -> tuple:
        """
        加密并保存数据

        Args:
            data: 要加密的数据
            name: 文件名 (不含扩展名)
            output_dir: 输出目录

        Returns:
            (data_file, key_file) 路径
        """
        out_path = Path(output_dir) / name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        return self.encrypt_file(data, str(out_path))

    def decrypt_and_load(self, name: str,
                         input_dir: str = "recon/out") -> dict:
        """
        解密并加载数据

        Args:
            name: 文件名 (不含扩展名)
            input_dir: 输入目录

        Returns:
            解密后的数据
        """
        data_file = Path(input_dir) / f"{name}.data.enc"
        key_file = Path(input_dir) / f"{name}.key.enc"

        if not data_file.exists() or not key_file.exists():
            raise FileNotFoundError(f"加密文件不存在: {name}")

        return self.decrypt_file(str(data_file), str(key_file))


# ==================== 全局实例 ====================

_crypto_manager = None

def get_crypto_manager() -> CryptoManager:
    """获取全局加密管理器"""
    global _crypto_manager
    if _crypto_manager is None:
        _crypto_manager = CryptoManager()
    return _crypto_manager


# ==================== 便捷函数 ====================

def encrypt_data(data: dict, name: str, output_dir: str = "recon/out") -> tuple:
    """便捷加密函数"""
    return get_crypto_manager().encrypt_and_save(data, name, output_dir)


def decrypt_data(name: str, input_dir: str = "recon/out") -> dict:
    """便捷解密函数"""
    return get_crypto_manager().decrypt_and_load(name, input_dir)


def encrypt_file_data(data: dict, output_path: str) -> tuple:
    """加密到指定路径"""
    return get_crypto_manager().encrypt_file(data, output_path)


def decrypt_file_data(data_path: str, key_path: str) -> dict:
    """从指定路径解密"""
    return get_crypto_manager().decrypt_file(data_path, key_path)
