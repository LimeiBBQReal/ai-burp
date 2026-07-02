"""
本地代理池客户端 — 从云端 GitHub 仓库拉取加密代理列表 + 本地解密 + 二次精筛

用法:
    from aiburp.proxy.proxy_pool_client import cloud_pool
    proxy = cloud_pool.get_alive_proxy(protocol="socks5")  # → "socks5://1.2.3.4:1080"
    proxy = cloud_pool.get_alive_proxy(protocol="http", n=3)  # → ["http://...", ...]

工作流:
    1. 从 GitHub raw 拉取 alive/http.enc + alive/socks5.enc (5分钟缓存)
    2. AES 解密得到明文代理列表
    3. 随机抽 N 条, 4s 并发测活
    4. 返回第一个 (或前 N 个) 活代理
    5. 命中的代理写入 hot cache (3分钟 TTL), 优先复用

环境变量:
    PROXY_AES_KEY — AES 加密密钥 (必须设置, 与云端 GitHub Secret 一致)
"""
from __future__ import annotations

import hashlib
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

# ── 配置 ──────────────────────────────────────────────
# 你的 GitHub 代理池仓库 (改成你自己的)
# 加密方案: 代理列表 AES 加密后 commit 到公开仓库, 别人只看到乱码
# 下载 URL 格式: https://raw.githubusercontent.com/<user>/<repo>/main/alive/<file>.enc
CLOUD_REPO_OWNER = "LimeiBBQReal"
CLOUD_REPO_NAME = "proxy-pool"
CLOUD_BRANCH = "main"
CLOUD_RAW_URL = f"https://raw.githubusercontent.com/{CLOUD_REPO_OWNER}/{CLOUD_REPO_NAME}/{CLOUD_BRANCH}/alive"

# AES 密钥 (优先从环境变量读, 与云端 GitHub Secret PROXY_AES_KEY 一致)
AES_KEY = os.environ.get("PROXY_AES_KEY", "")

# 后备公共源 (你的仓库还没建好时自动用, 不加密)
FALLBACK_SOURCES = {
    "http": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "socks5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
}

# 缓存 TTL
POOL_CACHE_TTL = 300  # 5 分钟
HOT_CACHE_TTL = 180   # 3 分钟

# 二次测活参数
# 注: probe 改为 gstatic.com (海外 + 大陆都通), 超时自动降级 cp.cloudflare
VERIFY_TIMEOUT_HTTP = 4
VERIFY_TIMEOUT_SOCKS5 = 8  # SOCKS5 三次握手 + 海外回程, 单独放宽
VERIFY_WORKERS = 30
VERIFY_SAMPLE = 30    # 每次随机抽多少条测
VERIFY_PROBE = "http://www.gstatic.com/generate_204"
VERIFY_PROBE_FALLBACK = "https://cp.cloudflare.com/generate_204"
VERIFY_EXPECT = 204
MAX_ROUNDS = 3        # 最多抽几轮
# ─────────────────────────────────────────────────────


def _build_proxy_url(ip: str, port: int, protocol: str) -> str:
    if protocol == "socks5":
        return f"socks5://{ip}:{port}"
    return f"http://{ip}:{port}"


def _aes_decrypt(encrypted: bytes, key: str) -> str:
    """AES-256-CBC 解密, 输入是 iv + ciphertext. 与云端 fetch_and_verify.aes_decrypt 行为一致."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
    except ImportError:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        key_bytes = hashlib.sha256(key.encode("utf-8")).digest()[:32]
        iv = encrypted[:16]
        ct = encrypted[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")

    key_bytes = hashlib.sha256(key.encode("utf-8")).digest()[:32]
    iv = encrypted[:16]
    ct = encrypted[16:]
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def _verify_one(ip: str, port: int, protocol: str) -> bool:
    """单代理快速测活 (超时自动降级 cp.cloudflare)."""
    proxies = {
        "http": _build_proxy_url(ip, port, protocol),
        "https": _build_proxy_url(ip, port, protocol),
    }
    timeout = VERIFY_TIMEOUT_SOCKS5 if protocol == "socks5" else VERIFY_TIMEOUT_HTTP
    urls = [VERIFY_PROBE]
    if VERIFY_PROBE_FALLBACK:
        urls.append(VERIFY_PROBE_FALLBACK)
    for url in urls:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
            if r.status_code == VERIFY_EXPECT:
                return True
        except requests.exceptions.Timeout:
            continue
        except Exception:
            return False
    return False


class CloudProxyPool:
    """云端代理池客户端: 拉取 → 缓存 → 二次测活 → 返回."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pool_cache: dict[str, list[tuple[str, int]]] = {}  # protocol → [(ip, port), ...]
        self._pool_fetched_at: float = 0
        self._hot_cache: dict[str, tuple[str, int, float]] = {}  # protocol → (ip, port, expire_ts)

    def _fetch_pool(self, protocol: str) -> list[tuple[str, int]]:
        """从云端拉取加密代理列表 → 解密 → 缓存."""
        now = time.time()
        with self._lock:
            if protocol in self._pool_cache and (now - self._pool_fetched_at) < POOL_CACHE_TTL:
                return self._pool_cache[protocol]

        entries: list[tuple[str, int]] = []

        # 1. 先试自己的仓库 (加密 .enc 文件)
        if AES_KEY:
            url = f"{CLOUD_RAW_URL}/{protocol}.enc"
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and r.content:
                    plaintext = _aes_decrypt(r.content, AES_KEY)
                    for line in plaintext.splitlines():
                        line = line.strip()
                        if ":" in line:
                            parts = line.rsplit(":", 1)
                            if len(parts) == 2:
                                try:
                                    entries.append((parts[0], int(parts[1])))
                                except ValueError:
                                    continue
                    if entries:
                        print(f"[pool] 从云端解密 {protocol}: {len(entries)} 条")
            except Exception as e:
                print(f"[pool] 云端拉取失败: {e}")

        # 2. 后备公共源 (仓库还没建好或 .enc 还没生成时用)
        if not entries:
            fb_url = FALLBACK_SOURCES.get(protocol, "")
            if fb_url:
                try:
                    r = requests.get(fb_url, timeout=10)
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            line = line.strip()
                            if ":" in line:
                                parts = line.rsplit(":", 1)
                                if len(parts) == 2:
                                    try:
                                        entries.append((parts[0], int(parts[1])))
                                    except ValueError:
                                        continue
                    if entries:
                        print(f"[pool] 从后备源拉取 {protocol}: {len(entries)} 条")
                except Exception:
                    pass

        with self._lock:
            self._pool_cache[protocol] = entries
            self._pool_fetched_at = now
        return entries

    def _get_hot(self, protocol: str) -> str | None:
        """从 hot cache 取一个未过期的代理."""
        now = time.time()
        with self._lock:
            if protocol in self._hot_cache:
                ip, port, expire = self._hot_cache[protocol]
                if now < expire:
                    return _build_proxy_url(ip, port, protocol)
                else:
                    del self._hot_cache[protocol]
        return None

    def _set_hot(self, protocol: str, ip: str, port: int) -> None:
        with self._lock:
            self._hot_cache[protocol] = (ip, port, time.time() + HOT_CACHE_TTL)

    def _sample_and_verify(self, protocol: str, need: int = 1) -> list[tuple[str, int]]:
        """随机抽样 + 并发测活, 返回活的列表."""
        pool = self._fetch_pool(protocol)
        if not pool:
            return []

        alive_found: list[tuple[str, int]] = []
        remaining = list(pool)

        for round_num in range(MAX_ROUNDS):
            if not remaining or len(alive_found) >= need:
                break

            sample_size = min(VERIFY_SAMPLE, len(remaining))
            sample = random.sample(remaining, sample_size)
            for s in sample:
                remaining.remove(s)

            with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as ex:
                futs = {
                    ex.submit(_verify_one, ip, port, protocol): (ip, port)
                    for ip, port in sample
                }
                for fut in as_completed(futs):
                    ip, port = futs[fut]
                    if fut.result():
                        alive_found.append((ip, port))
                        if len(alive_found) >= need:
                            break

            if len(alive_found) < need:
                print(f"[pool] 第{round_num+1}轮: 找到 {len(alive_found)}/{need}, 继续抽样...")

        return alive_found[:need]

    def get_alive_proxy(
        self, protocol: str = "http", n: int = 1
    ) -> str | list[str] | None:
        """
        获取活代理.

        Args:
            protocol: "http" 或 "socks5"
            n: 需要几个 (1 → 返回 str, >1 → 返回 list)

        Returns:
            n=1: "http://1.2.3.4:8080" 或 "socks5://1.2.3.4:1080" 或 None
            n>1: ["http://...", ...] 或 []
        """
        # 1. 先查 hot cache
        if n == 1:
            hot = self._get_hot(protocol)
            if hot:
                return hot

        # 2. 抽样测活
        alive = self._sample_and_verify(protocol, n)
        if not alive:
            print(f"[pool] 未能找到活的 {protocol} 代理")
            return None if n == 1 else []

        # 3. 写 hot cache
        if alive:
            self._set_hot(protocol, alive[0][0], alive[0][1])

        # 4. 返回
        urls = [_build_proxy_url(ip, port, protocol) for ip, port in alive]
        if n == 1:
            return urls[0]
        return urls

    def get_proxy_dict(self, protocol: str = "http") -> dict[str, str] | None:
        """
        返回 requests/httpx 格式的 proxies dict.

        Example:
            proxies = pool.get_proxy_dict("socks5")
            # → {"http": "socks5://1.2.3.4:1080", "https": "socks5://1.2.3.4:1080"}
        """
        url = self.get_alive_proxy(protocol, n=1)
        if not url:
            return None
        return {"http": url, "https": url}

    def stats(self) -> dict[str, Any]:
        """返回当前缓存状态."""
        now = time.time()
        with self._lock:
            return {
                "pool_cache_age": f"{now - self._pool_fetched_at:.0f}s" if self._pool_fetched_at else "empty",
                "http_pool_size": len(self._pool_cache.get("http", [])),
                "socks5_pool_size": len(self._pool_cache.get("socks5", [])),
                "hot_cache": {k: f"{v[0]}:{v[1]}" for k, v in self._hot_cache.items() if now < v[2]},
            }


# 全局单例
cloud_pool = CloudProxyPool()


if __name__ == "__main__":
    # 测试
    print("=== CloudProxyPool 测试 ===\n")

    print("[1] 获取 1 个 HTTP 代理:")
    p = cloud_pool.get_alive_proxy("http")
    print(f"    → {p}\n")

    print("[2] 获取 1 个 SOCKS5 代理:")
    p = cloud_pool.get_alive_proxy("socks5")
    print(f"    → {p}\n")

    print("[3] 获取 3 个 HTTP 代理:")
    ps = cloud_pool.get_alive_proxy("http", n=3)
    print(f"    → {ps}\n")

    print("[4] 获取 proxy dict:")
    pd = cloud_pool.get_proxy_dict("socks5")
    print(f"    → {pd}\n")

    print("[5] 缓存状态:")
    print(f"    {cloud_pool.stats()}")
