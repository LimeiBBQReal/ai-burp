"""
从 LimeiBBQReal/ai-burp-recon 仓库下载 out/ 目录全部 .enc 文件，
然后用本地的 recon_private.pem 私钥 + PROXY_AES_KEY 系统 AES 密钥解密，输出汇总。

使用前设置环境变量:
  $env:PROXY_AES_KEY="ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5"
  python ...\decrypt_all.py
"""
import base64, hashlib, json, os, sys, requests
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
PRIVATE_KEY_PATH = Path.home() / ".recon" / "recon_private.pem"
OUT_DIR = Path(__file__).resolve().parent / "_decrypted"
OUT_DIR.mkdir(exist_ok=True)

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def _aes_key() -> bytes:
    raw = os.environ.get("PROXY_AES_KEY", "")
    if not raw:
        print("[FATAL] 请先设置环境变量: $env:PROXY_AES_KEY=\"ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5\"")
        sys.exit(1)
    return hashlib.sha256(raw.encode("utf-8")).digest()[:32]


def aes_decrypt(encrypted_data: bytes) -> str:
    key = _aes_key()
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def rsa_decrypt_key(encrypted_key_bytes: bytes) -> bytes:
    private_key_pem = PRIVATE_KEY_PATH.read_bytes()
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    aes_key = private_key.decrypt(
        encrypted_key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


def download_and_decrypt():
    print("从 GitHub 下载并解密 out/ 资产...\n")

    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/out"
    r = requests.get(url, headers=HEADERS, timeout=15)
    if r.status_code != 200:
        print(f"ERR: 获取 out/ 目录失败, status={r.status_code}")
        return

    files = r.json()
    enc_files = {}
    for f in files:
        if f["name"].endswith(".enc"):
            base = f["name"].replace(".data.enc", "").replace(".key.enc", "")
            if base not in enc_files:
                enc_files[base] = {}
            if ".key.enc" in f["name"]:
                enc_files[base]["key"] = f
            else:
                enc_files[base]["data"] = f

    for task_name, parts in sorted(enc_files.items()):
        data_file = parts.get("data")
        key_file = parts.get("key")
        if not data_file or not key_file:
            print(f"  [SKIP] {task_name}: 缺少 data 或 key 文件")
            continue

        r_data = requests.get(data_file["download_url"], headers=HEADERS, timeout=30)
        if r_data.status_code != 200:
            print(f"  [ERR] {task_name} data download: {r_data.status_code}")
            continue

        r_key = requests.get(key_file["download_url"], headers=HEADERS, timeout=30)
        if r_key.status_code != 200:
            print(f"  [ERR] {task_name} key download: {r_key.status_code}")
            continue

        encrypted_data = r_data.content
        encrypted_key_bytes = r_key.content

        try:
            aes_key = rsa_decrypt_key(encrypted_key_bytes)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(encrypted_data[:16]))
            decryptor = cipher.decryptor()
            padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            text = plaintext.decode("utf-8")
        except Exception as e:
            print(f"  [ERR] {task_name}: RSA+AES 双层解密失败: {e}")
            continue

        # Save plaintext
        out_path = OUT_DIR / f"{task_name}.json"
        out_path.write_text(text, encoding="utf-8")
        data = json.loads(text)

        print(f"\n{'='*60}")
        print(f"  {task_name}")
        print(f"{'='*60}")

        if task_name == "subdomains":
            subs = data.get("subdomains", [])
            if not subs:
                subs = data.get("urls", [])
            if not subs:
                subs = data.get("results", [])
            elapsed = data.get("elapsed_s", "?")
            if isinstance(subs, list):
                unique = sorted(set(s.strip() for s in subs if s.strip()))
            else:
                unique = list(subs)
            if len(unique) > 1:
                print(f"  总计: {len(unique)} 个子域名, 耗时: {elapsed}s")
                for s in unique[:80]:
                    print(f"    {s}")
                if len(unique) > 80:
                    print(f"    ... 等 {len(unique)} 个")
            else:
                print(f"  (数据格式: {json.dumps(data, indent=2, ensure_ascii=False)[:500]}")

        elif task_name == "deep":
            subs = data.get("subdomains", data.get("urls", data.get("results", [])))
            elapsed = data.get("elapsed_s", "?")
            all_subs = sorted(set(subs)) if isinstance(subs, list) else list(subs)
            print(f"  总计: {len(all_subs)} 条, 耗时: {elapsed}s")
            for s in all_subs[:80]:
                print(f"    {s}")
            if len(all_subs) > 80:
                print(f"    ... 等 {len(all_subs)} 条")

        elif task_name == "urls":
            urls = data.get("urls", [])
            elapsed = data.get("elapsed_s", "?")
            print(f"  总计: {len(urls)} URLs, 耗时: {elapsed}s")
            for u in urls[:50]:
                print(f"    {u}")
            if len(urls) > 50:
                print(f"    ... 等 {len(urls)} 条")
            # Show params & extensions
            params = data.get("top_params", {})
            if params:
                print(f"\n  参数 TOP 10:")
                for k, v in list(params.items())[:10]:
                    print(f"    ?{k}: {v} 次")

        elif task_name == "ports":
            elapsed = data.get("elapsed_s", "?")
            ports = data.get("open_ports", data.get("ports", data.get("results", [])))
            print(f"  目标: {data.get('target','?')}, 耗时: {elapsed}s")
            for p in ports:
                print(f"    {p}")

        elif task_name == "banners":
            elapsed = data.get("elapsed_s", "?")
            services = data.get("services", data.get("results", data.get("banners", [])))
            print(f"  目标: {data.get('target','?')}, 耗时: {elapsed}s")
            for s in services:
                print(f"    {s}")

        elif task_name == "dns":
            elapsed = data.get("elapsed_s", "?")
            records = data.get("records", data.get("results", {}))
            print(f"  目标: {data.get('target','?')}, 耗时: {elapsed}s")
            for rtype, values in records.items():
                print(f"  [{rtype}]")
                if isinstance(values, list):
                    for v in values:
                        print(f"    {v}")
                else:
                    print(f"    {values}")

        elif task_name == "dirs":
            elapsed = data.get("elapsed_s", "?")
            found = data.get("found", data.get("results", []))
            print(f"  目标: {data.get('target','?')}, 耗时: {elapsed}s")
            for item in found[:30]:
                print(f"    {item}")
            if len(found) > 30:
                print(f"    ... 等 {len(found)} 条")

        elif task_name == "params":
            elapsed = data.get("elapsed_s", "?")
            results = data.get("results", [])
            print(f"  目标: {data.get('target','?')}, 耗时: {elapsed}s")
            for item in results[:30]:
                print(f"    {item}")
            if len(results) > 30:
                print(f"    ... 等 {len(results)} 条")

        elif task_name == "cidr":
            elapsed = data.get("elapsed_s", "?")
            segments = data.get("segments", data.get("results", data.get("cidr", [])))
            print(f"  目标: {data.get('target','?')}, 耗时: {elapsed}s")
            for s in segments:
                print(f"    {s}")

        elif task_name == "js_urls":
            urls = data.get("urls", data.get("results", []))
            elapsed = data.get("elapsed_s", "?")
            print(f"  总计: {len(urls)} JS URLs, 耗时: {elapsed}s")
            for u in urls[:30]:
                print(f"    {u}")
            if len(urls) > 30:
                print(f"    ... 等 {len(urls)} 条")

        else:
            print(json.dumps(data, indent=2, ensure_ascii=False)[:500])

    print(f"\n\n明文 JSON 已保存到: {OUT_DIR}")


if __name__ == "__main__":
    download_and_decrypt()
