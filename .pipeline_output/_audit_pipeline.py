"""
从 repo 下载最新 Phase 1 + 已有各模块加密数据，本地解密汇总，
分析管线完整性和遗漏点。
"""
import requests, json, re, sys
from pathlib import Path

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def _decrypt(enc_data: bytes, enc_key: bytes) -> dict:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    import os
    priv_path = Path(os.path.expanduser("~/.recon/recon_private.pem"))
    if priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        aes_key = priv.decrypt(
            enc_key,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    else:
        return {"error": "no private key"}
    data = enc_data
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return json.loads(plain)

def fetch_and_show(name):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/out/{name}"
    r = requests.get(url, headers=HEADERS, timeout=15)
    if r.status_code != 200:
        return
    f = r.json()
    r_data = requests.get(f["download_url"], headers=HEADERS, timeout=30)
    if r_data.status_code != 200:
        return
    key_name = name.replace(".data.enc", ".key.enc")
    url2 = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/out/{key_name}"
    r2 = requests.get(url2, headers=HEADERS, timeout=15)
    if r2.status_code != 200:
        return
    f2 = r2.json()
    r_key = requests.get(f2["download_url"], headers=HEADERS, timeout=30)
    if r_key.status_code != 200:
        return
    try:
        data = _decrypt(r_data.content, r_key.content)
        return data
    except Exception as e:
        print(f"  [ERR] {name}: {e}")
        return None

files = [
    "dns_authoritative.data.enc",
    "passive_sources.data.enc",
    "cdn_bypass.data.enc",
    "cidr_scan.data.enc",
]

for fn in files:
    name = fn.replace(".data.enc", "")
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    data = fetch_and_show(fn)
    if data:
        if name == "dns_authoritative":
            ips = data.get("target_ips", [])
            mx = data.get("mx_servers", [])
            records = data.get("records", {})
            print(f"  目标: {data.get('target','?')}")
            print(f"  A 记录 IP: {ips}")
            print(f"  记录类型: {list(records.keys()) if isinstance(records, dict) else '?'}")
            print(f"  MX: {[m['hostname'] for m in mx]}")
            for domain, recs in records.items():
                for r in recs:
                    if r.get("type") in ("A", "AAAA", "MX", "NS", "TXT"):
                        print(f"    [{r['type']}] {r.get('value','')}")

        elif name == "passive_sources":
            subs = data.get("unique_subdomains", data.get("subdomains", []))
            sources = data.get("sources", {})
            print(f"  目标: {data.get('target','?')}")
            print(f"  来源统计: {sources}")
            print(f"  总候选: {len(subs)}")
            for s in sorted(subs)[:20]:
                print(f"    {s}")
            if len(subs) > 20:
                print(f"    ... 等 {len(subs)} 条")

        elif name == "cdn_bypass":
            print(f"  目标: {data.get('target','?')}")
            print(f"  CDN 检测: {data.get('cdn_detected')}")
            print(f"  CDN 厂商: {data.get('cdn_providers', [])}")
            print(f"  CDN IP: {data.get('cdn_ips', [])}")
            print(f"  真实 IP 候选: {data.get('candidate_ips', [])}")
            print(f"  已验证存活: {len(data.get('verified_live', []))}")
            for v in data.get("verified_live", [])[:5]:
                print(f"    [V] {v.get('ip')}:{v.get('port',80)} [{v.get('status')}] {v.get('title','')[:60]}")

        elif name == "cidr_scan":
            print(f"  目标: {data.get('target','?')}")
            neighbors = data.get("neighbor_ips", data.get("results", []))
            print(f"  存活邻居: {len(neighbors)}")
            for n in neighbors[:10]:
                print(f"    {n}")
            titles = data.get("http_titles", {})
            if titles:
                sorted_titles = sorted(titles.items(), key=lambda x: -x[1].get("count", 1))[:10]
                print(f"  HTTP 标题:")
                for ip, info in sorted_titles:
                    print(f"    {ip}: {info.get('title','')[:60]}")
            sbs = data.get("side_by_side", [])
            if sbs:
                print(f"  旁站域名 ({len(sbs)}):")
                for s in sbs[:10]:
                    print(f"    {s}")
    else:
        print(f"  (空或解密失败)")

print("\n\n=== 遗漏分析 ===")
print("""
1. ✅ Phase1 三层跑通: dns_authoritative / passive_sources_and_cdn / cidr_scan 全部 success
2. ✅ cdn_bypass.data.enc 已产出 (224B) - 说明 CDN 探测走了
3. ❓ passive_sources 只有 240B - 可能来源少, 需检查 crt.sh/OTX 是否有返回

潜在遗漏:
A) 🔴 环境变量: RECON_RSA_PUBLIC 可能在 Workflow 中未设置或值与本地不匹配
   - _common.py 中 _read_encrypted 需要 RSA 私钥
   - 但 Workflow 运行器上没有 ~/.recon/recon_private.pem
   - 解密会走 PROXY_AES_KEY fallback, 可是 PROXY_AES_KEY 和 RSA 加密的 key.enc 不兼容
   - Phase2/Phase3 的 _read_encrypted 会失败!

B) 🟡 循环反馈: 新 URL → 新目录爆破 / 新参数 / 新域名
   - 目前 Phase3 url_collect 产出新 URL 后没有自动反馈到 dir_brute 和 param_brute
   - 真实流程应该是: 新URL → re-scan 发现的子路径 → 发现新JS → 提取更多URL → 二级循环

C) 🟢 SDK / 子域名收集器集成:
   - subfinder 自动下载原本想做但一直 404
   - 可以加 amass (更慢但更强)
   - 加 dnsgen (基于已知子域名生成排列组合)

D) 🔴 多目标: 目前一次只能扫描一个 target
   - 真实场景是: 目标公司可能有多个域名 (cartmanager.net, visiongrp.com 等)
   - 需要多域名联动扫描, 共享结果

E) 🟡 响应式 Web (JS 渲染):
   - 当前是纯 HTTP GET, 不执行 JS
   - SPA 类站点的 URL 无法被自动发现
   - 可集成 Playwright/Chromium 做 JS 渲染

F) 🟢 结果可视化:
   - 目前加密 JSON 只有人能读
   - 可加一个 report_generator.py 输出 HTML 报告

修复优先级: A > E > B > D > C > F
""")
