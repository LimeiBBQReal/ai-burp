"""全量增强版子域名枚举 — DNS 字典爆破 + crt.sh + subfinder (16+ 数据源).

功能 (3 层):
  1. DNS 字典爆破 (up to 10000+ 字典)
  2. crt.sh 证书透明度查询
  3. subfinder (ProjectDiscovery) — 自动下载, 聚合 16+ 数据源

输出 (双层加密):
  out/subdomains.data.enc + out/subdomains.key.enc
"""
from typing import Any

import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver

from _common import get_target, write_encrypted, http_get

SUBFINDER_BIN = Path(__file__).resolve().parent / "subfinder"
# 使用特定版本而非 latest,避免 GitHub 重定向问题
SUBFINDER_VERSION = "v2.6.7"
SUBFINDER_URL = (
    f"https://github.com/projectdiscovery/subfinder/releases/download/"
    f"{SUBFINDER_VERSION}/subfinder_{SUBFINDER_VERSION[1:]}_windows_amd64.zip"
)


def _install_subfinder() -> bool:
    """如果 subfinder 不存在则自动下载."""
    bin_path = SUBFINDER_BIN
    if bin_path.exists():
        return True

    # Windows 上尝试 .exe 后缀
    if sys.platform == "win32":
        exe_path = bin_path.with_suffix(".exe")
        if exe_path.exists():
            # 创建符号链接或复制为无后缀名称
            try:
                exe_path.link_to(bin_path) if hasattr(exe_path, "link_to") else exe_path.rename(bin_path)
            except Exception:
                pass
            return bin_path.exists()

    print(f"  [subfinder] 未找到, 自动下载 {SUBFINDER_VERSION}...", file=sys.stderr)
    import urllib.request
    import zipfile

    zip_path = bin_path.parent / "subfinder_tmp.zip"
    try:
        # 设置 User-Agent 避免 GitHub 403
        req = urllib.request.Request(SUBFINDER_URL, headers={
            "User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"
        })
        urllib.request.urlretrieve(req, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                # 查找 subfinder 可执行文件 (可能是 .exe)
                base = name.lower().split("/")[-1]
                if base.startswith("subfinder") and not base.endswith("/"):
                    data = zf.read(name)
                    # 写入无后缀名称
                    bin_path.write_bytes(data)
                    if sys.platform != "win32":
                        bin_path.chmod(0o755)
                    break
        zip_path.unlink(missing_ok=True)
        if not bin_path.exists() and sys.platform == "win32":
            # Windows 上尝试 .exe
            exe_path = bin_path.with_suffix(".exe")
            if exe_path.exists():
                return True
        return bin_path.exists()
    except Exception as e:
        print(f"  [WARN] subfinder 下载失败: {e}", file=sys.stderr)
        if zip_path.exists():
            zip_path.unlink(missing_ok=True)
        return False


def _resolve_subdomain(sub: str, domain: str) -> str | None:
    fqdn = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
        if answers:
            return str(answers[0].to_text())
    except Exception:
        return None
    return None


def _brute_dict(domain: str, wordlist: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}

    def probe(sub: str) -> tuple[str, str | None]:
        ip = _resolve_subdomain(sub, domain)
        return ip

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs_map: dict[Any, str] = {}
        for sub in wordlist:
            futs_map[ex.submit(probe, sub)] = sub
        for fut in as_completed(futs_map):
            ip = fut.result()
            sub = futs_map[fut]
            if ip:
                found[f"{sub}.{domain}"] = ip
    return found


def _load_l2_wordlist() -> list[str]:
    """加载 L2 专用字典."""
    l2_path = Path(__file__).resolve().parent / "wordlists" / "subdomains_l2.txt"
    if l2_path.exists():
        with open(l2_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []


def _brute_l2_subdomains(domain: str, l1_subs: list[str], wordlist: list[str],
                         max_l1: int = 20) -> dict[str, str]:
    """三级子域名爆破 — 基于已发现的 L1 子域名.

    例如: api.www.cartmanager.net (www 是 L1, api 是 L2 前缀)

    Args:
        domain: 根域名 (cartmanager.net)
        l1_subs: 已发现的 L1 子域名列表 (如 ["www", "api", "mail"])
        wordlist: L2 前缀字典
        max_l1: 最多使用多少个 L1 子域名作为种子 (避免请求量爆炸)

    Returns:
        {完整域名: IP} 字典
    """
    if not l1_subs or not wordlist:
        return {}

    # 选择最有希望的 L1 种子 (优先选择可能有多级子域名的)
    # 排除明显的 CDN/泛解析 IP,优先选择独特 IP 对应的子域名
    priority_keywords = {"api", "app", "admin", "dev", "test", "staging",
                         "internal", "intranet", "portal", "console", "manage",
                         "ops", "git", "jenkins", "ci", "cdn", "static",
                         "img", "image", "media", "video", "upload", "file",
                         "docs", "wiki", "help", "support", "blog", "forum",
                         "shop", "store", "pay", "order", "cart", "user",
                         "account", "auth", "sso", "oauth", "api1", "api2"}

    # 按优先级排序 L1 子域名
    def l1_priority(sub: str) -> int:
        if sub in priority_keywords:
            return 0  # 最高优先级
        if len(sub) <= 4:
            return 1  # 短名称更可能有子级
        return 2

    sorted_l1 = sorted(l1_subs, key=l1_priority)[:max_l1]

    found: dict[str, str] = {}
    total_probes = len(sorted_l1) * len(wordlist)
    print(f"  [L2爆破] 种子: {len(sorted_l1)} 个 L1, 字典: {len(wordlist)}, "
          f"总探测: {total_probes}", file=sys.stderr)

    def probe_l2(prefix: str, l1_sub: str) -> tuple[str, str | None]:
        fqdn = f"{prefix}.{l1_sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
            if answers:
                return fqdn, str(answers[0].to_text())
        except Exception:
            pass
        return fqdn, None

    # 加载 L2 专用字典 (如果存在)
    l2_wordlist = _load_l2_wordlist()
    if l2_wordlist:
        # 使用 L2 专用字典,限制数量以控制请求量
        effective_wordlist = l2_wordlist[:500]
        print(f"  [L2爆破] 使用 L2 专用字典: {len(effective_wordlist)} 个前缀", file=sys.stderr)
    else:
        # 回退到通用字典
        effective_wordlist = wordlist[:200]
        print(f"  [L2爆破] 使用通用字典: {len(effective_wordlist)} 个前缀", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs_map: dict[Any, tuple[str, str]] = {}
        for l1_sub in sorted_l1:
            for prefix in effective_wordlist:
                futs_map[ex.submit(probe_l2, prefix, l1_sub)] = (prefix, l1_sub)

        for fut in as_completed(futs_map):
            fqdn, ip = fut.result()
            if ip:
                found[fqdn] = ip

    return found


def _crt_sh(domain: str) -> list[str]:
    """crt.sh 证书透明度查询,带重试和速率限制."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    # crt.sh 速率限制: 每分钟 50 次,需要重试
    for attempt in range(3):
        r = http_get(url, timeout=20)
        if r and r.status_code == 200:
            try:
                subs = set()
                for item in r.json():
                    name = item.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            subs.add(sub)
                return sorted(subs)
            except Exception as e:
                print(f"  [WARN] crt.sh JSON 解析失败: {e}", file=sys.stderr)
                return []
        elif r and r.status_code == 429:
            # 速率限制,等待后重试
            wait = 10 * (attempt + 1)
            print(f"  [crt.sh] 速率限制 (429), 等待 {wait}s...", file=sys.stderr)
            time.sleep(wait)
        elif r and r.status_code == 503:
            # 服务不可用,等待后重试
            wait = 5 * (attempt + 1)
            print(f"  [crt.sh] 服务不可用 (503), 等待 {wait}s...", file=sys.stderr)
            time.sleep(wait)
        else:
            # 其他错误,不重试
            return []
    return []


def _resolve_many(domains: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}

    def resolve(domain: str) -> tuple[str, str | None]:
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=3)
            if answers:
                return domain, str(answers[0].to_text())
        except Exception:
            pass
        return domain, None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(resolve, d): d for d in domains}
        for fut in as_completed(futs):
            dom, ip = fut.result()
            if ip:
                found[dom] = ip
    return found


def _run_subfinder(domain: str) -> list[str]:
    """调用 subfinder 采集子域名."""
    if not _install_subfinder():
        return []

    # Windows 上尝试 .exe
    bin_path = SUBFINDER_BIN
    if sys.platform == "win32" and not bin_path.exists():
        bin_path = bin_path.with_suffix(".exe")

    cmd = [str(bin_path), "-d", domain, "-silent"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            subs = [line.strip().lower() for line in r.stdout.splitlines() if line.strip()]
            return sorted(set(subs))
        # subfinder 可能因网络问题失败,静默忽略
    except subprocess.TimeoutExpired:
        pass  # 超时静默忽略
    except FileNotFoundError:
        pass  # 不存在静默忽略
    except Exception:
        pass  # 其他错误静默忽略
    return []


def main() -> int:
    target = get_target()
    print(f"[subdomain] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 1. 加载字典
    from _common import load_wordlist
    small_list = load_wordlist("subdomains")
    large_list = load_wordlist("subdomains_large")

    if large_list:
        wordlist = large_list
        print(f"[+] 使用大字典: {len(large_list)} 条", file=sys.stderr)
    else:
        wordlist = small_list
        print(f"[+] 使用小字典: {len(small_list)} 条", file=sys.stderr)

    # 2. DNS 字典爆破
    print(f"[subdomain] DNS 字典爆破 ({len(wordlist)})...", file=sys.stderr)
    dns_found = _brute_dict(target, wordlist)
    print(f"  → {len(dns_found)} 命中", file=sys.stderr)

    # 3. crt.sh 查询
    print("[subdomain] crt.sh 查询...", file=sys.stderr)
    crt_subs = _crt_sh(target)
    print(f"  → {len(crt_subs)} 子域名", file=sys.stderr)

    crt_resolved = _resolve_many(crt_subs)
    print(f"  → 可解析 {len(crt_resolved)}", file=sys.stderr)

    all_subs: dict[str, str] = {**dns_found, **crt_resolved}

    # 4. subfinder
    sf_subs = _run_subfinder(target)
    if sf_subs:
        print(f"[subdomain] subfinder: {len(sf_subs)} 子域名", file=sys.stderr)
        sf_resolved = _resolve_many(sf_subs)
        all_subs.update({s: sf_resolved.get(s, "") for s in sf_subs})

    # 5. 三级子域名爆破 (基于 L1 种子)
    # 从已发现的 L1 子域名中提取前缀作为种子
    l2_found: dict[str, str] = {}
    l1_seeds = set()
    l1_ips: set[str] = set()
    for fqdn, ip in all_subs.items():
        parts = fqdn.split(".")
        if len(parts) == len(target.split(".")) + 1:
            l1_seeds.add(parts[0])
            if ip:
                l1_ips.add(ip)

    # 检查 L1 IP 是否全为 TEST-NET (RFC 5737 保留地址)
    testnet_prefixes = ("198.18.", "198.51.", "203.0.", "192.0.")
    all_testnet = l1_ips and all(
        any(ip.startswith(p) for p in testnet_prefixes) for ip in l1_ips
    )

    if all_testnet:
        print(f"\n[subdomain] ⚠️ 所有 L1 IP 均为 TEST-NET, 跳过 L2 爆破", file=sys.stderr)
        print(f"  [subdomain] 原因: 目标处于保留地址空间,深层子域名无意义", file=sys.stderr)
    elif l1_seeds:
        print(f"\n[subdomain] 三级子域名爆破 (L1 种子: {len(l1_seeds)})...", file=sys.stderr)
        l2_found = _brute_l2_subdomains(target, list(l1_seeds), small_list or wordlist)
        print(f"  → L2 命中: {len(l2_found)}", file=sys.stderr)
        all_subs.update(l2_found)

    elapsed = time.time() - t0
    print(f"\n[subdomain] 总计: {len(all_subs)} 子域名, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("subdomains", {
        "target": target,
        "total": len(all_subs),
        "dns_brute_found": len(dns_found),
        "crtsh_found": len(crt_subs),
        "subfinder_found": len(sf_subs) if sf_subs else 0,
        "l2_brute_found": len(l2_found) if l1_seeds else 0,
        "unique_subdomains": sorted(all_subs.keys()),
        "resolved": {k: v for k, v in all_subs.items() if v},
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())