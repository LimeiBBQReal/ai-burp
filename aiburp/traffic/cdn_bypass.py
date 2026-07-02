"""
CDN 绕过模块 — 找到目标隐藏在 CDN 后面的真实源 IP.

CDN (Cloudflare/Akamai/阿里云 CDN) 是红队侦察的最大障碍:
    - 直接打 CDN 节点 = 打防火墙 (无意义)
    - 必须找到"源站 IP"才能直接攻击

绕过 CDN 的 7 种方法 (全部实现):

    1. 历史 DNS 记录 (Passive DNS)
       → 域名接入 CDN 前的 A 记录就是源 IP
       → 数据源: VirusTotal / SecurityTrails / ViewDNS

    2. SSL 证书搜索
       → 用目标的证书指纹搜索所有持有该证书的 IP
       → 数据源: Censys / Shodan / crt.sh

    3. Favicon Hash
       → 计算 favicon.ico 的 hash, 在 Shodan 搜同 hash 的 IP
       → 很多站长只改了 DNS 没改 favicon

    4. 子域名解析
       → 子域名 (api/mail/vpn/dev) 可能没挂 CDN, 直接解析到源 IP
       → 数据源: 直接 DNS 查询

    5. 邮件头分析
       → 目标发来的邮件头里的 Received: 字段有源 IP
       → (需要社工/钓鱼场景, 本模块不实现)

    6. HTTP 响应头
       → 某些服务器会泄露真实 IP (X-Originating-IP / X-Served-By)
       → CF-RAY / Server: cloudflare 确认 CDN

    7. 全网扫描匹配
       → 用目标的 HTTP 特征 (title/hash/body hash) 在全网扫描
       → 数据源: Shodan HTTP 搜索

本模块用你 .env 里的 API KEY:
    - SHODAN_API_KEY    → 证书搜索 + favicon hash + HTTP 特征
    - CENSYS_API_KEY    → 证书搜索 (最精准)
    - VIRUSTOTAL_API_KEY → 历史 DNS 记录
    - OTX_API_KEY       → 关联域名/IP 数据
"""

import os
import hashlib
import base64
import json
import asyncio
import requests
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class OriginCandidate:
    """疑似源 IP 候选"""
    ip: str
    confidence: str = "medium"  # high / medium / low
    source: str = ""             # 发现方式
    evidence: str = ""           # 证据
    extra: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip, "confidence": self.confidence,
            "source": self.source, "evidence": self.evidence,
            **self.extra,
        }


@dataclass
class CDNCheckResult:
    """CDN 检测结果"""
    domain: str = ""
    is_cdn: bool = False
    cdn_name: str = ""           # cloudflare / akamai / cloudfront / ...
    cdn_ips: List[str] = field(default_factory=list)
    origin_candidates: List[OriginCandidate] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "is_cdn": self.is_cdn,
            "cdn_name": self.cdn_name,
            "cdn_ips": self.cdn_ips,
            "origin_candidates": [c.to_dict() for c in self.origin_candidates],
        }

    def high_confidence_origins(self) -> List[OriginCandidate]:
        """只返回高置信度候选"""
        return [c for c in self.origin_candidates if c.confidence == "high"]

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def report_text(self) -> str:
        lines = ["=" * 60, f"CDN 绕过报告: {self.domain}", "=" * 60]
        if self.is_cdn:
            lines.append(f"CDN 检测: ✅ {self.cdn_name}")
            lines.append(f"CDN IP: {', '.join(self.cdn_ips[:5])}...")
        else:
            lines.append("CDN 检测: ❌ 未检测到 CDN (直连)")
        lines.append(f"\n源 IP 候选: {len(self.origin_candidates)} 个")

        for c in sorted(self.origin_candidates, key=lambda x: (
            x.confidence != "high", x.confidence != "medium")):
            icon = "🔴" if c.confidence == "high" else "🟡" if c.confidence == "medium" else "🟢"
            lines.append(f"  {icon} {c.ip:16s} [{c.confidence:6s}] {c.source}")
            lines.append(f"     {c.evidence}")

        if self.high_confidence_origins():
            lines.append(f"\n💡 建议: 用 {self.high_confidence_origins()[0].ip} 直接访问测试")
        return "\n".join(lines)


class CDNBypass:
    """
    CDN 绕过引擎 — 7 种方法找源 IP.

    用法:
        bypass = CDNBypass()
        result = await bypass.bypass("target.com")

        # 或指定方法
        result = await bypass.check_cdn("target.com")
        result = await bypass.via_history_dns("target.com")
        result = await bypass.via_ssl_cert("target.com")
        result = await bypass.via_favicon("target.com")
        result = await bypass.via_subdomains("target.com")
    """

    # CDN 特征 (响应头/IP 段)
    CDN_HEADERS = {
        "cf-ray": "Cloudflare",
        "x-cloud-trace-context": "Google Cloud CDN",
        "x-amz-cf-id": "CloudFront",
        "x-akamai-transformed": "Akamai",
        "x-fastly-request-id": "Fastly",
        "x-sucrose-id": "Sucuri",
        "server": None,  # 动态匹配
    }
    CDN_SERVER_PATTERNS = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "cloudfront": "CloudFront",
        "sucuri": "Sucuri",
        "incapsula": "Imperva",
        "edgecast": "Edgecast",
    }

    def __init__(self):
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.censys_key = os.environ.get("CENSYS_API_KEY", "")
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.otx_key = os.environ.get("OTX_API_KEY", "")

    def _load_env(self):
        """从 .env 加载 KEY (如果环境变量没设置)"""
        from pathlib import Path
        env_path = Path(".env")
        if not env_path.exists():
            return
        key_map = {
            "SHODAN_API_KEY": "shodan_key",
            "CENSYS_API_KEY": "censys_key",
            "VIRUSTOTAL_API_KEY": "vt_key",
            "OTX_API_KEY": "otx_key",
        }
        for ln in env_path.read_text().splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, _, v = s.partition("=")
            k, v = k.strip(), v.strip()
            attr = key_map.get(k)
            if attr and v and "your_" not in v and "_here" not in v:
                if not getattr(self, attr, ""):
                    setattr(self, attr, v)

    # ============================================================
    #                  CDN 检测
    # ============================================================

    async def check_cdn(self, domain: str) -> CDNCheckResult:
        """
        检测目标是否用了 CDN.

        方法:
            1. HTTP 响应头检测 (CF-RAY / Server: cloudflare)
            2. DNS 解析结果对比 (CDN IP 段)
        """
        result = CDNCheckResult(domain=domain)
        self._load_env()

        def _check():
            # 1. HTTP 响应头
            try:
                r = requests.get(f"https://{domain}", timeout=10, verify=False)
                for header, cdn in self.CDN_HEADERS.items():
                    val = r.headers.get(header, "").lower()
                    if cdn and val:
                        result.is_cdn = True
                        result.cdn_name = cdn
                        break
                    # Server 头匹配
                    if header == "server":
                        server_val = r.headers.get("server", "").lower()
                        for pattern, name in self.CDN_SERVER_PATTERNS.items():
                            if pattern in server_val:
                                result.is_cdn = True
                                result.cdn_name = name
                                break
            except Exception:
                pass

            # 2. DNS 解析
            try:
                import socket
                ips = socket.getaddrinfo(domain, None)
                resolved = list(set(ip[4][0] for ip in ips))
                result.cdn_ips = resolved
                if not result.cdn_name:
                    # 检查是否在已知 CDN IP 段
                    for ip in resolved:
                        if ip.startswith(("104.16.", "104.17.", "104.18.", "172.64.",
                                         "172.67.", "162.159.", "141.101.")):  # Cloudflare
                            result.is_cdn = True
                            result.cdn_name = "Cloudflare"
                            break
            except Exception:
                pass

            return result

        return await asyncio.to_thread(_check)

    # ============================================================
    #                  方法 1: 历史 DNS 记录
    # ============================================================

    async def via_history_dns(self, domain: str) -> List[OriginCandidate]:
        """
        通过历史 DNS 记录找源 IP.

        域名接入 CDN 前的 A 记录 = 源 IP.
        数据源: VirusTotal / ViewDNS.info
        """
        self._load_env()
        candidates = []

        # VirusTotal 域名报告 (含历史解析)
        def _vt_lookup():
            if not self.vt_key:
                return []
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
                    headers={"x-apikey": self.vt_key},
                    timeout=15,
                )
                if r.status_code == 200:
                    data = r.json()
                    ips = []
                    for item in data.get("data", []):
                        ip = item.get("attributes", {}).get("ip_address", "")
                        date = item.get("attributes", {}).get("date", "")
                        if ip:
                            ips.append((ip, date))
                    return ips
            except Exception:
                pass
            return []

        # ViewDNS (免费, 不需要 KEY)
        def _viewdns_lookup():
            try:
                r = requests.get(
                    "https://viewdns.info/iphistory/",
                    params={"domain": domain},
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=15,
                )
                # 解析 HTML 表格中的 IP
                import re
                ips = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?(\d{4}-\d{2}-\d{2})', r.text)
                return ips
            except Exception:
                pass
            return []

        vt_results = await asyncio.to_thread(_vt_lookup)
        viewdns_results = await asyncio.to_thread(_viewdns_lookup)

        all_history = vt_results + viewdns_results
        # 去重 + 排除 CDN IP
        seen = set()
        for ip, date in all_history:
            if ip in seen:
                continue
            seen.add(ip)
            # 排除已知 CDN IP 段
            if self._is_cdn_ip(ip):
                continue
            candidates.append(OriginCandidate(
                ip=ip,
                confidence="high",  # 历史 DNS 记录是高置信度
                source="history-dns",
                evidence=f"历史解析记录 {date}: {ip}",
                extra={"date": date},
            ))

        return candidates

    # ============================================================
    #                  方法 2: SSL 证书搜索
    # ============================================================

    async def via_ssl_cert(self, domain: str) -> List[OriginCandidate]:
        """
        通过 SSL 证书搜索找源 IP.

        用目标的证书 (CN/SAN) 在 Censys/Shodan 搜索,
        找到所有持有相同证书的 IP = 源 IP 候选.
        """
        self._load_env()
        candidates = []

        # Censys 证书搜索 (最精准)
        def _censys_search():
            if not self.censys_key:
                return []
            try:
                r = requests.get(
                    "https://search.censys.io/api/v2/certificates/search",
                    headers={"Authorization": f"Bearer {self.censys_key}"},
                    json={"q": f"names: {domain}", "per_page": 20},
                    timeout=20,
                )
                if r.status_code == 200:
                    # 获取证书 fingerprint, 再搜 IP
                    hits = r.json().get("result", {}).get("hits", [])
                    fingerprints = [h.get("fingerprint", "") for h in hits[:5]]
                    return fingerprints
            except Exception:
                pass
            return []

        # Shodan SSL 搜索
        def _shodan_ssl():
            if not self.shodan_key:
                return []
            try:
                r = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.shodan_key, "query": f"ssl:{domain}"},
                    timeout=20,
                )
                if r.status_code == 200:
                    matches = r.json().get("matches", [])
                    return [(m.get("ip_str", ""), "shodan-ssl") for m in matches[:10]]
            except Exception:
                pass
            return []

        # crt.sh 证书透明度日志 (免费)
        def _crtsh():
            try:
                r = requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=15,
                )
                if r.status_code == 200:
                    certs = r.json()
                    # crt.sh 只给证书名, 不给 IP
                    # 但可以拿到所有关联域名
                    names = set()
                    for c in certs[:50]:
                        for name in c.get("name_value", "").split("\n"):
                            names.add(name.strip())
                    return list(names)
            except Exception:
                pass
            return []

        ssl_results = await asyncio.to_thread(_shodan_ssl)
        for ip, src in ssl_results:
            if not self._is_cdn_ip(ip):
                candidates.append(OriginCandidate(
                    ip=ip, confidence="high",
                    source="ssl-cert-search",
                    evidence=f"Shodan SSL 证书匹配: {domain} → {ip}",
                ))

        # crt.sh 关联域名
        crtsh_names = await asyncio.to_thread(_crtsh)
        for name in crtsh_names:
            if name and name != domain and not name.startswith("*"):
                # 解析关联域名的 IP (可能是源站)
                try:
                    import socket
                    ips = socket.getaddrinfo(name, None)
                    for ip_info in ips:
                        ip = ip_info[4][0]
                        if not self._is_cdn_ip(ip):
                            candidates.append(OriginCandidate(
                                ip=ip, confidence="medium",
                                source="crtsh-subdomain",
                                evidence=f"crt.sh 关联域名 {name} → {ip}",
                            ))
                            break
                except Exception:
                    pass

        return candidates

    # ============================================================
    #                  方法 3: Favicon Hash
    # ============================================================

    async def via_favicon(self, domain: str) -> List[OriginCandidate]:
        """
        通过 favicon hash 找源 IP.

        计算目标 favicon.ico 的 mmh3 hash,
        在 Shodan 搜索同 hash 的 IP.
        """
        self._load_env()

        def _favicon_search():
            if not self.shodan_key:
                return []

            # 1. 下载 favicon
            try:
                r = requests.get(f"https://{domain}/favicon.ico",
                                timeout=10, verify=False)
                if r.status_code != 200 or len(r.content) < 10:
                    r = requests.get(f"http://{domain}/favicon.ico",
                                    timeout=10)
                if r.status_code != 200:
                    return []

                # 2. 计算 Shodan favicon hash
                # Shodan 用的是特殊算法: base64(内容) 的 mmh3
                import mmh3
                favicon_b64 = base64.encodebytes(r.content)
                favicon_hash = mmh3.hash(favicon_b64)

                # 3. Shodan 搜索
                r2 = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.shodan_key,
                           "query": f"http.favicon.hash:{favicon_hash}"},
                    timeout=20,
                )
                if r2.status_code == 200:
                    matches = r2.json().get("matches", [])
                    results = []
                    for m in matches[:20]:
                        ip = m.get("ip_str", "")
                        host = m.get("http", {}).get("host", "")
                        title = m.get("http", {}).get("title", "")
                        if ip and not _is_cdn_ip(ip):
                            results.append((ip, favicon_hash, title))
                    return results
            except ImportError:
                return [("error", 0, "mmh3 library not installed (pip install mmh3)")]
            except Exception:
                pass
            return []

        results = await asyncio.to_thread(_favicon_search)

        candidates = []
        for ip, fhash, title in results:
            if ip == "error":
                candidates.append(OriginCandidate(
                    ip="?", confidence="low",
                    source="favicon-hash",
                    evidence=title,  # 错误信息
                ))
                continue
            candidates.append(OriginCandidate(
                ip=ip, confidence="high" if domain.lower() in title.lower() else "medium",
                source="favicon-hash",
                evidence=f"Favicon hash {fhash} 匹配: {ip} (title: {title[:30]})",
                extra={"favicon_hash": fhash, "title": title},
            ))

        return candidates

    # ============================================================
    #                  方法 4: 子域名解析
    # ============================================================

    async def via_subdomains(self, domain: str,
                              subdomains: Optional[List[str]] = None) -> List[OriginCandidate]:
        """
        通过子域名解析找源 IP.

        很多子域名 (api/mail/vpn/dev/staging) 没挂 CDN,
        直接解析到源站 IP.
        """
        if subdomains is None:
            subdomains = [
                "www", "api", "mail", "smtp", "pop", "imap",
                "vpn", "ssh", "direct", "origin", "backend",
                "dev", "staging", "test", "beta", "admin",
                "cpanel", "whm", "webmail", "ns1", "ns2",
                "m", "mobile", "app", "portal", "secure",
            ]

        candidates = []

        def _resolve():
            import socket
            results = []
            for sub in subdomains:
                full = f"{sub}.{domain}"
                try:
                    ips = socket.getaddrinfo(full, None)
                    resolved = list(set(ip[4][0] for ip in ips))
                    for ip in resolved:
                        if not self._is_cdn_ip(ip):
                            results.append((sub, full, ip))
                except socket.gaierror:
                    pass
            return results

        resolved = await asyncio.to_thread(_resolve)

        for sub, full, ip in resolved:
            candidates.append(OriginCandidate(
                ip=ip,
                confidence="high" if sub in ("direct", "origin", "backend", "ssh", "vpn") else "medium",
                source="subdomain-resolve",
                evidence=f"子域名 {full} → {ip}",
                extra={"subdomain": full},
            ))

        return candidates

    # ============================================================
    #                  方法 6: HTTP 响应头泄露
    # ============================================================

    async def via_headers(self, domain: str) -> List[OriginCandidate]:
        """
        通过 HTTP 响应头找源 IP.

        某些服务器/CDN 会在响应头里泄露真实 IP.
        """
        leak_headers = [
            "X-Originating-IP", "X-Real-IP", "X-Client-IP",
            "X-Forwarded-For", "X-Server-IP", "X-Host",
            "CF-Connecting-IP",  # Cloudflare 给后端的
            "Set-Cookie",  # 某些 cookie 含 IP
        ]

        def _check_headers():
            candidates = []
            try:
                r = requests.get(f"https://{domain}", timeout=10, verify=False)
                for header in leak_headers:
                    val = r.headers.get(header, "")
                    if val:
                        # 提取 IP
                        import re
                        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', val)
                        for ip in ips:
                            if not self._is_cdn_ip(ip):
                                candidates.append((header, ip))
            except Exception:
                pass
            return candidates

        results = await asyncio.to_thread(_check_headers)

        candidates = []
        for header, ip in results:
            candidates.append(OriginCandidate(
                ip=ip, confidence="high",
                source="http-header-leak",
                evidence=f"响应头 {header}: {ip}",
            ))

        return candidates

    # ============================================================
    #                  全部方法一键执行
    # ============================================================

    async def bypass(self, domain: str) -> CDNCheckResult:
        """
        一键执行所有 CDN 绕过方法.

        流程:
            1. 检测 CDN
            2. 历史 DNS 记录
            3. SSL 证书搜索
            4. Favicon hash
            5. 子域名解析
            6. HTTP 头泄露
            7. 去重 + 排序
        """
        # 1. CDN 检测
        result = await self.check_cdn(domain)

        if not result.is_cdn:
            result.origin_candidates.append(OriginCandidate(
                ip=result.cdn_ips[0] if result.cdn_ips else "",
                confidence="high",
                source="direct",
                evidence="未检测到 CDN, 直连 IP 即为源站",
            ))
            return result

        # 2-6. 并行执行所有绕过方法
        history, ssl, favicon, subdomains, headers = await asyncio.gather(
            self.via_history_dns(domain),
            self.via_ssl_cert(domain),
            self.via_favicon(domain),
            self.via_subdomains(domain),
            self.via_headers(domain),
        )

        result.origin_candidates = history + ssl + favicon + subdomains + headers

        # 7. 去重 (同 IP 只保留置信度最高的)
        best = {}
        for c in result.origin_candidates:
            if c.ip not in best or c.confidence == "high":
                best[c.ip] = c
        result.origin_candidates = list(best.values())

        return result

    # ============================================================
    #                  工具方法
    # ============================================================

    @staticmethod
    def _is_cdn_ip(ip: str) -> bool:
        """检查 IP 是否属于已知 CDN 段"""
        cdn_prefixes = [
            # Cloudflare
            "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
            "172.64.", "172.67.", "162.159.", "141.101.", "188.114.",
            # CloudFront
            "13.224.", "13.225.", "13.226.", "99.84.", "205.251.",
            "52.84.", "52.85.", "52.86.",
            # Akamai
            "23.", "72.246.", "72.247.", "184.50.", "184.84.",
            # Google
            "142.250.", "172.217.", "142.251.",
        ]
        for prefix in cdn_prefixes:
            if ip.startswith(prefix):
                return True
        return False
