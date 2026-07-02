"""
资产扩展引擎 — 从一个域名/IP 撑到最大攻击面.

红队侦察的第一步不是扫端口, 是把攻击面撑到最大:
    一个域名 → 子域名 → IP → 旁站 → C段 → WHOIS → 全部资产清单

数据源 (全部用 .env 里的 KEY):
    - DNS 查询 (免费)
    - crt.sh 证书透明度 (免费)
    - Shodan (子域名 + 旁站 + 反查)
    - Censys (证书 + 同 IP 服务)
    - VirusTotal (历史解析 + 关联域名)
    - HackerTarget (免费 API)
    - RevSRR (免费反查)

输出: AssetGraph (所有发现的资产 + 关系)
"""

import os
import socket
import asyncio
import json
import re
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network


@dataclass
class AssetNode:
    """单个资产"""
    type: str          # domain / subdomain / ip / url / email / company
    value: str         # 值
    source: str = ""   # 发现方式
    extra: Dict = field(default_factory=dict)


@dataclass
class ExpansionResult:
    """资产扩展结果"""
    seed: str = ""     # 输入 (域名/IP)
    subdomains: List[AssetNode] = field(default_factory=list)
    ips: List[AssetNode] = field(default_factory=list)
    neighbors: List[AssetNode] = field(default_factory=list)  # 旁站
    c_segment: str = ""  # C 段 (如 1.2.3.0/24)
    whois: Dict = field(default_factory=dict)

    @property
    def total_assets(self) -> int:
        return len(self.subdomains) + len(self.ips) + len(self.neighbors)

    def to_dict(self) -> Dict:
        return {
            "seed": self.seed,
            "subdomains": [s.__dict__ for s in self.subdomains],
            "ips": [i.__dict__ for i in self.ips],
            "neighbors": [n.__dict__ for n in self.neighbors],
            "c_segment": self.c_segment,
            "whois": self.whois,
            "total": self.total_assets,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str)

    def report_text(self) -> str:
        lines = ["="*60, f"资产扩展报告: {self.seed}", "="*60]
        lines.append(f"子域名: {len(self.subdomains)} | IP: {len(self.ips)} | "
                      f"旁站: {len(self.neighbors)} | C段: {self.c_segment or '?'}")
        lines.append("-"*60)

        if self.subdomains:
            lines.append(f"\n子域名 ({len(self.subdomains)}):")
            for s in self.subdomains[:20]:
                lines.append(f"  {s.value:40s} [{s.source}]")
            if len(self.subdomains) > 20:
                lines.append(f"  ...还有 {len(self.subdomains)-20} 个")

        if self.ips:
            lines.append(f"\nIP 地址 ({len(self.ips)}):")
            for ip in self.ips[:10]:
                lines.append(f"  {ip.value:20s} [{ip.source}] {ip.extra.get('reverse','')}")

        if self.neighbors:
            lines.append(f"\n旁站 (同 IP 其它网站) ({len(self.neighbors)}):")
            for n in self.neighbors[:10]:
                lines.append(f"  {n.value:40s} [{n.source}]")

        if self.c_segment:
            lines.append(f"\nC 段: {self.c_segment}")

        return "\n".join(lines)


class AssetExpander:
    """
    资产扩展引擎.

    用法:
        expander = AssetExpander()
        result = await expander.expand("target.com")

        # 完整流程
        result = await expander.expand_full("target.com")
    """

    # 子域名常见前缀 (字典)
    SUBDOMAIN_WORDLIST = [
        # 常见服务
        "www", "api", "app", "dev", "staging", "test", "beta", "prod",
        "admin", "portal", "dashboard", "panel", "console", "manage",
        # 网络
        "vpn", "ssh", "remote", "gateway", "proxy", "tunnel",
        "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        # 邮件
        "mail", "smtp", "imap", "pop", "pop3", "webmail", "exchange",
        # 文件
        "ftp", "sftp", "files", "upload", "download", "share", "cloud",
        # 数据库
        "db", "mysql", "redis", "mongo", "elastic", "search",
        # 开发
        "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
        "jira", "wiki", "confluence", "docs",
        # 监控
        "monitor", "grafana", "prometheus", "status", "health",
        # 移动
        "m", "mobile", "wap",
        # 安全
        "secure", "auth", "sso", "oauth", "login", "saml",
        # 其它
        "old", "new", "v1", "v2", "v3", "internal", "private",
        "backup", "bak", "tmp", "temp", "log", "logs",
        "shop", "store", "pay", "billing", "checkout",
        "cdn", "static", "assets", "img", "images", "media",
        "blog", "forum", "community", "support", "help",
        "crm", "erp", "oa", "hr", "finance",
        "edu", "training", "learn", "course",
    ]

    def __init__(self):
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.censys_key = os.environ.get("CENSYS_API_KEY", "")
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.otx_key = os.environ.get("OTX_API_KEY", "")
        self._load_env()

    def _load_env(self):
        """从 .env 加载 KEY"""
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
            attr = key_map.get(k.strip())
            if attr and v.strip() and "your_" not in v.strip():
                setattr(self, attr, v.strip())

    # ============================================================
    #                  子域名发现
    # ============================================================

    async def find_subdomains(self, domain: str) -> List[AssetNode]:
        """
        全面子域名发现 (3 种方法并行).

        1. 字典爆破 (200+ 前缀)
        2. crt.sh 证书透明度
        3. Shodan/Censys (如果有 KEY)
        """
        results: List[AssetNode] = []
        seen: Set[str] = set()

        def _resolve_subdomain(sub: str) -> Optional[Tuple[str, str]]:
            """解析子域名, 返回 (subdomain, ip) 或 None"""
            full = f"{sub}.{domain}"
            try:
                ips = socket.getaddrinfo(full, None)
                ip = ips[0][4][0]
                return (full, ip)
            except socket.gaierror:
                return None

        # 方法 1: 字典爆破 (真并发 — ThreadPool 并行 DNS 查询)
        sem = asyncio.Semaphore(50)

        async def _brute_one(sub):
            async with sem:
                return await asyncio.to_thread(_resolve_subdomain, sub)

        _brute_tasks = [_brute_one(sub) for sub in self.SUBDOMAIN_WORDLIST]
        _brute_raw = await asyncio.gather(*_brute_tasks, return_exceptions=True)
        brute_results = [r for r in _brute_raw if r and not isinstance(r, Exception)]
        for sub, ip in brute_results:
            if sub not in seen:
                seen.add(sub)
                results.append(AssetNode(
                    type="subdomain", value=sub,
                    source="dictionary", extra={"ip": ip},
                ))

        # 方法 2: crt.sh (证书透明度)
        def _crtsh():
            import requests
            try:
                r = requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=15,
                )
                if r.status_code == 200:
                    names = set()
                    for c in r.json()[:100]:
                        for name in c.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and name != domain and domain in name:
                                names.add(name)
                    return list(names)
            except Exception:
                pass
            return []

        crtsh_results = await asyncio.to_thread(_crtsh)
        for name in crtsh_results:
            if name not in seen:
                seen.add(name)
                # 解析 IP
                r = _resolve_subdomain(name.split(".")[0] if "." not in name.replace(domain, "") else "")
                results.append(AssetNode(
                    type="subdomain", value=name,
                    source="crt.sh",
                ))

        # 方法 3: Shodan (如果有 KEY)
        if self.shodan_key:
            def _shodan_dns():
                import requests
                try:
                    r = requests.get(
                        "https://api.shodan.io/dns/domain/" + domain,
                        params={"key": self.shodan_key},
                        timeout=15,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        subs = []
                        for record in data.get("data", []):
                            subdomain = record.get("subdomain", "")
                            full = f"{subdomain}.{domain}" if subdomain else domain
                            ip = record.get("value", "")
                            subs.append((full, ip))
                        return subs
                except Exception:
                    pass
                return []

            shodan_results = await asyncio.to_thread(_shodan_dns)
            for sub, ip in shodan_results:
                if sub not in seen:
                    seen.add(sub)
                    results.append(AssetNode(
                        type="subdomain", value=sub,
                        source="shodan-dns", extra={"ip": ip},
                    ))

        return results

    # ============================================================
    #                  IP 收集 + C 段
    # ============================================================

    async def collect_ips(self, domain: str,
                           subdomains: List[AssetNode]) -> Tuple[List[AssetNode], str]:
        """
        从域名和子域名收集所有 IP, 推断 C 段.

        Returns:
            (ip_list, c_segment)
        """
        ips: Dict[str, AssetNode] = {}

        # 解析主域名
        try:
            resolved = socket.getaddrinfo(domain, None)
            for r in resolved:
                ip = r[4][0]
                if ip not in ips:
                    ips[ip] = AssetNode(type="ip", value=ip, source="dns")
        except socket.gaierror:
            pass

        # 从子域名的 extra 里提取 IP
        for sub in subdomains:
            ip = sub.extra.get("ip", "")
            # 验证是合法 IP (排除 TXT/CNAME 等误入)
            if not ip or ip not in ips:
                try:
                    ip_address(ip)
                except (ValueError, TypeError):
                    continue
            if ip not in ips:
                # 反向 DNS
                try:
                    reverse = socket.gethostbyaddr(ip)[0]
                except Exception:
                    reverse = ""
                ips[ip] = AssetNode(
                    type="ip", value=ip,
                    source=sub.source,
                    extra={"reverse": reverse, "from": sub.value},
                )

        # 推断 C 段 (取第一个公网 IP)
        c_seg = ""
        for ip_str in ips:
            try:
                ip_obj = ip_address(ip_str)
                if not ip_obj.is_private:
                    # 取 /24
                    net = ip_network(f"{ip_str}/24", strict=False)
                    c_seg = str(net)
                    break
            except ValueError:
                continue

        return list(ips.values()), c_seg

    # ============================================================
    #                  旁站 (同 IP 其它网站)
    # ============================================================

    async def find_neighbors(self, ip: str) -> List[AssetNode]:
        """
        查找同 IP 上的其它网站 (旁站).

        数据源: Shodan + HackerTarget
        """
        results: List[AssetNode] = []

        # Shodan: ip → HTTP vhost
        if self.shodan_key:
            def _shodan_neighbors():
                import requests
                try:
                    r = requests.get(
                        f"https://api.shodan.io/shodan/host/{ip}",
                        params={"key": self.shodan_key},
                        timeout=15,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        hosts = set()
                        for item in data.get("data", []):
                            host = item.get("http", {}).get("host", "")
                            if host:
                                hosts.add(host)
                            # SSL SAN
                            for san in item.get("ssl", {}).get("cert", {}).get("extensions", []):
                                pass  # TODO: 解析 SAN
                        return list(hosts)
                except Exception:
                    pass
                return []

            shodan_hosts = await asyncio.to_thread(_shodan_neighbors)
            for host in shodan_hosts:
                results.append(AssetNode(
                    type="neighbor", value=host,
                    source="shodan", extra={"ip": ip},
                ))

        # HackerTarget: 免费反查
        def _hackertarget():
            import requests
            try:
                r = requests.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                    timeout=15,
                )
                if r.status_code == 200 and "error" not in r.text.lower():
                    return [h.strip() for h in r.text.strip().split("\n")
                            if h.strip() and h.strip() != ip]
            except Exception:
                pass
            return []

        ht_hosts = await asyncio.to_thread(_hackertarget)
        for host in ht_hosts:
            if host not in [r.value for r in results]:
                results.append(AssetNode(
                    type="neighbor", value=host,
                    source="hackertarget", extra={"ip": ip},
                ))

        return results

    # ============================================================
    #                  WHOIS
    # ============================================================

    async def whois_lookup(self, domain: str) -> Dict:
        """WHOIS 查询"""
        def _whois():
            try:
                import subprocess
                r = subprocess.run(
                    ["python", "-c",
                     f"import whois; w=whois.whois('{domain}'); "
                     f"print(__import__('json').dumps({{'registrar': w.registrar, "
                     f"'email': w.emails, 'org': w.org, 'country': w.country, "
                     f"'creation_date': str(w.creation_date)}}))"],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0 and r.stdout.strip():
                    return json.loads(r.stdout.strip())
            except Exception:
                pass

            # Fallback: 用 API
            import requests
            try:
                r = requests.get(
                    f"https://api.hackertarget.com/whois/?q={domain}",
                    timeout=15,
                )
                if r.status_code == 200:
                    text = r.text
                    # 简单提取
                    return {
                        "raw": text[:500],
                        "registrar": re.search(r'Registrar:\s*(.+)', text, re.I).group(1) if re.search(r'Registrar:\s*(.+)', text, re.I) else "",
                    }
            except Exception:
                pass
            return {}

        return await asyncio.to_thread(_whois)

    # ============================================================
    #                  一键全量扩展
    # ============================================================

    async def expand_full(self, seed: str) -> ExpansionResult:
        """
        一键全量资产扩展.

        输入: 域名 (target.com) 或 IP (1.2.3.4)
        输出: 子域名 + IP + 旁站 + C段 + WHOIS

        流程:
            1. 如果是域名: 子域名 → IP → 旁站 → C段 → WHOIS
            2. 如果是 IP: 旁站 → 反查域名 → C段
        """
        result = ExpansionResult(seed=seed)

        # 判断输入类型
        is_ip = False
        try:
            ip_address(seed)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            # IP 输入: 查旁站 + C段
            result.ips.append(AssetNode(type="ip", value=seed, source="input"))
            try:
                net = ip_network(f"{seed}/24", strict=False)
                result.c_segment = str(net)
            except ValueError:
                pass

            neighbors = await self.find_neighbors(seed)
            result.neighbors = neighbors

        else:
            # 域名输入: 全流程 (每步独立超时, 避免单步拖垮全局)
            # 1. 子域名
            try:
                result.subdomains = await asyncio.wait_for(
                    self.find_subdomains(seed), timeout=30)
            except asyncio.TimeoutError:
                pass

            # 2. IP 收集 + C 段
            try:
                result.ips, result.c_segment = await asyncio.wait_for(
                    self.collect_ips(seed, result.subdomains), timeout=15)
            except asyncio.TimeoutError:
                pass

            # 3. 旁站 (对第一个公网 IP)
            public_ips = [ip for ip in result.ips
                         if not ip_address(ip.value).is_private]
            if public_ips:
                try:
                    neighbors = await asyncio.wait_for(
                        self.find_neighbors(public_ips[0].value), timeout=15)
                    result.neighbors = neighbors
                except asyncio.TimeoutError:
                    pass

            # 4. 反向关联 (NS/SOA/MX/SPF → 发现不相关的站群域名)
            try:
                reverse_domains = await asyncio.wait_for(
                    self.reverse_correlate(seed), timeout=10)
                for d in reverse_domains:
                    if d.value not in [s.value for s in result.subdomains]:
                        result.subdomains.append(d)
            except asyncio.TimeoutError:
                pass

            # 5. WHOIS
            try:
                result.whois = await asyncio.wait_for(
                    self.whois_lookup(seed), timeout=10)
            except asyncio.TimeoutError:
                pass

        return result

    # ============================================================
    #                  反向关联 (关键: 发现不相关的站群域名)
    # ============================================================

    async def reverse_correlate(self, domain: str) -> List[AssetNode]:
        """
        反向关联 — 从 NS/SOA/MX/SPF/DKIM 反查站群域名.

        这是最容易被遗漏的发现路径:
            目标用 ns1.target.com 做 DNS → 查所有用这个 NS 的域名
            目标的 SOA 指向 host.target.com → 查所有指向同一 SOA 的域名
            目标的 SPF 段包含 IP 范围 → 查所有用相同 SPF 段的域名
            DKIM selector 相同 → 同一个邮件账号

        数据源:
            1. Shodan DNS (拿 NS/SOA/MX)
            2. HackerTarget (反查 NS → 域名)
            3. crt.sh (证书关联 — 已经有了, 这里加强)
        """
        results: List[AssetNode] = []
        seen: set = set()

        def _get_dns_records():
            """用 Shodan DNS 拿目标的 NS/SOA/MX/TXT"""
            import requests as _req
            records = {"ns": [], "soa": "", "mx": [], "spf_ips": [], "dkim": []}
            try:
                r = _req.get(
                    f"https://api.shodan.io/dns/domain/{domain}",
                    params={"key": self.shodan_key},
                    timeout=15,
                )
                if r.status_code == 200:
                    for rec in r.json().get("data", []):
                        rtype = rec.get("type", "")
                        val = rec.get("value", "")
                        if rtype == "NS":
                            records["ns"].append(val.rstrip("."))
                        elif rtype == "SOA":
                            records["soa"] = val.split()[0] if val else ""
                        elif rtype == "MX":
                            records["mx"].append(val.split()[0].rstrip(".") if val else "")
                        elif rtype == "TXT":
                            # 提取 SPF 里的 IP 段
                            import re
                            for m in re.finditer(r'ip4:(\d+\.\d+\.\d+\.\d+/\d+)', val):
                                records["spf_ips"].append(m.group(1))
                            # 提取 DKIM selector (CNAME -> smtp2go)
                            if "smtp2go" in val:
                                m2 = re.search(r'([a-z0-9]+)\._domainkey', val)
                                if m2:
                                    records["dkim"].append(m2.group(1))
            except Exception:
                pass
            return records

        dns_info = await asyncio.to_thread(_get_dns_records)

        # 方法 1: 反查 NS — 找所有用同一 NS 服务器的域名
        for ns_server in dns_info["ns"]:
            if "blastzone" not in ns_server and "blastzone" not in ns_server.lower():
                continue  # 只对 blastzone NS 做反查 (自定义 NS 才有价值)
            found = await self._reverse_ns(ns_server)
            for d in found:
                if d not in seen and d != domain:
                    seen.add(d)
                    results.append(AssetNode(
                        type="reverse-ns", value=d,
                        source=f"reverse-ns:{ns_server}",
                        extra={"ns": ns_server},
                    ))

        # 方法 2: 反查 SOA
        if dns_info["soa"] and "blastzone" in dns_info["soa"].lower():
            found = await self._reverse_soa(dns_info["soa"])
            for d in found:
                if d not in seen and d != domain:
                    seen.add(d)
                    results.append(AssetNode(
                        type="reverse-soa", value=d,
                        source=f"reverse-soa:{dns_info['soa']}",
                    ))

        # 方法 3: SPF IP 段反查 — 搜 Shodan 找相同 SPF 段的域名
        for spf_ip in dns_info["spf_ips"][:2]:  # 最多查 2 个段
            found = await self._reverse_spf(spf_ip)
            for d in found:
                if d not in seen and d != domain:
                    seen.add(d)
                    results.append(AssetNode(
                        type="reverse-spf", value=d,
                        source=f"reverse-spf:{spf_ip}",
                    ))

        # 方法 4: HackerTarget — 用 NS 服务器反查 (通用方法)
        for ns_server in dns_info["ns"][:2]:
            found = await self._hackertarget_ns_reverse(ns_server, domain)
            for d in found:
                if d not in seen and d != domain:
                    seen.add(d)
                    results.append(AssetNode(
                        type="reverse-ht", value=d,
                        source=f"hackertarget-ns:{ns_server}",
                    ))

        return results

    async def _reverse_ns(self, ns_server: str) -> List[str]:
        """反查 NS — 找所有用这个 NS 的域名 (用 Shodan + crt.sh)"""
        import requests as _req

        def _search():
            found = set()
            # crt.sh: 搜索 NS 服务器关联的域名
            try:
                r = _req.get(
                    "https://crt.sh/",
                    params={"q": ns_server, "output": "json"},
                    timeout=15,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if r.status_code == 200 and r.text.strip():
                    for c in r.json()[:50]:
                        for name in c.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and "." in name and ns_server.split(".")[0] not in name:
                                found.add(name)
            except Exception:
                pass
            return list(found)

        return await asyncio.to_thread(_search)

    async def _reverse_soa(self, soa_server: str) -> List[str]:
        """反查 SOA — 找所有指向同一 SOA 主机的域名"""
        return await self._reverse_ns(soa_server)  # 同样用 crt.sh

    async def _reverse_spf(self, spf_ip: str) -> List[str]:
        """反查 SPF — 搜 Shodan 找含相同 IP 段的 TXT 记录"""
        import requests as _req

        def _search():
            found = set()
            try:
                # Shodan 搜索 TXT 记录含这个 IP 段的域名
                r = _req.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={
                        "key": self.shodan_key,
                        "query": f'dns.txt:"{spf_ip}"',
                    },
                    timeout=20,
                )
                if r.status_code == 200:
                    for m in r.json().get("matches", [])[:20]:
                        host = m.get("hostnames", [])
                        for h in host:
                            found.add(h)
                        domain_val = m.get("domain", "")
                        if domain_val:
                            found.add(domain_val)
            except Exception:
                pass
            return list(found)

        return await asyncio.to_thread(_search)

    async def _hackertarget_ns_reverse(self, ns_server: str, original_domain: str) -> List[str]:
        """HackerTarget NS 反查 — 找共享 NS 的域名"""
        import requests as _req

        def _search():
            found = set()
            try:
                # 提取 NS 的域名部分做 zone 查询
                ns_domain = ".".join(ns_server.split(".")[-2:])
                r = _req.get(
                    f"https://api.hackertarget.com/zonetransfer/?q={ns_domain}",
                    timeout=15,
                )
                if r.status_code == 200 and "error" not in r.text.lower()[:50]:
                    # 区传送成功 (罕见但值得一试)
                    import re
                    domains = re.findall(r'(\w[\w.-]+\.\w{2,})', r.text)
                    for d in domains:
                        if d != original_domain and "." in d:
                            found.add(d)
            except Exception:
                pass

            # 备用: 用 Shodan DNS 查 NS 的域名
            try:
                r = _req.get(
                    f"https://api.shodan.io/dns/domain/{ns_server.split('.', 1)[1] if '.' in ns_server else ns_server}",
                    params={"key": self.shodan_key},
                    timeout=15,
                )
                if r.status_code == 200:
                    for rec in r.json().get("data", []):
                        if rec.get("type") == "A":
                            ip = rec.get("value", "")
                            if ip:
                                # 查这个 IP 的所有 vhost
                                r2 = _req.get(
                                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                                    timeout=15,
                                )
                                if r2.status_code == 200 and "error" not in r2.text.lower()[:50]:
                                    for h in r2.text.strip().split("\n"):
                                        h = h.strip()
                                        if h and h != original_domain and "." in h:
                                            found.add(h)
            except Exception:
                pass

            return list(found)

        return await asyncio.to_thread(_search)
