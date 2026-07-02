"""
资产情报聚合 — 输入一个 IP/域名, 一次查全部情报平台.

聚合你 .env 里的所有 KEY:
    - Shodan:         端口/服务/CVE/ISP/旁站(vhost)
    - Censys:         证书/服务指纹
    - VirusTotal:     历史 DNS/域名关联/恶意标记
    - OTX:            威胁情报/关联指标
    - SecurityTrails: 旁站/子域名/历史 DNS/ISP/WHOIS
    - Shodan InternetDB: 免费 KEYless 快速查询
    - MyIP.ms:         免费 KEYless 站群/旁站/ISP/IP段 (爬页面数据)

一次调用, 一次聚合, 输出完整资产画像.
"""

import os
import json
import asyncio
import base64
import hashlib
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class IntelReport:
    """资产情报报告"""
    target: str = ""
    ip: str = ""
    isp: str = ""
    org: str = ""
    country: str = ""
    asn: str = ""

    # 资产信息
    open_ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)  # {port: service_name}
    hostnames: List[str] = field(default_factory=list)      # 所有关联域名
    neighbors: List[str] = field(default_factory=list)      # 旁站
    subdomains: List[str] = field(default_factory=list)     # 子域名

    # 漏洞信息
    vulns: List[str] = field(default_factory=list)          # CVE 列表

    # 历史
    historical_ips: List[str] = field(default_factory=list)
    dns_history: List[Dict] = field(default_factory=list)

    # 情报
    malicious: bool = False
    threat_tags: List[str] = field(default_factory=list)

    # 元数据
    sources_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target, "ip": self.ip,
            "isp": self.isp, "org": self.org, "country": self.country, "asn": self.asn,
            "open_ports": self.open_ports,
            "services": self.services,
            "hostnames": self.hostnames[:20],
            "neighbors (旁站)": self.neighbors[:20],
            "subdomains": self.subdomains[:20],
            "vulns (CVE)": self.vulns[:10],
            "historical_ips": self.historical_ips[:10],
            "malicious": self.malicious,
            "threat_tags": self.threat_tags,
            "sources_used": self.sources_used,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def report_text(self) -> str:
        lines = ["="*60, f"资产情报: {self.target}", "="*60]
        if self.ip:
            lines.append(f"IP: {self.ip}")
        if self.isp:
            lines.append(f"ISP: {self.isp}")
        if self.org:
            lines.append(f"组织: {self.org}")
        if self.country:
            lines.append(f"国家: {self.country}")
        if self.asn:
            lines.append(f"ASN: {self.asn}")
        lines.append("-"*60)

        if self.open_ports:
            lines.append(f"\n开放端口 ({len(self.open_ports)}): {self.open_ports}")
        if self.services:
            lines.append(f"服务: {self.services}")
        if self.vulns:
            lines.append(f"\n🔴 CVE ({len(self.vulns)}): {self.vulns[:5]}")
        if self.neighbors:
            lines.append(f"\n旁站/站群 ({len(self.neighbors)}):")
            for n in self.neighbors[:10]:
                lines.append(f"  {n}")
        if self.hostnames:
            lines.append(f"\n关联域名 ({len(self.hostnames)}):")
            for h in self.hostnames[:10]:
                lines.append(f"  {h}")
        if self.historical_ips:
            lines.append(f"\n历史 IP ({len(self.historical_ips)}): {self.historical_ips[:5]}")
        if self.malicious:
            lines.append(f"\n⚠️ 威胁标签: {self.threat_tags}")

        lines.append(f"\n数据源: {', '.join(self.sources_used)}")
        return "\n".join(lines)


class IntelAggregator:
    """
    资产情报聚合器 — 一次查全部平台.

    用法:
        agg = IntelAggregator()
        report = await agg.lookup_ip("1.2.3.4")
        report = await agg.lookup_domain("target.com")
        print(report.report_text())
    """

    def __init__(self):
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.censys_key = os.environ.get("CENSYS_API_KEY", "")
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.otx_key = os.environ.get("OTX_API_KEY", "")
        self.st_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        self._load_env()

    def _load_env(self):
        from pathlib import Path
        env_path = Path(".env")
        if not env_path.exists():
            return
        key_map = {
            "SHODAN_API_KEY": "shodan_key",
            "CENSYS_API_KEY": "censys_key",
            "VIRUSTOTAL_API_KEY": "vt_key",
            "OTX_API_KEY": "otx_key",
            "SECURITYTRAILS_API_KEY": "st_key",
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
    #                  IP 查询 (全部平台)
    # ============================================================

    async def lookup_ip(self, ip: str) -> IntelReport:
        """
        输入 IP, 一次查全部情报平台.

        返回: ISP/组织/开放端口/服务/CVE/旁站/威胁标签
        """
        report = IntelReport(target=ip, ip=ip)

        # 并行查询所有平台
        tasks = []

        # Shodan InternetDB (免费, 无 KEY)
        tasks.append(("shodan-internetdb", self._shodan_internetdb(ip)))

        # MyIP.ms (免费, 无 KEY — ISP/站群/旁站)
        tasks.append(("myip.ms", self._myip_ms_ip(ip, report)))

        # Shodan 完整 API (需要 KEY)
        if self.shodan_key:
            tasks.append(("shodan", self._shodan_host(ip, report)))

        # Censys
        if self.censys_key:
            tasks.append(("censys", self._censys_host(ip, report)))

        # VirusTotal
        if self.vt_key:
            tasks.append(("virustotal", self._vt_ip(ip, report)))

        # OTX
        if self.otx_key:
            tasks.append(("otx", self._otx_ip(ip, report)))

        # 执行
        for name, coro in tasks:
            try:
                await coro
                report.sources_used.append(name)
            except Exception as e:
                report.errors.append(f"{name}: {str(e)[:50]}")

        return report

    # ============================================================
    #                  域名查询
    # ============================================================

    async def lookup_domain(self, domain: str) -> IntelReport:
        """
        输入域名, 一次查全部平台.

        返回: 解析 IP/子域名/历史 DNS/旁站/ISP/WHOIS
        """
        import socket
        report = IntelReport(target=domain)

        # 先解析 IP
        try:
            ips = socket.getaddrinfo(domain, None)
            report.ip = ips[0][4][0]
        except socket.gaierror:
            pass

        # 并行查询
        tasks = []

        # MyIP.ms (免费, 无 KEY — ISP/站群/旁站)
        tasks.append(("myip.ms", self._myip_ms_domain(domain, report)))

        # SecurityTrails (子域名 + 历史 DNS + 旁站)
        if self.st_key:
            tasks.append(("securitytrails", self._st_domain(domain, report)))

        # VirusTotal (历史 DNS + 关联)
        if self.vt_key:
            tasks.append(("virustotal", self._vt_domain(domain, report)))

        # Shodan DNS (子域名)
        if self.shodan_key:
            tasks.append(("shodan-dns", self._shodan_dns(domain, report)))

        # OTX (威胁情报)
        if self.otx_key:
            tasks.append(("otx", self._otx_domain(domain, report)))

        # 如果有 IP, 也查 IP 情报
        if report.ip:
            tasks.append(("ip-intel", self._merge_ip_intel(report)))

        for name, coro in tasks:
            try:
                await coro
                report.sources_used.append(name)
            except Exception as e:
                report.errors.append(f"{name}: {str(e)[:50]}")

        return report

    # ============================================================
    #                  Shodan InternetDB (免费无 KEY)
    # ============================================================

    async def _shodan_internetdb(self, ip: str):
        """Shodan InternetDB — 免费, 无需 KEY"""
        import requests

        def _query():
            r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            if r.status_code == 200:
                return r.json()
            return {}

        data = await asyncio.to_thread(_query)
        return data

    async def _shodan_host(self, ip: str, report: IntelReport):
        """Shodan 完整 API — 端口/服务/CVE/ISP/旁站"""
        import requests

        def _query():
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key},
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            return {}

        data = await asyncio.to_thread(_query)

        report.isp = data.get("isp", report.isp)
        report.org = data.get("org", report.org)
        report.country = data.get("country_name", report.country)
        report.asn = data.get("asn", report.asn)
        report.open_ports = data.get("ports", report.open_ports)

        # 服务详情
        for service in data.get("data", []):
            port = service.get("port", 0)
            product = service.get("product", "")
            version = service.get("version", "")
            host = service.get("http", {}).get("host", "")
            if port:
                svc_name = f"{product} {version}".strip() or service.get("_shodan", {}).get("module", "")
                report.services[str(port)] = svc_name
            if host and host not in report.neighbors:
                report.neighbors.append(host)

        # CVE
        for vuln in data.get("vulns", []):
            if vuln not in report.vulns:
                report.vulns.append(vuln)

        # 主机名
        for hn in data.get("hostnames", []):
            if hn not in report.hostnames:
                report.hostnames.append(hn)

    # ============================================================
    #                  SecurityTrails (子域名+旁站+历史)
    # ============================================================

    async def _st_domain(self, domain: str, report: IntelReport):
        """SecurityTrails — 子域名 + 历史 DNS + 旁站"""
        import requests

        def _query():
            headers = {"APIKEY": self.st_key}
            results = {}

            # 1. 子域名
            try:
                r = requests.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers=headers, timeout=15,
                )
                if r.status_code == 200:
                    subs = r.json().get("subdomains", [])
                    results["subdomains"] = [f"{s}.{domain}" for s in subs[:50]]
            except Exception:
                pass

            # 2. 历史 DNS (A 记录)
            try:
                r = requests.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                    headers=headers, timeout=15,
                )
                if r.status_code == 200:
                    records = r.json().get("records", [])
                    results["dns_history"] = records[:20]
                    # 提取历史 IP
                    results["historical_ips"] = list(set(
                        rec.get("values", [{}])[0].get("ip", "")
                        for rec in records if rec.get("values")
                    ))[:10]
            except Exception:
                pass

            # 3. 旁站 (同 IP 的其它域名)
            if report.ip:
                try:
                    r = requests.get(
                        f"https://api.securitytrails.com/v1/ip/list",
                        params={"ip": report.ip},
                        headers=headers, timeout=15,
                    )
                    if r.status_code == 200:
                        results["neighbors"] = r.json().get("paths", [])[:20]
                except Exception:
                    pass

            return results

        data = await asyncio.to_thread(_query)

        report.subdomains.extend(data.get("subdomains", []))
        report.dns_history.extend(data.get("dns_history", []))
        report.historical_ips.extend(data.get("historical_ips", []))
        report.neighbors.extend(data.get("neighbors", []))

    # ============================================================
    #                  Censys
    # ============================================================

    async def _censys_host(self, ip: str, report: IntelReport):
        """Censys — 服务指纹 + 证书"""
        import requests

        def _query():
            r = requests.get(
                f"https://search.censys.io/api/v2/hosts/{ip}",
                headers={"Authorization": f"Bearer {self.censys_key}"},
                timeout=15,
            )
            if r.status_code == 200:
                return r.json().get("result", {})
            return {}

        data = await asyncio.to_thread(_query)

        report.country = data.get("location", {}).get("country", report.country)
        report.asn = data.get("autonomous_system", {}).get("asn", report.asn)
        report.org = data.get("autonomous_system", {}).get("name", report.org)

        for service in data.get("services", []):
            port = service.get("port", 0)
            name = service.get("service_name", "")
            if port:
                report.services[str(port)] = name
                if port not in report.open_ports:
                    report.open_ports.append(port)

    # ============================================================
    #                  VirusTotal
    # ============================================================

    async def _vt_ip(self, ip: str, report: IntelReport):
        """VirusTotal — IP 威胁情报"""
        import requests

        def _query():
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
                timeout=15,
            )
            if r.status_code == 200:
                return r.json().get("data", {}).get("attributes", {})
            return {}

        data = await asyncio.to_thread(_query)

        report.asn = data.get("asn", report.asn)
        report.country = data.get("country", report.country)
        if data.get("reputation", 0) < 0:
            report.malicious = True
        # 威胁标签
        for tag in data.get("popular_threat_classification", {}).get("suggested_threat_label", "").split("/"):
            tag = tag.strip()
            if tag:
                report.threat_tags.append(tag)

    async def _vt_domain(self, domain: str, report: IntelReport):
        """VirusTotal — 域名历史解析"""
        import requests

        def _query():
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
                headers={"x-apikey": self.vt_key},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                ips = []
                for item in data[:20]:
                    ip = item.get("attributes", {}).get("ip_address", "")
                    if ip:
                        ips.append(ip)
                return ips
            return []

        ips = await asyncio.to_thread(_query)
        report.historical_ips.extend(ips)

    # ============================================================
    #                  Shodan DNS
    # ============================================================

    async def _shodan_dns(self, domain: str, report: IntelReport):
        """Shodan DNS API — 全部 DNS 记录 + 子域名"""
        import requests

        def _query():
            r = requests.get(
                f"https://api.shodan.io/dns/domain/{domain}",
                params={"key": self.shodan_key},
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            return {}

        data = await asyncio.to_thread(_query)

        for record in data.get("data", []):
            sub = record.get("subdomain", "")
            full = f"{sub}.{domain}" if sub else domain
            if full not in report.subdomains:
                report.subdomains.append(full)

    # ============================================================
    #                  OTX
    # ============================================================

    async def _otx_ip(self, ip: str, report: IntelReport):
        """OTX — IP 威胁情报"""
        import requests

        def _query():
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/ipv4/{ip}/general",
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            return {}

        data = await asyncio.to_thread(_query)
        report.asn = data.get("asn", report.asn)
        if data.get("pulse_info", {}).get("count", 0) > 0:
            report.malicious = True
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:3]:
                for tag in pulse.get("tags", [])[:3]:
                    if tag not in report.threat_tags:
                        report.threat_tags.append(tag)

    async def _otx_domain(self, domain: str, report: IntelReport):
        """OTX — 域名情报"""
        import requests

        def _query():
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            return {}

        data = await asyncio.to_thread(_query)
        if data.get("pulse_info", {}).get("count", 0) > 0:
            report.malicious = True

    # ============================================================
    #                  MyIP.ms (免费, 无 KEY)
    # ============================================================

    async def _myip_ms_ip(self, ip: str, report: IntelReport):
        """
        MyIP.ms IP 查询 — ISP/组织/国家/ASN/旁站.

        页爬 https://myip.ms/{ip}
        """
        import requests
        import re as _re

        def _query():
            r = requests.get(
                f"https://myip.ms/{ip}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=15,
            )
            if r.status_code != 200:
                return {}

            text = r.text
            result = {}

            # ISP / 组织
            m = _re.search(r'ISP/Organization[^<]*<[^>]+>([^<]+)', text)
            if m:
                result["isp"] = m.group(1).strip()

            # Country
            m = _re.search(r'Country[^<]*<[^>]+>([A-Za-z ]+)', text)
            if m:
                result["country"] = m.group(1).strip()

            # ASN
            m = _re.search(r'ASN[^<]*<[^>]+>AS(\d+)', text)
            if m:
                result["asn"] = "AS" + m.group(1)

            # 旁站 (同 IP 的其它网站 — 从页面提取域名)
            # MyIP.ms 在 "Websites on this IP" 或类似区块列旁站
            neighbors = set()
            for m in _re.finditer(r'(?:www\.myip\.ms/info/|/browse/sites/)([a-z0-9._-]+\.[a-z]{2,})', text, _re.I):
                domain = m.group(1).strip().lower()
                if domain and domain != ip:
                    neighbors.add(domain)
            # 备用模式: 直接从表格里提取域名链接
            if not neighbors:
                for m in _re.finditer(r'href="/www\.([a-z0-9._-]+\.[a-z]{2,})"', text, _re.I):
                    neighbors.add(m.group(1).lower())

            result["neighbors"] = list(neighbors)[:50]
            return result

        data = await asyncio.to_thread(_query)

        report.isp = data.get("isp", report.isp)
        report.country = data.get("country", report.country)
        report.asn = data.get("asn", report.asn)
        for n in data.get("neighbors", []):
            if n not in report.neighbors:
                report.neighbors.append(n)

    async def _myip_ms_domain(self, domain: str, report: IntelReport):
        """
        MyIP.ms 域名查询 — 托管 IP/ISP/站群/旁站.

        页爬 https://myip.ms/www/{domain}
        """
        import requests
        import re as _re

        def _query():
            r = requests.get(
                f"https://myip.ms/www/{domain}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=15,
            )
            if r.status_code != 200:
                return {}

            text = r.text
            result = {}

            # 托管 IP
            for m in _re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
                ip = m.group(1)
                # 排除私有 IP
                if not ip.startswith(("10.", "172.", "192.168.", "127.")):
                    result["ip"] = ip
                    break

            # ISP / 组织
            m = _re.search(r'ISP/Organization[^<]*<[^>]+>([^<]+)', text)
            if m:
                result["isp"] = m.group(1).strip()

            # Country
            m = _re.search(r'Country[^<]*<[^>]+>([A-Za-z ]+)', text)
            if m:
                result["country"] = m.group(1).strip()

            # 旁站 — MyIP.ms 在域名页也列 "Other sites on this server"
            neighbors = set()
            for m in _re.finditer(r'href="/www\.([a-z0-9._-]+\.[a-z]{2,})"', text, _re.I):
                n = m.group(1).lower()
                if n != domain:
                    neighbors.add(n)

            result["neighbors"] = list(neighbors)[:50]

            # IP 段 / Owner 信息
            m = _re.search(r'IP Range[^<]*<[^>]+>([^<]+)', text)
            if m:
                result["ip_range"] = m.group(1).strip()

            return result

        data = await asyncio.to_thread(_query)

        if data.get("ip") and not report.ip:
            report.ip = data["ip"]
        report.isp = data.get("isp", report.isp)
        report.country = data.get("country", report.country)
        for n in data.get("neighbors", []):
            if n not in report.neighbors:
                report.neighbors.append(n)

    # ============================================================
    #                  辅助
    # ============================================================

    async def _merge_ip_intel(self, report: IntelReport):
        """如果有 IP, 补查 IP 情报"""
        if not report.ip:
            return
        ip_report = await self.lookup_ip(report.ip)
        report.isp = ip_report.isp or report.isp
        report.org = ip_report.org or report.org
        report.country = ip_report.country or report.country
        report.open_ports.extend(ip_report.open_ports)
        report.vulns.extend(ip_report.vulns)
        report.neighbors.extend(ip_report.neighbors)
        if ip_report.malicious:
            report.malicious = True
