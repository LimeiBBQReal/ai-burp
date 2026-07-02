"""
AI-Burp 资产侦察模块 v0.1.0

基于 Host Depot (66.242.0.0/16) 扫描经验开发

功能:
1. 快速资产发现 (并行扫描)
2. ASP/PHP/JSP 站点识别
3. 参数自动发现
4. 批量 SQLi 检测
5. 拓扑报告生成

使用:
    recon = AssetRecon(burp)
    
    # 扫描单个 /24 网段
    assets = recon.scan_range("66.242.136.0/24")
    
    # 扫描多个网段
    assets = recon.scan_ranges(["66.242.136.0/24", "66.242.142.0/24"])
    
    # 测试发现的资产
    vulns = recon.test_assets(assets)
"""

import re
import time
import json
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from ..sync_wrapper import SyncBurp as Burp
from ..burp import Response


@dataclass
class Asset:
    """资产信息"""
    ip: str
    title: str = ""
    server: str = ""
    tech: str = ""  # asp, php, jsp, etc.
    params: List[str] = field(default_factory=list)  # 发现的参数 URL
    status: int = 0
    size: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "title": self.title,
            "server": self.server,
            "tech": self.tech,
            "params": self.params,
            "status": self.status,
            "size": self.size,
        }


@dataclass
class ReconResult:
    """侦察结果"""
    scan_range: str
    total_ips: int = 0
    alive_hosts: int = 0
    assets: List[Asset] = field(default_factory=list)
    asp_sites: List[Asset] = field(default_factory=list)
    php_sites: List[Asset] = field(default_factory=list)
    ecom_sites: List[Asset] = field(default_factory=list)
    vulns: List[Dict] = field(default_factory=list)
    
    def to_json(self) -> str:
        return json.dumps({
            "scan_range": self.scan_range,
            "total_ips": self.total_ips,
            "alive_hosts": self.alive_hosts,
            "assets": [a.to_dict() for a in self.assets],
            "asp_sites": [a.to_dict() for a in self.asp_sites],
            "php_sites": [a.to_dict() for a in self.php_sites],
            "ecom_sites": [a.to_dict() for a in self.ecom_sites],
            "vulns": self.vulns,
        }, ensure_ascii=False, indent=2)
    
    def __str__(self):
        lines = [
            "=" * 60,
            "📊 资产侦察报告",
            "=" * 60,
            f"扫描范围: {self.scan_range}",
            f"总 IP 数: {self.total_ips}",
            f"存活主机: {self.alive_hosts}",
            "",
            f"📋 ASP 站点: {len(self.asp_sites)}",
            f"📋 PHP 站点: {len(self.php_sites)}",
            f"📋 电商站点: {len(self.ecom_sites)}",
            f"🔴 发现漏洞: {len(self.vulns)}",
        ]
        
        if self.vulns:
            lines.append("")
            lines.append("🔴 漏洞详情:")
            for v in self.vulns[:10]:
                lines.append(f"  - [{v['ip']}] {v['type']}: {v['evidence']}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


class AssetRecon:
    """
    资产侦察器
    
    特点:
    1. 并行扫描 (可配置线程数)
    2. 智能识别站点类型
    3. 自动发现参数
    4. 批量漏洞检测
    """
    
    # 默认页面特征 (跳过)
    DEFAULT_PAGE_PATTERNS = [
        "Host Depot Web Hosting",
        "Welcome to nginx",
        "Apache2 Ubuntu Default Page",
        "IIS Windows Server",
        "It works!",
        "Index of /",
    ]
    
    # 电商特征
    ECOM_PATTERNS = [
        r"add.*cart", r"shopping.*cart", r"checkout",
        r"product", r"price", r"buy.*now",
        r"order", r"payment", r"credit.*card",
    ]
    
    # 技术栈识别
    TECH_PATTERNS = {
        "asp": [r"\.asp\?", r"\.aspx\?", r"ASP\.NET"],
        "php": [r"\.php\?", r"PHP/", r"X-Powered-By:.*PHP"],
        "jsp": [r"\.jsp\?", r"\.do\?", r"Servlet"],
        "coldfusion": [r"\.cfm\?", r"ColdFusion"],
    }
    
    def __init__(self, burp: Burp, max_workers: int = 50, timeout: int = 10):
        self.burp = burp
        self.max_workers = max_workers
        self.timeout = timeout
    
    def _check_host(self, ip: str) -> Optional[Asset]:
        """检查单个主机"""
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            
            r = requests.get(f"http://{ip}/", timeout=self.timeout, verify=False)
            
            # 跳过默认页
            for pattern in self.DEFAULT_PAGE_PATTERNS:
                if pattern in r.text and len(r.text) < 25000:
                    return None
            
            # 提取信息
            asset = Asset(ip=ip, status=r.status_code, size=len(r.text))
            
            # 服务器
            asset.server = r.headers.get("Server", "")
            
            # 标题
            match = re.search(r'<title[^>]*>([^<]+)</title>', r.text, re.I)
            if match:
                asset.title = match.group(1)[:50].strip()
            
            # 技术栈
            for tech, patterns in self.TECH_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, r.text, re.I) or re.search(pattern, str(r.headers), re.I):
                        asset.tech = tech
                        break
                if asset.tech:
                    break
            
            # 发现参数
            param_patterns = [
                r'href=["\']([^"\']*\.(asp|php|jsp|cfm)\?[^"\']*)["\']',
                r'action=["\']([^"\']*\.(asp|php|jsp|cfm)\?[^"\']*)["\']',
            ]
            for pattern in param_patterns:
                matches = re.findall(pattern, r.text, re.I)
                for m in matches:
                    url = m[0] if isinstance(m, tuple) else m
                    if url and '?' in url:
                        asset.params.append(url)
            
            # 去重
            asset.params = list(set(asset.params))[:10]
            
            return asset if asset.params or asset.tech else None
            
        except Exception:
            return None
    
    def scan_range(self, cidr: str) -> ReconResult:
        """
        扫描 IP 范围
        
        Args:
            cidr: CIDR 格式，如 "66.242.136.0/24"
        
        Returns:
            ReconResult 对象
        """
        result = ReconResult(scan_range=cidr)
        
        # 解析 CIDR
        ips = self._parse_cidr(cidr)
        result.total_ips = len(ips)
        
        print(f"📊 扫描 {cidr} ({len(ips)} 个 IP)...")
        
        # 并行扫描
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._check_host, ip): ip for ip in ips}
            
            for future in concurrent.futures.as_completed(futures):
                asset = future.result()
                if asset:
                    result.assets.append(asset)
                    result.alive_hosts += 1
                    
                    # 分类
                    if asset.tech == "asp":
                        result.asp_sites.append(asset)
                    elif asset.tech == "php":
                        result.php_sites.append(asset)
                    
                    # 电商检测
                    if self._is_ecom(asset):
                        result.ecom_sites.append(asset)
        
        print(f"   发现 {result.alive_hosts} 个存活主机")
        print(f"   ASP: {len(result.asp_sites)}, PHP: {len(result.php_sites)}, 电商: {len(result.ecom_sites)}")
        
        return result
    
    def scan_ranges(self, cidrs: List[str]) -> ReconResult:
        """扫描多个 IP 范围"""
        combined = ReconResult(scan_range=", ".join(cidrs))
        
        for cidr in cidrs:
            r = self.scan_range(cidr)
            combined.total_ips += r.total_ips
            combined.alive_hosts += r.alive_hosts
            combined.assets.extend(r.assets)
            combined.asp_sites.extend(r.asp_sites)
            combined.php_sites.extend(r.php_sites)
            combined.ecom_sites.extend(r.ecom_sites)
        
        return combined
    
    def test_assets(self, result: ReconResult, test_sqli: bool = True) -> ReconResult:
        """
        测试发现的资产
        
        Args:
            result: 侦察结果
            test_sqli: 是否测试 SQL 注入
        
        Returns:
            更新后的 ReconResult
        """
        print(f"\n📊 测试 {len(result.assets)} 个资产...")
        
        for asset in result.assets:
            if not asset.params:
                continue
            
            for param_url in asset.params[:3]:
                if '?' not in param_url:
                    continue
                
                path = param_url.split('?')[0]
                query = param_url.split('?')[1]
                
                if '=' not in query:
                    continue
                
                param = query.split('=')[0]
                value = query.split('=')[1].split('&')[0]
                
                if test_sqli:
                    vuln = self._test_sqli(asset.ip, path, param, value)
                    if vuln:
                        result.vulns.append(vuln)
                        print(f"   🔴 [{asset.ip}] {path}?{param} - {vuln['type']}")
        
        return result
    
    def _test_sqli(self, ip: str, path: str, param: str, value: str) -> Optional[Dict]:
        """测试 SQL 注入"""
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            
            base_url = f"http://{ip}/{path.lstrip('/')}"
            
            # 正常请求
            r1 = requests.get(base_url, params={param: value}, timeout=self.timeout, verify=False)
            
            # 单引号测试
            r2 = requests.get(base_url, params={param: f"{value}'"}, timeout=self.timeout, verify=False)
            
            # 检查错误
            errors = []
            error_patterns = [
                (r'80040e14|syntax.*error|unclosed.*quotation', "SQL语法错误"),
                (r'odbc|oledb|jet|sql.*server|microsoft.*access', "数据库错误"),
                (r'mysql|mysqli|pg_|postgresql', "数据库错误"),
            ]
            
            for pattern, desc in error_patterns:
                if re.search(pattern, r2.text, re.I):
                    errors.append(desc)
            
            if errors:
                return {
                    "ip": ip,
                    "path": path,
                    "param": param,
                    "type": "sqli",
                    "evidence": ", ".join(errors),
                }
            
            return None
            
        except Exception:
            return None
    
    def _is_ecom(self, asset: Asset) -> bool:
        """检测是否是电商站点"""
        text = asset.title.lower() + " ".join(asset.params).lower()
        for pattern in self.ECOM_PATTERNS:
            if re.search(pattern, text, re.I):
                return True
        return False
    
    def _parse_cidr(self, cidr: str) -> List[str]:
        """解析 CIDR 为 IP 列表"""
        if '/' not in cidr:
            return [cidr]
        
        base, mask = cidr.split('/')
        mask = int(mask)
        
        if mask == 32:
            return [base]
        
        parts = base.split('.')
        
        if mask == 24:
            # /24 网段
            prefix = '.'.join(parts[:3])
            return [f"{prefix}.{i}" for i in range(1, 255)]
        elif mask == 16:
            # /16 网段 (太大，只扫描部分)
            prefix = '.'.join(parts[:2])
            ips = []
            for third in range(0, 256):
                for fourth in range(1, 255):
                    ips.append(f"{prefix}.{third}.{fourth}")
            return ips
        else:
            # 其他情况简化处理
            return [base]
    
    def generate_topology(self, result: ReconResult) -> str:
        """生成拓扑报告"""
        lines = [
            "# 资产拓扑报告",
            "",
            "## 基本信息",
            "",
            f"| 项目 | 值 |",
            f"|------|-----|",
            f"| 扫描范围 | {result.scan_range} |",
            f"| 总 IP 数 | {result.total_ips} |",
            f"| 存活主机 | {result.alive_hosts} |",
            f"| ASP 站点 | {len(result.asp_sites)} |",
            f"| PHP 站点 | {len(result.php_sites)} |",
            f"| 电商站点 | {len(result.ecom_sites)} |",
            f"| 发现漏洞 | {len(result.vulns)} |",
            "",
            "## 资产列表",
            "",
            "| IP | 标题 | 技术 | 参数数 |",
            "|---|---|---|---|",
        ]
        
        for asset in result.assets[:50]:
            lines.append(f"| {asset.ip} | {asset.title[:30]} | {asset.tech} | {len(asset.params)} |")
        
        if result.vulns:
            lines.extend([
                "",
                "## 发现的漏洞",
                "",
                "| IP | 路径 | 类型 | 证据 |",
                "|---|---|---|---|",
            ])
            for v in result.vulns:
                lines.append(f"| {v['ip']} | {v['path']} | {v['type']} | {v['evidence']} |")
        
        return "\n".join(lines)


def recon_command(burp: Burp, target: str, test: bool = True) -> str:
    """资产侦察命令入口"""
    recon = AssetRecon(burp)
    result = recon.scan_range(target)
    
    if test:
        result = recon.test_assets(result)
    
    return str(result)
