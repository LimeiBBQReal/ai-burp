"""
AI-Burp 子域名枚举模块 v0.1.0

基于 Heritage IBT 实战经验开发

功能:
1. 智能子域名爆破 (带通配符检测)
2. 多级子域名枚举 (二级、三级)
3. 真实域名过滤 (排除占位页面)
4. CT Logs 查询
5. HTTP 验证

使用:
    from aiburp import SubdomainEnum
    
    enum = SubdomainEnum("example.com")
    
    # 快速枚举
    results = enum.enumerate()
    
    # 深度枚举 (包含三级子域名)
    results = enum.deep_enumerate()
    
    # 只获取真实域名
    real_domains = enum.get_real_domains()
"""

import socket
import requests
import json
import time
import re
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
import urllib3
urllib3.disable_warnings()

from .dns_validator import DNSValidator, WildcardResult


@dataclass
class SubdomainResult:
    """子域名结果"""
    domain: str
    ip: Optional[str] = None
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    server: str = ""
    title: str = ""
    content_length: int = 0
    is_placeholder: bool = False  # 是否是占位页面
    is_real: bool = True
    tech: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "http_status": self.http_status,
            "https_status": self.https_status,
            "server": self.server,
            "title": self.title,
            "content_length": self.content_length,
            "is_placeholder": self.is_placeholder,
            "is_real": self.is_real,
            "tech": self.tech,
        }


@dataclass 
class EnumReport:
    """枚举报告"""
    base_domain: str
    total_tested: int = 0
    total_resolved: int = 0
    total_real: int = 0
    has_wildcard: bool = False
    wildcard_ips: Set[str] = field(default_factory=set)
    results: List[SubdomainResult] = field(default_factory=list)
    real_domains: List[SubdomainResult] = field(default_factory=list)
    placeholder_domains: List[SubdomainResult] = field(default_factory=list)
    
    def to_json(self) -> str:
        return json.dumps({
            "base_domain": self.base_domain,
            "total_tested": self.total_tested,
            "total_resolved": self.total_resolved,
            "total_real": self.total_real,
            "has_wildcard": self.has_wildcard,
            "wildcard_ips": list(self.wildcard_ips),
            "results": [r.to_dict() for r in self.results],
            "real_domains": [r.to_dict() for r in self.real_domains],
        }, ensure_ascii=False, indent=2)
    
    def __str__(self):
        lines = [
            "=" * 60,
            f"📊 子域名枚举报告: {self.base_domain}",
            "=" * 60,
            f"测试数量: {self.total_tested}",
            f"DNS解析: {self.total_resolved}",
            f"真实域名: {self.total_real}",
            f"占位页面: {len(self.placeholder_domains)}",
            f"DNS通配符: {'是 ⚠️' if self.has_wildcard else '否'}",
        ]
        
        if self.has_wildcard:
            lines.append(f"通配符IP: {self.wildcard_ips}")
        
        if self.real_domains:
            lines.append("")
            lines.append("🔴 真实域名:")
            for r in self.real_domains[:20]:
                lines.append(f"  {r.domain} -> {r.ip} ({r.title[:30] if r.title else 'N/A'})")
        
        lines.append("=" * 60)
        return "\n".join(lines)


class SubdomainEnum:
    """
    子域名枚举器
    
    特点:
    1. 自动检测DNS通配符
    2. 过滤占位页面
    3. 识别真实服务
    4. 支持多级子域名
    """
    
    # 常用二级子域名前缀
    COMMON_PREFIXES = [
        # 核心
        "www", "mail", "webmail", "ftp", "sftp", "ssh",
        # 开发
        "dev", "test", "staging", "uat", "qa", "demo", "sandbox", "beta",
        # API
        "api", "api-v1", "api-v2", "rest", "graphql", "gateway",
        # 管理
        "admin", "panel", "console", "dashboard", "manage", "cms", "portal",
        # 内部
        "intranet", "internal", "private", "corp", "office", "vpn",
        # 数据库
        "db", "mysql", "postgres", "mongo", "redis", "elastic",
        # 认证
        "auth", "sso", "oauth", "login", "ldap",
        # 监控
        "monitor", "grafana", "kibana", "prometheus", "logs", "metrics",
        # CI/CD
        "jenkins", "gitlab", "ci", "cd", "build", "deploy",
        # 其他
        "cdn", "static", "assets", "media", "files", "upload",
        "support", "help", "docs", "blog", "shop", "store",
        "secure", "pay", "payment", "billing",
    ]
    
    # 三级子域名前缀
    LEVEL3_PREFIXES = [
        "api", "dev", "test", "staging", "admin", "internal",
        "backend", "frontend", "mobile", "app",
    ]
    
    # 占位页面特征
    PLACEHOLDER_PATTERNS = [
        "under development",
        "coming soon", 
        "under construction",
        "site is not available",
        "default page",
        "welcome to nginx",
        "apache2 ubuntu default",
        "iis windows server",
        "it works!",
        "index of /",
        "parked domain",
        "this domain",
    ]
    
    def __init__(self, base_domain: str, timeout: int = 5, max_workers: int = 30):
        self.base_domain = base_domain
        self.timeout = timeout
        self.max_workers = max_workers
        self.dns_validator = DNSValidator(timeout=timeout)
        self.wildcard_result: Optional[WildcardResult] = None
    
    def _resolve(self, domain: str) -> Optional[str]:
        """DNS解析"""
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def _check_http(self, domain: str, ip: str) -> SubdomainResult:
        """检查HTTP响应"""
        result = SubdomainResult(domain=domain, ip=ip)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Host": domain,
        }
        
        # HTTPS
        try:
            resp = requests.get(
                f"https://{domain}", 
                headers=headers, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            result.https_status = resp.status_code
            result.server = resp.headers.get("Server", "")
            result.content_length = len(resp.text)
            
            # 提取标题
            match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
            if match:
                result.title = match.group(1).strip()[:50]
            
            # 检查是否是占位页面
            text_lower = resp.text.lower()
            for pattern in self.PLACEHOLDER_PATTERNS:
                if pattern in text_lower:
                    result.is_placeholder = True
                    break
            
            # 技术识别
            if "php" in resp.headers.get("X-Powered-By", "").lower():
                result.tech = "php"
            elif "asp" in resp.headers.get("X-Powered-By", "").lower():
                result.tech = "asp"
            elif ".php" in resp.text.lower():
                result.tech = "php"
            elif ".asp" in resp.text.lower():
                result.tech = "asp"
                
        except:
            pass
        
        # HTTP (如果HTTPS失败)
        if not result.https_status:
            try:
                resp = requests.get(
                    f"http://{domain}",
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                result.http_status = resp.status_code
                if not result.server:
                    result.server = resp.headers.get("Server", "")
                if not result.content_length:
                    result.content_length = len(resp.text)
                if not result.title:
                    match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
                    if match:
                        result.title = match.group(1).strip()[:50]
                        
                # 检查占位页面
                text_lower = resp.text.lower()
                for pattern in self.PLACEHOLDER_PATTERNS:
                    if pattern in text_lower:
                        result.is_placeholder = True
                        break
            except:
                pass
        
        # 判断是否真实
        if result.is_placeholder:
            result.is_real = False
        elif not result.http_status and not result.https_status:
            result.is_real = False
        elif result.content_length < 500 and not result.title:
            result.is_real = False
        
        return result
    
    def _check_single(self, domain: str) -> Optional[SubdomainResult]:
        """检查单个域名"""
        ip = self._resolve(domain)
        if not ip:
            return None
        
        # 如果有通配符，检查IP是否在通配符IP列表中
        if self.wildcard_result and self.wildcard_result.has_wildcard:
            if ip in self.wildcard_result.resolved_ips:
                # 可能是通配符解析，需要进一步验证HTTP
                pass
        
        result = self._check_http(domain, ip)
        return result
    
    def detect_wildcard(self) -> WildcardResult:
        """检测DNS通配符"""
        self.wildcard_result = self.dns_validator.detect_wildcard(self.base_domain)
        return self.wildcard_result
    
    def enumerate(self, prefixes: List[str] = None, 
                  check_wildcard: bool = True) -> EnumReport:
        """
        枚举子域名
        
        Args:
            prefixes: 自定义前缀列表，默认使用内置列表
            check_wildcard: 是否先检测通配符
            
        Returns:
            EnumReport 对象
        """
        report = EnumReport(base_domain=self.base_domain)
        
        # 检测通配符
        if check_wildcard:
            print(f"[*] 检测DNS通配符: {self.base_domain}")
            self.detect_wildcard()
            report.has_wildcard = self.wildcard_result.has_wildcard
            if self.wildcard_result.has_wildcard:
                report.wildcard_ips = set(self.wildcard_result.resolved_ips)
                print(f"    ⚠️ 检测到通配符! IPs: {report.wildcard_ips}")
        
        # 生成域名列表
        if prefixes is None:
            prefixes = self.COMMON_PREFIXES
        
        domains = [f"{p}.{self.base_domain}" for p in prefixes]
        report.total_tested = len(domains)
        
        print(f"[*] 枚举 {len(domains)} 个子域名...")
        
        # 并行检查
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._check_single, d): d for d in domains}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    report.total_resolved += 1
                    report.results.append(result)
                    
                    if result.is_real:
                        report.total_real += 1
                        report.real_domains.append(result)
                    else:
                        report.placeholder_domains.append(result)
        
        print(f"    解析成功: {report.total_resolved}")
        print(f"    真实域名: {report.total_real}")
        print(f"    占位页面: {len(report.placeholder_domains)}")
        
        return report
    
    def deep_enumerate(self, level2_domains: List[str] = None) -> EnumReport:
        """
        深度枚举 (包含三级子域名)
        
        Args:
            level2_domains: 要枚举三级子域名的二级域名列表
            
        Returns:
            EnumReport 对象
        """
        # 先枚举二级子域名
        report = self.enumerate()
        
        # 选择要深入的二级域名
        if level2_domains is None:
            # 默认选择真实的二级域名
            level2_domains = [r.domain for r in report.real_domains[:5]]
        
        if not level2_domains:
            return report
        
        print(f"\n[*] 深度枚举三级子域名...")
        
        # 枚举三级子域名
        for level2 in level2_domains:
            level3_domains = [f"{p}.{level2}" for p in self.LEVEL3_PREFIXES]
            
            print(f"    {level2}: 测试 {len(level3_domains)} 个三级子域名")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self._check_single, d): d for d in level3_domains}
                
                found = 0
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        report.total_resolved += 1
                        report.results.append(result)
                        found += 1
                        
                        if result.is_real:
                            report.total_real += 1
                            report.real_domains.append(result)
                        else:
                            report.placeholder_domains.append(result)
                
                print(f"      发现: {found} 个")
        
        report.total_tested += len(level2_domains) * len(self.LEVEL3_PREFIXES)
        
        return report
    
    def get_ct_domains(self) -> List[str]:
        """从证书透明度日志获取域名"""
        print(f"[*] 查询CT Logs: {self.base_domain}")
        
        try:
            url = f"https://crt.sh/?q=%.{self.base_domain}&output=json"
            resp = requests.get(url, timeout=30)
            
            if resp.status_code == 200:
                data = resp.json()
                domains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for d in name.split("\n"):
                        d = d.strip().lower()
                        if d and d.endswith(self.base_domain) and "*" not in d:
                            domains.add(d)
                
                print(f"    发现 {len(domains)} 个域名")
                return sorted(domains)
        except Exception as e:
            print(f"    错误: {e}")
        
        return []
    
    def get_real_domains(self) -> List[SubdomainResult]:
        """获取真实域名列表"""
        report = self.enumerate()
        return report.real_domains


# 便捷函数
def enum_subdomains(base_domain: str, deep: bool = False) -> EnumReport:
    """快速枚举子域名"""
    enum = SubdomainEnum(base_domain)
    if deep:
        return enum.deep_enumerate()
    return enum.enumerate()
