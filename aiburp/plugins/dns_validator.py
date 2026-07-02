"""
AI-Burp DNS 验证模块 v0.1.0

基于 Heritage IBT 实战经验开发

功能:
1. DNS 通配符检测
2. 保留IP段识别 (198.18.0.0/15, 10.x, 192.168.x 等)
3. 真实域名 vs 假域名区分
4. 多DNS服务器对比验证
5. 蜜罐/欺骗检测

使用:
    from aiburp import DNSValidator
    
    validator = DNSValidator()
    
    # 检查单个域名
    result = validator.check_domain("training.example.com")
    
    # 批量验证子域名
    real_domains = validator.filter_real_domains(["sub1.example.com", "sub2.example.com"])
    
    # 检测DNS通配符
    has_wildcard = validator.detect_wildcard("example.com")
"""

import socket
import subprocess
import random
import string
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import re


@dataclass
class DNSResult:
    """DNS验证结果"""
    domain: str
    local_ip: Optional[str] = None
    external_ip: Optional[str] = None
    is_reserved_ip: bool = False
    ip_type: str = ""  # public, private, reserved, bogon
    is_real: bool = True
    confidence: float = 1.0
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "local_ip": self.local_ip,
            "external_ip": self.external_ip,
            "is_reserved_ip": self.is_reserved_ip,
            "ip_type": self.ip_type,
            "is_real": self.is_real,
            "confidence": self.confidence,
            "notes": self.notes,
        }


@dataclass
class WildcardResult:
    """通配符检测结果"""
    domain: str
    has_wildcard: bool = False
    wildcard_ip: Optional[str] = None
    test_domains: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class DNSValidator:
    """
    DNS 验证器
    
    检测:
    1. DNS通配符配置
    2. 保留/私有IP段
    3. DNS劫持/欺骗
    4. 蜜罐环境
    """
    
    # IANA 保留IP段
    RESERVED_RANGES = [
        ("0.0.0.0", "0.255.255.255", "This Network"),
        ("10.0.0.0", "10.255.255.255", "Private (RFC 1918)"),
        ("100.64.0.0", "100.127.255.255", "Shared Address Space"),
        ("127.0.0.0", "127.255.255.255", "Loopback"),
        ("169.254.0.0", "169.254.255.255", "Link Local"),
        ("172.16.0.0", "172.31.255.255", "Private (RFC 1918)"),
        ("192.0.0.0", "192.0.0.255", "IETF Protocol"),
        ("192.0.2.0", "192.0.2.255", "TEST-NET-1"),
        ("192.168.0.0", "192.168.255.255", "Private (RFC 1918)"),
        ("198.18.0.0", "198.19.255.255", "Benchmarking (RFC 2544)"),  # Heritage IBT 用的就是这个!
        ("198.51.100.0", "198.51.100.255", "TEST-NET-2"),
        ("203.0.113.0", "203.0.113.255", "TEST-NET-3"),
        ("224.0.0.0", "239.255.255.255", "Multicast"),
        ("240.0.0.0", "255.255.255.255", "Reserved"),
    ]
    
    # 外部DNS服务器
    EXTERNAL_DNS = [
        "8.8.8.8",      # Google
        "1.1.1.1",      # Cloudflare
        "9.9.9.9",      # Quad9
        "208.67.222.222",  # OpenDNS
    ]
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def _ip_to_int(self, ip: str) -> int:
        """IP转整数"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def _check_ip_type(self, ip: str) -> Tuple[str, str]:
        """
        检查IP类型
        
        Returns:
            (type, description)
        """
        if not ip:
            return ("none", "No IP")
        
        try:
            ip_int = self._ip_to_int(ip)
            
            for start, end, desc in self.RESERVED_RANGES:
                start_int = self._ip_to_int(start)
                end_int = self._ip_to_int(end)
                
                if start_int <= ip_int <= end_int:
                    return ("reserved", desc)
            
            return ("public", "Public IP")
            
        except Exception:
            return ("invalid", "Invalid IP")
    
    def _resolve_local(self, domain: str) -> Optional[str]:
        """本地DNS解析"""
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def _resolve_external(self, domain: str, dns_server: str = "8.8.8.8") -> Optional[str]:
        """使用外部DNS解析"""
        try:
            result = subprocess.check_output(
                ["nslookup", domain, dns_server],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL
            ).decode()
            
            # 解析结果
            lines = result.split("\n")
            for i, line in enumerate(lines):
                if "Address:" in line and i > 1:
                    ip = line.split(":")[-1].strip()
                    # 跳过DNS服务器自己的IP
                    if ip and not ip.startswith(dns_server.split('.')[0]):
                        return ip
        except:
            pass
        return None
    
    def _generate_random_subdomain(self, base_domain: str) -> str:
        """生成随机子域名用于通配符检测"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        return f"{random_str}.{base_domain}"
    
    def check_domain(self, domain: str) -> DNSResult:
        """
        检查单个域名的DNS真实性
        
        Args:
            domain: 要检查的域名
            
        Returns:
            DNSResult 对象
        """
        result = DNSResult(domain=domain)
        
        # 本地解析
        result.local_ip = self._resolve_local(domain)
        
        # 外部解析 (使用多个DNS服务器)
        for dns in self.EXTERNAL_DNS[:2]:
            result.external_ip = self._resolve_external(domain, dns)
            if result.external_ip:
                break
        
        # 检查IP类型
        ip_to_check = result.local_ip or result.external_ip
        if ip_to_check:
            ip_type, desc = self._check_ip_type(ip_to_check)
            result.ip_type = ip_type
            
            if ip_type == "reserved":
                result.is_reserved_ip = True
                result.notes.append(f"⚠️ IP在保留段: {desc}")
                result.confidence *= 0.5
            elif ip_type == "private":
                result.is_reserved_ip = True
                result.notes.append(f"⚠️ 私有IP: {desc}")
                result.confidence *= 0.3
        
        # 检查本地和外部DNS是否一致
        if result.local_ip and result.external_ip:
            if result.local_ip != result.external_ip:
                result.notes.append(f"⚠️ DNS不一致: 本地={result.local_ip}, 外部={result.external_ip}")
                result.confidence *= 0.7
        
        # 判断是否真实
        if result.confidence < 0.5:
            result.is_real = False
        
        return result
    
    def detect_wildcard(self, base_domain: str, test_count: int = 3) -> WildcardResult:
        """
        检测DNS通配符配置
        
        Args:
            base_domain: 基础域名 (如 example.com)
            test_count: 测试的随机域名数量
            
        Returns:
            WildcardResult 对象
        """
        result = WildcardResult(domain=base_domain)
        
        # 生成随机子域名
        for _ in range(test_count):
            random_domain = self._generate_random_subdomain(base_domain)
            result.test_domains.append(random_domain)
            
            ip = self._resolve_local(random_domain)
            if ip:
                result.resolved_ips.append(ip)
        
        # 如果随机域名都能解析，说明有通配符
        if len(result.resolved_ips) == test_count:
            result.has_wildcard = True
            
            # 检查是否都解析到同一个IP
            unique_ips = set(result.resolved_ips)
            if len(unique_ips) == 1:
                result.wildcard_ip = result.resolved_ips[0]
                result.notes.append(f"🔴 检测到DNS通配符，所有随机域名解析到: {result.wildcard_ip}")
            else:
                result.notes.append(f"🔴 检测到DNS通配符，解析到多个IP: {unique_ips}")
        elif len(result.resolved_ips) > 0:
            result.has_wildcard = True
            result.notes.append(f"⚠️ 部分随机域名可解析 ({len(result.resolved_ips)}/{test_count})")
        else:
            result.notes.append("✅ 未检测到DNS通配符")
        
        return result
    
    def filter_real_domains(self, domains: List[str], 
                           check_wildcard: bool = True,
                           check_http: bool = True,
                           max_workers: int = 20) -> Tuple[List[str], List[str]]:
        """
        过滤出真实域名
        
        Args:
            domains: 域名列表
            check_wildcard: 是否检查通配符
            check_http: 是否检查HTTP响应
            max_workers: 并行线程数
            
        Returns:
            (real_domains, fake_domains)
        """
        real_domains = []
        fake_domains = []
        
        # 先检测通配符
        if check_wildcard and domains:
            base_domain = '.'.join(domains[0].split('.')[-2:])
            wildcard = self.detect_wildcard(base_domain)
            
            if wildcard.has_wildcard:
                print(f"⚠️ 检测到DNS通配符: {base_domain}")
                print(f"   {wildcard.notes[0] if wildcard.notes else ''}")
        
        # 并行检查域名
        def check_single(domain: str) -> Tuple[str, bool, str]:
            result = self.check_domain(domain)
            
            # 如果IP在保留段，需要进一步验证HTTP
            if result.is_reserved_ip and check_http:
                has_real_http = self._check_http_response(domain)
                if has_real_http:
                    return (domain, True, "HTTP响应真实")
                else:
                    return (domain, False, "保留IP且无真实HTTP响应")
            
            return (domain, result.is_real, "; ".join(result.notes))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_single, d): d for d in domains}
            
            for future in concurrent.futures.as_completed(futures):
                domain, is_real, reason = future.result()
                if is_real:
                    real_domains.append(domain)
                else:
                    fake_domains.append(domain)
        
        return real_domains, fake_domains
    
    def _check_http_response(self, domain: str) -> bool:
        """检查是否有真实的HTTP响应"""
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            
            # 尝试HTTPS
            resp = requests.get(f"https://{domain}", timeout=self.timeout, verify=False)
            
            # 检查是否是占位页面
            placeholder_patterns = [
                "under development",
                "coming soon",
                "under construction",
                "site is not available",
                "default page",
            ]
            
            text_lower = resp.text.lower()
            for pattern in placeholder_patterns:
                if pattern in text_lower and len(resp.text) < 5000:
                    return False
            
            # 有实质内容
            if len(resp.text) > 1000:
                return True
            
            # 检查是否有重定向到真实页面
            if resp.status_code in [301, 302, 303] and resp.headers.get("Location"):
                return True
            
            return False
            
        except:
            return False
    
    def analyze_subdomain_batch(self, domains: List[str]) -> Dict:
        """
        批量分析子域名
        
        Returns:
            分析报告字典
        """
        report = {
            "total": len(domains),
            "real": [],
            "fake": [],
            "reserved_ip": [],
            "wildcard_detected": False,
            "ip_distribution": {},
            "recommendations": [],
        }
        
        # 检测通配符
        if domains:
            base_domain = '.'.join(domains[0].split('.')[-2:])
            wildcard = self.detect_wildcard(base_domain)
            report["wildcard_detected"] = wildcard.has_wildcard
            
            if wildcard.has_wildcard:
                report["recommendations"].append(
                    "⚠️ 检测到DNS通配符，大量子域名可能是假的"
                )
        
        # 检查每个域名
        for domain in domains:
            result = self.check_domain(domain)
            
            # IP分布统计
            if result.local_ip:
                prefix = '.'.join(result.local_ip.split('.')[:2])
                report["ip_distribution"][prefix] = report["ip_distribution"].get(prefix, 0) + 1
            
            if result.is_reserved_ip:
                report["reserved_ip"].append(domain)
            
            if result.is_real:
                report["real"].append(domain)
            else:
                report["fake"].append(domain)
        
        # 生成建议
        if report["reserved_ip"]:
            report["recommendations"].append(
                f"🔴 {len(report['reserved_ip'])} 个域名解析到保留IP段"
            )
        
        if len(report["ip_distribution"]) == 1:
            report["recommendations"].append(
                "⚠️ 所有域名解析到同一IP段，可能是蜜罐或测试环境"
            )
        
        return report


# 便捷函数
def validate_dns(domain: str) -> DNSResult:
    """快速验证单个域名"""
    return DNSValidator().check_domain(domain)


def check_wildcard(base_domain: str) -> WildcardResult:
    """快速检测通配符"""
    return DNSValidator().detect_wildcard(base_domain)


def filter_real(domains: List[str]) -> Tuple[List[str], List[str]]:
    """快速过滤真实域名"""
    return DNSValidator().filter_real_domains(domains)
