"""
AI-Burp 端口扫描模块

提供:
- PortScanner: 单目标端口扫描
- NetworkScanner: 网段扫描
"""

import socket
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


# 常用端口
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 1433, 1521, 5432, 6379,
    27017, 9200, 11211, 50000, 161, 162, 389, 636, 873, 1099, 1883,
    2049, 2181, 2375, 2376, 4443, 5000, 5001, 5601, 6000, 6443, 7001,
    7002, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
    8088, 8089, 8090, 8091, 8161, 8443, 8880, 8888, 9000, 9001, 9090,
    9091, 9200, 9300, 9418, 9999, 10000, 10250, 10443, 27018, 28017,
]

# 服务指纹
SERVICE_BANNERS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    27017: "mongodb",
}


@dataclass
class PortInfo:
    """端口信息"""
    port: int
    state: str = "open"
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class ScanResult:
    """扫描结果"""
    host: str
    open_ports: List[PortInfo] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    scan_time: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "open_ports": [
                {"port": p.port, "service": p.service, "banner": p.banner}
                for p in self.open_ports
            ],
            "closed_count": self.closed_count,
            "scan_time": self.scan_time
        }


class PortScanner:
    """端口扫描器"""
    
    def __init__(self, timeout: float = 2.0, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency
    
    def _parse_ports(self, ports: str) -> List[int]:
        """解析端口参数"""
        if ports == "top100":
            return TOP_100_PORTS[:100]
        elif ports == "top1000":
            return list(range(1, 1001))
        elif ports == "all":
            return list(range(1, 65536))
        elif "-" in ports:
            start, end = ports.split("-")
            return list(range(int(start), int(end) + 1))
        elif "," in ports:
            return [int(p) for p in ports.split(",")]
        else:
            return [int(ports)]
    
    def _check_port(self, host: str, port: int) -> Optional[PortInfo]:
        """检查单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                service = SERVICE_BANNERS.get(port, "unknown")
                banner = ""
                
                # 尝试获取 banner
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                except:
                    pass
                
                sock.close()
                return PortInfo(port=port, service=service, banner=banner)
            
            sock.close()
            return None
            
        except Exception:
            return None
    
    def scan(self, host: str, ports: str = "top100") -> ScanResult:
        """扫描目标"""
        import time
        start_time = time.time()
        
        port_list = self._parse_ports(ports)
        open_ports = []
        closed_count = 0
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port
                for port in port_list
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                else:
                    closed_count += 1
        
        # 按端口排序
        open_ports.sort(key=lambda x: x.port)
        
        return ScanResult(
            host=host,
            open_ports=open_ports,
            closed_count=closed_count,
            scan_time=time.time() - start_time
        )


class NetworkScanner:
    """网段扫描器"""
    
    def __init__(self, timeout: float = 2.0, concurrency: int = 500):
        self.timeout = timeout
        self.concurrency = concurrency
        self.port_scanner = PortScanner(timeout=timeout, concurrency=50)
    
    def _parse_cidr(self, cidr: str) -> List[str]:
        """解析 CIDR"""
        import ipaddress
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            return [cidr]
    
    def scan_range(self, cidr: str, ports: str = "top100") -> List[ScanResult]:
        """扫描网段"""
        hosts = self._parse_cidr(cidr)
        results = []
        
        for host in hosts:
            result = self.port_scanner.scan(host, ports)
            if result.open_ports:
                results.append(result)
        
        return results


def report(results: List[ScanResult]) -> str:
    """生成报告"""
    lines = [
        "=" * 60,
        "🔍 端口扫描报告",
        "=" * 60,
        ""
    ]
    
    total_open = 0
    for r in results:
        if r.open_ports:
            lines.append(f"🎯 {r.host}")
            for p in r.open_ports:
                lines.append(f"   {p.port}/tcp  {p.service}")
                total_open += 1
            lines.append("")
    
    lines.append("=" * 60)
    lines.append(f"总计: {len(results)} 台主机, {total_open} 个开放端口")
    lines.append("=" * 60)
    
    return "\n".join(lines)
