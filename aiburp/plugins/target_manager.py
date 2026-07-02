"""
AI-Burp 批量目标管理 v1.0.0

功能:
1. 导入/导出目标列表
2. 批量指纹识别
3. 批量漏洞扫描
4. 目标状态跟踪
5. 扫描结果汇总

用法:
    # CLI
    aiburp targets import urls.txt --project heritage
    aiburp targets fingerprint --project heritage
    aiburp targets scan --project heritage --types sqli xss
    aiburp targets list --project heritage
    aiburp targets export --project heritage -o targets.json
    
    # Python API
    from aiburp.target_manager import TargetManager
    
    tm = TargetManager("heritage")
    tm.import_urls("urls.txt")
    tm.fingerprint_all()
    tm.scan_all(types=["sqli", "xss"])
    tm.export("results.json")
"""

import json
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse


class TargetStatus(Enum):
    NEW = "new"
    ALIVE = "alive"
    DEAD = "dead"
    SCANNED = "scanned"
    VULNERABLE = "vulnerable"


@dataclass
class Target:
    """目标"""
    url: str
    status: TargetStatus = TargetStatus.NEW
    technologies: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    notes: str = ""
    last_scan: str = ""
    response_code: int = 0
    response_size: int = 0
    response_time: float = 0
    
    def __post_init__(self):
        if isinstance(self.status, str):
            self.status = TargetStatus(self.status)
    
    @property
    def domain(self) -> str:
        parsed = urllib.parse.urlparse(self.url)
        return parsed.netloc
    
    @property
    def path(self) -> str:
        parsed = urllib.parse.urlparse(self.url)
        return parsed.path or "/"
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['status'] = self.status.value
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Target':
        data['status'] = TargetStatus(data['status'])
        return cls(**data)


@dataclass
class ScanResult:
    """扫描结果"""
    target_url: str
    vuln_type: str
    parameter: str
    payload: str
    evidence: str
    severity: str = "medium"
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        return asdict(self)


class TargetManager:
    """
    批量目标管理器
    
    用法:
        tm = TargetManager("heritage")
        
        # 导入目标
        tm.import_urls("urls.txt")
        tm.add_url("https://target.com/api")
        
        # 检查存活
        tm.check_alive()
        
        # 指纹识别
        tm.fingerprint_all()
        
        # 漏洞扫描
        tm.scan_all(types=["sqli", "xss"])
        
        # 查看结果
        tm.print_summary()
        tm.export("results.json")
    """
    
    def __init__(self, project: str = "default", burp=None):
        self.project = project
        self.data_dir = Path.home() / ".aiburp" / project / "targets"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.targets: Dict[str, Target] = {}
        self.results: List[ScanResult] = []
        
        # 延迟导入 Burp
        self._burp = burp
        
        # 加载已保存的目标
        self._load()
    
    @property
    def burp(self):
        if self._burp is None:
            from ..sync_wrapper import SyncBurp as Burp
            self._burp = Burp(project=self.project, delay=1.0)
        return self._burp
    
    def _targets_file(self) -> Path:
        return self.data_dir / "targets.json"
    
    def _results_file(self) -> Path:
        return self.data_dir / "results.json"
    
    def _load(self):
        """加载保存的目标"""
        targets_file = self._targets_file()
        if targets_file.exists():
            try:
                with open(targets_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    target = Target.from_dict(item)
                    self.targets[target.url] = target
            except:
                pass
        
        results_file = self._results_file()
        if results_file.exists():
            try:
                with open(results_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.results = [ScanResult(**item) for item in data]
            except:
                pass
    
    def _save(self):
        """保存目标"""
        with open(self._targets_file(), 'w', encoding='utf-8') as f:
            json.dump([t.to_dict() for t in self.targets.values()], f, indent=2, ensure_ascii=False)
        
        with open(self._results_file(), 'w', encoding='utf-8') as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2, ensure_ascii=False)
    
    def add_url(self, url: str) -> Target:
        """添加单个目标"""
        if url not in self.targets:
            self.targets[url] = Target(url=url)
            self._save()
        return self.targets[url]
    
    def add_urls(self, urls: List[str]) -> int:
        """批量添加目标"""
        count = 0
        for url in urls:
            url = url.strip()
            if url and url not in self.targets:
                self.targets[url] = Target(url=url)
                count += 1
        self._save()
        return count
    
    def import_urls(self, filepath: str) -> int:
        """从文件导入目标"""
        path = Path(filepath)
        if not path.exists():
            print(f"❌ 文件不存在: {filepath}")
            return 0
        
        urls = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # 自动添加协议
                    if not line.startswith(('http://', 'https://')):
                        line = f"https://{line}"
                    urls.append(line)
        
        count = self.add_urls(urls)
        print(f"✅ 导入 {count} 个新目标 (总计 {len(self.targets)} 个)")
        return count
    
    def remove_url(self, url: str) -> bool:
        """移除目标"""
        if url in self.targets:
            del self.targets[url]
            self._save()
            return True
        return False
    
    def clear(self):
        """清空所有目标"""
        self.targets.clear()
        self.results.clear()
        self._save()
    
    def check_alive(self, threads: int = 10) -> Dict[str, int]:
        """
        检查目标存活状态
        
        Returns:
            统计: {"alive": n, "dead": n}
        """
        stats = {"alive": 0, "dead": 0}
        targets = list(self.targets.values())
        
        print(f"🔍 检查 {len(targets)} 个目标存活状态...")
        
        def check_one(target: Target) -> Target:
            try:
                r = self.burp.get(target.url)
                target.response_code = r.status
                target.response_size = r.length
                target.response_time = r.time_ms
                
                if r.ok and r.status < 500:
                    target.status = TargetStatus.ALIVE
                else:
                    target.status = TargetStatus.DEAD
            except:
                target.status = TargetStatus.DEAD
            return target
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_one, t): t for t in targets}
            for future in as_completed(futures):
                target = future.result()
                if target.status == TargetStatus.ALIVE:
                    stats["alive"] += 1
                else:
                    stats["dead"] += 1
        
        self._save()
        print(f"   ✅ 存活: {stats['alive']} | ❌ 死亡: {stats['dead']}")
        return stats

    
    def fingerprint_all(self, threads: int = 5) -> Dict[str, List[str]]:
        """
        批量指纹识别
        
        Returns:
            技术统计: {"PHP": [url1, url2], ...}
        """
        from .fingerprint import TechDetector
        
        alive_targets = [t for t in self.targets.values() if t.status == TargetStatus.ALIVE]
        if not alive_targets:
            print("⚠️ 没有存活的目标，请先运行 check_alive()")
            return {}
        
        print(f"🔍 指纹识别 {len(alive_targets)} 个目标...")
        
        detector = TechDetector()
        tech_stats: Dict[str, List[str]] = {}
        
        def fingerprint_one(target: Target) -> Target:
            try:
                result = detector.detect(target.url)
                target.technologies = [t.name for t in result.technologies]
                
                for tech in target.technologies:
                    if tech not in tech_stats:
                        tech_stats[tech] = []
                    tech_stats[tech].append(target.url)
            except:
                pass
            return target
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(fingerprint_one, t): t for t in alive_targets}
            for i, future in enumerate(as_completed(futures), 1):
                target = future.result()
                if target.technologies:
                    print(f"   [{i}/{len(alive_targets)}] {target.domain}: {', '.join(target.technologies[:3])}")
        
        self._save()
        
        # 打印统计
        print(f"\n📊 技术栈统计:")
        for tech, urls in sorted(tech_stats.items(), key=lambda x: -len(x[1]))[:10]:
            print(f"   {tech}: {len(urls)} 个")
        
        return tech_stats
    
    def scan_all(
        self,
        types: List[str] = None,
        threads: int = 3,
        depth: str = "quick"
    ) -> List[ScanResult]:
        """
        批量漏洞扫描
        
        Args:
            types: 漏洞类型 ["sqli", "xss", "lfi", ...]
            threads: 线程数
            depth: 扫描深度 (quick/normal/full)
        
        Returns:
            扫描结果列表
        """
        from .detectors import VulnScanner
        
        if types is None:
            types = ["sqli", "xss"]
        
        alive_targets = [t for t in self.targets.values() if t.status == TargetStatus.ALIVE]
        if not alive_targets:
            print("⚠️ 没有存活的目标")
            return []
        
        print(f"🎯 扫描 {len(alive_targets)} 个目标 (类型: {', '.join(types)})")
        
        scanner = VulnScanner(self.burp)
        new_results = []
        
        for i, target in enumerate(alive_targets, 1):
            print(f"\n[{i}/{len(alive_targets)}] {target.url}")
            
            # 发现参数
            params = self._discover_params(target.url)
            target.parameters = params
            
            if not params:
                print(f"   ⚠️ 未发现参数")
                continue
            
            print(f"   📝 发现参数: {', '.join(params[:5])}")
            
            # 扫描每个参数
            for param in params[:5]:  # 限制参数数量
                try:
                    findings = scanner.scan(
                        target.url,
                        param,
                        "1",  # 默认值
                        types=types
                    )
                    
                    for finding in findings:
                        result = ScanResult(
                            target_url=target.url,
                            vuln_type=finding.get("type", "unknown"),
                            parameter=param,
                            payload=finding.get("payload", ""),
                            evidence=finding.get("evidence", ""),
                            severity=finding.get("severity", "medium"),
                        )
                        new_results.append(result)
                        self.results.append(result)
                        
                        target.vulnerabilities.append(f"{finding.get('type', 'unknown')}:{param}")
                        target.status = TargetStatus.VULNERABLE
                        
                        print(f"   🔴 {finding.get('type', 'unknown')} in {param}")
                except Exception as e:
                    pass
            
            target.status = TargetStatus.SCANNED if target.status != TargetStatus.VULNERABLE else target.status
            target.last_scan = datetime.now().isoformat()
            
            time.sleep(self.burp.delay)
        
        self._save()
        
        print(f"\n{'='*50}")
        print(f"📊 扫描完成: 发现 {len(new_results)} 个漏洞")
        print(f"{'='*50}")
        
        return new_results
    
    def _discover_params(self, url: str) -> List[str]:
        """发现 URL 参数"""
        params = []
        
        # 从 URL 提取
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        params.extend(query_params.keys())
        
        # 常见参数名
        common_params = ["id", "page", "q", "search", "query", "name", "user", "file", "path", "url", "cat", "category"]
        
        # 测试常见参数
        for param in common_params:
            if param not in params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=1"
                r = self.burp.get(test_url)
                if r.ok and r.status == 200:
                    params.append(param)
                time.sleep(self.burp.delay * 0.5)
        
        return list(set(params))
    
    def get_by_status(self, status: TargetStatus) -> List[Target]:
        """按状态筛选目标"""
        return [t for t in self.targets.values() if t.status == status]
    
    def get_by_tech(self, tech: str) -> List[Target]:
        """按技术栈筛选目标"""
        return [t for t in self.targets.values() if tech.lower() in [t.lower() for t in t.technologies]]
    
    def get_vulnerable(self) -> List[Target]:
        """获取有漏洞的目标"""
        return self.get_by_status(TargetStatus.VULNERABLE)
    
    def list_targets(self) -> List[Target]:
        """列出所有目标"""
        return list(self.targets.values())
    
    def get_summary(self) -> Dict:
        """获取摘要统计"""
        summary = {
            "total": len(self.targets),
            "new": 0,
            "alive": 0,
            "dead": 0,
            "scanned": 0,
            "vulnerable": 0,
            "vulnerabilities": len(self.results),
            "domains": len(set(t.domain for t in self.targets.values())),
        }
        
        for t in self.targets.values():
            summary[t.status.value] += 1
        
        return summary
    
    def print_summary(self):
        """打印摘要"""
        summary = self.get_summary()
        
        print("=" * 50)
        print(f"📊 目标管理器 - {self.project}")
        print("=" * 50)
        print(f"总目标: {summary['total']} ({summary['domains']} 个域名)")
        print(f"  🆕 新增: {summary['new']}")
        print(f"  ✅ 存活: {summary['alive']}")
        print(f"  ❌ 死亡: {summary['dead']}")
        print(f"  🔍 已扫描: {summary['scanned']}")
        print(f"  🔴 有漏洞: {summary['vulnerable']}")
        print(f"\n发现漏洞: {summary['vulnerabilities']} 个")
        print("=" * 50)
    
    def export(self, filepath: str, format: str = "json") -> str:
        """
        导出结果
        
        Args:
            filepath: 输出文件路径
            format: 格式 (json/txt/csv)
        """
        if format == "json":
            data = {
                "project": self.project,
                "exported_at": datetime.now().isoformat(),
                "summary": self.get_summary(),
                "targets": [t.to_dict() for t in self.targets.values()],
                "results": [r.to_dict() for r in self.results],
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        elif format == "txt":
            lines = [
                f"# AI-Burp 目标列表 - {self.project}",
                f"# 导出时间: {datetime.now().isoformat()}",
                f"# 总计: {len(self.targets)} 个目标",
                "",
            ]
            for t in self.targets.values():
                status_icon = {"new": "🆕", "alive": "✅", "dead": "❌", "scanned": "🔍", "vulnerable": "🔴"}.get(t.status.value, "?")
                lines.append(f"{status_icon} {t.url}")
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines))
        
        elif format == "csv":
            import csv
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Status", "Technologies", "Vulnerabilities", "Last Scan"])
                for t in self.targets.values():
                    writer.writerow([
                        t.url,
                        t.status.value,
                        "|".join(t.technologies),
                        "|".join(t.vulnerabilities),
                        t.last_scan,
                    ])
        
        print(f"✅ 已导出: {filepath}")
        return filepath


# 便捷函数
def import_targets(project: str, filepath: str) -> TargetManager:
    """快速导入目标"""
    tm = TargetManager(project)
    tm.import_urls(filepath)
    return tm
