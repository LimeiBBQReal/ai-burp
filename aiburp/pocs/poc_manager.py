"""
POC 管理器 - 统一管理五层 POC 体系

使用方式:
    manager = POCManager()
    
    # 按 CVE 查找并执行
    result = manager.run_by_cve("CVE-2024-1234", "https://target.com")
    
    # 按技术栈批量检测
    results = manager.run_by_tech("wordpress", "https://target.com")
    
    # 列出所有可用 POC
    pocs = manager.list_pocs()
"""

import os
import importlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum


class POCLevel(Enum):
    """POC 层级"""
    L1_BUILTIN = 1       # 内置高频
    L2_NUCLEI_AUTO = 2   # Nuclei 自动转换
    L3_NUCLEI_MANUAL = 3 # Nuclei 手工转换
    L4_GITHUB = 4        # GitHub 适配
    L5_CUSTOM = 5        # 全新编写


class Severity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class POCResult:
    """POC 执行结果"""
    poc_id: str
    name: str
    vulnerable: bool
    severity: Severity = Severity.INFO
    evidence: str = ""
    details: Dict = field(default_factory=dict)
    
    def __str__(self):
        status = "🔴 漏洞确认" if self.vulnerable else "✅ 安全"
        return f"[{self.severity.value.upper()}] {self.name}: {status}"
    
    def to_dict(self):
        return {
            "poc_id": self.poc_id,
            "name": self.name,
            "vulnerable": self.vulnerable,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "details": self.details
        }


@dataclass
class POCInfo:
    """POC 元信息"""
    id: str
    name: str
    level: POCLevel
    severity: Severity
    cve: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""
    check_func: Optional[Callable] = None
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "level": self.level.name,
            "severity": self.severity.value,
            "cve": self.cve,
            "tags": self.tags,
            "description": self.description
        }


class POCManager:
    """POC 管理器"""
    
    def __init__(self):
        self.pocs: Dict[str, POCInfo] = {}
        self.cve_index: Dict[str, str] = {}  # CVE -> POC ID
        self.tag_index: Dict[str, List[str]] = {}  # Tag -> POC IDs
        
        # 加载所有 POC
        self._load_builtin_pocs()
    
    def _load_builtin_pocs(self):
        """加载 L1 内置 POC"""
        from .builtin import info_leak, misconfig, cms
        
        # 信息泄露类
        for poc in info_leak.POCS:
            self.register(poc)
        
        # 配置错误类
        for poc in misconfig.POCS:
            self.register(poc)
        
        # CMS 类
        for poc in cms.POCS:
            self.register(poc)
    
    def register(self, poc: POCInfo):
        """注册 POC"""
        self.pocs[poc.id] = poc
        
        # 建立 CVE 索引
        if poc.cve:
            self.cve_index[poc.cve.upper()] = poc.id
        
        # 建立标签索引
        for tag in poc.tags:
            if tag not in self.tag_index:
                self.tag_index[tag] = []
            self.tag_index[tag].append(poc.id)
    
    def run_by_cve(self, cve: str, url: str, **kwargs) -> Optional[POCResult]:
        """按 CVE 编号执行 POC"""
        cve = cve.upper()
        if cve not in self.cve_index:
            return None
        
        poc_id = self.cve_index[cve]
        return self.run(poc_id, url, **kwargs)
    
    def run_by_tag(self, tag: str, url: str, **kwargs) -> List[POCResult]:
        """按标签批量执行 POC"""
        results = []
        tag = tag.lower()
        
        if tag not in self.tag_index:
            return results
        
        for poc_id in self.tag_index[tag]:
            result = self.run(poc_id, url, **kwargs)
            if result:
                results.append(result)
        
        return results
    
    def run(self, poc_id: str, url: str, **kwargs) -> Optional[POCResult]:
        """执行指定 POC"""
        if poc_id not in self.pocs:
            return None
        
        poc = self.pocs[poc_id]
        if not poc.check_func:
            return None
        
        try:
            return poc.check_func(url, **kwargs)
        except Exception as e:
            return POCResult(
                poc_id=poc_id,
                name=poc.name,
                vulnerable=False,
                details={"error": str(e)}
            )
    
    def run_all(self, url: str, tags: List[str] = None, **kwargs) -> List[POCResult]:
        """执行所有匹配的 POC"""
        results = []
        
        if tags:
            # 按标签过滤
            poc_ids = set()
            for tag in tags:
                if tag in self.tag_index:
                    poc_ids.update(self.tag_index[tag])
        else:
            poc_ids = self.pocs.keys()
        
        for poc_id in poc_ids:
            result = self.run(poc_id, url, **kwargs)
            if result:
                results.append(result)
        
        return results
    
    def list_pocs(self, level: POCLevel = None, tag: str = None) -> List[POCInfo]:
        """列出 POC"""
        pocs = list(self.pocs.values())
        
        if level:
            pocs = [p for p in pocs if p.level == level]
        
        if tag:
            tag = tag.lower()
            pocs = [p for p in pocs if tag in p.tags]
        
        return pocs
    
    def search(self, keyword: str) -> List[POCInfo]:
        """搜索 POC"""
        keyword = keyword.lower()
        results = []
        
        for poc in self.pocs.values():
            if (keyword in poc.id.lower() or 
                keyword in poc.name.lower() or
                keyword in poc.description.lower() or
                (poc.cve and keyword in poc.cve.lower())):
                results.append(poc)
        
        return results
    
    def stats(self) -> Dict:
        """统计信息"""
        level_counts = {}
        severity_counts = {}
        
        for poc in self.pocs.values():
            level_counts[poc.level.name] = level_counts.get(poc.level.name, 0) + 1
            severity_counts[poc.severity.value] = severity_counts.get(poc.severity.value, 0) + 1
        
        return {
            "total": len(self.pocs),
            "by_level": level_counts,
            "by_severity": severity_counts,
            "cve_count": len(self.cve_index),
            "tags": list(self.tag_index.keys())
        }
    
    def report(self, results: List[POCResult]) -> str:
        """生成报告"""
        lines = ["=" * 60, "🔍 POC 扫描报告", "=" * 60, ""]
        
        vulns = [r for r in results if r.vulnerable]
        safe = [r for r in results if not r.vulnerable]
        
        if vulns:
            lines.append(f"🔴 发现 {len(vulns)} 个漏洞:")
            lines.append("")
            for r in vulns:
                lines.append(f"  [{r.severity.value.upper()}] {r.name}")
                if r.evidence:
                    lines.append(f"      证据: {r.evidence[:100]}...")
                lines.append("")
        
        lines.append(f"✅ 安全检查: {len(safe)} 项通过")
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)
