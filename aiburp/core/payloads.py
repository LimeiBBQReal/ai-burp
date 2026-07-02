"""
Payload 加载器

统一从 payloads/ 目录加载字典文件
所有插件通过此模块获取 payload，不硬编码
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
from functools import lru_cache


class PayloadLoader:
    """
    Payload 字典加载器
    
    使用示例:
        loader = PayloadLoader()
        
        # 加载单个文件
        payloads = loader.load("sqli/quick.txt")
        
        # 加载多个文件
        payloads = loader.load_multiple(["sqli/quick.txt", "sqli/error_based.txt"])
        
        # 按类型加载
        payloads = loader.get("sqli", "quick")  # sqli/quick.txt
        payloads = loader.get("xss", "bypass")  # xss/bypass.txt
    """
    
    def __init__(self, base_path: str = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            # 默认: aiburp 同级的 payloads 目录
            self.base_path = Path(__file__).parent.parent.parent / "payloads"
    
    @lru_cache(maxsize=100)
    def load(self, filename: str) -> List[str]:
        """
        加载单个字典文件
        
        Args:
            filename: 相对路径 (如 "sqli/quick.txt")
        
        Returns:
            payload 列表
        """
        filepath = self.base_path / filename
        
        if not filepath.exists():
            return []
        
        payloads = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
        except Exception:
            pass
        
        return payloads
    
    def load_multiple(self, filenames: List[str], dedupe: bool = True) -> List[str]:
        """
        加载多个字典文件
        
        Args:
            filenames: 文件路径列表
            dedupe: 是否去重
        
        Returns:
            合并后的 payload 列表
        """
        all_payloads = []
        for filename in filenames:
            all_payloads.extend(self.load(filename))
        
        if dedupe:
            seen = set()
            result = []
            for p in all_payloads:
                if p not in seen:
                    seen.add(p)
                    result.append(p)
            return result
        
        return all_payloads
    
    def get(self, category: str, name: str) -> List[str]:
        """
        按类型加载
        
        Args:
            category: 类型 (sqli, xss, ssrf, etc.)
            name: 文件名 (不含 .txt)
        
        Returns:
            payload 列表
        """
        return self.load(f"{category}/{name}.txt")
    
    def list_files(self, category: str = None) -> List[str]:
        """列出可用的字典文件"""
        if category:
            cat_path = self.base_path / category
            if cat_path.exists():
                return [f.name for f in cat_path.glob("*.txt")]
            return []
        
        # 列出所有
        files = []
        for cat_dir in self.base_path.iterdir():
            if cat_dir.is_dir() and not cat_dir.name.startswith("."):
                for f in cat_dir.glob("*.txt"):
                    files.append(f"{cat_dir.name}/{f.name}")
        return sorted(files)
    
    def list_categories(self) -> List[str]:
        """列出所有类型"""
        return sorted([
            d.name for d in self.base_path.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ])


# 全局单例
_loader = None

def get_loader() -> PayloadLoader:
    """获取全局 PayloadLoader 实例"""
    global _loader
    if _loader is None:
        _loader = PayloadLoader()
    return _loader


# 便捷函数
def load_payloads(filename: str) -> List[str]:
    """加载 payload 文件"""
    return get_loader().load(filename)

def get_payloads(category: str, name: str) -> List[str]:
    """按类型获取 payload"""
    return get_loader().get(category, name)

def list_payload_files(category: str = None) -> List[str]:
    """列出字典文件"""
    return get_loader().list_files(category)
