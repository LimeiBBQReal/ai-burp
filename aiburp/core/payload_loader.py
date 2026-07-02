"""
Payload 字典加载器

从 payloads/ 目录加载 payload 文件，支持缓存和按需加载。
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
from functools import lru_cache


class PayloadLoader:
    """Payload 字典加载器"""
    
    def __init__(self, base_dir: str = None):
        """
        初始化加载器
        
        Args:
            base_dir: payloads 目录路径，默认为 aiburp/payloads/
        """
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # 默认路径: aiburp 包同级的 payloads 目录
            self.base_dir = Path(__file__).parent.parent.parent / "payloads"
        
        self._cache: Dict[str, List[str]] = {}
    
    def load(self, category: str, name: str) -> List[str]:
        """
        加载指定字典文件
        
        Args:
            category: 分类目录 (sqli, xss, ssrf, etc.)
            name: 文件名 (不含 .txt 后缀)
        
        Returns:
            payload 列表
        
        Example:
            loader.load("sqli", "quick")  # 加载 payloads/sqli/quick.txt
        """
        cache_key = f"{category}/{name}"
        
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        file_path = self.base_dir / category / f"{name}.txt"
        payloads = self._read_file(file_path)
        
        self._cache[cache_key] = payloads
        return payloads
    
    def load_all(self, category: str) -> Dict[str, List[str]]:
        """
        加载分类目录下所有字典文件
        
        Args:
            category: 分类目录
        
        Returns:
            {文件名: payload列表} 字典
        """
        result = {}
        category_dir = self.base_dir / category
        
        if not category_dir.exists():
            return result
        
        for file_path in category_dir.glob("*.txt"):
            name = file_path.stem
            result[name] = self.load(category, name)
        
        return result
    
    def load_merged(self, category: str, names: List[str] = None) -> List[str]:
        """
        合并加载多个字典文件
        
        Args:
            category: 分类目录
            names: 文件名列表，None 表示加载全部
        
        Returns:
            合并后的 payload 列表 (去重)
        """
        if names is None:
            all_files = self.load_all(category)
            merged = []
            for payloads in all_files.values():
                merged.extend(payloads)
        else:
            merged = []
            for name in names:
                merged.extend(self.load(category, name))
        
        # 去重但保持顺序
        seen = set()
        result = []
        for p in merged:
            if p not in seen:
                seen.add(p)
                result.append(p)
        
        return result
    
    def list_categories(self) -> List[str]:
        """列出所有分类目录"""
        if not self.base_dir.exists():
            return []
        
        return [d.name for d in self.base_dir.iterdir() 
                if d.is_dir() and not d.name.startswith(('.', '_'))]
    
    def list_files(self, category: str) -> List[str]:
        """列出分类下所有字典文件"""
        category_dir = self.base_dir / category
        
        if not category_dir.exists():
            return []
        
        return [f.stem for f in category_dir.glob("*.txt")]
    
    def _read_file(self, file_path: Path) -> List[str]:
        """读取字典文件"""
        if not file_path.exists():
            return []
        
        payloads = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\n\r')
                    # 跳过空行和注释
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except Exception:
            pass
        
        return payloads
    
    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()
    
    def stats(self) -> Dict:
        """返回字典统计信息"""
        stats = {
            "categories": {},
            "total_files": 0,
            "total_payloads": 0,
            "cached": len(self._cache),
        }
        
        for category in self.list_categories():
            files = self.list_files(category)
            payload_count = 0
            for name in files:
                payload_count += len(self.load(category, name))
            
            stats["categories"][category] = {
                "files": len(files),
                "payloads": payload_count,
            }
            stats["total_files"] += len(files)
            stats["total_payloads"] += payload_count
        
        return stats


# 全局单例
_loader: Optional[PayloadLoader] = None


def get_loader() -> PayloadLoader:
    """获取全局 PayloadLoader 实例"""
    global _loader
    if _loader is None:
        _loader = PayloadLoader()
    return _loader


def load(category: str, name: str) -> List[str]:
    """快捷方法: 加载字典"""
    return get_loader().load(category, name)


def load_merged(category: str, names: List[str] = None) -> List[str]:
    """快捷方法: 合并加载"""
    return get_loader().load_merged(category, names)
