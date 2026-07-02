"""
AI-Burp 插件模块

这里包含非核心但有用的功能模块。
可以按需导入。

使用方式：
    from aiburp.plugins import recon, subdomain, browser
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class PluginResult:
    """插件执行结果"""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


class AuxPlugin:
    """辅助插件基类"""
    name: str = "base"
    description: str = ""
    
    def execute(self, **kwargs) -> PluginResult:
        raise NotImplementedError


# 可用插件列表
__all__ = [
    "AuxPlugin",
    "PluginResult",
    "recon",
    "subdomain", 
    "dns_validator",
    "browser",
    "deep_analysis",
    "discovery",
    "extractor",
    "fuzzer",
    "param_discover",
    "report_generator",
    "smart_payload",
    "specialized_scanners",
    "target_manager",
]

