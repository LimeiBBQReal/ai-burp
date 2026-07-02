"""
扫描插件包

包含各种漏洞检测插件，所有 payload 从 payloads/ 字典加载
"""

from .sqli import SQLiPlugin
from .xss import XSSPlugin
from .ssrf import SSRFPlugin
from .ssti import SSTIPlugin
from .lfi import LFIPlugin
from .cmdi import CMDiPlugin
from .nosqli import NoSQLiPlugin
from .xxe import XXEPlugin
from .redirect import RedirectPlugin
from .crlf import CRLFPlugin
from .cors import CORSPlugin

__all__ = [
    "SQLiPlugin",
    "XSSPlugin", 
    "SSRFPlugin",
    "SSTIPlugin",
    "LFIPlugin",
    "CMDiPlugin",
    "NoSQLiPlugin",
    "XXEPlugin",
    "RedirectPlugin",
    "CRLFPlugin",
    "CORSPlugin",
]
