"""
AI-Burp POC 五层体系

L1: builtin/     - 内置高频 POC (手工精选)
L2: nuclei_auto/ - Nuclei 简单模板自动转换
L3: nuclei_manual/ - Nuclei 复杂模板手工转换
L4: github_adapted/ - GitHub POC 手工适配
L5: custom/      - 全新 POC 从 CVE 编写
"""

from .poc_manager import POCManager, POCResult
from .builtin import info_leak, misconfig, cms

__all__ = ['POCManager', 'POCResult', 'info_leak', 'misconfig', 'cms']
