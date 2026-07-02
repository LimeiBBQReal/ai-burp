"""
L4: GitHub POC 手工适配

此目录存放从 GitHub 获取并适配的 POC

适配流程:
1. 使用 GitHubPOCFetcher 搜索 POC
2. 阅读理解原始代码
3. 适配为 AI-Burp POC 格式
4. 修复依赖和兼容性问题
5. 测试验证
"""

import os
import importlib
from ..poc_manager import POCInfo

POCS = []

# 动态加载
_dir = os.path.dirname(__file__)
for _file in os.listdir(_dir):
    if _file.endswith('.py') and not _file.startswith('_'):
        _module_name = _file[:-3]
        try:
            _module = importlib.import_module(f'.{_module_name}', package=__name__)
            if hasattr(_module, 'POC_INFO'):
                POCS.append(_module.POC_INFO)
        except Exception as e:
            pass
