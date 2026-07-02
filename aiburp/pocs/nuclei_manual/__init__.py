"""
L3: Nuclei 复杂模板手工转换

此目录存放需要手工转换的复杂 Nuclei 模板

复杂模板特征:
- 多步骤请求
- DSL 表达式
- 变量依赖
- 条件逻辑

转换流程:
1. 阅读原始 Nuclei 模板
2. 理解漏洞原理和检测逻辑
3. 手工编写 Python POC
4. 测试验证
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
