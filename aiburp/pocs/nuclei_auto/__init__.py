"""
L2: Nuclei 简单模板自动转换

此目录存放由 nuclei2py 转换器自动生成的 POC

使用方式:
    from aiburp.pocs.converters import NucleiConverter
    
    converter = NucleiConverter()
    converter.convert_directory(
        "path/to/nuclei-templates/cves/",
        "aiburp/pocs/nuclei_auto/",
        severity_filter=["critical", "high"]
    )
"""

# 自动加载此目录下的所有 POC
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
