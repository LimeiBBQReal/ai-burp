"""
L5: 全新 POC 从 CVE 编写

此目录存放完全手工编写的 POC

编写流程:
1. 阅读 CVE 详情和漏洞分析文章
2. 理解漏洞原理
3. 设计检测逻辑
4. 编写 Python POC
5. 测试验证

POC 模板:
```python
from ..poc_manager import POCInfo, POCResult, POCLevel, Severity
import requests

def check_cve_xxxx_xxxx(url: str, **kwargs) -> POCResult:
    '''检测 CVE-XXXX-XXXX'''
    try:
        # 检测逻辑
        resp = requests.get(f"{url}/vulnerable/path", timeout=10, verify=False)
        
        if "vulnerable_indicator" in resp.text:
            return POCResult(
                poc_id="CVE-XXXX-XXXX",
                name="漏洞名称",
                vulnerable=True,
                severity=Severity.HIGH,
                evidence="证据描述",
                details={"key": "value"}
            )
    except:
        pass
    
    return POCResult(
        poc_id="CVE-XXXX-XXXX",
        name="漏洞名称",
        vulnerable=False
    )

POC_INFO = POCInfo(
    id="CVE-XXXX-XXXX",
    name="漏洞名称",
    level=POCLevel.L5_CUSTOM,
    severity=Severity.HIGH,
    cve="CVE-XXXX-XXXX",
    tags=["tag1", "tag2"],
    description="漏洞描述",
    check_func=check_cve_xxxx_xxxx
)
```
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
