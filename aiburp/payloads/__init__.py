# aiburp/payloads/ package — V4 突破口 payload 映射
# 兼容旧导入: 从 payloads.py 重新导出所有符号
import importlib.util
import os

# 加载同级的 payloads.py (不是本包)
_py_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads.py")
_spec = importlib.util.spec_from_file_location("_aiburp_payloads_py", _py_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# 重新导出
Payloads = _mod.Payloads
SQLiPayloads = _mod.SQLiPayloads
BypassPayloads = _mod.BypassPayloads
PayloadFile = _mod.PayloadFile
PayloadCategory = _mod.PayloadCategory
SQLI = _mod.SQLI
XSS = _mod.XSS
LFI = _mod.LFI
SSRF = _mod.SSRF
CMDi = _mod.CMDi
SSTI = _mod.SSTI
Bypass = _mod.Bypass
get_payloads = _mod.get_payloads
