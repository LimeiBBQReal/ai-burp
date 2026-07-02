"""
aiburp/rce 包 — RCE 能力确认 / C2 接入(预留).

设计原则:
  - 只确认能力 (time/echo/OOB 三种检测点)
  - 不反弹 shell, 不建 C2
  - 确认成功后写入报告, 等用户拍板
"""
from .confirm import RCEConfirm

__all__ = ["RCEConfirm"]