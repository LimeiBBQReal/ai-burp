"""
L1: 内置高频 POC

分类:
- info_leak: 信息泄露 (phpinfo, .git, .env, backup)
- misconfig: 配置错误 (目录遍历, 默认凭据, debug)
- cms: CMS 漏洞 (WordPress, Drupal, Joomla)
"""

from . import info_leak
from . import misconfig
from . import cms

__all__ = ['info_leak', 'misconfig', 'cms']
