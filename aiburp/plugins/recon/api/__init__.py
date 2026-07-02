"""
外部 API 集成

支持的 API:
- Shodan: IP/端口/服务/漏洞/Favicon
- Censys: 证书搜索/主机搜索
- crt.sh: CT Logs 子域名
- SecurityTrails: 子域名历史/DNS记录
- Fofa: 中国资产搜索
"""

import os
from pathlib import Path
from typing import Optional

# 尝试加载 .env 文件
def load_env():
    """加载 .env 配置"""
    env_path = Path(__file__).parent.parent.parent.parent / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip())

load_env()

def get_api_key(name: str) -> Optional[str]:
    """获取 API Key"""
    return os.environ.get(name)

__all__ = ["get_api_key", "load_env"]
