"""
AI-Burp 代理模块 (aiburp/proxy/)

从 qwen2API/proxy 迁移. 提供代理节点采集/验证/轮换能力.

核心模块:
    MiniClash  — mihomo 代理控制器 (V2Ray/Trojan/Hysteria2)
    NodePool   — IP + 积分池 (并发安全)

用法:
    from aiburp.proxy import MiniClash, NodePool

    mc = MiniClash(config_path="aiburp/proxy/yaml/dola_capable.yaml")
    mc.start()
"""

try:
    from .mini_clash import MiniClash
except ImportError:
    MiniClash = None

try:
    from .node_pool import NodePool
except ImportError:
    NodePool = None

__all__ = ["MiniClash", "NodePool"]
