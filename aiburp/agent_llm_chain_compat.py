"""
aiburp/agent_llm_chain_compat.py
LLMChain 兼容性入口 — 避免命名冲突: aiburp/agent.py (文件) vs aiburp/agent/ (目录).
此模块仅做 re-export, 实际实现在 aiburp/agent_llm_chain_impl.py 中.

注意: 整个项目其它地方请用:
    from aiburp.agent_llm_chain_compat import LLMChain
"""
from aiburp.agent_llm_chain_impl import (
    LLMChain,
    LLMUnavailableError,
    _count_tokens,
)  # noqa: F401
