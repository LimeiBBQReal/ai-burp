"""
Recon Pipeline V2 - 大模型接口层

大模型作为核心决策引擎，负责:
1. 资产相关性判断 (替代评分系统)
2. 协议识别判断
3. 响应数据分析
4. 漏洞验证

开发期间由 CatPaw AI 代替，生产环境可接入任何 LLM API。
"""
from .base import BaseLLM, LLMResponse
from .catpaw_backend import CatPawBackend
from .openai_backend import OpenAIBackend

__all__ = ["BaseLLM", "LLMResponse", "CatPawBackend", "OpenAIBackend"]
