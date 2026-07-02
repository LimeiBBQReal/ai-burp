"""
aiburp/prompts/__init__.py
All-in-One 提示词导出

本子包仅导出流水线相关常量; PromptTemplates 类定义在同级模块 aiburp/prompts.py (历史原因同名).
为兼容旧代码 `from aiburp.prompts import PromptTemplates`, 这里额外提供一个 alias.
"""
import sys as _sys

from .pipeline import (
    PIPELINE_PROMPT,
    PHASE1_PROMPT,
    PHASE2_PROMPT,
    PHASE3_PROMPT,
    PHASE4_PROMPT,
    LLM_JOURNAL_ANALYSIS_PROMPT,
)


def _resolve_prompt_templates():
    """解析真正的 PromptTemplates 类.

    aiburp 包下同时存在 prompts.py (模块, 定义 PromptTemplates 类) 和 prompts/ (子包, 本文件),
    Python 的 import 系统会因为名称冲突只保留其中一个. 在 import aiburp.prompts 时,
    会优先加载子包 (因为目录带 __init__.py), 而 prompts.py 模块就被 shadow 掉了.

    因此 importlib.import_module("aiburp.prompts") 在子包内调用会无限递归.
    解法: 直接通过文件路径加载 prompts.py, 避免走子包路径.
    """
    import importlib.util
    import pathlib
    pkg_root = pathlib.Path(__file__).resolve().parent.parent
    prompts_py = pkg_root / "prompts.py"
    spec = importlib.util.spec_from_file_location(
        "_aiburp_prompts_py_alias", prompts_py
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载 {prompts_py}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "PromptTemplates"):
        raise ImportError("aiburp/prompts.py 未定义 PromptTemplates")
    return mod.PromptTemplates


# 始终在 __init__ 阶段解析, 避免后续属性访问触发递归.
PromptTemplates = _resolve_prompt_templates()

__all__ = [
    "PIPELINE_PROMPT",
    "PHASE1_PROMPT",
    "PHASE2_PROMPT",
    "PHASE3_PROMPT",
    "PHASE4_PROMPT",
    "LLM_JOURNAL_ANALYSIS_PROMPT",
    "PromptTemplates",
]
