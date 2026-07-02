"""
aiburp/deep_mining/llm_decider.py
LLM 决策调用 — 3 轮收敛 (聚类 → 方向 → 收敛).

设计原则 (Fail-Fast):
  - LLM 是硬依赖, 不是可选增强
  - 任何一轮 LLM 不可用 → 立即 raise LLMUnavailableError
  - 上层 (mining_loop / pipeline) 捕获后中止整个流程
  - 不允许静默 fallback 到启发式 (用户要求的安全冗余设计)

3 轮决策:
  Round 1: 聚类 + value 标签
  Round 2: 方向决策
  Round 3: 收敛决策
"""
import json
import logging
import re
from pathlib import Path
from typing import Dict, List

from .url_template import cluster_urls

log = logging.getLogger("aiburp.deep_mining.llm_decider")


_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    p = _PROMPTS_DIR / name
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


def _format_candidates(urls: List[str], max_show: int = 200) -> str:
    if len(urls) > max_show:
        urls = urls[:max_show]
        suffix = f"\n... (省略 {len(urls)} 条)"
    else:
        suffix = ""
    return "\n".join(f"- {u}" for u in urls) + suffix


def _safe_json_parse(text: str):
    """LLM 输出可能含 markdown 围栏, 容忍提取."""
    if not text:
        return None
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    try:
        return json.loads(text)
    except Exception:
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                return json.loads(text[start:end + 1])
        except Exception:
            pass
    return None


class LLMDecider:
    """
    3 轮决策 (LLM 硬依赖, 失败时 raise 不 fallback).
    """

    def __init__(self, llm_chain):
        """
        Args:
            llm_chain: LLMChain 实例. 不可为 None — 上层必须保证 LLM 可用.
        """
        if llm_chain is None:
            raise ValueError(
                "LLMDecider 需要 LLMChain 实例 (LLM 是硬依赖). "
                "请先调用 LLMChain.assert_available() 通过再构造 decider."
            )
        self.llm = llm_chain

    def assert_available(self) -> None:
        """预检 LLM 链路. 不可用时 raise LLMUnavailableError."""
        self.llm.assert_available()

    def decide_round_1(self, candidates: List[str],
                       layer_signals: Dict) -> Dict:
        """
        Round 1: 聚类 + 打价值标签.

        Returns:
            {
              "clusters": [...],
              "must_probe": [...],
              "skip": [...],
              "summary": "..."
            }

        Raises:
            LLMUnavailableError: LLM 调用失败 (fail-fast)
            ValueError: LLM 输出无法解析为 JSON
        """
        ctx = {
            "candidates": _format_candidates(candidates).replace("{", "{{").replace("}", "}}"),
            "form_count": layer_signals.get("form_count", 0),
            "asset_count": layer_signals.get("asset_count", 0),
            "header_link_count": layer_signals.get("header_link_count", 0),
            "active_probe_count": layer_signals.get("active_probe_count", 0),
            "hidden_param_count": layer_signals.get("hidden_param_count", 0),
            "context": layer_signals.get("context", "无额外上下文").replace("{", "{{").replace("}", "}}"),
        }

        prompt = _load_prompt("cluster_decision.md").format(**ctx)

        # Fail-fast: LLM 不可用直接 raise, 不静默 fallback
        result = self.llm.ask(prompt)
        parsed = _safe_json_parse(result.get("response", ""))
        if not parsed or "clusters" not in parsed:
            raise ValueError(
                f"[LLMDecider] Round 1 LLM 输出无法解析: "
                f"{result.get('response', '')[:200]}"
            )
        return parsed

    def decide_round_2(self, round1: Dict, new_assets: List[str],
                       current_high: List[str],
                       candidate_count: int) -> Dict:
        """
        Round 2: 方向决策. 失败时 raise LLMUnavailableError.
        """
        ctx = {
            "round1_summary": json.dumps(round1, ensure_ascii=False)[:2000],
            "new_assets": _format_candidates(new_assets, max_show=50),
            "current_high": _format_candidates(current_high, max_show=50),
            "candidate_count": candidate_count,
        }
        prompt = _load_prompt("direction_decision.md").format(**ctx)

        result = self.llm.ask(prompt)
        parsed = _safe_json_parse(result.get("response", ""))
        if not parsed or "continue" not in parsed:
            raise ValueError(
                f"[LLMDecider] Round 2 LLM 输出无法解析: "
                f"{result.get('response', '')[:200]}"
            )
        return parsed

    def decide_round_3(self, round2: Dict, accumulated_high: List[str],
                       candidate_count: int) -> Dict:
        """
        Round 3: 收敛决策. 失败时 raise LLMUnavailableError.
        """
        ctx = {
            "round2_summary": json.dumps(round2, ensure_ascii=False)[:1500],
            "accumulated_high": _format_candidates(accumulated_high, max_show=80),
            "candidate_count": candidate_count,
        }
        prompt = _load_prompt("convergence_decision.md").format(**ctx)

        result = self.llm.ask(prompt)
        parsed = _safe_json_parse(result.get("response", ""))
        if not parsed or "converged" not in parsed:
            raise ValueError(
                f"[LLMDecider] Round 3 LLM 输出无法解析: "
                f"{result.get('response', '')[:200]}"
            )
        if "final_high_list" not in parsed:
            parsed["final_high_list"] = accumulated_high
        return parsed