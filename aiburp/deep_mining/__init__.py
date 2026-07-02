"""
aiburp/deep_mining — 深度挖掘 + LLM 决策中枢.

Layer 1.5-7 (URL 模板去重 / HTML / JS+CSS+模板 / 响应头 / 主动探查 /
              隐藏参数 / session 隔离) + 3 轮 LLM 收敛决策.
"""
from .url_template import url_to_template, cluster_urls, representatives
from .html_parser import parse_html, extract_form_endpoints
from .asset_extractor import AssetExtractor, extract_endpoints
from .header_parser import parse_response_headers, is_api_endpoint, is_spa_hint
from .active_probe import probe_active, probe_active_sync, WELL_KNOWN_PATHS
from .hidden_param import infer_hidden_params
from .session_manager import SessionManager
from .llm_decider import LLMDecider
from .mining_loop import DeepMiningLoop

__all__ = [
    "url_to_template", "cluster_urls", "representatives",
    "parse_html", "extract_form_endpoints",
    "AssetExtractor", "extract_endpoints",
    "parse_response_headers", "is_api_endpoint", "is_spa_hint",
    "probe_active", "probe_active_sync", "WELL_KNOWN_PATHS",
    "infer_hidden_params",
    "SessionManager",
    "LLMDecider",
    "DeepMiningLoop",
]