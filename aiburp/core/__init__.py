"""
AIBURP Core - 核心模块

流量是一切的起点，AI 是决策中心
"""

from .models import Request, Response, Finding, PageView
from .history import History
from .repeater import Repeater, VulnResult, CompareResult, FuzzResult
from .intruder import Intruder, AttackResult, AttackReport
from .asset_graph import AssetGraph, Asset, Relation
from .auth_manager import AuthManager, Account
from .proxy import Proxy, ProxyConfig, InterceptRule, create_proxy
from .reporter import Reporter, ReportConfig, create_report
from .oob import InteractshClient, OOBManager, OOBCallback, create_oob
from .payload_loader import PayloadLoader, get_loader, load, load_merged
from .param_analyzer import ParamAnalyzer, ParamAnalysis, RequestAnalysis
from .traffic_diff import TrafficDiff, ParamVariation, ResponseVariation, TrafficDiffResult, CrossEndpointResult
from .traffic_manager import TrafficManager
from .ai_helper import AIHelper, ActionSuggestion, TestSuggestion, ResponseAnalysis, PrioritizedRequest

__all__ = [
    # 数据模型
    "Request",
    "Response",
    "Finding",
    "PageView",
    # 核心功能
    "History",
    "Repeater",
    "VulnResult",
    "CompareResult",
    "FuzzResult",
    "Intruder",
    "AttackResult",
    "AttackReport",
    # 增强模块
    "AssetGraph",
    "Asset",
    "Relation",
    "AuthManager",
    "Account",
    # 代理
    "Proxy",
    "ProxyConfig",
    "InterceptRule",
    "create_proxy",
    # 报告
    "Reporter",
    "ReportConfig",
    "create_report",
    # OOB 外带
    "InteractshClient",
    "OOBManager",
    "OOBCallback",
    "create_oob",
    # Payload 加载
    "PayloadLoader",
    "get_loader",
    "load",
    "load_merged",
    # 参数分析
    "ParamAnalyzer",
    "ParamAnalysis",
    "RequestAnalysis",
    # 流量对比
    "TrafficDiff",
    "ParamVariation",
    "ResponseVariation",
    "TrafficDiffResult",
    "CrossEndpointResult",
    # 流量查询
    "TrafficManager",
    # AI 决策辅助
    "AIHelper",
    "ActionSuggestion",
    "TestSuggestion",
    "ResponseAnalysis",
    "PrioritizedRequest",
]
