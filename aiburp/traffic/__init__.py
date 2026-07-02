"""
AI-Burp V4 - Traffic Layer (统一协议模型 UPM)

"ALL-IN-TRAFFIC": 所有流量接口 (HTTP/HTTPS/TCP/UDP/DNS/WebSocket/TLS...) 都可以
成为渗透的起点。本包把任意协议的渗透交互抽象成统一的 5 个原语:

    Probe   - 探活 / 指纹
    Send    - 注入请求
    Reflect - 直接回显
    OOB     - 外带回显 (与 core.oob 联动)
    State   - 协议会话状态机

核心抽象:
    TrafficRequest  - 任意协议的请求
    TrafficResponse - 任意协议的响应 (是 aiburp.Response 的超集)
    ProtocolAdapter - 协议适配器基类
    TrafficEngine   - 统一流量引擎 (对外入口)

设计原则 (三条红线, 与 V3 兼容):
    1. 不破坏现有 HTTP API  - AsyncBurp/Response 对外行为不变
    2. Decision/KB/OOB 复用 - 决策层协议无关, 一套通用
    3. 渐进式              - 每个协议 adapter 独立可测

快速开始:

    from aiburp.traffic import TrafficEngine, TrafficRequest

    async with TrafficEngine() as engine:
        # 自动协议识别
        decision = await engine.smart_probe("example.com:6379")

        # 手动指定协议
        req = TrafficRequest(protocol="tcp", target="example.com:6379",
                             payload=b"PING\\r\\n")
        resp = await engine.send(req)
        print(resp.banner, resp.text)
"""

from .base import (
    # 数据结构
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
    ProtocolError,
)
from .engine import TrafficEngine
from .oob_channel import OOBChannel, OOBCallbackUnified
from .scan_result import ScanResult, AssetEntry
from .deep_collector import DeepCollector, DeepCollectResult
from .logic_vuln import LogicVulnScanner, LogicScanResult, LogicVulnFinding
from .waf_bypass import WAFBypass, BypassResult
from .jwt_tool import JWTTool, JWTParts
from .exploits import ExploitManager
from .attack_chain import AttackChain, AttackChainResult, AttackStep, Phase

from .anti_trace import AntiTrace, TraceRiskReport
from .report_generator_v4 import ReportGenerator
from .revshell import ReverseShellGenerator
from .docker_exploit import docker_rce, kubelet_rce
from .cdn_bypass import CDNBypass, CDNCheckResult, OriginCandidate
from .asset_expander import AssetExpander, ExpansionResult, AssetNode
from .github_leaks import GithubLeakScanner, GithubLeak
from .upload_scan import check_file_upload
from .ssrf_exploit import exploit_ssrf
# Phase 1: 凭据突破
from .targeted_dict import (
    TargetedDictGenerator,
    generate_dict,
    generate_usernames,
    generate_multi_dict,
)
from .web_login_brute import (
    WebLoginBruteForcer,
    LoginFormInfo,
    BruteResult,
    BruteReport,
    brute_phpmyadmin,
    extract_csrf_tokens,
)
# Phase 2: 供应链攻击
from .hosting_panel_detect import (
    HostingPanelDetect,
    AsyncHostingPanelDetect,
    PanelInfo,
    PanelDetectResult,
    detect_panels,
    async_detect_panels,
)
# Phase 3: 流量闭环
from .traffic_collector import TrafficCollector, CollectorStats, create_collector
from .extras import (
    get_remediation, wayback_urls, detect_cms,
    generate_deserialization_payloads, internal_recon,
    whois_lookup, icp_lookup, take_screenshot,
    persistence_payloads, create_session_manager,
    save_session_from_response,
    REMEDIATION_GUIDE, CMS_SIGNATURES,
)
from .traffic_analyzer import TrafficAnalyzer, AnalysisReport, TrafficFinding
from .experience_rules import TrafficRuleEngine, TrafficRule, RuleHit, DEFAULT_RULES
from .intel_aggregator import IntelAggregator, IntelReport
from .attack_checklist import AttackChecklist, CheckResult
from .injector import MultiChannelInjector, InjectionFinding, ScanReport

# ProxyManager 是可选的 (依赖 proxy/ 子模块)
try:
    from ..proxy_manager import ProxyManager
    _PROXY_AVAILABLE = True
except ImportError:
    ProxyManager = None  # type: ignore
    _PROXY_AVAILABLE = False

__all__ = [
    # 基础
    "TrafficRequest",
    "TrafficResponse",
    "ProtocolAdapter",
    "ProtocolError",
    "TrafficEngine",
    # 采集
    "OOBChannel",
    "OOBCallbackUnified",
    "ScanResult",
    "AssetEntry",
    "DeepCollector",
    "DeepCollectResult",
    # 业务逻辑漏洞
    "LogicVulnScanner",
    "LogicScanResult",
    "LogicVulnFinding",
    # WAF 绕过
    "WAFBypass",
    "BypassResult",
    # JWT
    "JWTTool",
    "JWTParts",
    # N-day exploit
    "ExploitManager",
    # 攻击链
    "AttackChain",
    "AttackChainResult",
    "AttackStep",
    "Phase",
    # 代理 (可选)
    "ProxyManager",
    # 反溯源
    "AntiTrace",
    "TraceRiskReport",
    # 报告
    "ReportGenerator",
    # 反弹 shell
    "ReverseShellGenerator",
    # Docker/K8s 利用
    "docker_rce",
    "kubelet_rce",
    # CDN 绕过
    "CDNBypass",
    "CDNCheckResult",
    "OriginCandidate",
    # 资产扩展
    "AssetExpander",
    "ExpansionResult",
    "AssetNode",
    # H-1~H-8
    "GithubLeakScanner",
    "check_file_upload",
    "exploit_ssrf",
    "get_remediation",
    "wayback_urls",
    "detect_cms",
    "generate_deserialization_payloads",
    "internal_recon",
    # 被动流量分析
    "TrafficAnalyzer",
    "AnalysisReport",
    "TrafficFinding",
    # 情报聚合
    "IntelAggregator",
    "IntelReport",
    # 攻击清单 (全维度方法论)
    "AttackChecklist",
    "CheckResult",
    # 情报聚合
    "IntelAggregator",
    "IntelReport",
    # 攻击清单 (全维度方法论)
    "AttackChecklist",
    "CheckResult",
    # 多通道参数注入引擎
    "MultiChannelInjector",
    "InjectionFinding",
    "ScanReport",
    # 经验规则引擎 (EXPERIENCE_LESSONS -> 流量规则)
    "TrafficRuleEngine",
    "TrafficRule",
    "RuleHit",
    "DEFAULT_RULES",
    "TrafficCollector",
    "CollectorStats",
    "create_collector",
    # 凭据突破
    "TargetedDictGenerator",
    "generate_dict",
    "generate_usernames",
    "generate_multi_dict",
    "WebLoginBruteForcer",
    "LoginFormInfo",
    "BruteResult",
    "BruteReport",
    "brute_phpmyadmin",
    "extract_csrf_tokens",
    # 供应链攻击
    "HostingPanelDetect",
    "AsyncHostingPanelDetect",
    "PanelInfo",
    "PanelDetectResult",
    "detect_panels",
    "async_detect_panels",
]

__version__ = "4.0.0"
