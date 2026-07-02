"""
AI-Burp: AI 驱动的安全测试工具包

专为大模型(LLM)设计的红队安全测试框架。
工具采集，AI决策。

核心功能：
- 异步高并发请求引擎
- 智能漏洞检测 (SQLi, XSS, SSRF, CMDi, LFI, SSTI)
- 决策系统 (Decision) - 为AI提供结构化的决策接口
- 完整的Payload库

快速开始：

    from aiburp import SmartBurp, SQLI
    
    with SmartBurp() as burp:
        # 智能探测
        decision = burp.smart_probe("https://target.com/api", "id", "1")
        print(decision)
        
        # 批量Fuzz
        results = burp.fuzz("https://target.com/api?id=§", SQLI.quick)
        for r in results:
            if r.is_interesting:
                print(f"⚠️ {r.payload}: {r.error}")
"""

__version__ = "4.0.0"

# ============================================================
# 核心模块
# ============================================================

# 异步核心引擎 (推荐)
from .burp import (
    AsyncBurp,           # 异步HTTP客户端
    AsyncSmartBurp,      # 异步智能引擎
    IntentAnalyzer,      # 语义分析器
    Response,            # 响应对象
    Decision,            # 决策对象（AI接口）
)

# 同步包装器 (兼容)
from .sync_wrapper import (
    SyncBurp,            # 同步HTTP客户端
    SyncSmartBurp,       # 同步智能引擎
)

# 别名 - 默认使用同步版本
Burp = SyncBurp
SmartBurp = SyncSmartBurp

# ============================================================
# 漏洞检测
# ============================================================

from .detectors import (
    AsyncVulnScanner,    # 异步漏洞扫描器
    VulnScanner,         # 同步漏洞扫描器
    Finding,             # 漏洞发现结果
    # 专用检测器
    SQLiDetector,
    XSSDetector,
    SSRFDetector,
    CMDiDetector,
    LFIDetector,
    SSTIDetector,
)

# ============================================================
# Payload 库
# ============================================================

from .payloads import (
    Payloads,            # Payload加载器
    SQLI,                # SQL注入
    XSS,                 # 跨站脚本
    LFI,                 # 本地文件包含
    SSRF,                # 服务端请求伪造
    CMDi,                # 命令注入
    SSTI,                # 模板注入
    Bypass,              # WAF绕过
    get_payloads,        # 获取payload函数
)

# ============================================================
# 辅助模块
# ============================================================

from .constants import SQL_ERRORS, WAF_SIGNATURES, SENSITIVE_PATTERNS
from .intel import KnowledgeBase, VulnerabilityChainer, AttackGraph
from .stealth import StealthClient, AdaptiveRateLimiter

# ============================================================
# Burp Suite 风格模块
# ============================================================

from .core import (
    History,             # 请求历史
    Repeater,            # 请求重放
    Intruder,            # 批量攻击
)
from .core.models import Request, PageView

# ============================================================
# 侦察模块 (保留基本侦察在核心，高级侦察已移至插件)
# ============================================================
# 注意：recon.py 和 subdomain.py 已移动到 plugins
# 如果需要在核心包中暴露插件，可以在这里按需导入，或者让用户从 plugins 导入
# 这里为了保持核心纯净，暂不自动导入插件内容，由用户显式导入：
# from aiburp.plugins import recon

# ============================================================
# 编排与记忆 (Orchestration & Memory)
# ============================================================

from .orchestrator import SecurityOrchestrator
from .memory import MemoryManager

# ============================================================
# Agent 模式 (Autonomous Security Research)
# ============================================================

from .agent import SecurityAgent, LLMClient, LLMConfig, ActionParser, check_llm_status

# ============================================================
# V4 统一流量层 (ALL-IN-TRAFFIC)
# ============================================================
# TrafficEngine 是 V4 顶层入口, 取代 AsyncBurp 成为流量调度中枢.
# 支持 HTTP/HTTPS/TCP/UDP/DNS/WebSocket... 任意协议 (按需扩展).
# 详见 aiburp/traffic/__init__.py
#
# 降级保护: traffic 子包未来可能依赖可选库 (websockets/cryptography...),
# 任一缺失不应让整个 aiburp 不可用 - V3 核心功能 (HTTP 检测/Decision/KB)
# 必须始终可用. 失败时只把 V4 入口设为 None, 用户访问时给清晰错误.

try:
    from .traffic import (
        TrafficEngine,
        TrafficRequest,
        TrafficResponse,
        ProtocolAdapter,
    )
    _TRAFFIC_AVAILABLE = True
except ImportError as _e:
    TrafficEngine = None  # type: ignore
    TrafficRequest = None  # type: ignore
    TrafficResponse = None  # type: ignore
    ProtocolAdapter = None  # type: ignore
    _TRAFFIC_AVAILABLE = False
    _TRAFFIC_IMPORT_ERROR = _e


# ============================================================
# Triage — 突破点验证门控
# ============================================================

from .triage import TriageGate

# ============================================================
# 漏洞模式库 (从 Claude-BugHunter 知识库提取)
# ============================================================

from .payloads.pattern_library import (
    IDOR_PATTERNS, FILE_UPLOAD_PATTERNS, SSRF_PATTERNS,
    BREAKTHROUGH_PATTERNS, BREAKTHROUGH_TYPES, PAYLOAD_CATEGORIES,
)

# ============================================================
# 公开API
# ============================================================

__all__ = [
    # 版本
    "__version__",
    
    # 核心
    "AsyncBurp", "AsyncSmartBurp",
    "SyncBurp", "SyncSmartBurp",
    "Burp", "SmartBurp",  # 别名
    "Response", "Decision", "IntentAnalyzer",
    
    # 检测器
    "AsyncVulnScanner", "VulnScanner", "Finding",
    "SQLiDetector", "XSSDetector", "SSRFDetector",
    "CMDiDetector", "LFIDetector", "SSTIDetector",
    
    # Payload
    "Payloads", "SQLI", "XSS", "LFI", "SSRF", "CMDi", "SSTI", "Bypass",
    "get_payloads",
    
    # 辅助
    "SQL_ERRORS", "WAF_SIGNATURES", "SENSITIVE_PATTERNS",
    "KnowledgeBase", "VulnerabilityChainer", "AttackGraph",
    "StealthClient", "AdaptiveRateLimiter",
    
    # Burp Suite 模块
    "History", "Repeater", "Intruder", "Request", "PageView",
    
    # 编排与记忆
    "SecurityOrchestrator", "MemoryManager",
    
    # Agent 模式
    "SecurityAgent", "LLMClient", "LLMConfig", "ActionParser", "check_llm_status",

    # Triage — 突破点验证门控
    "TriageGate",

    # 漏洞模式库
    "BREAKTHROUGH_PATTERNS", "BREAKTHROUGH_TYPES", "PAYLOAD_CATEGORIES",
    "IDOR_PATTERNS", "FILE_UPLOAD_PATTERNS", "SSRF_PATTERNS",

    # V4 统一流量层
    "TrafficEngine", "TrafficRequest", "TrafficResponse", "ProtocolAdapter",
]
