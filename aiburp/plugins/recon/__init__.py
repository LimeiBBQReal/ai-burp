"""
红队打点插件包

流程: 打点 -> 所有流量记录到 History -> AI 分析决策

包含:
- subdomain: 子域名枚举
- portscan: 端口扫描
- discovery: 目录/参数发现
- waf_detect: WAF 检测/绕过
- traffic_analyzer: 流量深度分析 (JS/HTML/JSON 参数提取)
- api/shodan: Shodan API
- api/censys: Censys API
- api/crtsh: crt.sh API
"""

# 延迟导入，避免循环依赖
def __getattr__(name):
    if name == "SubdomainPlugin":
        from .subdomain import SubdomainPlugin
        return SubdomainPlugin
    elif name == "PortscanPlugin":
        from .portscan import PortscanPlugin
        return PortscanPlugin
    elif name == "QuickAlivePlugin":
        from .portscan import QuickAlivePlugin
        return QuickAlivePlugin
    elif name == "DiscoveryPlugin":
        from .discovery import DiscoveryPlugin
        return DiscoveryPlugin
    elif name == "ParamDiscoverPlugin":
        from .discovery import ParamDiscoverPlugin
        return ParamDiscoverPlugin
    elif name == "WAFDetectPlugin":
        from .waf_detect import WAFDetectPlugin
        return WAFDetectPlugin
    elif name == "TrafficAnalyzerPlugin":
        from .traffic_analyzer import TrafficAnalyzerPlugin
        return TrafficAnalyzerPlugin
    elif name == "TrafficAnalyzer":
        from .traffic_analyzer import TrafficAnalyzer
        return TrafficAnalyzer
    elif name == "analyze_traffic":
        from .traffic_analyzer import analyze_traffic
        return analyze_traffic
    elif name == "analyze_response":
        from .traffic_analyzer import analyze_response
        return analyze_response
    elif name == "extract_js_assets":
        from .traffic_analyzer import extract_js_assets
        return extract_js_assets
    elif name == "ShodanPlugin":
        try:
            from .api.shodan import ShodanPlugin
            return ShodanPlugin
        except (ImportError, ValueError):
            return None
    elif name == "CensysPlugin":
        try:
            from .api.censys import CensysPlugin
            return CensysPlugin
        except (ImportError, ValueError):
            return None
    elif name == "CrtshPlugin":
        try:
            from .api.crtsh import CrtshPlugin
            return CrtshPlugin
        except ImportError:
            return None
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "SubdomainPlugin",
    "PortscanPlugin",
    "QuickAlivePlugin",
    "DiscoveryPlugin",
    "ParamDiscoverPlugin",
    "WAFDetectPlugin",
    "TrafficAnalyzerPlugin",
    "TrafficAnalyzer",
    "analyze_traffic",
    "analyze_response",
    "extract_js_assets",
    "ShodanPlugin",
    "CensysPlugin",
    "CrtshPlugin",
]
