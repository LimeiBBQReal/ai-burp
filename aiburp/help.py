"""
AI-Burp 帮助文档系统

通过 aiburp --help 或 aiburp help <topic> 查看详细帮助
"""

from typing import Dict, Optional

# 版本信息
VERSION = "4.0.0"

# ============================================================
#                      帮助文档内容
# ============================================================

HELP_TOPICS: Dict[str, str] = {
    "overview": """
╔══════════════════════════════════════════════════════════════╗
║                    AI-Burp v{version}                        ║
║            AI 驱动的渗透测试工具包                            ║
╚══════════════════════════════════════════════════════════════╝

🎯 核心功能:
  • 智能漏洞检测 (SQLi, XSS, SSRF, CMDi, LFI, SSTI)
  • 异步高并发请求引擎
  • 决策系统 - 为 AI 提供结构化接口
  • 完整的 Payload 库 (200万+)

📦 模块分类:
  [扫描] auto-scan, probe, scan, fuzz, smart-fuzz
  [注入] extract, mssql-extract, deep-analyze
  [发现] dirfuzz, param-discover, fingerprint
  [侦察] recon, subdomain, dork, portscan
  [绕过] bypass403, waf-detect
  [API]  api-json, api-rest, api-graphql
  [管理] auth, targets, report

💡 快速开始:
  aiburp auto-scan https://target.com
  aiburp probe https://target.com/api id 1
  aiburp help commands    # 查看所有命令
  aiburp help plugins     # 查看插件列表
""".format(version=VERSION),

    "commands": """
📋 命令列表 (aiburp <command> --help 查看详情)

═══════════════════════════════════════════════════════════════
🔍 扫描类
═══════════════════════════════════════════════════════════════
  auto-scan      自动扫描 (推荐入口)
                 aiburp auto-scan https://target.com --depth full
  
  probe          参数探测 (快速判断是否有漏洞)
                 aiburp probe https://target.com/api id 1
  
  scan           漏洞扫描 (指定类型)
                 aiburp scan https://target.com/api id 1 --types sqli xss
  
  fuzz           批量 Payload 测试
                 aiburp fuzz "https://target.com?id=§" --payloads sqli
  
  smart-fuzz     智能 Fuzz (自动 WAF 绕过)
                 aiburp smart-fuzz https://target.com/api id 1

═══════════════════════════════════════════════════════════════
💉 注入利用
═══════════════════════════════════════════════════════════════
  extract        UNION 注入数据提取
                 aiburp extract https://target.com/product.asp pid 118
  
  mssql-extract  MSSQL 报错注入提取 (支持日文表名)
                 aiburp mssql-extract https://target.com/api id 24
  
  deep-analyze   深度注入分析 (评估可利用性)
                 aiburp deep-analyze https://target.com/login user test

═══════════════════════════════════════════════════════════════
🔎 发现类
═══════════════════════════════════════════════════════════════
  dirfuzz        目录爆破/敏感文件发现
                 aiburp dirfuzz https://target.com --wordlist asp
  
  param-discover 参数发现 (JS/表单/隐藏参数)
                 aiburp param-discover https://target.com --probe
  
  fingerprint    技术栈指纹识别
                 aiburp fingerprint https://target.com
  
  poc-scan       POC 漏洞扫描 (五层体系)
                 aiburp poc-scan https://target.com --tags wordpress

═══════════════════════════════════════════════════════════════
🌐 侦察类
═══════════════════════════════════════════════════════════════
  recon          资产侦察 (CIDR 扫描)
                 aiburp recon 192.168.1.0/24 --test
  
  subdomain      子域名收集
                 aiburp subdomain target.com --verify
  
  dork           搜索引擎 Dork
                 aiburp dork target.com --engine shodan
  
  portscan       端口扫描与服务识别
                 aiburp portscan 192.168.1.1 --ports top100

═══════════════════════════════════════════════════════════════
🛡️ 绕过类
═══════════════════════════════════════════════════════════════
  bypass403      403/401 绕过测试
                 aiburp bypass403 https://target.com/admin
  
  waf-detect     WAF 检测
                 aiburp waf-detect https://target.com

═══════════════════════════════════════════════════════════════
🔌 API 测试
═══════════════════════════════════════════════════════════════
  api-json       JSON API 参数测试
                 aiburp api-json https://api.target.com/user -b '{"id":"1"}' -p id
  
  api-rest       REST API 路径参数测试
                 aiburp api-rest "https://api.target.com/users/§1§/profile"
  
  api-graphql    GraphQL API 测试
                 aiburp api-graphql https://target.com/graphql -q "..."

═══════════════════════════════════════════════════════════════
⚙️ 管理类
═══════════════════════════════════════════════════════════════
  auth           认证会话管理
                 aiburp auth login https://target.com -u admin -p pass --save s1
  
  targets        批量目标管理
                 aiburp targets import urls.txt
  
  report         生成渗透测试报告
                 aiburp report generate -o report.html
""",

    "plugins": """
🔌 插件列表 (aiburp/plugins/)

核心插件:
  deep_analysis.py      深度注入分析
  discovery.py          目录发现/敏感文件
  extractor.py          UNION 注入数据提取
  mssql_extractor.py    MSSQL 报错注入提取
  recon.py              资产侦察
  subdomain.py          子域名收集
  fuzzer.py             高性能异步 Fuzzer
  reporter.py           报告生成器

辅助插件:
  browser.py            浏览器自动化 (Playwright)
  dns_validator.py      DNS 验证
  param_discover.py     参数发现
  smart_payload.py      智能 Payload 生成
  target_manager.py     目标管理

POC 模块 (aiburp/pocs/):
  builtin/              内置 POC (23+)
  nuclei_auto/          Nuclei 自动转换
  nuclei_manual/        Nuclei 手工适配
  github_adapted/       GitHub POC 适配
  custom/               自定义 POC

使用插件:
  from aiburp.plugins import recon, subdomain
  from aiburp.plugins.deep_analysis import DeepAnalyzer
""",

    "payloads": """
📦 Payload 库 (payloads/)

目录结构:
  sqli/           SQL 注入
    ├── quick.txt       快速测试 (50)
    ├── error.txt       报错注入
    ├── time.txt        时间盲注
    ├── union.txt       联合查询
    ├── auth_bypass.txt 认证绕过
    └── waf_bypass.txt  WAF 绕过
  
  xss/            跨站脚本
    ├── quick.txt       快速测试
    ├── reflected.txt   反射型
    ├── dom.txt         DOM 型
    └── filter_bypass.txt 过滤绕过
  
  lfi/            本地文件包含
  ssrf/           服务端请求伪造
  cmdi/           命令注入
  ssti/           模板注入
  bypass/         WAF 绕过技巧
  discovery/      目录发现字典

代码使用:
  from aiburp import SQLI, XSS, LFI
  
  # 快速 payload
  for p in SQLI.quick:
      print(p)
  
  # 完整 payload
  for p in SQLI.all:
      print(p)
""",

    "examples": """
💡 使用示例

═══════════════════════════════════════════════════════════════
场景 1: 快速扫描一个网站
═══════════════════════════════════════════════════════════════
  # 自动扫描 (推荐)
  aiburp auto-scan https://target.com
  
  # 深度扫描
  aiburp auto-scan https://target.com --depth full --output report.html

═══════════════════════════════════════════════════════════════
场景 2: 测试 SQL 注入
═══════════════════════════════════════════════════════════════
  # 1. 先探测
  aiburp probe https://target.com/product.asp pid 118
  
  # 2. 深度分析
  aiburp deep-analyze https://target.com/product.asp pid 118
  
  # 3. 数据提取
  aiburp extract https://target.com/product.asp pid 118 --db access

═══════════════════════════════════════════════════════════════
场景 3: 目录爆破
═══════════════════════════════════════════════════════════════
  # 快速扫描
  aiburp dirfuzz https://target.com --wordlist quick
  
  # ASP 站点专用
  aiburp dirfuzz https://target.com --wordlist asp --threads 10
  
  # 查看可用字典
  aiburp dirfuzz --list-wordlists

═══════════════════════════════════════════════════════════════
场景 4: 批量目标扫描
═══════════════════════════════════════════════════════════════
  # 导入目标
  aiburp targets import urls.txt
  
  # 检查存活
  aiburp targets check --threads 20
  
  # 批量指纹识别
  aiburp targets fingerprint
  
  # 批量漏洞扫描
  aiburp targets scan --types sqli xss

═══════════════════════════════════════════════════════════════
场景 5: 带认证的扫描
═══════════════════════════════════════════════════════════════
  # 登录并保存会话
  aiburp auth login https://target.com/login -u admin -p pass --save mysession
  
  # 使用会话扫描
  aiburp auto-scan https://target.com/admin --session mysession
""",

    "ide": """
🖥️ IDE 模式 (aiburp-ide)

专为 Kiro/Cursor 等 AI IDE 设计的命令行接口，输出 JSON 格式。

命令列表:
  aiburp-ide prompt <project_id>              获取恢复 Prompt
  aiburp-ide memory add <project_id> ...      添加记忆
  aiburp-ide memory search <project_id> ...   搜索记忆
  aiburp-ide finding add <project_id> ...     添加发现
  aiburp-ide status <project_id>              查看状态
  aiburp-ide tool probe <url> <param> <value> 探测参数
  aiburp-ide agent start <project_id>         启动自主审计

Prompt 类型:
  --type recovery     恢复上下文 (默认)
  --type researcher   研究员模式
  --type exhaustive   穷举模式
  --type hacker       黑客思维
  --type chaos        组合混沌
  --type cthulhu      克苏鲁混沌

示例:
  aiburp-ide prompt myproject --type hacker
  aiburp-ide tool probe https://target.com/api id 1
  aiburp-ide agent start myproject -i "审计 SQL 注入"
""",

    "api": """
📚 Python API

基础用法:
  from aiburp import SmartBurp, SQLI
  
  with SmartBurp() as burp:
      # 智能探测
      decision = burp.smart_probe("https://target.com/api", "id", "1")
      print(decision)
      
      # 批量 Fuzz
      results = burp.fuzz("https://target.com/api?id=§", SQLI.quick)
      for r in results:
          if r.is_interesting:
              print(f"⚠️ {r.payload}: {r.error}")

异步用法:
  from aiburp import AsyncSmartBurp
  import asyncio
  
  async def main():
      async with AsyncSmartBurp() as burp:
          decision = await burp.smart_probe("https://target.com/api", "id", "1")
          print(decision)
  
  asyncio.run(main())

漏洞扫描:
  from aiburp import VulnScanner, SmartBurp
  
  with SmartBurp() as burp:
      scanner = VulnScanner(burp)
      findings = scanner.scan("https://target.com/api", "id", "1")
      for f in findings:
          print(f)

编排器 (Orchestrator):
  from aiburp import SecurityOrchestrator
  
  orch = SecurityOrchestrator("my_project")
  orch.set_target(type="blackbox", url="https://target.com")
  prompt = orch.generate_recovery_prompt()
"""
}


def get_help(topic: str = "overview") -> str:
    """获取帮助文档"""
    topic = topic.lower()
    if topic in HELP_TOPICS:
        return HELP_TOPICS[topic]
    
    # 模糊匹配
    for key in HELP_TOPICS:
        if topic in key or key in topic:
            return HELP_TOPICS[key]
    
    return f"""
❌ 未找到帮助主题: {topic}

可用主题:
  overview   - 概览
  commands   - 命令列表
  plugins    - 插件列表
  payloads   - Payload 库
  examples   - 使用示例
  ide        - IDE 模式
  api        - Python API

用法: aiburp help <topic>
"""


def print_help(topic: str = "overview"):
    """打印帮助文档"""
    print(get_help(topic))


# CLI 入口
if __name__ == "__main__":
    import sys
    topic = sys.argv[1] if len(sys.argv) > 1 else "overview"
    print_help(topic)
