# AI-Burp 安全知识库

> 来源: [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
> 提取日期: 2026-06-26
> 许可: MIT

## 目录结构

```
knowledge/
├── hunt-skills/           # 48 个漏洞检测技能 (按类型分类)
│   ├── hunt-sqli.md       # SQL 注入检测模式
│   ├── hunt-xss.md        # XSS 检测模式
│   ├── hunt-ssrf.md       # SSRF 检测模式
│   ├── hunt-idor.md       # IDOR 检测模式
│   ├── hunt-rce.md        # RCE 检测模式
│   ├── hunt-ssti.md       # SSTI 检测模式
│   ├── hunt-oauth.md      # OAuth 漏洞
│   ├── hunt-graphql.md    # GraphQL 漏洞
│   ├── hunt-file-upload.md # 文件上传漏洞
│   └── ...                # 更多见目录
│
├── methodology/           # 方法论 (5 个文件)
│   ├── triage-validation.md   # 7-Question Gate — 提交前验证门控
│   ├── bb-methodology.md      # Bug bounty 工作流
│   ├── redteam-mindset.md     # 红队思维
│   ├── bug-bounty.md          # 基础概念
│   └── security-arsenal.md    # 安全工具箱
│
├── reporting/             # 报告与证据 (4 个文件)
│   ├── evidence-hygiene.md    # 证据处理规范 (cookie 脱敏、PII 黑条)
│   ├── report-writing.md      # 报告写作模板 (H1/Bugcrowd/Intigriti/Immunefi)
│   ├── bugcrowd-reporting.md  # Bugcrowd VRT 映射
│   └── redteam-report-template.md  # 红队报告模板
│
├── disclosed-reports/     # 公开漏洞报告模式库 (24 个文件, 681+ 模式)
│   ├── hunt-sqli.md       # SQLi 模式: error-based, blind, union, OOB
│   ├── hunt-xss.md        # XSS 模式: reflected, stored, DOM, mXSS
│   ├── hunt-ssrf.md       # SSRF 模式: redirect, DNS rebinding, cloud
│   ├── hunt-idor.md       # IDOR 模式: numeric, UUID, indirect
│   ├── hunt-rce.md        # RCE 模式: deserialization, SSTI, command injection
│   └── ...                # 每个文件含多个已披露报告的模式和 payload
│
├── enterprise/            # 企业平台攻击链 (11 个文件)
│   ├── m365-entra-attack.md   # Microsoft 365 / Entra ID
│   ├── okta-attack.md         # Okta 身份平台
│   ├── cloud-iam-deep.md      # 云 IAM (AWS/GCP/Azure)
│   ├── vmware-vcenter-attack.md  # VMware vCenter
│   ├── enterprise-vpn-attack.md  # SSL VPN 设备
│   ├── hunt-sharepoint.md     # SharePoint 攻击
│   └── ...                    # 更多企业平台
│
├── osint/                 # OSINT 与侦察 (18 个文件)
│   ├── offensive-osint.md     # 攻击性 OSINT
│   ├── web2-recon.md          # Web 侦察
│   ├── recon-techniques.md    # 侦察技巧
│   ├── dork-corpus.md         # Google Dork 语料库
│   ├── secret-patterns.md     # 敏感信息模式
│   └── ...                    # 更多 OSINT 参考
│
└── engine/                # 引擎参考代码 (5 个文件)
    ├── skill_map.py       # 技能映射器 (URL → hunt-* 技能匹配)
    ├── agent.py           # 交互式 agent
    ├── engine.py          # 引擎核心
    ├── recon.py           # 侦察模块
    └── scope.py           # 范围管理
```

## 使用方式

### 1. LLM 分析时参考
在 AI-Burp 的 LLM 分析阶段 (Phase ③)，可以参考 `disclosed-reports/` 中的模式库来识别漏洞。

### 2. Payload 设计时参考
`hunt-skills/` 中每个技能都包含具体的 payload 和绕过技巧，可用于 Phase ④ 的精准验证。

### 3. 报告编写时参考
`reporting/` 中的模板和规范可用于标准化报告输出。

### 4. 侦察阶段参考
`osint/` 中的侦察技巧和工具可用于 Phase ① 的资产收集。

### 5. 企业目标参考
`enterprise/` 中的企业平台攻击链可用于针对特定平台的深度测试。
