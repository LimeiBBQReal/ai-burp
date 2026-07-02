"""Recon 管线架构说明 — 线性三阶段递进式采集 (GitHub Actions 兼容).

问题:
  CartManager.net 有 Cloudflare 泛解析攻击感知, 直接 DNS 字典爆破全假.

方案: 三阶段管线 (Pipeline)

  Phase 1 — 地基打点 (True DNS / WHOIS / Passive)
  Phase 2 — 真子域名鉴定 + 基础设施测绘
  Phase 3 — Web 应用深度扫描 (目录/端口/URL/参数)

依赖关系: Phase1 → Phase2 → Phase3 串行,
           每个 Phase 内部可并行 (GitHub Actions matrix).

============================================================
Phase 1: 地基打点 (不受泛解析影响)
============================================================

目标: 获取"真"IP / 真 NS / 真子域名

1a. dns_authoritative — 真实权威记录
    - A / AAAA    ← Cloudflare CDN IP (for true domain)
    - MX          ← 真实邮件服务器 (和主站不同IP)
    - NS          ← Cloudflare 权威 NS
    - SOA / TXT / CNAME
  
  输出: dns.json / 真IP列表

1b. passive_sources — 被动子域名收集 (不受 DNS 影响)
    - crt.sh (证书透明度)
    - AlienVault OTX
    - SecurityTrails
    - Wayback Machine CDX
    - URLScan.io
    - 以上都是"历史记录", 不是 DNS 请求, 不会被泛解析干扰
  
  输出: passive_subdomains 列表

1c. ip_to_domain — 对 1a 获得的真IP反查
    - IP 所属 C 段扫描 (同网段 20-40 个 IP)
    - 反查 PTR 记录
    - HTTP 标题抓取 (区分是否同一组织)
    - 旁站发现
  
  输出: cidr_map / neighbor_ips

1d. whois_lookup — WHOIS / ASN
    - 目标域名 WHOIS (注册商, 注册邮箱)
    - IP WHOIS (ASN, 网段, 供应商)
  
  输出: org_info

============================================================
Phase 2: 真子域名鉴定 (消除泛解析)
============================================================

2a. verify_subdomains — 验证 Phase 1 收集子域名
    - 对每个候选域名:
      a) DNS A 记录 → 检查是否泛解析 IP (198.18.x.x / 0.0.0.0 / 特定CDN IP)
      b) HTTP HEAD → 检查 Server 头 / 标题 (与泛解析页面对比)
      c) 端口可达性 → TCP 连接验证
    - 泛解析特征 IP 过滤掉
  
  输出: verified_subdomains.json

2b. http_fingerprint — HTTP 指纹识别 (对验证通过的)
    - GET / → status, title, server, content-length
    - HEAD 响应头
    - 常见路径探针 (robots.txt, sitemap.xml)
  
  输出: live_details.json

2c. deep_subdomain — 对 Phase 2a 真子域名递归爆破
    - 只对通过验证的子域名进行二级、三级深度探测
    - 也做泛解析过滤
  
  输出: deep_subdomains.json

============================================================
Phase 3: Web 应用深入扫描 (只对真域名/真IP)
============================================================

3a. port_scan — 端口扫描
    - 对 Phase 1c 获得的真 IP (非 198.18.x.x) 进行端口探测
    - Top 82 端口, TCP connect
  
3b. dir_brute — 目录爆破
    - 只对 Phase 2b 确认存活的 URL
    - 大字典 ~5000 条
  
3c. url_collect — URL 采集
    - WayBack + OTX + 对存活 URL 爬取 (HTML/JS/CSS)
    - 依赖 Phase 2b 的 live_details
    - 新发现的 URL 可反馈给 Phase 3b/3d

3d. param_brute — 隐藏参数挖掘
    - 使用 url_collect 发现的参数作为种子
    - 加上通用参数字典 1048+

3e. js_extract — JS 分析
    - 从 url_collect 中提取 JS 文件
    - 调取内容出来做二次 URL 提取

============================================================
GitHub Actions 管线编排
============================================================

方案: 手动编排的 workflow_dispatch

因为 Actions 不支持跨 workflow 动态判断 (不能判断 Phase1/2 是否产出真数据),
所以用 3 个 workflow 串联:

  trigger-phase1.yml   → 跑 1a 1b 1c 1d (并行 4 个 job)
  trigger-phase2.yml   → 依赖 Phase1 产出, 跑 2a 2b 2c
  trigger-phase3.yml   → 依赖 Phase2 产出, 跑 3a 3b 3c 3d 3e

人工触发:
  1) 触发 phase1 → 等跑完
  2) 手动检查 out/ 确认有真数据
  3) 触发 phase2
  4) 检查 phase2 验证结果
  5) 触发 phase3

也可以用 GitHub Actions 的 workflow_run 触发器自动串联:
  phase1.yml   push → out/dns.json
  phase2.yml   trigger: workflow_run (phase1 completed)
  phase3.yml   trigger: workflow_run (phase2 completed)

但自动串联可能浪费分钟 (若 Phase1 无真数据), 建议人工阶段触发.
"""
