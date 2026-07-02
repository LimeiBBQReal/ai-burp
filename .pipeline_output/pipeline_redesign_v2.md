# AI-Burp 资产侦察管线 — 重新设计方案

## 核心问题诊断

**当前管线是"单域名 → 单轮"设计**，但 CartManager.net 实际是一个电商矩阵（17 个站点）。
真正的资产挖掘需要 **"发现 → 扩散 → 再发现"的链式循环**。

## 新管线架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Phase 1: Foundation（地基）                      │
│                                                                     │
│  dns_authoritative ──→ passive_sources ──→ cidr_scan               │
│        │                    │                  │                    │
│        │                    │                  ▼                    │
│        │                    │         ptr_expand                    │
│        │                    │            │                          │
│        │                    │            ▼                          │
│        │                    │     domain_chain ◄── 链式扩散        │
│        │                    │            │                          │
│        │                    │            ▼                          │
│        │                    │     zone_transfer ◄── AXFR尝试        │
│        │                    │                                          │
│        │                    ▼                                          │
│        │         ip_recon ◄── Shodan/Censys按IP反查                    │
│        │            │                                                  │
│        │            ▼                                                  │
│        │         search_dork ◄── Google/Bing Dork                      │
│        │                                                               │
│        ▼                                                               │
│  cdn_bypass ◄── CDN绕过（所有域名）                                      │
│                                                                     │
│  输出: out/phase1_all_domains.json  (所有发现的域名+子域+IP)            │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Phase 2: Verification（验证）                       │
│                                                                     │
│  verify_subdomains ──→ deep_subdomain ──→ http_fingerprint          │
│     (DNS+HTTP双重验证)    (depth=2递归爆破)      (robots/sitemap)     │
│                                                                     │
│  输出: out/verified_subdomains.json                                  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Phase 3: Web Application（Web扫描）                  │
│                                                                     │
│  port_scan ──→ banner_grab ──→ dir_brute ──→ url_collect            │
│     (多端口)      (服务指纹)      (目录爆破)     (JS/CSS/HTML提取)    │
│                                                                     │
│  └──→ param_brute ──→ js_extract                                   │
│       (参数挖掘)       (JS深度分析)                                   │
│                                                                     │
│  输出: out/urls_all.json, out/params_all.json, out/ports_all.json   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Phase 4: Feedback Loop（反馈循环）                   │
│                                                                     │
│  从 Phase 3 的 url_collect 中提取新域名/子域名                        │
│  如果有 > 5 个新域名 → 投喂回 Phase 1 的 passive_sources             │
│  重复直到收敛（连续两轮无新域名）                                      │
│                                                                     │
│  输出: out/final_asset_report.json                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## 关键改进

### 1. 链式扩散 (domain_chain)

```python
# 伪代码
def domain_chain(all_domains):
    for domain in all_domains:
        # 对每个域名跑 crt.sh + 子域名爆破
        subs = crt_sh(domain) | dns_brute(domain)
        yield domain, subs
```

### 2. 多端口扫描

```python
# 不再只扫 80/443
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995,
                3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090]
```

### 3. DNS Zone Transfer

```python
def zone_transfer(domain):
    for ns in get_ns_records(domain):
        try:
            axfr = dns.query.xfr(ns, domain, timeout=5)
            for record in axfr:
                yield record
        except:
            pass
```

### 4. 搜索引擎 Dork

```python
def google_dork(domain):
    # site:domain.com filetype:pdf
    # site:domain.com intitle:"admin"
    # site:domain.com inurl:"login"
    queries = [
        f'site:{domain}',
        f'site:{domain} filetype:pdf',
        f'site:{domain} intitle:"admin"',
        f'site:{domain} inurl:"login"',
        f'site:{domain} inurl:"config"',
    ]
    for q in queries:
        # 爬取 Google 搜索结果
        pass
```

### 5. IP 反查

```python
def ip_recon(ips):
    for ip in ips:
        # Shodan API: https://api.shodan.io/shodan/host/{ip}
        # Censys API: https://search.censys.io/hosts/{ip}
        pass
```

### 6. 反馈循环收敛

```python
def feedback_loop(phase3_urls, max_rounds=3):
    for round in range(max_rounds):
        new_domains = extract_domains_from_urls(phase3_urls)
        if len(new_domains) <= 5:
            break
        # 投喂回 passive_sources
        phase1_results = passive_sources(new_domains)
        phase3_urls = port_scan + dir_brute + url_collect(phase1_results)
    return phase3_urls
```

## 数据流

```
out/
├── phase1_all_domains.json    # 所有发现的域名+子域+IP（Phase 1 合并输出）
├── verified_subdomains.json   # Phase 2 验证通过
├── urls_all.json              # Phase 3 URL 采集
├── params_all.json            # Phase 3 参数挖掘
├── ports_all.json             # Phase 3 端口扫描
├── final_asset_report.json    # Phase 4 最终报告
```

## 执行策略

### 方案 A: 单仓库多 Workflow（推荐）

```
Phase 1: 5 jobs 并行
  dns_authoritative
  passive_sources + cdn_bypass
  cidr_scan
  ptr_expand
  domain_chain (依赖 ptr_expand)

Phase 2: 3 jobs 串行
  verify_subdomains → deep_subdomain → http_fingerprint

Phase 3: 6 jobs 并行
  port_scan → banner_grab + dir_brute + url_collect
  param_brute + js_extract (依赖 url_collect)

Phase 4: 1 job
  feedback_loop (依赖 Phase 3)
```

### 方案 B: 单 Workflow 多 Job（简化）

```
phase1-foundation.yml: 5 jobs
phase2-verify.yml: 3 jobs
phase3-web.yml: 6 jobs
phase4-feedback.yml: 1 job
```

## 新增脚本清单

| 脚本 | 功能 | 依赖 |
|------|------|------|
| `domain_chain.py` | 链式扩散：每个域名跑 crt.sh + 爆破 | `ptr_expand.data.enc` |
| `zone_transfer.py` | DNS AXFR 尝试 | `phase1_all_domains.json` |
| `ip_recon.py` | Shodan/Censys 按 IP 反查 | `cidr_scan.data.enc` |
| `search_dork.py` | Google/Bing 搜索 | `phase1_all_domains.json` |
| `feedback_loop.py` | Phase 3 → Phase 1 反馈 | `urls_all.json` |

## 字典扩容

| 字典 | 当前 | 目标 |
|------|------|------|
| `subdomains_large.txt` | 1522 | 5000+ |
| `dirs_large.txt` | 5000 | 10000+ |
| `params.txt` | 1048 | 2000+ |

## 时间估算

| Phase | 预计耗时 |
|-------|----------|
| Phase 1 | 8-12 分钟 |
| Phase 2 | 5-8 分钟 |
| Phase 3 | 10-15 分钟 |
| Phase 4 | 3-5 分钟 |
| **总计** | **26-40 分钟** |
