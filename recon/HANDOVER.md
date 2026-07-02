# AI-Burp Recon 项目接手文档

> 文档版本：v1.0 | 编写日期：2026-07-01 | 管线仓库：`LimeiBBQReal/ai-burp-recon`

---

## 目录

1. [项目概述](#1-项目概述)
2. [管线架构](#2-管线架构)
3. [Phase 1 现状](#3-phase-1-现状)
4. [Phase 2 & Phase 3 现状](#4-phase-2--phase-3-现状)
5. [已知 Bug 清单（必须修复）](#5-已知-bug-清单必须修复)
6. [技术债务](#6-技术债务)
7. [未解决的问题](#7-未解决的问题)
8. [下一步任务](#8-下一步任务)
9. [关键文件索引](#9-关键文件索引)
10. [附录：API Key 清单](#10-附录api-key-清单)

---

## 1. 项目概述

### 1.1 项目目标

对目标网站（当前目标：CartManager.net）执行自动化安全侦察（Reconnaissance），产出资产清单（域名、IP、子域名、HTTP 指纹等），为后续安全测试提供输入。

### 1.2 技术栈

| 组件 | 选择 |
|------|------|
| 编排引擎 | GitHub Actions（13 个 workflow 文件） |
| 语言 | Python 3.11 |
| 核心依赖 | `requests` `dnspython` `cryptography` |
| 输出加密 | AES-256-CBC + RSA-2048 双层加密 |
| 密钥管理 | GitHub Secrets |
| 存储 | 直接 commit 到仓库 `out/` 目录 |

### 1.3 当前管线状态

```
Phase 1 (Foundation) ───  ✅ 可运行，30% 数据残缺
    ↓ (手动触发)
Phase 2 (Recon) ─────────  ❌ 有代码但未验证
    ↓ (手动触发)
Phase 3 (WebScan) ───────  ❌ 有代码但未验证
```

当前 Phase 1 可在 GitHub Actions 上完整跑通，但产出数据只有预期的 30% 左右。Phase 2 和 Phase 3 虽然代码已写，**从未在实际环境中触发过**，不确定能否正常运行。

---

## 2. 管线架构

### 2.1 三阶段设计

```
Phase 1 ── Foundation（基础资产发现）
  ├── dns_authoritative       # DNS 权威记录查询（A/MX/NS/TXT/SPF）
  ├── passive_sources         # 13 个 OSINT 数据源 + CDN 绕过
  ├── cidr_scan               # /24 邻居扫描（TCP + HTTP 标题）
  └── ptr_expand             # PTR 反向查询 + 子域名扩展
       ↓ (手动触发)

Phase 2 ── Recon（深度侦察）
  ├── verify_subdomains       # DNS + HTTP 双重验证子域名存活
  ├── deep_subdomain          # 对已发现域名继续做子域名枚举
  └── http_fingerprint       # HTTP 指纹识别（Wappalyzer 风格）
       ↓ (手动触发)

Phase 3 ── WebScan（Web 扫描）
  ├── port_scan              # 全端口扫描
  ├── banner_grab            # 服务 Banner 采集
  ├── dir_brute             # 目录爆破
  ├── url_collect           # URL 收集（JS/Sitemap/robots）
  ├── param_brute           # 参数爆破
  └── js_extract            # JavaScript 敏感信息提取
```

### 2.2 跨阶段依赖问题

**Phase 1 → Phase 2 → Phase 3 的依赖是断的。** GitHub Actions 不支持一个 workflow 自动触发另一个 workflow（`workflow_dispatch` 只能手动）。所以 Operators 必须手动依次触发：

1. 触发 `phase1-foundation.yml`（约 8 分钟跑完）
2. 确认所有 Job 成功后 → 触发 `phase2-recon.yml`
3. Phase 2 完成后 → 触发 `phase3-webscan.yml`

### 2.3 加密方案

当前使用 AES-256-CBC + RSA-2048 双层加密：

```
明文 JSON → AES-256-CBC 加密（密钥：随机 32 字节）
          → RSA-2048 加密 AES 密钥（公钥：RECON_RSA_PUBLIC）

输出：
  out/<name>.data.enc   ← AES 密文
  out/<name>.key.enc    ← RSA 加密的 AES 密钥（256 bytes）
```

解密需要 `RECON_RSA_PRIVATE` 私钥。私钥存储在 GitHub Secrets 中，不在磁盘上。

#### 本地解密方法

```bash
cd recon
python -c "
from _common import _read_encrypted, _load_dotenv
_load_dotenv()
data = _read_encrypted('dns_authoritative')
print(data)
"
```

### 2.4 密钥文件位置

| 文件 | 位置 | 用途 |
|------|------|------|
| `~/.recon/recon_private.pem` | 本地开发机 | RSA 私钥（base64 PEM） |
| `~/.recon/recon_public.pem` | 本地开发机 | RSA 公钥（base64 PEM） |
| GitHub Secret `RECON_RSA_PRIVATE` | CI 环境 | RSA 私钥 |
| GitHub Secret `RECON_RSA_PUBLIC` | CI 环境 | RSA 公钥 |
| GitHub Secret `PROXY_AES_KEY` | CI 环境 | 旧加密方案回退（过渡期使用） |

---

## 3. Phase 1 现状

### 3.1 最新一次成功运行（commit `bb5ea23`）

| Job | 状态 | 耗时 | 产出 |
|-----|------|------|------|
| dns_authoritative | ✅ | ~10s | 2 个 A 记录（192.41.22.8 / .47）+ 1 条 SPF |
| passive_sources_and_cdn | ✅ | ~30s | 13 个数据源 0 活跃（见 Bug #1）|
| cidr_scan | ✅ | ~15s | 21 个存活邻居，28/28 HTTP 标题成功 |
| ptr_expand | ✅ | ~15s | 22 个 PTR 记录 → 17 个关联域名 |

### 3.2 实际产出数据

**DNS 记录：**
- A 记录：192.41.22.8（smtp.visiongrp.com）、192.41.22.47（cartmanager.net）
- SPF：`v=spf1 mx ip4:192.41.22.8 ip4:192.41.22.32 a -all`
- MX/NS：无

**CIDR /24 扫描（21 个存活邻居）：**
```
192.41.22.34 → CartSquare
192.41.22.36 → HTML Manager
192.41.22.37 → Shopping Cart Software（QCCart）
192.41.22.38 → ProsPayCart
192.41.22.39 → RTCart
192.41.22.40 → GlobalCart
192.41.22.41 → LinkPointCart
192.41.22.42 → DesignCart
192.41.22.44 → Virtual Shopper（IntelliCart）
192.41.22.46 → ECI
192.41.22.47 → CartManager（主站）
192.41.22.56 → Okolowitz Main Page
```

**PTR 反查发现的关联域名（17 个）：**
```
cartmanager.net  cartsquare.net  cartxl.net  designcart.net
eci-cart.net  eci-corp.com  globalcart.net  htmlmanager.net
iwgcart.com  linkpointcart.net  prospaycart.com  qccart.net
rtcart.net  ulexpress.com  virtualshopper.net  visiongrp.com
knowlespage.com（不属于同一集团）
```

---

## 4. Phase 2 & Phase 3 现状

### 4.1 代码存在但未经测试

所有源文件已编写完成：

| 文件 | 行数 | 功能描述 | 验证状态 |
|------|------|---------|---------|
| `verify_subdomains.py` | 210 | 读取 Phase 1 输出 → DNS+HTTP 双重验证 | ❌ 未触发过 |
| `deep_subdomain.py` | ~120 | 对已验证域名递归枚举子域名 | ❌ 未触发过 |
| `http_fingerprint.py` | ~100 | HTTP 指纹识别 | ❌ 未触发过 |
| `port_scan.py` | ~150 | 全端口扫描（TCP SYN/Connect） | ❌ 未触发过 |
| `banner_grab.py` | ~120 | 服务 Banner 采集 | ❌ 未触发过 |
| `dir_brute.py` | ~140 | 目录爆破（使用 wordlists/dirs.txt） | ❌ 未触发过 |
| `url_collect.py` | 161 | 从 JS/Sitemap/robots/CSS 提取 URL | ❌ 未触发过 |
| `param_brute.py` | ~130 | 参数名爆破 | ❌ 未触发过 |
| `js_extract.js` | ~100 | JS 敏感信息提取 | ❌ 未触发过 |

### 4.2 phase2-recon.yml 的 3 个 Job

```
verify_subdomains ──→ deep_subdomain ──→ http_fingerprint
（无依赖）          （串联）           （串联）
```

### 4.3 phase3-webscan.yml 的 6 个 Job

```
              ┌── banner_grab
port_scan ────┼── dir_brute
              └── url_collect ──┬── param_brute
                                └── js_extract
```

### 4.4 风险点

Phase 2 和 Phase 3 存在以下风险：
1. **依赖 Phase 1 输入格式**：读取 `.enc` 文件时依赖 Phase 1 输出的 schema 格式（如 `verify_subdomains.py` 读 `passive_sources` 的 `subdomains` 字段）
2. **字典文件可能不够大**：`subdomains_large.txt`（1520 条）对中型企业不够
3. **`url_collect.py` 依赖域名解析**：需要 SSL 正常工作（同 Bug #1）

---

## 5. 已知 Bug 清单（必须修复）

### Bug #1 [P0] http_get() 未处理 SSL 证书问题

**严重程度：致命** | 影响范围：Phase 1/2/3 所有模块 | 修复预估：30 分钟

**现象：** 13 个 OSINT 数据源全部返回 0 条数据。日志无报错（异常被静默捕获）。

**根因：** 见 [\_common.py:L121-L128](file:///e:/CursorDEV/CKFinder/ai-burp/recon/_common.py#L121-L128)

```python
def http_get(url: str, timeout: int = 10, **kwargs) -> requests.Response | None:
    try:
        return requests.get(url, timeout=timeout, headers=headers, **kwargs)
    except Exception as e:
        print(f"  [ERR] {url}: {e}", file=sys.stderr)
        return None
```

`requests.get()` 默认 `verify=True`。在 CI 环境或某些 API（如 crt.sh）遇到 SSL 证书验证失败时，**异常被 `except Exception` 捕获**，函数返回 `None`。每个 OSINT 函数收到 `None` 后认为请求失败，直接返回空集。

**复现：** 在无 certifi 根证书的环境下触发 Phase 1，即可看到所有 API 来源返回 0。

**修复方案：**

```python
# _common.py 中添加
import os
_recon_ssl_verify = os.environ.get("RECON_SSL_VERIFY", "1").lower() in ("0", "false", "no")

def http_get(url: str, timeout: int = 10, **kwargs) -> requests.Response | None:
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
    kwargs.setdefault("verify", not _recon_ssl_verify)
    try:
        return requests.get(url, timeout=timeout, headers=headers, **kwargs)
    except Exception as e:
        print(f"  [ERR] {url}: {e}", file=sys.stderr)
        return None
```

同时需要在 `phase1-foundation.yml` 的每个 Job 中添加 `RECON_SSL_VERIFY: "0"` 环境变量。

---

### Bug #2 [P0] bypass_cdn.py _fetch_history_ips() 始终返回空集

**严重程度：致命** | 影响范围：CDN 历史 IP 查找 | 修复预估：5 分钟

**现象：** CDN 绕过模块的"历史 IP"功能永远输出空列表。

**根因：** 见 [bypass_cdn.py:L220](file:///e:/CursorDEV/CKFinder/ai-burp/recon/bypass_cdn.py#L220)

```python
def _fetch_history_ips(domain: str) -> set[str]:
    ips: set[str] = {}           # ← BUG！{} 是 dict，不是 set！
```

第 220 行用 `{}` 初始化了一个声明为 `set[str]` 的变量。Python 类型注解不强制，实际创建的是空字典。执行到 `ips.add(ip_val)` 时抛 `AttributeError: 'dict' object has no attribute 'add'`，被 `except Exception: pass` 静默吞掉。函数最后返回 `set()`（硬编码空集）。

**修复方案：**

```python
ips: set[str] = set()            # 改为 set()
return ips                       # 返回 ips 而非 set()
```

---

### Bug #3 [P1] 所有 OSINT 函数的 except Exception: pass 静默吞错误

**严重程度：中** | 影响范围：6 个文件 | 修复预估：15 分钟

**波及文件：**
- [passive_sources.py](file:///e:/CursorDEV/CKFinder/ai-burp/recon/passive_sources.py) — 13 个函数全部 `except Exception: pass`
- [ptr_expand.py](file:///e:/CursorDEV/CKFinder/ai-burp/recon/ptr_expand.py) — `_crt_sh()` 和 `_wayback()` 同模式
- [cidr_scan.py](file:///e:/CursorDEV/CKFinder/ai-burp/recon/cidr_scan.py) — `_http_title()` 的 `except Exception: return None`

这些 `pass` 导致：
- JSON 解析失败 → 无日志 → 难以调试
- crt.sh 返回 HTML 限流页 → JSON 解析异常 → 被 pass
- API 返回格式变化 → 被 pass

**修复方案：** 所有 `except Exception: pass` 改为 `except Exception as e: print(f"  [模块] 错误: {e}", file=sys.stderr)`

---

### Bug #4 [P1] Workflow 重复代码

**严重程度：中** | 影响范围：3 个 workflow 文件 | 修复预估：30 分钟

`phase1-foundation.yml` 中 4 个 Job 的 Commit 步骤完全重复：
```yaml
- name: Commit results
  if: always()
  env:
    PAT_TOKEN: ${{ secrets.PAT_TOKEN }}
  run: |
    git config user.name "LimeiBBQReal"
    git config user.email "LimeiBBQReal@users.noreply.github.com"
    git add out/
    ...
```

**修复方案：** 抽取为 shell 脚本 `scripts/commit_results.sh`，4 个 Job 调用同一份。

---

## 6. 技术债务

### 6.1 代码重复

| 重复函数 | 出现次数 | 涉及文件 |
|---------|---------|---------|
| `_crt_sh()` | 3 | passive_sources.py, ptr_expand.py, cidr_scan.py |
| `_wayback()` | 2 | passive_sources.py, ptr_expand.py |
| `Commit results` YAML | 4 | phase1-foundation.yml |
| `git pull` 步骤 | 2 | phase1-foundation.yml |

**建议：** `_crt_sh()` 和 `_wayback()` 抽取到 `_common.py`。

### 6.2 硬编码

| 位置 | 内容 | 建议 |
|------|------|------|
| `bypass_cdn.py:L41-146` | CDN IP 段 100+ 行字面量 | 移至外部 `cdn-ranges.txt` |
| `passive_sources.py:L45` | `DNS_FALLBACK_THRESHOLD = 50` | 改为参数 |
| `passive_sources.py:L399` | `wordlist[:2000]` 硬编码切分 | 改为配置 |
| `phase1-foundation.yml` | `github.com/LimeiBBQReal/ai-burp-recon.git` 重复出现 | 用 `$GITHUB_REPOSITORY` |

### 6.3 字典文件

| 文件 | 注释声称 | 实际 |
|------|---------|------|
| `subdomains_large.txt` | ~11,000 | 1,520 |
| `dirs_large.txt` | ~5,000 | 1,541 |

注释与实际严重不符。1,520 条子域名对中型企业不够用。

---

## 7. 未解决的问题

### 7.1 Phase 2/3 缺乏实际验证

Phase 2 和 Phase 3 的代码从未在 CI 环境中实际运行过。主要风险：
- 加密文件读取路径可能和 Phase 1 输出不兼容
- 6 个 Job 的串行/并行依赖可能超时
- `dir_brute` 用了全字典（~1500 条），可能超过 30 分钟超时

### 7.2 API Key 有效性未知

GitHub Secrets 中配置了以下 API Key，但从未验证它们是否有效：

| Secret 名 | 用途 | 状态 |
|-----------|------|------|
| `SHODAN_API_KEY` | Shodan 搜索 | ❓ 未知 |
| `CENSYS_API_KEY` | Censys 搜索 | ❓ 未知 |
| `OTX_API_KEY` | AlienVault OTX | ❓ 未知 |
| `VIRUSTOTAL_API_KEY` | VirusTotal | ❓ 未知 |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | ❓ 未知 |
| `FOFA_EMAIL` + `FOFA_API_KEY` | Fofa 搜索 | ❓ 未知 |
| `HUNTER_API_KEY` | Hunter.io | ❓ 未知 |

### 7.3 工作流数量膨胀

`recon/.github/workflows/` 下有 **13 个 YAML 文件**。除了核心的 3 个 Phase workflow 外，还有按模块拆分的独立 workflow（如 `recon-subdomain.yml`、`recon-portscan.yml` 等），这些可能是在开发过程中废弃的旧版本。建议清理到仅保留 3 个活跃的 Phase workflow。

### 7.4 没有反馈循环

Phase 3 的 `url_collect.py` 理论上可能发现新域名（如 JS 文件中嵌入的 API 域名），但没有任何机制把新域名反馈回 Phase 1 重新采集。管线是一次性的，不收敛。

---

## 8. 下一步任务

### 8.1 立即修复（优先级：高）

1. **修复 Bug #1**：`http_get()` 增加 SSL 绕过
2. **修复 Bug #2**：`bypass_cdn.py` 的 `{}` → `set()`
3. **修复 Bug #3**：所有 `except Exception: pass` → 打印错误
4. **添加 `RECON_SSL_VERIFY: "0"`** 到 Phase 1/2/3 所有 workflow 的 env

### 8.2 验证 Phase 2（优先级：中）

1. 手动触发 `phase2-recon.yml`，观察 verify_subdomains 是否正常工作
2. 如失败，排查 `_read_encrypted()` 的输入格式兼容性
3. 记录输出并决定是否需要修 deep_subdomain 和 http_fingerprint

### 8.3 验证 Phase 3（优先级：中）

1. Phase 2 成功后手动触发 `phase3-webscan.yml`
2. 注意 30 分钟超时限制——`dir_brute` 可能需要切分字典或增加超时

### 8.4 清理与优化（优先级：低）

1. 删除 `workflows/` 中 10 个废弃的独立 workflow
2. 更新 `wordlists/` 注释或补充字典到声称的数量
3. 将 `_crt_sh()` 和 `_wayback()` 抽取到 `_common.py`
4. 将 CDN IP 段移到外部文件 `cdn-ranges.txt`

---

## 9. 关键文件索引

### 核心文件

| 文件 | 用途 | 行数 |
|------|------|------|
| `_common.py` | 共享工具（加密/解密/HTTP/字典加载） | ~196 |
| `passive_sources.py` | 13 个 OSINT 数据源采集 | 500 |
| `bypass_cdn.py` | CDN 绕过 + 真实 IP 发现 | 459 |
| `cidr_scan.py` | /24 邻居扫描 + HTTP 标题 | 281 |
| `ptr_expand.py` | PTR 反查 + 关联域名 | 193 |
| `dns_authoritative.py` | DNS 权威记录查询 | 164 |

### Phase 2 文件

| 文件 | 用途 | 建议 |
|------|------|------|
| `verify_subdomains.py` | DNS+HTTP 双重验证 | 等待 Phase 1 修复后测试 |
| `deep_subdomain.py` | 递归子域名枚举 | 同上 |
| `http_fingerprint.py` | HTTP 指纹识别 | 同上 |

### Phase 3 文件

| 文件 | 用途 | 建议 |
|------|------|------|
| `port_scan.py` | 全端口扫描 | 等待 Phase 2 修复后测试 |
| `banner_grab.py` | 服务 Banner | 同上 |
| `dir_brute.py` | 目录爆破 | 同上 |
| `url_collect.py` | URL 收集（JS/Sitemap/robots） | 同上 |
| `param_brute.py` | 参数爆破 | 同上 |
| `js_extract.py` | JS 敏感信息提取 | 同上 |

### Workflow 文件

| 文件 | 用途 |
|------|------|
| `phase1-foundation.yml` | Phase 1（4 个 Job，~8 分钟） |
| `phase2-recon.yml` | Phase 2（3 个 Job，已验证 0%） |
| `phase3-webscan.yml` | Phase 3（6 个 Job，已验证 0%） |

---

## 10. 附录：API Key 清单

要使用付费的 OSINT 数据源，需要在本地 `.env` 文件中配置以下 API Key（从 GitHub Secrets 获取）：

```bash
# repo/.env
SECURITYTRAILS_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
CENSYS_API_KEY=your_key_here
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
FOFA_EMAIL=your_email_here
FOFA_API_KEY=your_key_here
HUNTER_API_KEY=your_key_here
PROXY_AES_KEY=your_key_here          # 本地开发需要（旧加密方案回退）
```

当前 `.env` 文件不在仓库中，需要从 GitHub Secrets 手动导出。

---

> **文档编写说明：** 本文档基于 commit `bb5ea23`（Phase 1 最近一次完全通过）和 `cdd91f2`（仓库最新状态）编写。所有文件路径基于 `recon/` 子目录。
