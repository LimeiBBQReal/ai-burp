# CartManager.net 全流程进度看板

> 监理模式 · 决策权交给 ENV LLM · 探针与业务解耦

## 状态机
- [▶] Phase 0 — 代理准备 (Google 探针) — **进行中** (4500/18511, alive=156)
- [✅] Phase 1 — 资产发现 — **已修复 TUN DNS 劫持, 干净 inventory 已落盘**
- [ ] Phase 2 — reachability + 指纹 + 敏感文件
- [ ] Phase 2.5 — deep_mining (LLM 决策聚类)
- [ ] Phase 3 — 漏洞测试
- [ ] Phase 4 — 报告

## Phase 0 详情
- 探针: `google.com/generate_204` + `httpbin.org/ip` + `gstatic.com/generate_204`
- 拉源: `aiburp/proxy/proxy_sources.json` + `extra_sources.json`
- 脚本: `aiburp/proxy/verify_google_probes.py`
- 产物: `.proxy_state/cartmanager_proxy_pool.json` / `alive.yaml` / `cartmanager_journal.pkl`
- 当前: 加载 18511 唯一代理, 4500 已测, 156 alive / 16 anonymous
- 预计: 跑完全部 18511 大约还需 25-40 分钟 (60 并发)

## Phase 1 详情 — v3.1 干净 inventory 已落盘

**脚本**: `.pipeline_output/cartmanager_phase1_recon.py` (v3.1 DoH-only + banner 取证)

### TUN DNS 劫持最终结论 (四层)
| 层 | 表现 | 绕过方式 |
|---|---|---|
| 系统 DNS (`getaddrinfo`) | 被劫持 → 198.18.0.x | 完全不调用 |
| UDP/53 显式 NS (8.8.8.8/1.1.1.1/9.9.9.9) | 仍被劫持 | 完全不调用 |
| **DoH (HTTPS)** | **真实** (返回 192.41.22.x) | **采用** |
| TCP SYN/ACK (端口扫描) | 被劫持 (TUN 伪造 SYN/ACK) | **必须 banner 取证** |

### v3.1 关键修复
1. **port_scan 改为 banner 取证**: 废除 `connect_ex==0` 即 open 的判定, 必须读到应用层响应 (HTTP 200 / SMTP 220 / Redis +PONG / SSH banner 等) 才算 open, 否则标 `no_banner`, TUN 在 L3/L4 模拟 SYN/ACK 是常事但模拟不出正确应用层协议
2. **443 TLS 独立握手 + 证书指纹**: 用 `ssl.wrap_socket` 取 cert SHA-256, 证明目标是否同一实体
3. **Wayback 改 https + 90s 超时**: `https://web.archive.org/cdx/search/cdx`, UA=Mozilla/5.0
4. **OUT 路径修正**: `parents[2]` → `parent` (消除 `ai-burp/.pipeline_output/.pipeline_output/...` 双嵌套)

### v3.1 干净 inventory 结果
- **3 个真实 IP** (DoH 解析 + 剔除保留段):
  - `192.41.22.30` ← `cartmanager.net` / `www.cartmanager.net` / `nat.cartmanager.net` / `smtp.cartmanager.net` / `seaside.cartmanager.net` 等
  - `192.41.22.32` ← `angersteins` / `dudadiesel` / `freeonehand` / `gripleash` 等
  - `192.41.22.47` ← `comwww` / `redrockthreads` / `starmedia` / `testmachine` / `wholehousefan` / `windrift` / `hyelighting` 等
- **19 个子域** (crt.sh 超时 30s, rapiddns + OTX 完整)
- **Wayback 500 条历史快照** (含 `cartmanager.net:80/+expires_date.toGMTString()+` 等可疑 URL)
- **端口证据** (banner 取证后):
  - `192.41.22.30`: 0 真开放 (全部 `no_banner`) — TUN 持续伪造
  - `192.41.22.32`: 0 真开放 (全部 `no_banner`) — TUN 持续伪造
  - `192.41.22.47`: **真开放 [80]**, banner `HTTP/1.1 403 Forbidden\r\nDate: ... Server: Apache\r\n...` — 真·HTTP 服务, 但用 IP 直访被拒 (403)
- **污染日志**: 空 (DoH 全干净, 因为 UDP/53 不再调用)

### 关键诊断文件
- `diagnose_dns.py` — 证明 4 层劫持
- `diagnose_portscan_anomaly.py` — 证明 2 IP 同 33 端口是 TUN 伪造
- `cartmanager_dns_pollution_evidence.json` — v2 时代的污染证据 (审计用, 不再生成新)

## Phase 2 待办 (下一步)
- 只对 `192.41.22.47:80` 做有意义的真实探测
- Host 头用各子域 (`Host: cartmanager.net`, `Host: www.cartmanager.net` 等), 看是否返回非 403 内容
- 指纹: Apache 版本, Server banner, 是否有 WAF (Cloudflare?)
- 敏感文件: `/.git/HEAD`, `/robots.txt`, `/.env`, `/sitemap.xml`, `/phpinfo.php`, `/server-status`, `/.well-known/`
- 子域应用归类: 19 子域对应 3 IP, 跑 reachability 时按 IP 分组

## 监理日志
- 2026-06-27 (Asia/Singapore) 启动
- Phase 0 启动: 18511 proxy 加载完成, 测活进行中
- Phase 1 v1 → 失败 (16 子域全 198.18.0.x): TUN 系统 DNS 劫持
- Phase 1 v2 → 失败 (改显式 NS 仍 198.18.0.x): TUN UDP/53 劫持
- Phase 1 v3.1 → **干净**: DoH-only + banner 取证, 落盘 3 真实 IP + 19 子域
- Phase 2 准备中: 唯一可达 `192.41.22.47:80` (Apache, 403 on IP-direct)
