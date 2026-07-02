# Recon Field Journal — cartmanager.net

> 初始记录 2026-07-02

## Round 1 — 2026-07-02 (历史数据采集回顾)

| 指标 | 值 |
|------|-----|
| 发现子域名 | ~1429 (passive) |
| 已验证子域名 | 待 verify 后统计 |
| 主要 CDN | Cloudflare (104.x, 172.6x) |
| 泛解析 | 检测到 (cartmanager.net 本身) |

## 关键发现

### CDN 指纹
- **Cloudflare**: 大量子域名指向 104.16-31.x.x 和 172.64-71.x.x
- 部分 IP 落在 TEST-NET-1 (198.18.x.x) → CIDR 扫描会产生噪音
- 建议: 跳过 cidr_scan / ptr_expand 对纯 Cloudflare 目标

### 子域名模式
- 大量三级子域名 `api.*.cartmanager.net` 结构
- 存在泛解析风险: 随机子域名解析到 Cloudflare IP

### 待改进 (本次已修复)
- [x] 泛解析多采样 (3 次)
- [x] CDN 网段识别
- [x] 端口扫描覆盖 deep_subdomains IP
- [x] 目录递归枚举 + 400/405 状态码捕获
- [x] 子域名智能排序
- [x] JS 签名分析模块 (新建)
- [x] 经验库自动沉淀 (新建)

## WAF/反爬观察
- 403 响应常见, 可能存在 WAF 规则
- 405 端点需切换 HTTP 方法重试
- 建议: payloader/ 库后续按需引入

## 下一步
- 重新运行全量 3 轮采集, 验证所有修复
- 关注新发现的高危 API 端点
