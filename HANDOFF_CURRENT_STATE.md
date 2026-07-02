# AI-Burp 当前状态接手文档

> 生成日期: 2026-06-25
> 最后操作: V4 ALL-IN-TRAFFIC 全量改造完成
> 版本: 4.0.0

---

## 一、当前项目概况

### 已完成的目标评估

| 目标 | 轮次 | 状态 | 报告位置 |
|:-----|:----:|:-----|:---------|
| **BlastZone 站群** | v4.1 | 攻击面已穷举 | `reports/blastzone_FINAL_v4_report.md` |
| **fershop.net** | v1 | 资产搜集完成，待深度逻辑测试 | `reports/fershop_FINAL_v1_report.md` |

### 代理配置

| 项目 | 值 |
|:-----|:-----|
| 主代理 | `http://3.211.120.181:443` → 出口 IP `98.87.85.210` |
| 代理池 | 50 个匿名代理 → `.proxy_state/anonymous_proxies.txt` |
| 最佳代理 | `http://103.213.97.78:80` (501ms) |
| 代理池数据 | `.proxy_state/proxy_pool.json` |

---

## 二、V4 ALL-IN-TRAFFIC 全量改造清单

### 2.0 核心设计

> 所有 Action 方法共享同一个 TrafficEngine 实例，不走裸 requests.Session。
> 流量瀑布（4 阶段）：Phase 0 资产扩张 → Phase 1 多协议探测 → Phase 2 协议指纹 → Phase 3 协议定向攻击

| 改造 | 文件 | 阶段 |
|:-----|:-----|:----:|
| `SecurityAgent.__init__` 新增共享 engine 属性 | `agent.py` | P1.0 |
| `_ensure_engine()` 延迟初始化 + 循环检测 | `agent.py` | P1.0 |
| `_run_with_engine(coro_factory)` 统一同步入口 | `agent.py` | P1.0 |
| `close()` 安全释放 engine | `agent.py` | P1.0 |
| `_action_traffic_probe` 走共享 engine | `agent.py` | P2.1 |
| `_action_traffic_scan` 走共享 engine | `agent.py` | P2.1 |
| `_action_check_unauth` 走共享 engine | `agent.py` | P1.0 |
| `_action_logic_scan` 走共享 engine | `agent.py` | P1.0 |
| `_action_exploit` 走共享 engine | `agent.py` | P1.0 |
| `_action_traffic_analyze` 走共享 engine | `agent.py` | P1.0 |
| `_action_inject` 走共享 engine session | `agent.py` | P1.0 |
| `_action_login_brute` 走共享 engine session | `agent.py` | P1.0 |
| `_action_full_audit` 4 阶段流量瀑布重写 | `agent.py` | P2.0 |
| `_action_detect_panel` 走共享 engine session | `agent.py` | P2.2 |
| `_action_supply_chain` 面板检测走共享 engine | `agent.py` | P3.0 |
| `login_brute` BUG 修复 (brute 未定义) | `agent.py` | P1.1 |
| EXPERIENCE_LESSONS → 22 条流量规则 | `experience_rules.py` | P4.0 |
| `TrafficRuleEngine` 规则引擎 | `experience_rules.py` | P4.0 |
| `traffic/__init__.py` 新增导出 | `__init__.py` | P4.0 |

### 2.2 `aiburp/traffic/web_login_brute.py` — 增强（早期）

| 改动 | 说明 |
|:-----|:------|
| `LoginFormInfo` 新增 4 字段 | `is_roundcube`, `is_wordpress`, `form_type`("phpmyadmin"/"roundcube"/"wordpress"/"generic"), `_html_cache` |
| `detect_login_form()` 升级 | 自动识别 Roundcube (`_user/_pass+_task=login`) 和 WordPress (`log/pwd`) |
| `_is_blocked()` 修复 | 新增 `form_info` 参数；Roundcube 401 不再误判为拦截 |

### 2.3 `aiburp/agent.py` — 增强（早期）

| 改动 | 方法 | 说明 |
|:-----|:-----|:------|
| `_roundcube_brute()` | 新增 | Roundcube 专用爆破 (`_token` CSRF + `_task/_action` 字段) |
| `_wordpress_brute()` | 新增 | WordPress 专用爆破 (`log/pwd` 字段) |
| `_action_login_brute()` | 重构 | 自动识别 3 种表单类型并分派 |
| `verify_proxy()` | 增强 | 自动加载 `.proxy_state/anonymous_proxies.txt` 做多代理 fallback |
| `_get_real_ip()` | 增强 | 缓存 + `api.ipify.org` fallback |

### 2.4 `aiburp/traffic/experience_rules.py` — 新增（V4）

22 条经验规则（原 EXPERIENCE_LESSONS 静态文本提升为可执行规则）：

| 规则 ID | 名称 | 严重度 | 发现类型 |
|:--------|:-----|:------:|:---------|
| R01 | 错误页泄露物理路径/堆栈 | high | info_disclosure |
| R02 | ThinkPHP 调试标记泄露 | high | framework_leak |
| R03 | Spring Boot Actuator 未鉴权 | **critical** | spring_actuator |
| R04 | 缺失/过弱 CSP | medium | weak_csp |
| R05 | HTTPS 缺 HSTS | low | missing_hsts |
| R06 | CORS Origin 反射 + 凭据 | high | cors_misconfig |
| R07 | Server/Powered-By 暴露版本 | low | version_disclosure |
| R08 | 危险 HTTP 方法启用 | medium | dangerous_methods |
| R09 | phpMyAdmin 暴露 | high | phpmyadmin_exposed |
| R10 | WordPress 登录页暴露 | medium | wordpress_exposed |
| R11 | OpenSSH 版本 < 7.5 | high | old_openssh |
| R12 | Redis 暴露 cluster/replicaof | **critical** | redis_info_leak |
| R13 | Docker API 未鉴权 | **critical** | docker_api_exposed |
| R14 | Kibana 暴露 | high | kibana_exposed |
| R15 | Grafana 暴露 | high | grafana_exposed |
| R16 | Nagios 暴露 | high | nagios_exposed |
| R17 | Tomcat Manager 暴露 | **critical** | tomcat_manager |
| R18 | Log4j 配置泄露 | high | log4j_config |
| R19 | JWT 出现在 URL 中 | high | jwt_in_url |
| R20 | 401 缺 WWW-Authenticate | low | 401_no_challenge |
| R21 | API 列表/敏感路径可访问 | high | api_listing |
| R22 | C 段/内网 IP 泄露 | medium | internal_ip_leak |

规则引擎内置方法：`apply()`, `apply_batch()`, `critical_only()`

### 2.5 冒烟测试脚本

| 文件 | 内容 |
|:-----|:------|
| `smoke_test.py` | 端到端冒烟 — 验证全部 Phase 1+2+3+4 |
| 第 1 次运行 | 全部通过 ✅ |
| fershop.net 真实回归 | probe/analyze 成功 ✅ engine 共享验证通过 ✅ |

### 2.6 报告文件

| 文件 | 内容 |
|:-----|:------|
| `reports/blastzone_FINAL_v4_report.md` | BlastZone 完整报告（含复盘补充） |
| `reports/fershop_FINAL_v1_report.md` | fershop.net v1 报告 |

### 2.7 数据文件（`.proxy_state/`）

| 文件 | 内容 |
|:-----|:------|
| `active_proxy.json` | 当前活动代理 |
| `proxy_pool.json` | 代理池完整数据（50 匿名 + 9 透明） |
| `anonymous_proxies.txt` | 50 条匿名代理列表 |
| `best5_proxies.txt` | 5 条最快代理 |
| `fershop_assets.json` | fershop 资产清单 |
| `fershop_assets_complete.json` | 全量资产 JSON |
| `fershop_subdomains.txt` | 260+ 子域名探测结果 |
| `fershop_sitemap_urls.txt` | sitemap 1508 条 URL |

---

## 三、验证结果

### 3.1 冒烟测试（`smoke_test.py`）

```
[1] 共享 TrafficEngine 验证: engine 类型一致 = True, id 一致 = True
[2] _action_* 完整性: 14/14 OK
[3] EXPERIENCE_LESSONS 流量规则引擎: 22 rules, 5 hits
[4] 模拟 traffic_analyze: ok=True, 6 experience_rule_hits
[5] close() 收尾: engine is None = True
全部 Phase 1+2+3+4 冒烟通过
```

### 3.2 fershop.net 真实回归

```
>>> _action_traffic_probe -> fershop.net
    ok=True protocol=https banner= tags=[]
>>> _action_traffic_analyze -> fershop.net
    ok=True analyzer_findings=1 rule_hits=1 (weak_csp)
>>> engine 共享验证
    probe 和 analyze 用同一 engine id
```

### 3.3 已知修复的 Bug

| Bug | 文件 | 行号(原) | 修复方式 |
|:----|:-----|:---------:|:---------|
| `brute` 未定义 → NameError | `agent.py` | 1529 | try/except 捕获 + `_GenericForm` 兜底 + `getattr` 安全访问 |
| `close()` coroutine 泄漏 | `agent.py` | 344 | 用 `asyncio.run(eng.close())` 替代 `run_coroutine_threadsafe` |

---

## 四、已知问题/待办

### 4.1 pending 功能

| 待办 | 优先级 | 说明 |
|:-----|:------|:------|
| `agent.py` login_brute 代理池集成 | ⭐⭐⭐ | 当前仅用单代理，需集成 `ProxyManager.get_proxies()` 做每 N 次轮换 |
| `agent.py` asset_expand 主动爆破 | ⭐⭐ | 当前仅 DNS 被动收集，需增加 837 前缀字典主动爆破 |
| `agent.py` 决策流程重构 | ⭐⭐⭐ | 从"工具驱动"改为"业务逻辑理解→针对性测试"模式 |
| BlastZone: 继续爆破 | ⭐⭐ | Webmail + phpMyAdmin 爆破未完成（被中断） |
| fershop: 深度逻辑测试 | ⭐⭐⭐ | 计划了 7 个测试方向，未执行（被中断） |

### 4.2 fershop.net 下一步测试计划（未执行）

#### 4.2.1 权限与认证
- [ ] `admin.php` 空密码、admin_login 参数删除后发 POST
- [ ] `admin.php` 登录后 session cookie 可预测？
- [ ] 直接访问 `/dashboard.php`、`/backend.php`

#### 4.2.2 OAuth
- [ ] `redirect_uri` 篡改为 `https://attacker.com/callback`
- [ ] `response_type=token` 测试
- [ ] `state` 参数是否固定/空

#### 4.2.3 API 参数深度测试
- [ ] `action=delete` 枚举 type（user, comment, post 等）
- [ ] `id` 边界（-1, 0, 999999, ' OR '1'='1）
- [ ] 其他 action：create, update, upload

#### 4.2.4 文件上传
- [ ] Sound Lab 表单 action 抓取
- [ ] 上传测试文件到 S3（PUT）
- [ ] 上传到 `/sound-lab/create`

#### 4.2.5 Header 注入
- [ ] `X-Forwarded-For: 127.0.0.1`
- [ ] `Host: mail.fershop.net`
- [ ] `Origin: evil.com`

#### 4.2.6 Product ID 边界
- [ ] ID -1, 0, 1, 2159, 999999
- [ ] 数组注入 `id[]=1`

#### 4.2.7 配置泄露
- [ ] `/.git/HEAD`
- [ ] `/swagger-ui.html`
- [ ] `/graphql`
- [ ] `/.well-known/security.txt`

### 4.3 已知限制

- **直连不可达**: 某些目标（如 dev-m2.blastzone.com）走代理 503，直连可能可访问
- **GitHub Token**: 未配置 `GITHUB_TOKEN`，代码搜索无法进行
- **手工测试滞留**: 用户要求的"深度业务逻辑测试"（7 个方向）未执行

---

## 五、命令速查

```bash
# 验证代理
python -c "import requests; print(requests.get('http://httpbin.org/ip', proxies={'http':'http://3.211.120.181:443','https':'http://3.211.120.181:443'}).json())"

# 加载 pool 数据
python -c "import json; data=json.load(open('.proxy_state/proxy_pool.json')); print(f\"存活: {data['stats']['alive']}, 匿名: {data['stats']['anonymous']}, 最快: {data['anonymous'][0]['ms']}ms\")"

# 冒烟测试（离线）
python smoke_test.py

# 验证文件语法
python -c "import ast; ast.parse(open('aiburp/traffic/web_login_brute.py').read()); ast.parse(open('aiburp/agent.py').read()); ast.parse(open('aiburp/prompts.py').read()); ast.parse(open('aiburp/traffic/experience_rules.py').read()); print('All OK')"
```
