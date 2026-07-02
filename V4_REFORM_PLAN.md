# V4 ALL-IN-TRAFFIC 三段论改造方案 V4

> 基于"打点零 payload → 流量化零 payload → LLM 分析找突破口 → 精准 payload 验证"四阶段模型。
> 覆盖：代码结构、数据模型、提示词、编排逻辑、已发现的 Bug。
> **V4 修订**：对照真实代码逐条核实，修正事实性错误、消除重复造轮子、统一调用约定。

---

## 核心思路

```
Phase ①: 打点 ————— 零 payload
     ↓ 产出: AssetInventory
Phase ②: 流量化 ——— 零 payload，纯正常发包采集流量
     ↓ 产出: TrafficJournal（干净的请求/响应记录）
Phase ③: LLM 分析 —— 读完整 TrafficJournal，找突破口
     ↓ 产出: BreakthroughList（每个突破口含 payload_category）
Phase ④: 精准验证 —— 根据突破口指定的 payload_category 选取 payload 验证
     ↓ 产出: 漏洞确认/修复报告
```

### 关键原则

1. **Phase ① 和 ② 不发任何恶意 payload**。发的都是正常的 HTTP GET/POST、TCP connect、banner grab。目的是采集"系统真实的样子"，不影响服务状态。
2. **Phase ③ LLM 看到的流量是干净的**。没有被 payload 污染的响应，没有被 WAF 拦截的 body，LLM 能准确判断系统指纹、认证机制、API 结构。
3. **Payload 只在 Phase ④ 使用**——而且只发 LLM 指定的那几类，不是全量盲打。
4. **Payload 库按突破口类型组织**，不是按攻击类型。LLM 说"这是 IDOR"，就从映射表查到 `vuln_type="idor"`，交给现有 `MultiChannelInjector.scan_all()` 执行。
5. **engine 不自动写 journal**——`engine.py` 里没有任何 `record_http/journal` 调用。Phase ② 必须在每个 trafficify 方法里手动 `journal.record_http()`。

---

## 前提：当前代码审查中发现的 Bug

### BUG-1: `_action_detect_panel` 把 AsyncClient 当同步 session 传给 detect_panels

- **文件**: `agent.py` L2224-L2226
- **现状**: 代码已有 `requests.Session()` 兜底，但只在 `session is None` 时触发。当 engine 的 `_client` 非空时（常见情况），拿到的是 `httpx.AsyncClient`（`burp.py` L351 确认）。
- **问题**: `detect_panels()` 内部执行 `session.get(url, allow_redirects=True)`（同步 requests 风格）。`httpx.AsyncClient.get()` 返回 coroutine，不会真正发请求；且 `allow_redirects` 参数名 httpx 不认（httpx 用 `follow_redirects`）。
- **后果**: 只要 engine client 非空，面板检测就是坏的，静默无结果。
- **修复**: 引入 `_get_http_session()` 工厂方法，始终返回同步 `requests.Session`。

### BUG-2: `_action_probe` 和 `_action_scan` 仍用旧 SyncBurp

- **文件**: `agent.py` L1005-L1022, L1042-L1061
- **代码**: `from .sync_wrapper import SyncBurp; burp = SyncBurp(...)`
- **后果**: 不走 V4 TrafficEngine，不共享代理/连接池/journal
- **修复**: 改走共享 engine 或统一代理池

### BUG-3: `_action_supply_chain` 面板检测同 BUG-1

- **文件**: `agent.py` L2167（`_action_supply_chain` 内的 panel 检测段）
- 同 BUG-1，`detect_panels(..., session=burp._client)` 把 AsyncClient 当同步 session 传。

### BUG-4（新增）: `_action_inject` 把 AsyncClient 直接传给 MultiChannelInjector

- **文件**: `agent.py` L1509-L1510
- **代码**:
  ```python
  session = burp._client  # 注释写"httpx.Client (同步视图)"但实际是 AsyncClient
  ```
- **问题**: `MultiChannelInjector` 的 docstring 明确写"session: 已配好代理的 requests.Session"，内部 `_send_payload` 是同步调用。`try` 块只是属性访问，不会抛异常，所以永远不会走到下面 `requests.Session` 的兜底分支。
- **后果**: 所有注入请求都不会真正发出，或返回 coroutine 被当 dict 访问报错。
- **修复**: 统一用 `_get_http_session()`，与 BUG-1 同一个工厂方法。

### 统一修复：`_get_http_session()` 工厂方法

```python
def _get_http_session(self) -> "requests.Session":
    """
    获取一个真正的同步 requests.Session。
    仅用于不兼容 async 的第三方库调用（hosting_panel_detect / MultiChannelInjector）。
    不走 V4 engine 的 async client，但共享代理配置。
    """
    import requests
    import urllib3
    urllib3.disable_warnings()
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    if self.proxy_manager:
        try:
            proxy_url = self.proxy_manager.get_proxy() or getattr(self.proxy_manager, 'url', None)
            if proxy_url:
                session.proxies = {'http': proxy_url, 'https': proxy_url}
        except Exception:
            pass
    return session
```

修复范围：`_action_detect_panel`、`_action_supply_chain`、`_action_inject` 三处统一替换。

---

## 第一阶段：打点标准化 — 零 payload

### 目标

所有 Phase ① action 产出统一格式的资产清单，且**不发任何攻击性 payload**。下游 Phase ② 直接消费。

### 新增文件: `aiburp/traffic/asset_schema.py`

```python
@dataclass
class AssetItem:
    type: str          # "domain" / "ip" / "url" / "port" / "subdomain" / "credential" / "directory"
    value: str         # 资产值
    source: str        # 来源: "asset_expand" / "traffic_scan" / "dir_fuzz" / ...
    metadata: Dict     # service, banner, tags, confidence, version, ...
    confidence: float  # 0.0 ~ 1.0
    discovered_at: float
    tags: List[str]    # 语义标签: ["http", "admin", "redis", "panel:phpmyadmin", ...]

@dataclass
class AssetInventory:
    target: str        # 原始目标
    items: List[AssetItem]
    created_at: float
```

### Phase ① 涉及的 action（全部零 payload）

| action | 功能 | 零 payload 确保方式 |
|:-------|:-----|:-------------------|
| `_action_asset_expand` | DNS **子域名**/旁站/**C段**枚举 | 仅 DNS 查询，无 HTTP 请求 |
| `_action_intel_lookup` | IP/域名情报 | 仅查数据库，无请求 |
| `_action_cdn_bypass` | CDN 绕过 | 仅 DNS 遍历 |
| `_action_github_leaks` | GitHub 泄露搜索 | 仅 Git API 调用 |
| `_action_traffic_scan` | 多协议**端口**探测 | TCP connect + banner grab，不发送攻击数据 |
| `_action_detect_panel` | 检测管理面板/登录页 | 仅发正常 GET 请求，检测响应特征 |
| `_action_dir_fuzz`（新增） | **目录**枚举 | 仅发正常 GET 请求（不带任何 SQLi/XSS payload），通过响应码/长度判断路径是否存在 |
| `_action_login_brute` | **→ 移出 Phase ①** | 弱口令涉及恶意请求，归 Phase ④ |

> **为什么子域名/端口/目录/C段全放 Phase ①？**
> 这四类穷举的本质是"发现未知资产"，发的都是标准协议请求（DNS 查询、TCP 连接、HTTP GET），**不携带任何攻击 payload**，不会触发 WAF 或修改服务状态。Phase ② 只需要消费 Phase ① 的产出，然后对已发现的资产做正常流量采集即可。

**关键调整**：`_action_login_brute` 不走 Phase ① 自动化，仅在 LLM 发现"这里有登录面"后作为验证手段调用。

### `_action_dir_fuzz` 关键参数

```python
def _action_dir_fuzz(self, params: Dict) -> Dict:
    """
    目录枚举 — 仅发正常 GET, 不带任何 payload。

    Args:
        url: 目标根 URL (如 https://example.com)
        wordlist: (可选) 自定义字典路径; 默认用内置小字典
        max_paths: 最大路径数, 默认 200 (控制规模, 避免打挂目标)
        concurrency: 并发数, 默认 10
        delay: 请求间隔秒数, 默认 0.3 (限速, 避免封 IP)
    """
```

- **wordlist 来源**：内置 `aiburp/payloads/wordlists/common_dirs.txt`（约 200 条常见路径），或用户指定
- **规模控制**：默认 200 条，可配置；超过 500 条需 LLM 显式批准
- **限速**：每请求间隔 0.3s，并发 10
- **判断逻辑**：响应码 200/301/302/403 = 路径存在；404 = 不存在；记录响应长度用于 Phase ③ 分析

### `_run_phase1_auto()` 伪代码

```python
def _run_phase1_auto(self, target: str) -> AssetInventory:
    """
    Phase ① 自动编排: 按顺序跑打点 action, 合并产出到 AssetInventory。
    """
    from .traffic.asset_schema import AssetInventory, AssetItem
    inventory = AssetInventory(target=target, items=[], created_at=time.time())

    # 1. 情报查询
    intel = self._action_intel_lookup({"target": target})

    # 2. 资产扩展 (子域名/旁站/C段)
    expand = self._action_asset_expand({"domain": target})
    for sub in expand.get("data", {}).get("subdomains", []):
        inventory.items.append(AssetItem(
            type="subdomain", value=sub, source="asset_expand",
            metadata={}, confidence=0.8, discovered_at=time.time(),
            tags=["http"],
        ))

    # 3. CDN 绕过 (找源 IP)
    cdn = self._action_cdn_bypass({"domain": target})

    # 4. 端口扫描
    scan = self._action_traffic_scan({"target": target})
    for port_info in scan.get("data", {}).get("hosts", []):
        inventory.items.append(AssetItem(
            type="port", value=f"{port_info['host']}:{port_info['port']}",
            source="traffic_scan", metadata=port_info,
            confidence=0.9, discovered_at=time.time(),
            tags=[port_info.get("service", "unknown")],
        ))

    # 5. 目录枚举 (对主域名)
    dir_result = self._action_dir_fuzz({"url": f"https://{target}"})
    for found_path in dir_result.get("data", {}).get("found", []):
        inventory.items.append(AssetItem(
            type="directory", value=found_path["url"],
            source="dir_fuzz", metadata=found_path,
            confidence=0.7, discovered_at=time.time(),
            tags=["dir"],
        ))

    # 6. 面板检测
    panel = self._action_detect_panel({"url": f"https://{target}"})
    for p in panel.get("data", {}).get("panels", []):
        inventory.items.append(AssetItem(
            type="url", value=p["login_url"], source="detect_panel",
            metadata=p, confidence=0.9, discovered_at=time.time(),
            tags=["panel", p["panel_type"]],
        ))

    self._inventory = inventory
    return inventory
```

### Phase ① 产出物

```
self._inventory = AssetInventory(target=domain)
# 包含: 子域名 / IP / C段 / 开放端口及服务 / 目录路径 / 面板URL / 认证端点 / ...
```

---

## 第二阶段：资产转流量 — 零 payload，纯正常发包

### 目标

对所有已发现的资产，**只发正常的、不带任何攻击性的请求**来采集流量，全部手动写入 TrafficJournal（engine 不会自动写）。

### 原则

1. HTTP 请求不加任何 SQLi/XSS/SSRF payload
2. 不加 `'`、`"`、`OR 1=1`、`<script>` 等测试字符
3. 不加 path traversal（`../`）
4. 不加非常规的 Header（`X-Forwarded-For: 127.0.0.1` 之类也先不发）
5. TCP/UDP 连接只做标准协议握手 + banner grab
6. **所有结果手动 `journal.record_http()` 写入**，engine 不自动写

### 核心新增: `_trafficify_assets()`

```python
def _trafficify_assets(self, inventory: AssetInventory = None) -> Dict:
    """
    把 AssetInventory 中的所有资产批量转流量,
    只发正常请求, 结果写入 TrafficJournal.
    """
    inventory = inventory or getattr(self, "_inventory", None)
    if not inventory:
        return {"ok": False, "error": "无资产清单"}

    journal = self._ensure_journal()
    count_before = len(journal._entries)

    for item in inventory.items:
        try:
            if item.type == "url":
                self._trafficify_url(item, journal)
            elif item.type in ("subdomain",):
                self._trafficify_subdomain(item, journal)
            elif item.type == "port":
                self._trafficify_port(item, journal)
            elif item.type == "directory":
                self._trafficify_url(item, journal)  # 目录已有完整 URL, 复用 url 逻辑
            elif item.type == "credential":
                # Phase ② 不验证凭据, 仅记录 (打码)
                journal.record_raw(
                    protocol="credential", target=item.value,
                    summary=f"凭证: {item.metadata.get('username', '?')}:***",
                    direction="none", source="trafficify",
                )
        except Exception:
            continue

    entries_added = len(journal._entries) - count_before
    return {
        "ok": True,
        "entries_added": entries_added,
        "journal_summary": journal.llm_summary(last_n=entries_added or 50),
    }
```

### 子方法 — 全部改走 `_run_with_engine()`

> **关键修正**：不再用 `asyncio.new_event_loop()`（会触发跨 loop 错误），统一走 `_run_with_engine(coro_factory)`。

#### `_trafficify_url()` — 对单个 URL 发正常 GET 请求

```python
def _trafficify_url(self, item, journal):
    """对 URL 发正常 GET, 不加任何 payload, 走共享 engine"""
    async def _do(eng):
        client = eng._adapters["http"]._burp._client
        if client is None:
            return
        try:
            resp = await client.get(item.value, timeout=10, follow_redirects=False)
            body_hint = resp.text[:2000] if resp.text else ""
            journal.record_http(
                method="GET", url=item.value,
                status=resp.status_code,
                headers=dict(resp.headers),
                length=len(resp.content),
                body=body_hint,
                source="trafficify",
            )
        except Exception as e:
            journal.record_raw(
                protocol="http", target=item.value,
                summary=f"GET → error: {str(e)[:60]}",
                direction="request", source="trafficify",
                error=str(e)[:80],
            )

    self._run_with_engine(_do)
```

#### `_trafficify_subdomain()` — 对子域名发 GET 请求

```python
def _trafficify_subdomain(self, item, journal):
    """子域名 → 默认协议探测 + 正常 GET"""
    host = item.value
    urls_to_try = []
    if item.metadata.get("protocol"):
        urls_to_try.append(f"{item.metadata['protocol']}://{host}")
    elif item.metadata.get("port") == 443:
        urls_to_try.append(f"https://{host}")
    else:
        urls_to_try.append(f"http://{host}")
        urls_to_try.append(f"https://{host}")

    async def _do(eng):
        client = eng._adapters["http"]._burp._client
        if client is None:
            return
        for url in urls_to_try:
            try:
                resp = await client.get(url, timeout=8, follow_redirects=False)
                journal.record_http(
                    method="GET", url=url, status=resp.status_code,
                    headers=dict(resp.headers),
                    length=len(resp.content),
                    body=resp.text[:2000] if resp.text else "",
                    source="trafficify",
                )
            except Exception:
                continue

    self._run_with_engine(_do)
```

#### `_trafficify_port()` — 对开放端口做标准协议探测

```python
def _trafficify_port(self, item, journal):
    """端口 → 根据服务类型做标准 banner grab, 不发恶意 payload"""
    host = item.metadata.get("host", "")
    port = item.metadata.get("port", item.value.split(":")[-1] if ":" in item.value else "")
    service = item.metadata.get("service", "").lower()

    if service in ("http", "https") and host:
        return  # HTTP 端口已通过 url type 覆盖

    async def _do(eng):
        target = f"{host}:{port}" if host else item.value
        result = await eng.smart_probe(target, timeout=8)
        if result:
            journal.record_raw(
                protocol=service or "tcp",
                target=target,
                summary=f"banner: {str(result)[:100]}",
                direction="response", source="trafficify",
            )

    try:
        self._run_with_engine(_do)
    except Exception as e:
        journal.record_raw(
            protocol=service or "tcp",
            target=f"{host}:{port}",
            summary=f"probe error: {str(e)[:60]}",
            direction="request", source="trafficify",
            error=str(e)[:80],
        )
```

---

## 第三阶段：LLM 流量分析 — 读干净流量找突破口

### 目标

LLM 读取完整的 TrafficJournal（干净的、未被 payload 污染的流量），分析系统结构，找到突破口。**每个突破口输出时附带 payload_category**，供 Phase ④ 精准发 payload。

### 修改 `prompts.py` — 新增 `TRAFFIC_ANALYZER` 提示词

```python
class PromptTemplates:
    TRAFFIC_ANALYZER = """
# 流量包分析 — 你面前是一份完整的渗透测试流量日志

## 重要约束
这份流量日志是 **干净的**。所有请求都是正常流量，没有混入任何攻击 payload。
这确保了你看的是系统的真实面貌，没有被 WAF 干扰、没有被 payload 污染响应。

## 你的任务

这是一份针对 {target} 的完整流量日志（TrafficJournal）。
你的工作是：**读流量，找突破口，并为每个突破口指定 payload 分类**。

## 什么是"突破口"？

突破口不是漏洞列表。突破口是：
1. **认证绕过** — 未授权访问了管理接口？用泄露的 token 访问了受限资源？
2. **信息升级** — 从低危信息（版本号、路径泄露）升级到更高危的攻击
3. **组合攻击** — 两个看起来无害的发现组合成一个 exploit
4. **业务逻辑缺陷** — 流量模式揭示了不正常的业务操作顺序
5. **隐藏攻击面** — 响应中出现了 API 文档、隐藏参数、调试接口

## 分析框架

### Step 1: 流量概览
- 这个系统是什么？（从 Server header、响应体指纹判断）
- 暴露了哪些服务？（HTTP/Redis/Docker/SSH/...）
- 有哪些认证机制？（Session/JWT/Basic/OAuth/无）
- 请求-响应模式是什么？（JSON API / 表单提交 / 文件上传 / ...）

### Step 2: 逐条深度分析

对每条流量，标注：
```
[Entry #{id}]
协议: {protocol}
方向: {direction}
摘要: {summary}
关键信号: {error_signals}
---
问题: 这条流量暴露了什么？
      - 敏感信息? (版本/路径/token/凭证)
      - 异常行为? (错误/超时/不一致)
      - 攻击面? (可控参数/未授权接口)
      - 组合线索? (能和其他条目组合吗)
```

### Step 3: 模式发现

- 同一端点不同参数 → IDOR 可能
- 多次 500/403 → 参数边界探索
- 302 + Set-Cookie → 会话分析
- 静态文件返回动态内容 → 网关绕过
- 响应长度突变 → 注入点

### Step 4: 突破口生成

输出结构：
```json
[
  {{
    "type": "突破口类型",
    "target": "目标URL/IP",
    "evidence": "流量证据（引用具体的 entry id 和值）",
    "impact": "利用后的影响",
    "confidence": "高/中/低",
    "payload_category": "指定验证所需 payload 分类",
    "payload_args": {{"param": "id", "base_value": "1", "method": "GET"}},
    "requires_combination": false,
    "combo_with": []
  }}
]
```

### payload_category 可选值

| 分类 | 适用场景 |
|:-----|:---------|
| `idor` | 参数替换（订单/用户ID/文件ID） |
| `sqli_reflection` | 参数回显在响应中，可能是 SQL 注入反射点 |
| `sqli_blind` | 参数可能影响数据库，需时间盲注检测 |
| `xss_reflected` | 参数值出现在 HTML 中，可能反射 XSS |
| `xss_stored` | 提交内容在其他页面显示，可能存储 XSS |
| `ssrf` | 目标请求外部 URL，可能 SSRF |
| `lfi` | 文件读取参数，可能本地文件包含 |
| `path_traversal` | 路径参数未过滤 |
| `cmdi` | 系统命令执行参数 |
| `ssti` | 模板引擎渲染用户输入 |
| `jwt_none` | 使用 JWT 且可能 alg: none |
| `jwt_weak_secret` | JWT 可能弱密钥 |
| `upload_bypass` | 文件上传功能可能绕过 |
| `unauth_bypass` | 接口未授权访问 |
| `auth_brute` | 登录面爆破 |
| `cors_misconfig` | CORS 配置可能允许任意 Origin+凭据 |
| `redirect_open` | 重定向参数可控 |
| `api_discovery` | 需要进一步发现 API 端点 |
| `graphql_introspect` | GraphQL 端点可能可内省 |
| `no_auth_check` | 需要检测是否真正鉴权 |

### 约束
- 每个突破口必须有流量日志中的具体证据支持
- 每个突破口必须指定一个 `payload_category`
- 如果流量不足，明确说"需要更多 {'url': ['/admin', '/api']}的探测"——此时可请求回退到 Phase ①/② 补点
- 区分"可直接利用"和"需要条件"

## 流量日志

{journal}

---

基于上述分析，列出你找到的突破口：
"""
```

### 修改 `agent.py` — 新增 `_llm_analyze_journal()` 方法

> **关键修正**：
> - `self.llm_client.chat([...])` → `self.llm.ask(prompt)`（真实 API）
> - `_parse_llm_json()` 不存在，用 `self.parser.parse()` 或内联 JSON 解析
> - TrafficRuleEngine context 改为嵌套结构 `{"response": {...}, "request": {...}}`

```python
def _llm_analyze_journal(self, target: str) -> Dict:
    """
    把当前 TrafficJournal 发给 LLM 分析,
    返回突破口列表（每个突破口含 payload_category）。
    """
    journal = self._ensure_journal()
    if len(journal._entries) < 3:
        return {"ok": False, "error": "流量不足 (< 3 条), 先补充流量"}

    from .prompts import PromptTemplates
    from .traffic.experience_rules import TrafficRuleEngine

    journal_text = journal.llm_summary(last_n=100)

    # 附加规则引擎分析结果（作为补充信号，非主流）
    tre = TrafficRuleEngine()
    rule_hits = []
    for entry in journal._entries[-100:]:
        # 关键修正: experience_rules.py 读的是嵌套结构
        ctx = {
            "response": {
                "status": getattr(entry, "status", 0),
                "body": getattr(entry, "body", ""),
                "headers": getattr(entry, "headers", {}),
                "url": getattr(entry, "url", ""),
                "banner": getattr(entry, "summary", ""),
            },
            "request": {
                "headers": {},
            },
            "url": getattr(entry, "url", ""),
        }
        rule_hits.extend(tre.apply(ctx))
    if rule_hits:
        journal_text += "\n### TrafficRuleEngine 自动命中:\n"
        for h in rule_hits[:10]:
            journal_text += f"- [{h.severity}] {h.finding_type}: {h.evidence[:80]}\n"

    prompt = PromptTemplates.TRAFFIC_ANALYZER.format(
        target=target,
        journal=journal_text,
    )

    try:
        response = self.llm.ask(prompt)
        # 解析 LLM 输出的 JSON 突破口列表
        import json
        import re
        # 尝试从响应中提取 JSON 数组
        m = re.search(r'\[.*\]', response, re.DOTALL)
        breakthroughs = json.loads(m.group(0)) if m else []
        for bt in breakthroughs:
            bt["_source"] = "llm_journal_analysis"
            self._add_to_context("breakthrough", bt.get("target", "?"), bt)
        return {
            "ok": True,
            "breakthroughs": breakthroughs,
            "summary": f"找到 {len(breakthroughs)} 个突破口",
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
```

---

## 第四阶段：精准 payload 验证 — 复用 MultiChannelInjector

### 目标

根据 LLM 在 Phase ③ 输出的突破口列表（每个含 `payload_category`），**映射到现有 `MultiChannelInjector` 的 `vuln_type`**，直接复用其 `scan_all()` 执行验证。不另起炉灶。

### 现有能力（已存在，复用）

`MultiChannelInjector`（`injector.py:145`）已有：
- `_get_payloads(vuln_type)` — 按漏洞类型选 payload（sqli/xss/ssrf/cmdi/ssti/lfi/idor/auth-bypass）
- `_detect_sqli()` / `_detect_xss()` / `_detect_ssrf()` / `_detect_idor()` / `_detect_ssti()` — 完整检测器
- `scan_all(url, vuln_types, channels)` — 全量扫描

### 新增: `aiburp/payloads/by_breakthrough.py`（仅映射表）

```python
"""
突破口 payload_category → MultiChannelInjector vuln_type 映射。

不另建 payload 库, 不另写检测器,
只做一层翻译, 直接复用 MultiChannelInjector.scan_all()。
"""

# payload_category → injector vuln_type
CATEGORY_TO_VULNTYPE = {
    "idor": "idor",
    "sqli_reflection": "sqli",
    "sqli_blind": "sqli",
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "ssrf": "ssrf",
    "lfi": "lfi",
    "path_traversal": "lfi",           # 路径遍历复用 LFI 检测器
    "cmdi": "cmdi",
    "ssti": "ssti",
    "jwt_none": "auth-bypass",         # JWT alg:none 归认证绕过
    "jwt_weak_secret": "auth-bypass",
    "upload_bypass": None,             # 文件上传需专用逻辑, injector 暂不覆盖
    "unauth_bypass": "auth-bypass",
    "auth_brute": None,                # 登录爆破走 _action_login_brute
    "cors_misconfig": None,            # CORS 需专用检测
    "redirect_open": None,             # 开放重定向需专用检测
    "api_discovery": None,             # API 发现是 Phase ①/② 范畴
    "graphql_introspect": None,        # GraphQL 需专用检测
    "no_auth_check": "auth-bypass",
}


def get_vuln_types(category: str) -> list:
    """
    payload_category → vuln_types 列表 (供 MultiChannelInjector.scan_all 用)。

    返回空列表表示该类别不适用 injector, 需走专用验证方法。
    """
    vt = CATEGORY_TO_VULNTYPE.get(category)
    return [vt] if vt else []
```

### 核心新增: `_verify_breakthrough()` — 复用 injector

```python
def _verify_breakthrough(self, bt: Dict) -> Dict:
    """
    根据 LLM 输出的一个突破口, 精准发 payload 验证。
    复用 MultiChannelInjector, 不另写检测器。
    """
    target = bt.get("target", "")
    category = bt.get("payload_category", "")
    args = bt.get("payload_args", {})

    if not target or not category:
        return {"ok": False, "error": "突破口缺 target 或 payload_category"}

    from .payloads.by_breakthrough import get_vuln_types

    vuln_types = get_vuln_types(category)
    if not vuln_types:
        # 不适用 injector 的类别, 走专用验证
        return self._verify_special(target, category, args)

    # 用 _get_http_session() 拿同步 session (修复 BUG-4)
    session = self._get_http_session()

    try:
        from .traffic.injector import MultiChannelInjector
        injector = MultiChannelInjector(session)
        report = injector.scan_all(target, vuln_types=vuln_types)

        findings = [f.to_dict() for f in report.findings]
        confirmed = any(f["confidence"] == "confirmed" for f in findings)

        self._add_to_context("verify_result", target, {
            "breakthrough_type": bt.get("type"),
            "category": category,
            "confirmed": confirmed,
            "findings": findings,
        })

        return {
            "ok": True,
            "target": target,
            "category": category,
            "confirmed": confirmed,
            "findings": findings,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def _verify_special(self, target: str, category: str, args: Dict) -> Dict:
    """
    处理 injector 不覆盖的类别:
    - upload_bypass: 调 _action_attack_checklist 的上传检测维度
    - auth_brute: 调 _action_login_brute
    - cors_misconfig / redirect_open / graphql_introspect: 专用检测
    - api_discovery: 回退到 Phase ① 补点
    """
    if category == "auth_brute":
        return self._action_login_brute({"url": target})
    if category == "upload_bypass":
        return self._action_attack_checklist({"url": target})
    if category == "api_discovery":
        # 请求回退到 Phase ① 补点
        return {"ok": False, "error": "需要回退 Phase ① 补充 API 端点探测",
                "needs_rerun": True}
    # cors / redirect / graphql: 简单专用检测
    return {"ok": True, "target": target, "category": category,
            "confirmed": False, "note": "专用检测待实现"}
```

### Phase ② → Phase ④ 的完整流转

```
Phase ② 产出干净的 TrafficJournal
    ↓
Phase ③ LLM 分析, 产出突破口列表:
    [
        {
            "type": "IDOR",
            "target": "https://fershop.net/api/order?id=1",
            "payload_category": "idor",
            "payload_args": {"param": "id", "method": "GET", "base_value": "1"},
            "confidence": "高",
        },
        {
            "type": "SQL 注入反射",
            "target": "https://fershop.net/search?q=hello",
            "payload_category": "sqli_reflection",
            "payload_args": {"param": "q", "method": "GET"},
            "confidence": "中",
        },
    ]
    ↓
Phase ④: 遍历突破口列表，对每个突破口:
    - 取 payload_category="idor"
    - 查 CATEGORY_TO_VULNTYPE["idor"] → ["idor"]
    - 调 MultiChannelInjector.scan_all(target, vuln_types=["idor"])
    - injector 内部自动: 取 payload → 发请求 → 检测响应
    - 如果 confirmed, 标记, 停
```

---

## 第五阶段：四阶段 pipeline 改造 — `run()` 重构

### 目标

在现有 `run()` 方法（`agent.py:465`）基础上，增加四阶段自动 pipeline。不新建 `start()` 或 `_ooda_loop()`。

### 整体流程

```python
def run(self, initial_instruction: str = None) -> Dict:
    """
    V4 三段论: 打点→流量化→LLM分析→精准验证
    在现有 run() 基础上, 前置四阶段自动 pipeline, 然后进入原有 OODA 循环。
    """

    # === OpSec 安全闸门 (保持原有逻辑) ===
    if not self.is_ready:
        return {"ok": False, "error": "LLM 未配置"}
    if self._proxy_required:
        pv = self.verify_proxy()
        if not pv["safe"]:
            return {"ok": False, "error": f"OpSec 拒绝: {pv.get('error')}"}

    self.running = True
    self.iteration = 0
    target = initial_instruction or ""
    self._phase = 0  # 新增: 阶段标记

    # === Phase ①: 打点 ===
    print(f"\n{'='*60}")
    print(f"  Phase ①: 打点 — 零 payload 资产收集")
    print(f"{'='*60}")
    self._run_phase1_auto(target)
    self._phase = 1

    # === Phase ②: 流量化 ===
    print(f"\n{'='*60}")
    print(f"  Phase ②: 流量化 — 零 payload 正常流量采集")
    print(f"{'='*60}")
    traffic_result = self._trafficify_assets()
    if not traffic_result.get("ok"):
        print(f"  [WARN] 流量化失败: {traffic_result.get('error')}")
        return self._enter_ooda_loop(initial_instruction)
    self._phase = 2

    # === Phase ③: LLM 分析 ===
    print(f"\n{'='*60}")
    print(f"  Phase ③: LLM 分析 — 读流量找突破口")
    print(f"{'='*60}")
    bt_result = self._llm_analyze_journal(target=target)
    breakthroughs = bt_result.get("breakthroughs", [])
    self._phase = 3

    print(f"  找到 {len(breakthroughs)} 个突破口")
    for i, bt in enumerate(breakthroughs):
        print(f"    [{i+1}] [{bt.get('confidence','?')}] "
              f"{bt.get('type','?')} → {bt.get('target','?')[:60]} "
              f"(payload: {bt.get('payload_category','?')})")

    # === Phase ④: 精准验证 ===
    print(f"\n{'='*60}")
    print(f"  Phase ④: 精准验证 — 按突破口发 payload")
    print(f"{'='*60}")
    confirmed = []
    for bt in breakthroughs:
        result = self._verify_breakthrough(bt)
        if result.get("confirmed"):
            confirmed.append(bt)
            print(f"  ✅ 确认: {bt.get('type','?')} @ {bt.get('target','?')[:60]}")
        elif result.get("needs_rerun"):
            # 软门控: 允许回退补点
            print(f"  ↩️ 回退补点: {bt.get('payload_category')} 需要更多探测")
    self._phase = 4

    print(f"\n  确认 {len(confirmed)}/{len(breakthroughs)} 个突破口")

    # === 进入原有 OODA 循环 ===
    context_msg = (
        f"目标: {target}\n"
        f"资产清单: {len(getattr(self, '_inventory', None) and self._inventory.items or [])} 项\n"
        f"流量日志: {len(self._ensure_journal()._entries)} 条\n"
        f"突破口: {len(breakthroughs)} 个 (已确认 {len(confirmed)})\n"
        f"请根据已验证的突破口深入利用, 或要求继续打点/流量化."
    )
    return self._enter_ooda_loop(context_msg)
```

### Action 重新归类

| action | 阶段归属 | payload? |
|:-------|:--------:|:--------:|
| `intel_lookup` | ① 打点 | ❌ |
| `asset_expand` | ① 打点 | ❌ |
| `cdn_bypass` | ① 打点 | ❌ |
| `github_leaks` | ① 打点 | ❌ |
| `traffic_scan` | ① 打点 | ❌ |
| `detect_panel` | ① 打点 | ❌ |
| `supply_chain` | ① 打点 | ❌ |
| `dir_fuzz` | **① 打点** | ❌ |
| `traffic_probe` | ② 流量化 | ❌ |
| `check_unauth` | ② 流量化 | ❌ |
| `traffic_analyze` | ③ LLM 分析 | ❌ |
| `finding` | ③ LLM 分析 | ❌ |
| `memory` | 跨阶段 | ❌ |
| `think` | 跨阶段 | ❌ |
| `exploit` | **④ 精准验证** | ✅ |
| `inject` | **④ 精准验证** | ✅ |
| `probe` | **④ 精准验证** | ✅ |
| `scan` | **④ 精准验证** | ✅ |
| `revshell` | **④ 精准验证** | ✅ |
| `login_brute` | **④ 精准验证** | ✅ |
| `attack_checklist` | **④ 精准验证** | ✅ |
| `logic_scan` | **④ 精准验证** | ✅ |
| `jwt_analyze` | **④ 精准验证** | ✅ |

### `_execute_action()` 软门控

> **关键修正**：不再用刚性 `if self._phase >= 1: return error`，改为软门控——允许 LLM 回退补点，只记录告警。

```python
# 四阶段常量
_PHASE1_ACTIONS = {
    "intel_lookup", "asset_expand", "cdn_bypass",
    "github_leaks", "traffic_scan", "detect_panel", "supply_chain",
    "dir_fuzz",
}
_PHASE2_ACTIONS = {"traffic_probe", "check_unauth"}
_PHASE3_ACTIONS = {"traffic_analyze", "finding"}
_PHASE4_ACTIONS = {
    "exploit", "inject", "probe", "scan", "revshell",
    "login_brute", "attack_checklist", "logic_scan", "jwt_analyze",
}

def _execute_action(self, action: Dict) -> Dict:
    """
    带软门控的 action 执行。
    允许 LLM 在后期阶段调用前期 action (补点), 只记录告警。
    """
    action_type = action["action"]
    params = action.get("params", {})

    # Phase ①: 打点
    if action_type in self._PHASE1_ACTIONS:
        if getattr(self, "_phase", 0) > 1:
            print(f"  ⚠️ 软门控: 已进入 Phase {self._phase}, LLM 回退补点 ({action_type})")
        return self._dispatch_action(action_type, params)

    # Phase ②: 流量化
    if action_type in self._PHASE2_ACTIONS:
        if getattr(self, "_phase", 0) > 2:
            print(f"  ⚠️ 软门控: 已进入 Phase {self._phase}, LLM 回退补流量 ({action_type})")
        if not getattr(self, "_inventory", None):
            self._run_phase1_auto("")
        return self._dispatch_action(action_type, params)

    # Phase ③: LLM 分析
    if action_type in self._PHASE3_ACTIONS:
        if not getattr(self, "_trafficified", False):
            self._trafficify_assets()
            self._trafficified = True
        return self._dispatch_action(action_type, params)

    # Phase ④: 精准 payload 验证
    if action_type in self._PHASE4_ACTIONS:
        return self._dispatch_action(action_type, params)

    # 非阶段 action（memory / think / ...）
    return self._dispatch_action(action_type, params)

def _dispatch_action(self, action_type: str, params: Dict) -> Dict:
    """原 _execute_action 的 if-elif 分派逻辑, 保持不变"""
    # ... 原有代码搬过来 ...
```

---

## 第六阶段：payload 库清理与重组

### 当前问题

payload 散布在 16 个文件、50+ 处，包括 `prompts.py` 中的 `PAYLOADS` 和 `CTHULHU_PAYLOADS` 两个大字典。这些字典是静态的、无法被 LLM 按突破口的 `payload_category` 索引的。

### 重组方案

1. **保留 `aiburp/payloads/` 目录**作为底层数据源（`MultiChannelInjector._get_payloads()` 已在用）
2. **新增 `aiburp/payloads/by_breakthrough.py`** 仅作映射表（见 Phase ④），不重复 payload
3. **清理 `prompts.py`** 中的 `PAYLOADS` 和 `CTHULHU_PAYLOADS` 字典：
   - 它们的 content 可以作为底层数据源迁移到 `aiburp/payloads/` 目录下的 txt 文件
   - 或者迁移到 `by_breakthrough.py` 的 `BREAKTHROUGH_PAYLOADS` 字典中
   - 删除 `prompts.py` 中的原始字典定义
4. **`prompts.py` 中的 `EXPERIENCE_LESSONS` 常量**已由 `aiburp/traffic/experience_rules.py` 替代，删除

### 删除清单

| 文件 | 行号 | 内容 | 替代 |
|:-----|:----:|:-----|:-----|
| `prompts.py` | 1109 | `PAYLOADS` 字典 | `aiburp/payloads/by_breakthrough.py` |
| `prompts.py` | 1896 | `CTHULHU_PAYLOADS` 字典 | `aiburp/payloads/by_breakthrough.py` |
| `prompts.py` | 约 100 行 | `EXPERIENCE_LESSONS` 常量 | `traffic/experience_rules.py` |

---

## 总结：变更清单

| 阶段 | 改动量 | 核心文件 | 类型 |
|:-----|:------:|:---------|:----:|
| **Bug 修复** | 小 | `agent.py` (3 处统一 `_get_http_session()`) | 修复 |
| **Phase ① 打点标准化** | 中 | `asset_schema.py` (新增), `agent.py` (8 个 action + `_run_phase1_auto`) | 代码 |
| **Phase ② 零 payload 流量化** | 中 | `agent.py` (4 个方法, 走 `_run_with_engine`) | 代码 |
| **Phase ③ LLM 提示词 + payload_category** | 中 | `prompts.py`, `agent.py` (`self.llm.ask`) | 提示词+代码 |
| **Phase ④ 精准验证** | 小 | `by_breakthrough.py` (仅映射表), `agent.py` (复用 injector) | 代码 |
| **Phase ⑤ 四阶段 pipeline** | 大 | `agent.py` (`run()` 重构 + 软门控 `_execute_action`) | 编排 |
| **Phase ⑥ payload 库清理** | 中 | `prompts.py`, `by_breakthrough.py` | 清理+迁移 |

### 优先级建议

```
高优先级（立即修）:
  BUG-1/3/4: AsyncClient 当同步 session 用 — 统一 _get_http_session()
  BUG-2: _action_probe/_action_scan 不走 V4 engine

中优先级（本周内）:
  Phase ②: _trafficify_assets() + 3 个子方法 (走 _run_with_engine)
  Phase ③: TRAFFIC_ANALYZER prompt + _llm_analyze_journal() (self.llm.ask)
  Phase ④: by_breakthrough.py 映射表 + _verify_breakthrough() (复用 injector)

低优先级（按需）:
  Phase ①: AssetInventory schema + _run_phase1_auto() (可渐进式改造)
  Phase ⑤: run() 四阶段 pipeline + 软门控 (可渐进式改造)
  Phase ⑥: payload 库清理 (不阻塞功能)
```

### V4 修订对照表

| V3 问题 | V4 修正 |
|:--------|:--------|
| BUG-1/3 描述过时（说"未修复"但已有兜底） | 改为"AsyncClient 当同步 session 用 + 参数名不兼容"，说明兜底不生效的原因 |
| 漏掉 `_action_inject` 同样问题 | 新增 BUG-4 |
| `self.llm_client.chat([...])` 不存在 | 改为 `self.llm.ask(prompt)` |
| `start()` / `_ooda_loop()` 不存在 | 改为重构 `run()`，新增 `_enter_ooda_loop()` |
| `_parse_llm_json()` 不存在 | 内联 `json.loads` + `re.search` |
| `asyncio.new_event_loop()` 反模式 | 全部改走 `_run_with_engine(coro_factory)` |
| Phase ④ 平行实现 payload 库 + 检测器 | 退化成映射表，复用 `MultiChannelInjector.scan_all()` |
| TrafficRuleEngine context 扁平结构 | 改为嵌套 `{"response": {...}, "request": {...}}` |
| 阶段门控刚性（不允许回退） | 改为软门控（允许回退补点，记录告警） |
| 凭证明文写入 journal | 打码 `username:***` |
| `engine 自动写 journal` 的误解 | 明确标注"engine 不自动写，需手动 record_http" |
| `_run_phase1_auto()` 缺失 | 补充伪代码 |
| `_action_dir_fuzz` 参数缺失 | 补充 wordlist/规模/限速参数 |
```
