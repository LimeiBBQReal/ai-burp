# AI-Burp V4 迁移指南

> **V4.0.0 — ALL-IN-TRAFFIC**: 所有流量接口都能成为渗透起点

V4 是 AI-Burp 的重大升级：从"HTTP 扫描器"变成"全流量红队平台"。本文档帮你快速理解 V3 → V4 的变化。

---

## 核心理念

> **"Tools for collection, AI for decision-making, Agents for evolution."**
>
> 工具采集 → 数据越丰富，AI 决策越准确。V4 把"采集"从 HTTP 一层撑到了全流量。

V3 只能扫 Web（HTTP/HTTPS）。V4 新增 **12 个协议**，覆盖红队 90% 攻击面。

---

## V3 → V4 变化一览

| 维度 | V3 | V4 |
|------|-----|-----|
| 协议覆盖 | HTTP/HTTPS | HTTP + TCP + DNS + Redis + Docker + Kubelet + WebSocket + UDP + TLS + SNMP + MySQL + RMI + SMB |
| 流量入口 | `AsyncBurp` | `TrafficEngine`（取代，含原 AsyncBurp 能力）|
| 决策接口 | `Decision` | `Decision` + `TrafficResponse`（协议无关）|
| 语义分析 | `IntentAnalyzer`（HTTP）| `IntentAnalyzer.analyze_response`（多协议）|
| 批量扫描 | ❌ | `scan_cidr` / `scan_hosts` |
| 未授权检测 | 手写 | `check_unauth`（Redis/Docker/K8s/MySQL/SMB/SNMP）|
| CLI | `aiburp probe/scan` | + `aiburp-ide traffic probe/scan/check` |
| Agent | HTTP-only | + `traffic_probe` / `traffic_scan` action |
| 测试 | 基础 | 183 个测试 + 安全固化 |

---

## 向后兼容（重要）

**V3 代码无需任何改动即可在 V4 运行。**

```python
# 这些 V3 代码在 V4 完全可用：
from aiburp import AsyncBurp, SmartBurp, Decision, IntentAnalyzer

burp = AsyncBurp()
r = await burp.get("https://target.com/api?id=1")
tags = IntentAnalyzer.analyze("https://target.com/login", None)
detectors = IntentAnalyzer.suggest_detectors(["DB", "AUTH"])
```

V4 的新功能是**附加**的，不破坏 V3 API。

---

## 快速开始：V4 新能力

### 1. 多协议探活（自动路由）

```python
import asyncio
from aiburp.traffic import TrafficEngine

async def main():
    async with TrafficEngine() as engine:
        # 自动识别协议: 6379->redis, 443->http, 3306->mysql
        resp = await engine.smart_probe("10.0.0.1:6379")
        print(resp.banner)    # "redis"
        print(resp.tags)      # ['REDIS', 'HIGH-VALUE', 'UNAUTH-CHECK']
        print(resp.to_dict()) # AI 友好的 JSON

asyncio.run(main())
```

### 2. 一键未授权检测

```python
async with TrafficEngine() as engine:
    # Redis 未授权 + RCE 可能性
    resp = await engine.check_unauth("10.0.0.1:6379")
    # tags: ['REDIS', 'UNAUTH-CONFIRMED', 'HIGH-VALUE', 'RCE-PATH']

    # Docker API 未授权 (确定性 RCE)
    resp = await engine.check_unauth("10.0.0.1:2375")

    # MySQL 弱口令
    resp = await engine.check_unauth("10.0.0.1:3306")
```

### 3. 批量资产扫描

```python
async with TrafficEngine() as engine:
    # 扫一个 C 段, 26 个高危端口
    result = await engine.scan_cidr("10.0.0.0/24")

    print(result.report_text())               # 人类可读报告
    print(result.summary())                   # 统计摘要
    for e in result.high_value_entries():     # 只看高危
        print(f"{e.target} {e.service} {e.tags}")
```

### 4. CLI 直接用

```bash
# 多协议探活
aiburp-ide traffic probe 10.0.0.1:6379

# 批量扫描 (人类报告, 只看高危)
aiburp-ide traffic scan 10.0.0.0/24 --text --high-value-only

# 未授权检测
aiburp-ide traffic check 10.0.0.1:2375
```

### 5. Agent 自主调用

LLM 可以输出这些 action 让 Agent 执行：

```json
{"action": "traffic_probe", "params": {"target": "10.0.0.1:6379"}}
{"action": "traffic_scan", "params": {"cidr": "10.0.0.0/24", "ports": [22, 80, 6379]}}
```

---

## 协议覆盖对照表

| 协议 | V3 | V4 | 未授权检测 |
|------|:--:|:--:|-----------|
| HTTP/HTTPS | ✅ | ✅ | V3 既有 |
| TCP | ❌ | ✅ | banner 指纹 |
| DNS | ❌ | ✅ | AXFR + version.bind |
| **Redis** | ❌ | ✅ | UNAUTH + RCE 检测 |
| **Docker** | ❌ | ✅ | UNAUTH + RCE 检测 |
| **Kubelet** | ❌ | ✅ | UNAUTH + RCE 检测 |
| **WebSocket** | ❌ | ✅ | CSWSH 跨域劫持 |
| **UDP** | ❌ | ✅ | 数据报基建 |
| **TLS** | ❌ | ✅ | SAN 泄露 + 弱套件 |
| **SNMP** | ❌ | ✅ | 默认 community 爆破 |
| **MySQL** | ❌ | ✅ | 弱口令 + UDF RCE |
| **RMI** | ❌ | ✅ | 反序列化风险标注 |
| **SMB** | ❌ | ✅ | EternalBlue + 空会话 |

---

## TrafficResponse：V4 的核心数据结构

V3 的 `Response` 是 HTTP 专用。V4 新增 `TrafficResponse`，是**所有协议的统一响应**：

```python
from aiburp.traffic import TrafficResponse

resp = TrafficResponse(
    protocol="redis",      # 协议标识
    ok=True,               # 是否成功
    banner="redis/7.0",    # 服务指纹
    tags=["REDIS", "HIGH-VALUE"],  # 语义标签 (AI 消费)
    anomalies=["unauth-access"],   # 异常标记
)

# AI 友好序列化 (JSON 安全, bytes 用 base64)
resp.to_dict()
resp.to_json()

# IntentAnalyzer 分析
from aiburp.burp import IntentAnalyzer
tags = IntentAnalyzer.analyze_response(resp)
steps = IntentAnalyzer.suggest_next_steps(tags, "redis")
```

---

## 依赖变化

### 新增必需依赖
- `python-dotenv>=1.0.0`（V3 用了但没声明，V4 补上）

### 可选协议库（按需安装）
```bash
pip install websockets    # WebSocket adapter
pip install pymysql       # MySQL adapter
pip install cryptography  # TLS 证书解析
pip install impacket      # SMB adapter (完整模式)
```

缺失可选库时，对应 adapter **优雅降级**（返回 `library-not-installed` 错误，不阻断其它协议）。

### Python 版本
- V3: `>=3.8`
- V4: `>=3.9`（`asyncio.to_thread` 需要 3.9+）

---

## 从 V3 迁移到 V4 的建议

### 不迁移（V3 代码继续用）
V4 完全向后兼容。如果你的 V3 代码工作正常，**不需要改任何东西**。

### 渐进式采用 V4
1. **第一步**：用 CLI 试新协议
   ```bash
   aiburp-ide traffic probe 10.0.0.1:6379
   ```
2. **第二步**：在侦察阶段用 `scan_cidr` 替代手动 nmap
3. **第三步**：用 `check_unauth` 自动化未授权检测
4. **第四步**：让 Agent 用 `traffic_probe/scan` 做多协议决策

### 完全迁移到 V4
```python
# V3 写法
from aiburp import AsyncBurp
burp = AsyncBurp()
resp = await burp.get("https://target.com/api")

# V4 等价写法 (推荐, 协议无关)
from aiburp.traffic import TrafficEngine, TrafficRequest
async with TrafficEngine() as engine:
    resp = await engine.send(TrafficRequest(
        protocol="http", target="https://target.com/api"
    ))
```

---

## 常见问题

### Q: V4 会影响我现有的扫描器插件吗？
**不会。** V3 的 `VulnScanner` / `SQLI` / 检测器全部不变。V4 是新增层，不动 V3 核心。

### Q: 不装可选库会怎样？
对应 adapter 返回明确错误（`websockets-library-not-installed`），不影响其它协议。`TrafficEngine` 初始化时自动跳过缺库的 adapter。

### Q: TrafficEngine 会取代 AsyncBurp 吗？
**不会取代，而是包装。** `HttpAdapter` 内部就是调用 `AsyncBurp`。新代码建议用 `TrafficEngine`，旧代码继续用 `AsyncBurp`。

### Q: Agent 模式现在支持多协议了吗？
**是的。** Agent 新增了 `traffic_probe` 和 `traffic_scan` 两个 action，LLM 可以输出这些 action 让 Agent 扫描非 HTTP 协议。

---

## 测试覆盖

V4 包含 **183 个测试**，覆盖：
- 协议适配器（13 个协议的成功/失败/边界路径）
- 安全防护（RESP 注入、nuclei 代码注入、ReDoS）
- 批量扫描（CIDR、并发、大网段保护）
- CLI 命令（probe/scan/check）
- Agent 集成（VALID_ACTIONS、action 执行）

```bash
pytest tests/ -v
```

---

## 相关文档

- [README.md](README.md) - 项目总览
- [DEVELOPMENT_PROGRESS.md](DEVELOPMENT_PROGRESS.md) - 开发进度
- [ARCHITECTURE.md](ARCHITECTURE.md) - 架构设计
