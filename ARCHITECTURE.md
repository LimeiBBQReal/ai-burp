# AI-Burp 架构

## 核心理念：精准决策

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI 安全决策师 (Claude)                        │
├─────────────────────────────────────────────────────────────────┤
│  在关键决策点介入：                                              │
│  1. 探测完成 → 选择攻击向量                                      │
│  2. 发现错误 → 确认漏洞，选择利用方式                            │
│  3. 被 WAF 拦截 → 选择绕过策略                                   │
│  4. 测试完成 → 分析结果，决定下一步                              │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Decision (决策请求)
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    SmartBurp (智能工具)                          │
├─────────────────────────────────────────────────────────────────┤
│  发现异常时自动暂停，生成决策报告：                              │
│  - 当前状态                                                      │
│  - 发现了什么                                                    │
│  - 可选的下一步                                                  │
│  - 工具的建议                                                    │
└─────────────────────────────────────────────────────────────────┘
```

## 决策机制

### Decision 类

```python
@dataclass
class Decision:
    type: str           # probe_done, error_found, waf_blocked, fuzz_done
    status: str         # 当前状态描述
    findings: Dict      # 发现了什么
    options: List[Dict] # 可选操作 [{action, desc}, ...]
    suggestion: str     # 工具建议
    data: Any           # 相关数据
```

### 决策触发点

| 触发点 | type | 典型场景 |
|--------|------|----------|
| 探测完成 | `probe_done` | 完成参数探测，需要选择攻击向量 |
| 发现错误 | `error_found` | 触发数据库错误，需要确认漏洞 |
| 被拦截 | `waf_blocked` | 连续被 WAF 拦截，需要选择绕过策略 |
| 测试完成 | `fuzz_done` | 批量测试完成，需要分析结果 |
| 确认结果 | `confirm_result` | 漏洞确认完成，需要选择利用方式 |

### 工作流程

```
1. smart_probe() 探测参数
   │
   ├─ 发现错误 → Decision(type="error_found")
   │              options: [confirm_time, confirm_error, confirm_union]
   │              suggestion: "建议用时间盲注确认"
   │
   ├─ 被拦截 → Decision(type="waf_blocked")
   │            options: [bypass_encoding, bypass_case, bypass_comment]
   │            suggestion: "建议尝试编码绕过"
   │
   └─ 正常 → Decision(type="probe_done")
              options: [fuzz_sqli, fuzz_xss, skip]
              suggestion: "可尝试 SQL 注入测试"

2. AI 根据 Decision 选择操作
   │
   └─ 选择 "confirm_time"

3. confirm_sqli() 确认漏洞
   │
   ├─ 确认成功 → Decision(type="confirm_result")
   │              findings: {确认方式, 有效payload, 延迟时间}
   │              options: [extract_version, extract_tables, dump_data]
   │
   └─ 确认失败 → Decision(suggestion="尝试其他确认方式")

4. AI 继续决策...
```

## 使用示例

```python
from aiburp import SmartBurp, SQLI, Bypass

burp = SmartBurp()

# 1. 智能探测
decision = burp.smart_probe("https://target.com/api", "id", "1")
print(decision)

# 输出:
# ==================================================
# 🎯 决策点: error_found
# ==================================================
# 
# 📊 状态: 探测完成: https://target.com/api 参数 id
# 
# 🔍 发现:
#   - 基线: 200/1234b
#   - WAF: 无
#   - 触发错误: {'单引号': 'mysql'}
# 
# 📋 可选操作:
#   1. [confirm_time] 时间盲注确认 (SLEEP)
#   2. [confirm_error] 报错注入确认
#   3. [confirm_union] UNION 注入确认
# 
# 💡 建议: 发现 mysql 错误，建议用时间盲注确认
# ==================================================

# 2. 根据决策执行
if decision.type == "error_found":
    # 确认漏洞
    confirm = burp.confirm_sqli(
        "https://target.com/api", "id", "1", 
        method="time"
    )
    print(confirm)

# 3. 智能 Fuzz (发现异常自动暂停)
decision = burp.smart_fuzz(
    "https://target.com/api?id=§",
    SQLI.time_based,
    pause_on_finding=True
)
print(decision)
# 发现错误时自动暂停，返回决策请求
```

## 漏洞检测器架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    VulnScanner (统一接口)                        │
├─────────────────────────────────────────────────────────────────┤
│  scan_all()   - 全面扫描 (6种漏洞)                               │
│  quick_scan() - 快速扫描 (SQLi + XSS)                           │
│  scan()       - 指定类型扫描                                     │
│  report()     - 生成扫描报告                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ SQLiDetector  │   │  XSSDetector  │   │ SSRFDetector  │
├───────────────┤   ├───────────────┤   ├───────────────┤
│ - 错误检测    │   │ - 反射检测    │   │ - 内网探测    │
│ - 时间盲注    │   │ - 上下文分析  │   │ - 云元数据    │
│ - 布尔盲注    │   │ - 编码检测    │   │ - OOB外带     │
└───────────────┘   └───────────────┘   │ - 协议走私    │
                                        └───────────────┘
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ CMDiDetector  │   │  LFIDetector  │   │ SSTIDetector  │
├───────────────┤   ├───────────────┤   ├───────────────┤
│ - 时间盲注    │   │ - Linux文件   │   │ - 模板计算    │
│ - 输出检测    │   │ - Windows文件 │   │ - 错误信息    │
│ - OOB外带     │   │ - PHP包装器   │   │ - 引擎识别    │
└───────────────┘   └───────────────┘   └───────────────┘
```

### Finding 数据结构

```python
@dataclass
class Finding:
    vuln_type: str      # sqli, xss, ssrf, cmdi, lfi, ssti
    confidence: str     # high, medium, low
    evidence: str       # 证据描述
    payload: str        # 触发的 payload
    details: Dict       # 详细信息
```

### 检测流程

```
1. 获取基线响应
   │
2. 发送检测 payload
   │
   ├─ 错误信息匹配 → Finding(confidence="high")
   │
   ├─ 时间延迟检测 → Finding(confidence="high")
   │
   ├─ 响应差异分析 → Finding(confidence="medium")
   │
   └─ OOB 外带请求 → Finding(confidence="low", 需人工确认)
```

## 文件结构

```
ai-burp/
├── aiburp/
│   ├── __init__.py   # 入口
│   ├── burp.py       # 核心 (Burp, SmartBurp, Decision)
│   ├── payloads.py   # Payload 加载器
│   ├── detectors.py  # 漏洞检测器 (6种)
│   └── cli.py        # 命令行
└── payloads/         # Payload 文件库 (50+ txt)
    ├── sqli/         # 12 个文件
    ├── xss/          # 8 个文件
    ├── lfi/          # 5 个文件
    ├── ssrf/         # 5 个文件
    ├── cmdi/         # 5 个文件
    ├── ssti/         # 4 个文件
    └── bypass/       # 13 个文件
```

## 设计原则

1. **工具采集，AI 决策** - 工具负责执行和检测，AI 负责分析和决策
2. **关键点暂停** - 发现异常时自动暂停，不无脑继续
3. **决策报告清晰** - 告诉 AI 发生了什么、有哪些选项、建议是什么
4. **精准出牌** - Payload 库充足，但根据情况精准选择
5. **省 Token** - 只在关键决策点消耗 Token，常规操作工具自动完成
6. **全面覆盖** - 6种漏洞类型，每种都有专用检测器
7. **OOB 支持** - SSRF/CMDi 支持外带检测，适应无回显场景
