# AI安全研究助手 - 编排器设计文档

> **创建日期**: 2026-01-03
> **版本**: 1.0
> **状态**: 设计阶段

---

## 目录

1. [核心理念](#核心理念)
2. [三位一体架构](#三位一体架构)
3. [编排器详细设计](#编排器详细设计)
4. [状态持久化机制](#状态持久化机制)
5. [RAG记忆系统](#rag记忆系统)
6. [Prompt激活器](#prompt激活器)
7. [工作流程](#工作流程)
8. [API设计](#api设计)
9. [实现路线图](#实现路线图)

---

## 核心理念

### 问题背景

大模型(LLM)在安全审计中存在以下局限：

1. **上下文窗口有限**：无法记住长代码/多文件
2. **新会话无记忆**：每次对话都是全新开始
3. **思维模式单一**：倾向于快速给出答案而非深度探索
4. **缺乏动态能力**：只能静态分析，无法动态测试

### 解决方案

构建"三位一体"系统：

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         三位一体：AI安全研究助手                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│     ┌──────────────┐      ┌──────────────┐      ┌──────────────┐        │
│     │   Prompt     │      │     RAG      │      │   AI-Burp    │        │
│     │   激活器     │      │   项目记忆   │      │   安全工具   │        │
│     └──────┬───────┘      └──────┬───────┘      └──────┬───────┘        │
│            │                     │                     │                 │
│            │ 激活深度思考        │ 保持上下文         │ 执行测试        │
│            │                     │                     │                 │
│            └─────────────────────┼─────────────────────┘                 │
│                                  │                                       │
│                           ┌──────▼──────┐                                │
│                           │   LLM Core  │                                │
│                           │ (已有知识)  │                                │
│                           └─────────────┘                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 关键洞察

1. **LLM已有知识远超任何数据库**：不需要存储CVE/攻击技术，LLM已经知道
2. **RAG是工作记忆，不是知识库**：用于存储当前项目的代码和分析过程
3. **工具提供动态能力**：AI-Burp执行黑盒测试，收集信息供LLM分析
4. **Prompt改变思维模式**：从"扫描器"变成"研究员"

---

## 三位一体架构

### 1. Prompt激活器

**作用**：改变LLM的思维模式

```
默认模式：
  用户问 → LLM快速回答 → 遇到困难就放弃

激活后模式：
  用户问 → LLM列出所有可能路径 → 逐条深入分析 → 
  遇到防护尝试绕过 → 组合多个弱点 → 给出详细结论
```

### 2. RAG项目记忆

**作用**：保持长上下文记忆

```
存储内容：
- 当前项目的代码片段
- 分析过程中的中间发现
- 跨文件的依赖关系
- 审计历史和进度

不存储：
- CVE数据库（LLM已知）
- 攻击技术（LLM已知）
- Gadget Chain（LLM已知）
```

### 3. AI-Burp工具

**作用**：执行安全测试，收集信息

```
能力：
- HTTP请求发送
- 漏洞检测（6种）
- 智能探测
- 批量Fuzz
- 决策系统（Decision）
```

---

## 编排器详细设计

### 核心问题

**问题**：新对话中，LLM没有之前的记忆，如何继续执行？

**解决**：状态文件 + 恢复Prompt

### 编排器架构

```python
class SecurityOrchestrator:
    """
    安全研究编排器
    
    职责：
    1. 管理任务状态（保存/加载）
    2. 协调三个组件（Prompt/RAG/AI-Burp）
    3. 生成恢复Prompt
    4. 记录分析历史
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.state_file = f".audit/{project_id}.json"
        self.memory = Memory()  # mem0
        self.burp = SmartBurp()
        
    # 核心方法
    def load_state(self) -> dict
    def save_state(self, state: dict)
    def generate_recovery_prompt(self) -> str
    def add_finding(self, finding: dict)
    def update_progress(self, task: str, status: str)
    def run_aiburp(self, target, params) -> Decision
```

### 工作流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 新会话开始                                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. 用户输入: "继续CKFinder审计"                                         │
│                                                                          │
│  2. 编排器自动:                                                          │
│     ├─ 加载状态文件 (.audit/ckfinder.json)                              │
│     ├─ 从RAG获取代码上下文                                               │
│     └─ 生成恢复Prompt                                                    │
│                                                                          │
│  3. Prompt注入到LLM:                                                     │
│     "你正在审计CKFinder 3.7.0，目标RCE..."                               │
│     "已发现: containsHtml不检测PHP..."                                   │
│     "待探索: 竞态条件..."                                                │
│                                                                          │
│  4. LLM继续分析:                                                         │
│     "好的，让我检查竞态条件..."                                          │
│                                                                          │
│  5. 如需动态测试:                                                        │
│     └─ 调用AI-Burp: burp.smart_probe(...)                               │
│                                                                          │
│  6. 发现新问题:                                                          │
│     ├─ 更新状态文件                                                      │
│     └─ 保存到RAG                                                         │
│                                                                          │
│  7. 会话结束时:                                                          │
│     └─ 自动保存当前状态                                                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 状态持久化机制

### 状态文件结构

```json
{
    "meta": {
        "project_id": "ckfinder_audit_2026",
        "created": "2026-01-03T22:00:00",
        "last_updated": "2026-01-03T23:00:00",
        "status": "in_progress"
    },
    
    "target": {
        "type": "whitebox",
        "name": "CKFinder 3.7.0",
        "path": "E:/CursorDEV/CKFinder/...",
        "goal": "RCE"
    },
    
    "progress": {
        "phase": "deep_analysis",
        "current_task": "检查Phar反序列化可能性",
        "completed_tasks": [
            "依赖扫描完成",
            "危险函数定位完成",
            "认证机制分析完成"
        ]
    },
    
    "findings": [
        {
            "id": "FINDING-001",
            "type": "design_flaw",
            "severity": "medium",
            "title": "containsHtml不检测PHP标签",
            "location": "Utils.php:247",
            "details": "...",
            "exploitable": false,
            "conditions": ["需配合扩展名绕过"]
        }
    ],
    
    "exploration": {
        "tried": [
            {"path": "Phar反序列化", "result": "blocked", "reason": "operationId正则限制"},
            {"path": "配置注入", "result": "blocked", "reason": "路径硬编码"}
        ],
        "pending": [
            "竞态条件检查",
            "缓存投毒分析"
        ]
    },
    
    "aiburp_state": {
        "last_decision": {
            "type": "probe_done",
            "findings": {},
            "chosen_action": "confirm_time"
        },
        "history": []
    },
    
    "context_chunks": [
        {"file": "OperationManager.php", "key_lines": [203, 208], "summary": "unserialize调用"},
        {"file": "Utils.php", "key_lines": [247], "summary": "HTML检测逻辑"}
    ]
}
```

### 状态文件位置

```
project_root/
├── .audit/
│   ├── ckfinder_2026.json      # 项目状态
│   ├── another_project.json
│   └── ...
```

---

## RAG记忆系统

### 推荐方案：mem0

**GitHub**: https://github.com/mem0ai/mem0

```python
from mem0 import Memory

# 初始化
memory = Memory()

# 添加项目上下文
memory.add(
    "CKFinder OperationManager.php:208 存在unserialize调用",
    metadata={"project": "ckfinder", "file": "OperationManager.php"}
)

# 检索相关记忆
results = memory.search(
    "unserialize漏洞", 
    user_id="ckfinder"
)
```

### 记忆分类

| 类型 | 内容 | 生命周期 |
|------|------|---------|
| **项目上下文** | 代码片段、依赖关系 | 项目持续期间 |
| **分析发现** | 漏洞、可疑点 | 永久 |
| **探索历史** | 尝试过的路径 | 项目持续期间 |
| **用户指令** | 重点关注方向 | 项目持续期间 |

---

## Prompt激活器

### 安全研究员Prompt模板

```markdown
# 安全研究员模式

你是一名顶级安全研究员，你的目标是找到0day漏洞。

## 思维框架
1. **攻击者视角**：不是"这安全吗？"而是"如果我想RCE，需要什么？"
2. **假设挑战**：开发者认为X是安全的，但真的吗？
3. **不轻易放弃**：遇到第一层防护，寻找绕过而非停止
4. **组合攻击**：单个弱点可能无害，组合起来可能致命

## 强制流程
1. 列出所有攻击目标（RCE、LFI、SQLi等）
2. 对每个目标，列出所有可能的实现路径
3. 对每条路径，检查每一层防护
4. 对每层防护，尝试至少3种绕过技术
5. 记录所有"差一点就成功"的情况

## 技术清单（必须逐一检查）
- [ ] Phar反序列化
- [ ] 编码绕过（UTF-8/Unicode）
- [ ] 竞态条件
- [ ] 类型混淆
- [ ] 依赖库CVE
- [ ] Gadget Chain
- [ ] 路径规范化差异
- [ ] 协议处理差异
```

### 恢复Prompt模板

```markdown
# 安全审计任务恢复

## 任务上下文
- **项目**: {target.name}
- **类型**: {target.type}
- **目标**: {target.goal}
- **当前阶段**: {progress.phase}
- **当前任务**: {progress.current_task}

## 已完成
{foreach completed_tasks}
✅ {task}
{/foreach}

## 已发现问题
{foreach findings}
{index}. [{severity}] {title} ({location})
   - {details}
{/foreach}

## 已探索路径
{foreach exploration.tried}
❌ {path} - {reason}
{/foreach}

## 待探索
{foreach exploration.pending}
- [ ] {item}
{/foreach}

## 关键代码记忆
{foreach context_chunks}
- {file}:{key_lines} → {summary}
{/foreach}

## 指令
继续上次的分析。当前任务：{progress.current_task}
请从"待探索"列表中选择下一个方向。
```

---

## 工作流程

### 白盒审计流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. 初始化                                                                │
├─────────────────────────────────────────────────────────────────────────┤
│    orchestrator = SecurityOrchestrator("project_name")                  │
│    orchestrator.set_target(type="whitebox", path="...", goal="RCE")    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. 信息收集 (自动)                                                       │
├─────────────────────────────────────────────────────────────────────────┤
│    - 依赖扫描                                                            │
│    - 危险函数定位                                                        │
│    - 代码结构分析                                                        │
│    → 结果存入RAG和状态文件                                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. 深度分析 (LLM + 人工)                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│    - 生成恢复Prompt                                                      │
│    - LLM分析可疑点                                                       │
│    - 尝试攻击路径                                                        │
│    - 记录发现                                                            │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. 验证利用 (AI-Burp)                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│    - 构造PoC                                                             │
│    - 动态测试                                                            │
│    - 确认可利用性                                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. 报告生成                                                              │
├─────────────────────────────────────────────────────────────────────────┤
│    - 汇总所有发现                                                        │
│    - 生成详细报告                                                        │
│    - 保存审计历史                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 黑盒测试流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. 初始化                                                                │
├─────────────────────────────────────────────────────────────────────────┤
│    orchestrator = SecurityOrchestrator("target_blackbox")               │
│    orchestrator.set_target(type="blackbox", url="https://...", goal="RCE")│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. 侦察 (AI-Burp)                                                        │
├─────────────────────────────────────────────────────────────────────────┤
│    - 端口扫描                                                            │
│    - 指纹识别                                                            │
│    - 目录爆破                                                            │
│    - 参数发现                                                            │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. 漏洞扫描 (AI-Burp)                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│    - VulnScanner.scan_all()                                             │
│    - 每个Decision暂停等待LLM决策                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. LLM分析决策                                                           │
├─────────────────────────────────────────────────────────────────────────┤
│    - 分析AI-Burp返回的Decision                                           │
│    - 选择下一步操作                                                      │
│    - 调整攻击策略                                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. 循环直到完成                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## API设计

### Orchestrator类

```python
class SecurityOrchestrator:
    """安全研究编排器"""
    
    def __init__(self, project_id: str, config: dict = None):
        """
        初始化编排器
        
        Args:
            project_id: 项目唯一标识
            config: 配置选项
        """
        pass
    
    # ========== 状态管理 ==========
    
    def load_state(self) -> dict:
        """加载项目状态"""
        pass
    
    def save_state(self) -> None:
        """保存当前状态"""
        pass
    
    def set_target(self, type: str, **kwargs) -> None:
        """
        设置目标
        
        Args:
            type: whitebox | blackbox | greybox
            path: 代码路径（白盒）
            url: 目标URL（黑盒）
            goal: 目标（RCE, LFI, etc.）
        """
        pass
    
    # ========== Prompt生成 ==========
    
    def generate_recovery_prompt(self) -> str:
        """生成恢复Prompt，用于新会话"""
        pass
    
    def generate_analysis_prompt(self, focus: str) -> str:
        """生成分析Prompt"""
        pass
    
    # ========== 发现管理 ==========
    
    def add_finding(self, finding: dict) -> str:
        """
        添加发现
        
        Returns:
            finding_id
        """
        pass
    
    def update_finding(self, finding_id: str, updates: dict) -> None:
        """更新发现"""
        pass
    
    def get_findings(self, severity: str = None) -> list:
        """获取发现列表"""
        pass
    
    # ========== 进度管理 ==========
    
    def update_progress(self, task: str, status: str) -> None:
        """更新进度"""
        pass
    
    def add_exploration(self, path: str, result: str, reason: str) -> None:
        """记录探索路径"""
        pass
    
    def get_pending_explorations(self) -> list:
        """获取待探索列表"""
        pass
    
    # ========== RAG集成 ==========
    
    def add_context(self, content: str, metadata: dict) -> None:
        """添加上下文到RAG"""
        pass
    
    def search_context(self, query: str, limit: int = 10) -> list:
        """搜索相关上下文"""
        pass
    
    # ========== AI-Burp集成 ==========
    
    def run_probe(self, url: str, param: str, value: str) -> Decision:
        """运行智能探测"""
        pass
    
    def run_scan(self, url: str, types: list = None) -> list:
        """运行漏洞扫描"""
        pass
    
    def run_fuzz(self, url: str, payloads: list) -> list:
        """运行Fuzz测试"""
        pass
    
    # ========== 报告生成 ==========
    
    def generate_report(self, format: str = "markdown") -> str:
        """生成审计报告"""
        pass
```

### 使用示例

```python
from aiburp.orchestrator import SecurityOrchestrator

# 初始化
orch = SecurityOrchestrator("ckfinder_audit")

# 设置目标
orch.set_target(
    type="whitebox",
    path="E:/CursorDEV/CKFinder/3.7.0",
    goal="RCE"
)

# 新会话恢复
prompt = orch.generate_recovery_prompt()
print(prompt)  # 发送给LLM

# 记录发现
orch.add_finding({
    "type": "design_flaw",
    "severity": "medium",
    "title": "containsHtml不检测PHP标签",
    "location": "Utils.php:247"
})

# 更新进度
orch.update_progress("Phar反序列化分析", "completed")
orch.add_exploration(
    path="Phar反序列化",
    result="blocked",
    reason="operationId正则限制"
)

# 保存状态
orch.save_state()

# 生成报告
report = orch.generate_report()
```

---

## 实现路线图

### Phase 1: 基础架构 (1周)

- [ ] 创建Orchestrator类骨架
- [ ] 实现状态文件加载/保存
- [ ] 实现恢复Prompt生成
- [ ] 基础测试

### Phase 2: RAG集成 (1周)

- [ ] 集成mem0
- [ ] 实现上下文添加/搜索
- [ ] 与状态文件联动

### Phase 3: AI-Burp集成 (1周)

- [ ] 整合AI-Burp工具
- [ ] 实现probe/scan/fuzz接口
- [ ] Decision处理

### Phase 4: Prompt系统 (1周)

- [ ] 设计Prompt模板库
- [ ] 实现安全研究员Prompt
- [ ] 实现任务特定Prompt

### Phase 5: 完善与测试 (1周)

- [ ] 完整流程测试
- [ ] 文档完善
- [ ] 示例项目

---

## 附录

### 相关资源

- **mem0**: https://github.com/mem0ai/mem0
- **MemGPT**: https://github.com/cpacker/MemGPT
- **LangChain**: https://github.com/langchain-ai/langchain

### 参考项目

- AI-Burp: 本项目的安全工具组件
- CKFinder审计: 作为测试用例

---

*文档最后更新: 2026-01-03*
