# AI安全研究助手 - 设计文档索引

> 三位一体：Prompt激活器 + RAG记忆 + AI-Burp工具

---

## 📁 文档目录

| 文档 | 描述 | 状态 |
|------|------|------|
| [ORCHESTRATOR_DESIGN.md](./ORCHESTRATOR_DESIGN.md) | 编排器核心设计 | ✅ 完成 |
| [PROMPT_TEMPLATES.md](./PROMPT_TEMPLATES.md) | Prompt激活器模板 | ✅ 完成 |
| [RAG_MEMORY_DESIGN.md](./RAG_MEMORY_DESIGN.md) | RAG记忆系统设计 | ✅ 完成 |

---

## 🎯 核心概念

### 三位一体

```
┌─────────────────────────────────────────────────────────────────────────┐
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

1. **LLM已有知识远超任何数据库**
   - 不需要存储CVE/攻击技术
   - 只需要激活和引导

2. **RAG是工作记忆，不是知识库**
   - 存储当前项目的代码和分析
   - 保持跨会话的上下文连续性

3. **工具提供动态能力**
   - AI-Burp执行测试
   - 返回结构化Decision供LLM决策

4. **Prompt改变思维模式**
   - 从"快速回答"到"深度探索"
   - 从"遇困难就放弃"到"尝试绕过"

---

## 🚀 快速开始实现

### Phase 1: 基础架构

```python
# 创建Orchestrator骨架
class SecurityOrchestrator:
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.state_file = f".audit/{project_id}.json"
    
    def load_state(self) -> dict: ...
    def save_state(self, state: dict): ...
    def generate_recovery_prompt(self) -> str: ...
```

### Phase 2: 集成mem0

```python
from mem0 import Memory

class MemoryManager:
    def __init__(self, project_id: str):
        self.memory = Memory()
        self.project_id = project_id
    
    def add_code(self, content: str, **metadata): ...
    def search(self, query: str) -> list: ...
```

### Phase 3: 集成AI-Burp

```python
from aiburp import SmartBurp, Decision

class SecurityOrchestrator:
    def run_probe(self, url, param, value) -> Decision:
        with SmartBurp() as burp:
            return burp.smart_probe(url, param, value)
```

---

## 📋 实现检查清单

### 核心功能

- [ ] Orchestrator类基础实现
- [ ] 状态文件加载/保存
- [ ] 恢复Prompt生成
- [ ] mem0集成
- [ ] AI-Burp集成
- [ ] 完整工作流程

### 文档完善

- [x] 编排器设计文档
- [x] Prompt模板库
- [x] RAG设计文档
- [ ] API参考文档
- [ ] 使用教程

---

## 💡 设计决策记录

### 为什么选择mem0？

- 准确率比OpenAI Memory高26%
- Token使用减少90%
- 响应速度快91%
- 简单易用的API

### 为什么使用状态文件+RAG双存储？

- **状态文件**：结构化数据，任务进度
- **RAG**：非结构化数据，代码片段，支持语义搜索

### 为什么Prompt模板库？

- 不同任务需要不同的思维模式
- 预定义模板提高一致性
- 便于迭代优化

---

## 🔗 相关资源

- [mem0 GitHub](https://github.com/mem0ai/mem0)
- [MemGPT GitHub](https://github.com/cpacker/MemGPT)
- [AI-Burp 主项目](../)

---

*创建日期: 2026-01-03*
*最后更新: 2026-01-03*
