# RAG记忆系统设计文档

> 使用RAG保持项目上下文，而非存储通用知识

---

## 核心理念

### 重要澄清

**RAG不是知识库！**

LLM的训练数据已包含：
- 所有公开的CVE
- 各种攻击技术
- Gadget Chain
- 绕过方法

所以RAG**不应该**存储这些。

### RAG的正确用途

RAG是**工作记忆**，用于存储：

| 存储内容 | 目的 |
|---------|------|
| 当前项目代码 | 不遗漏任何文件 |
| 分析中间结果 | 保持分析连贯性 |
| 跨文件依赖 | 理解整体架构 |
| 本次审计发现 | 累积成果 |
| 探索历史 | 避免重复劳动 |

---

## 技术选型

### 推荐：mem0

**GitHub**: https://github.com/mem0ai/mem0

**优点**：
- 比OpenAI Memory准确率高26%
- Token使用减少90%
- 响应速度快91%
- 易于集成

**安装**：
```bash
pip install mem0ai
```

### 备选方案

| 方案 | 特点 | 适用场景 |
|------|------|---------|
| **MemGPT** | 类OS内存管理 | 超长对话 |
| **OpenMemory** | 本地优先 | 隐私敏感 |
| **LangChain Memory** | LangChain原生 | 现有LangChain项目 |

---

## 集成设计

### 数据结构

```python
class ContextItem:
    """RAG存储单元"""
    id: str
    project_id: str
    type: str  # code, finding, exploration, instruction
    content: str
    metadata: dict
    timestamp: datetime
```

### 记忆类型

#### 1. 代码上下文 (code)

```python
{
    "type": "code",
    "content": "unserialize(file_get_contents($filePath))",
    "metadata": {
        "file": "OperationManager.php",
        "line": 208,
        "function": "getStatus",
        "class": "OperationManager"
    }
}
```

#### 2. 发现记录 (finding)

```python
{
    "type": "finding",
    "content": "containsHtml函数不检测PHP标签<?php",
    "metadata": {
        "severity": "medium",
        "file": "Utils.php",
        "line": 247,
        "exploitable": false
    }
}
```

#### 3. 探索历史 (exploration)

```python
{
    "type": "exploration",
    "content": "尝试Phar反序列化，被operationId正则阻止",
    "metadata": {
        "path": "Phar反序列化",
        "result": "blocked",
        "reason": "正则^[a-z0-9]{16}$不允许phar://"
    }
}
```

#### 4. 用户指令 (instruction)

```python
{
    "type": "instruction",
    "content": "重点关注资金流向和权限控制",
    "metadata": {
        "priority": "high"
    }
}
```

---

## API设计

### MemoryManager类

```python
class MemoryManager:
    """RAG记忆管理器"""
    
    def __init__(self, project_id: str):
        """
        初始化
        
        Args:
            project_id: 项目唯一标识（用于隔离不同项目的记忆）
        """
        from mem0 import Memory
        self.memory = Memory()
        self.project_id = project_id
    
    def add_code(self, content: str, file: str, line: int, **metadata) -> str:
        """
        添加代码上下文
        
        Args:
            content: 代码片段
            file: 文件名
            line: 行号
            **metadata: 其他元数据（function, class等）
        
        Returns:
            memory_id
        """
        pass
    
    def add_finding(self, content: str, severity: str, file: str, 
                    line: int, **metadata) -> str:
        """添加发现"""
        pass
    
    def add_exploration(self, path: str, result: str, reason: str) -> str:
        """添加探索历史"""
        pass
    
    def add_instruction(self, content: str, priority: str = "normal") -> str:
        """添加用户指令"""
        pass
    
    def search(self, query: str, type: str = None, limit: int = 10) -> list:
        """
        搜索相关记忆
        
        Args:
            query: 搜索关键词
            type: 过滤类型（可选）
            limit: 返回数量
        
        Returns:
            List[ContextItem]
        """
        pass
    
    def get_all(self, type: str = None) -> list:
        """获取所有记忆（可按类型过滤）"""
        pass
    
    def format_for_prompt(self, items: list) -> str:
        """将记忆格式化为Prompt可用的文本"""
        pass
    
    def clear(self, type: str = None) -> None:
        """清除记忆（可按类型）"""
        pass
```

### 使用示例

```python
from aiburp.memory import MemoryManager

# 初始化
mem = MemoryManager("ckfinder_audit")

# 添加代码上下文
mem.add_code(
    content="unserialize(file_get_contents($filePath))",
    file="OperationManager.php",
    line=208,
    function="getStatus"
)

# 添加发现
mem.add_finding(
    content="containsHtml不检测PHP标签",
    severity="medium",
    file="Utils.php",
    line=247,
    exploitable=False
)

# 添加探索历史
mem.add_exploration(
    path="Phar反序列化",
    result="blocked",
    reason="operationId正则限制"
)

# 搜索相关记忆
results = mem.search("unserialize", type="code")
for r in results:
    print(f"{r.metadata['file']}:{r.metadata['line']}: {r.content}")

# 格式化为Prompt
context_text = mem.format_for_prompt(results)
```

---

## 与Orchestrator集成

```python
class SecurityOrchestrator:
    def __init__(self, project_id: str):
        self.memory = MemoryManager(project_id)
        # ...
    
    def generate_recovery_prompt(self) -> str:
        """生成恢复Prompt"""
        state = self.load_state()
        
        # 获取所有相关记忆
        code_context = self.memory.get_all(type="code")
        findings = self.memory.get_all(type="finding")
        explorations = self.memory.get_all(type="exploration")
        instructions = self.memory.get_all(type="instruction")
        
        # 格式化
        prompt = self._format_recovery_prompt(
            state=state,
            code_context=self.memory.format_for_prompt(code_context),
            findings=self.memory.format_for_prompt(findings),
            explorations=self.memory.format_for_prompt(explorations),
            instructions=self.memory.format_for_prompt(instructions)
        )
        
        return prompt
    
    def add_finding(self, finding: dict) -> str:
        """添加发现并同步到RAG"""
        # 保存到状态文件
        state = self.load_state()
        finding_id = self._generate_id()
        finding['id'] = finding_id
        state['findings'].append(finding)
        self.save_state(state)
        
        # 同步到RAG
        self.memory.add_finding(
            content=finding['title'],
            severity=finding['severity'],
            file=finding.get('location', ''),
            line=finding.get('line', 0),
            **finding
        )
        
        return finding_id
```

---

## 智能检索策略

### 1. 按相关性检索

当LLM分析某个点时，自动检索相关上下文：

```python
def analyze_with_context(self, focus_point: str) -> str:
    """带上下文的分析"""
    
    # 搜索相关记忆
    relevant = self.memory.search(focus_point, limit=20)
    
    # 格式化上下文
    context = self.memory.format_for_prompt(relevant)
    
    # 构建Prompt
    prompt = f"""
## 相关上下文
{context}

## 当前分析任务
{focus_point}

请基于上述上下文进行分析。
"""
    return prompt
```

### 2. 按文件检索

分析某个文件时，获取该文件所有上下文：

```python
def get_file_context(self, filename: str) -> str:
    """获取文件相关的所有上下文"""
    
    items = self.memory.search(
        filename, 
        type="code"
    )
    
    # 按行号排序
    items.sort(key=lambda x: x.metadata.get('line', 0))
    
    return self.memory.format_for_prompt(items)
```

### 3. 按漏洞类型检索

分析特定漏洞类型时：

```python
def get_vuln_context(self, vuln_type: str) -> str:
    """获取特定漏洞类型的上下文"""
    
    # 搜索相关代码
    code = self.memory.search(vuln_type, type="code")
    
    # 搜索相关发现
    findings = self.memory.search(vuln_type, type="finding")
    
    # 搜索探索历史
    explorations = self.memory.search(vuln_type, type="exploration")
    
    return self._combine_context(code, findings, explorations)
```

---

## 存储优化

### 去重

```python
def add_code(self, content: str, **metadata) -> str:
    # 检查是否已存在
    existing = self.memory.search(content, limit=1)
    if existing and self._is_duplicate(existing[0], content, metadata):
        return existing[0].id
    
    # 添加新记忆
    return self._add(content, "code", metadata)
```

### 摘要

对于长代码，存储摘要：

```python
def add_long_code(self, content: str, **metadata) -> str:
    if len(content) > 500:
        # 存储摘要
        summary = self._summarize(content)
        metadata['full_content'] = content
        return self._add(summary, "code", metadata)
    
    return self._add(content, "code", metadata)
```

### 过期清理

```python
def cleanup_old(self, days: int = 30) -> int:
    """清理旧记忆"""
    cutoff = datetime.now() - timedelta(days=days)
    
    old_items = [
        item for item in self.memory.get_all()
        if item.timestamp < cutoff
    ]
    
    for item in old_items:
        self.memory.delete(item.id)
    
    return len(old_items)
```

---

## 隐私考虑

### 本地优先选项

如果需要完全本地运行：

```python
# 使用OpenMemory（本地）
from openmemory import Memory

class LocalMemoryManager(MemoryManager):
    def __init__(self, project_id: str):
        self.memory = Memory(storage="local")
        self.project_id = project_id
```

### 数据加密

```python
class SecureMemoryManager(MemoryManager):
    def __init__(self, project_id: str, encryption_key: str):
        super().__init__(project_id)
        self.cipher = Fernet(encryption_key)
    
    def _add(self, content: str, type: str, metadata: dict) -> str:
        # 加密内容
        encrypted = self.cipher.encrypt(content.encode())
        return super()._add(encrypted, type, metadata)
    
    def search(self, query: str, **kwargs) -> list:
        results = super().search(query, **kwargs)
        # 解密内容
        for r in results:
            r.content = self.cipher.decrypt(r.content).decode()
        return results
```

---

*文档最后更新: 2026-01-03*
