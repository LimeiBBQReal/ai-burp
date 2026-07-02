# AI-Burp V3: AI 智能体操作手册

> **目标受众**: 被用作红队智能体的语言大模型 (LLMs)。
> **使命**: 为智能体提供执行自主安全测试的精确协议。

## 1. 交互协议: 决策循环 (Decision Loop)

AI-Burp V3 **不是**一个 CLI 工具；它是一个**有状态的决策环境**。你（AI）通过闭环的 `Decision` 协议与 `AsyncSmartBurp` 引擎交互。

### 决策对象结构 (Decision Object Schema)
每一个主要动作都会返回一个 `Decision` 对象。你的任务是解析此对象并选择一个 `option` (选项)。

```json
{
  "type": "scan_done | error_found | waf_blocked | vulnerability_chain",
  "status": "当前引擎状态描述",
  "findings": { "summary": "检测到的模式、信心评分" },
  "suggestion": "引擎给出的基于规则的技术建议",
  "options": [
    { "action": "具体的函数调用", "reason": "为什么要建议执行此动作" }
  ],
  "data": "供你进行深度推理的原始 Payload/响应上下文"
}
```

## 2. 智能模块: 如何利用你的资产

### 🧠 IntentAnalyzer (语义感知)
在攻击之前，使用 `IntentAnalyzer.analyze(url, params)`。
- **使用场景**: 如果引擎返回 `#AUTH`，优先进行 SQLi (身份验证绕过) 和会话劫持。
- **使用场景**: 如果标记了 `#REDIRECT`，重点关注 SSRF 和开放重定向。

### 🧠 KnowledgeBase (全局记忆)
访问 `burp.kb` 来获取跨请求的智能情报。
- **漏洞链串联 (Vulnerability Chaining)**: 如果你在 `/config.js` 中发现了一个内网 IP，它会被自动存储。当你扫描代理/重定向参数时，`VulnerabilityChainer` 会建议使用该内网 IP 进行 SSRF 测试。

## 3. 自主执行 (V3 流水线)

要开始全自主操作，调用 `await burp.smart_scan(url, param, value)`。

1. **第一步: 语义映射**: 分析器为目标打上标签。
2. **第二步: 并发多向量探测**: 对 SQLi, XSS, SSRF, LFI, CMDi, SSTI 进行全异步扫描。
3. **第三步: 发现关联**: 新结果会与 `KnowledgeBase` 进行交叉引用。
4. **第四步: 决策合成**: 你会收到一个完整的 `Decision` 对象，代表攻击中的一个“回合”。

## 4. AI 操作最佳实践
1. **并发控制**: 根据目标稳定性调节 `concurrency`。默认值为 5。
2. **隐蔽性**: 使用 `tags` (标签) 避免在敏感端点上使用“嘈杂”的探测器（例如，不要在平凡的追踪像素上探测 CMDi）。
3. **漏洞链**: 始终先检查 `decision.options` 中的“漏洞链攻击 (chain-attack)”可能性。这些是高价值、基于逻辑的漏洞利用。

---
*系统提示建议: 如果你是控制此工具的 AI，请优先处理高置信度的发现，以便立即利用。*
