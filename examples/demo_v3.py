"""
AI-Burp V3 - Autonomous Logic Demonstration
演示 V3 的异步并发与漏洞链感知能力
"""

import asyncio
from aiburp import AsyncSmartBurp, KnowledgeBase

async def main():
    print("🚀 [System] Starting AI-Burp V3 Autonomous Demo...")
    
    # 1. 初始化异步智能引擎 (项目名为 demo)
    async with AsyncSmartBurp(project="demov3", concurrency=20) as burp:
        
        # 2. 模拟情报搜集 (手动注入一条知识)
        # 假设之前的 JS 扫描发现了一个内部测试 IP
        burp.kb.add("internal_ip", "10.0.0.15", "https://target.com/assets/config.js", "Found in JS comments")
        
        # 3. 执行智能扫描
        # 目标是一个带有 redirect 参数的接口 (SemanticAnalyzer 会识别出重定向语义)
        target_url = "https://example.com/api/v1/redirect"
        param = "url"
        value = "https://google.com"
        
        print(f"🔍 [Scan] Target: {target_url}?{param}={value}")
        print("⚡ [Step 1] Semantic Analysis & Async Concurrent Scanning...")
        
        decision = await burp.smart_scan(target_url, param, value)
        
        # 4. 展示 AI 决策
        print("\n" + "="*50)
        print(f"📊 [AI Report] {decision.status}")
        print(f"🧠 [AI Suggestion] {decision.suggestion}")
        
        if decision.options:
            print("\n📋 [AI Options]")
            for i, opt in enumerate(decision.options, 1):
                print(f"  {i}. [{opt['action']}] {opt['reason']}")
        
        # 5. 模拟漏洞链触发
        print("\n" + "="*50)
        print("🔗 [Chaining] How it works:")
        print("  - IntentAnalyzer recognized 'url' param -> SSRF prioritized.")
        print("  - VulnerabilityChainer combined 'SSRF' + 'Internal IP (10.0.0.15)'.")
        print("  - AI suggested: 'ssrf_scan_internal' against '10.0.0.15'.")
        print("="*50)

if __name__ == "__main__":
    asyncio.run(main())
