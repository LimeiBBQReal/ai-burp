"""
LLM Driver — 可选模块，用于 LLM 深度分析页面和 JS
当正则提取不足时触发
"""

import json
from typing import List, Dict, Optional


LLM_PAGE_ANALYSIS_PROMPT = """你是一个 Web 安全侦察专家。分析以下页面 HTML，完成以下任务:

1. 识别页面功能 (login/dashboard/api_docs/admin_panel/...)
2. 提取所有可能访问的 URL 路径和 API 端点
3. 识别隐藏/未公开的接口 (注释中、JS 中、可能存在的 IDOR 参数)
4. 判断 SPA 路由模式 (React/Vue/Angular)
5. 标记高价值目标 (admin/panel/debug/内部接口)

只输出 JSON，不要解释:
{
  "page_type": "login|dashboard|api_docs|...",
  "confidence": 0.0-1.0,
  "endpoints": [{"path": "...", "method": "GET|POST|...", "confidence": "high|medium|low", "reason": "..."}],
  "priority_routes": ["...", "..."],
  "suspicious": ["..."]
}
"""

LLM_JS_ANALYSIS_PROMPT = """你是一个 Web 安全侦察专家。分析以下 JavaScript 代码，提取所有 API 端点和路由定义。

重点关注:
1. fetch / XMLHttpRequest / axios 调用中的 URL
2. React Router / Vue Router 路由定义
3. Webpack 动态导入路径
4. 环境变量中引用的 API 地址
5. WebSocket 端点
6. 注释中的隐藏/废弃接口

只输出 JSON，不要解释:
{
  "endpoints": [{"path": "...", "method": "GET|POST|...", "confidence": "high|medium|low", "source": "fetch|router|env|..."}],
  "spa_routes": [{"path": "...", "component": "..."}],
  "suspicious": ["..."]
}
"""


def llm_analyze_page(html_text: str, url: str, llm_client=None, max_chars: int = 6000) -> Optional[Dict]:
    if not llm_client:
        return None

    truncated = html_text[:max_chars]
    if len(html_text) > max_chars:
        truncated += "\n\n... [TRUNCATED]"

    try:
        resp = llm_client.ask(
            prompt=f"URL: {url}\n\nHTML:\n```html\n{truncated}\n```",
            system_prompt=LLM_PAGE_ANALYSIS_PROMPT,
        )
        if not resp:
            return None
        text = resp.strip()
        if '```json' in text:
            text = text.split('```json')[1].split('```')[0].strip()
        elif '```' in text:
            text = text.split('```')[1].split('```')[0].strip()
        return json.loads(text)
    except Exception:
        return None


def llm_analyze_js(js_text: str, source_url: str = '', llm_client=None, max_chars: int = 8000) -> Optional[Dict]:
    if not llm_client:
        return None

    truncated = js_text[:max_chars]
    if len(js_text) > max_chars:
        truncated += "\n\n... [TRUNCATED]"

    try:
        resp = llm_client.ask(
            prompt=f"Source: {source_url}\n\nJS:\n```javascript\n{truncated}\n```",
            system_prompt=LLM_JS_ANALYSIS_PROMPT,
        )
        if not resp:
            return None
        text = resp.strip()
        if '```json' in text:
            text = text.split('```json')[1].split('```')[0].strip()
        elif '```' in text:
            text = text.split('```')[1].split('```')[0].strip()
        return json.loads(text)
    except Exception:
        return None
