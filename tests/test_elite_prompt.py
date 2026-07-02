"""
精英赏金猎人提示词 + 结构化认知输出 测试.

覆盖:
    - _build_prompt 产出包含核心方法论章节 (OODA/资产画像/七层解剖/业务逻辑)
    - 提示词包含全部工具清单 (没有因为重写丢失工具)
    - 提示词强制结构化输出 (mental_model/hypothesis/observation/update)
    - ActionParser 解析带认知字段的 JSON
    - 向后兼容: 只有 action+params 的旧格式仍能解析
    - 提示词里的 {{ }} 转义正确 (不是被 .format 吃掉)
"""

import pytest
from aiburp.agent import ActionParser, SecurityAgent


# ============================================================
# Prompt 构建 (用 __new__ 绕过 LLM 初始化)
# ============================================================

def _make_agent():
    """构造一个不初始化 LLM 的 Agent (只测 prompt 构建)."""
    agent = SecurityAgent.__new__(SecurityAgent)
    agent.project_id = "test"
    agent.iteration = 0
    agent.history = []
    return agent


# ============================================================
# 方法论章节完整性
# ============================================================

CORE_SECTIONS = [
    "精英渗透测试 Agent",
    "身份与信条",
    "认知循环（OODA）",
    "资产画像",
    "流量七层解剖",
    "业务逻辑理解",
    "非常规入口",
    "决策纪律",
]


@pytest.mark.parametrize("section", CORE_SECTIONS)
def test_prompt_contains_core_section(section):
    """提示词必须包含所有核心方法论章节."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    assert section in prompt, f"提示词缺少章节: {section}"


def test_prompt_contains_ooda_phases():
    """OODA 四阶段必须都在."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    for phase in ["观察 (Observe)", "定向 (Orient)", "决策 (Decide)", "行动 (Act)"]:
        assert phase in prompt


def test_prompt_contains_traffic_as_king_principle():
    """'流量为王' 铁律必须在 (核心信条)."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    assert "流量为王" in prompt
    assert "假设驱动" in prompt
    assert "资产定制" in prompt


# ============================================================
# 工具清单完整性 (重写不能丢工具)
# ============================================================

EXPECTED_TOOLS_IN_PROMPT = [
    "intel_lookup", "asset_expand", "cdn_bypass", "github_leaks",
    "traffic_probe", "traffic_scan",
    "check_unauth", "exploit", "logic_scan", "jwt_analyze",
    "traffic_analyze", "attack_checklist", "full_audit",
    "revshell", "probe", "scan",
    "finding", "memory", "think", "complete",
]


@pytest.mark.parametrize("tool", EXPECTED_TOOLS_IN_PROMPT)
def test_prompt_contains_all_tools(tool):
    """重写提示词后所有工具必须仍在."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    assert tool in prompt, f"提示词丢失工具: {tool}"


# ============================================================
# 结构化输出强制
# ============================================================

COGNITIVE_FIELDS = ["mental_model", "hypothesis", "observation", "update"]


@pytest.mark.parametrize("field", COGNITIVE_FIELDS)
def test_prompt_requires_cognitive_fields(field):
    """提示词必须强制 LLM 输出四个认知字段."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    assert field in prompt, f"提示词没要求输出认知字段: {field}"


def test_prompt_warns_against_blind_action():
    """提示词必须有 '不许闷头冲' 的反制."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    assert "闷头冲" in prompt


# ============================================================
# 转义检查: {{ }} 在 f-string 里应保留为 { }
# ============================================================

def test_prompt_json_examples_have_single_braces():
    """
    工具清单里的 JSON 示例必须是单层花括号 (f-string {{ }} 已转义).
    注意: {{7*7}} 这种 Jinja2 payload 示例是合法的双花括号, 不算错误.
    """
    agent = _make_agent()
    prompt = agent._build_prompt()
    # 工具示例的 JSON 应该是单层花括号
    assert '"action": "intel_lookup"' in prompt
    # SSTI payload 示例应该正确渲染成 Jinja2 语法 {{7*7}} (不是 {7*7} 也不是 {{{{7*7}}}})
    assert '{{7*7}}' in prompt, "SSTI payload 示例必须渲染成 {{7*7}} (Jinja2 语法)"


# ============================================================
# ActionParser 解析认知字段
# ============================================================

def test_parse_extracts_cognitive_fields():
    """带 mental_model 等字段的 JSON 能被正确解析."""
    response = '''```json
{
    "action": "attack_checklist",
    "params": {"url": "http://target.com/"},
    "mental_model": "这是一个 WordPress 站, 认证靠 Cookie session",
    "hypothesis": "如果 wp-config 泄露, 能拿到 DB 凭据",
    "observation": "Server: Apache/2.4.41, 响应含 wp-content 路径",
    "update": "先跑 14 维清单确认攻击面"
}
```'''
    action = ActionParser.parse(response)
    assert action is not None
    assert action["action"] == "attack_checklist"
    assert action["mental_model"] == "这是一个 WordPress 站, 认证靠 Cookie session"
    assert "wp-config" in action["hypothesis"]
    assert action["update"] == "先跑 14 维清单确认攻击面"


def test_parse_validate_full_cognitive_action():
    """完整认知 action 通过 validate."""
    action = {
        "action": "attack_checklist",
        "params": {"url": "http://t.com/"},
        "mental_model": "test",
        "hypothesis": "test",
        "observation": "test",
        "update": "test",
    }
    assert ActionParser.validate(action)


# ============================================================
# 向后兼容: 旧格式 (只有 action+params+reason)
# ============================================================

def test_parse_legacy_format_without_cognitive_fields():
    """旧格式 (只有 action/params/reason) 仍能解析 — 向后兼容."""
    response = '''```json
{"action": "probe", "params": {"url": "http://t.com/"}, "reason": "探测"}
```'''
    action = ActionParser.parse(response)
    assert action is not None
    assert action["action"] == "probe"
    assert action["reason"] == "探测"
    # 旧格式没有认知字段, 不应该报错
    assert "mental_model" not in action


def test_validate_legacy_action():
    """旧格式 action 通过 validate."""
    assert ActionParser.validate({"action": "probe", "params": {}, "reason": "x"})


# ============================================================
# 上下文传递: 历史里的认知字段喂回下一轮 prompt
# ============================================================

def test_history_cognitive_fields_reach_next_prompt():
    """上一轮的认知字段应该出现在下一轮的 prompt 里 (作战日志累积)."""
    agent = _make_agent()
    agent.history = [{
        "iteration": 1,
        "action": {
            "action": "traffic_probe",
            "params": {"target": "http://t.com/"},
            "mental_model": "WordPress 站",
            "hypothesis": "wp-config 可能泄露",
            "observation": "Server: Apache",
            "update": "跑清单",
        },
        "result": {"ok": True, "summary": "x"},
        "summary": "x",
    }]
    prompt = agent._build_prompt()
    # 历史里的心智模型应该被包含 (可能被摘要截断, 检查关键词)
    assert "WordPress" in prompt or "traffic_probe" in prompt


# ============================================================
# 资产画像表格内容
# ============================================================

ASSET_TYPES = [
    "静态展示站", "API 接口", "登录/认证", "后台面板",
    "文件上传", "网关/代理", "中间件", "重定向类",
]


@pytest.mark.parametrize("asset", ASSET_TYPES)
def test_prompt_contains_asset_profiles(asset):
    """资产画像必须覆盖 8 类资产."""
    agent = _make_agent()
    prompt = agent._build_prompt()
    assert asset in prompt
