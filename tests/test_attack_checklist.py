"""
attack_checklist 单元测试.

覆盖:
    - 14 个维度方法全部存在且可调用 (回归 _dim2_response_diff 命名 bug)
    - run() 在网络失败时不崩溃 (返回 error 结果)
    - _extract_session_id 正确解析 Set-Cookie
    - _add / _base_url / _get_url_params 工具方法
    - report_text 生成报告
"""

import pytest
from unittest.mock import patch, MagicMock

from aiburp.traffic.attack_checklist import AttackChecklist, CheckResult


# ============================================================
# 维度方法完整性 (回归 _dim2_response_diff → _dim12_response_diff)
# ============================================================

EXPECTED_DIMENSIONS = [
    "_dim1_info_extraction",
    "_dim2_auth_analysis",
    "_dim3_api_enumeration",
    "_dim4_param_discovery",
    "_dim5_access_control",
    "_dim6_injection_probes",
    "_dim7_cve_matching",
    "_dim8_config_files",
    "_dim9_method_type_switch",
    "_dim10_directory_discovery",
    "_dim11_business_logic",
    "_dim12_response_diff",      # ← 原来误写成 _dim2_response_diff
    "_dim13_request_structure",  # 新增: 请求结构分析
    "_dim14_session_interaction",# 新增: 会话交互分析
]


def test_all_14_dimensions_exist():
    """所有 14 个维度方法必须存在 (防止命名 typo 导致 AttributeError)."""
    for method_name in EXPECTED_DIMENSIONS:
        assert hasattr(AttackChecklist, method_name), \
            f"缺少维度方法: {method_name}"


def test_no_legacy_dim2_response_diff():
    """旧的错误命名 _dim2_response_diff 必须已删除."""
    assert not hasattr(AttackChecklist, "_dim2_response_diff"), \
        "_dim2_response_diff 应该已重命名为 _dim12_response_diff"


def test_dim12_renamed_correctly():
    """维度 12 必须是 _dim12_response_diff."""
    assert hasattr(AttackChecklist, "_dim12_response_diff")
    assert callable(getattr(AttackChecklist, "_dim12_response_diff"))


# ============================================================
# 数据结构
# ============================================================

def test_check_result_dataclass():
    """CheckResult 默认值."""
    r = CheckResult(dimension="test", check_name="x", target="http://t")
    assert r.result == ""
    assert r.severity == "info"
    assert r.evidence == ""
    assert r.recommendation == ""


# ============================================================
# 工具方法
# ============================================================

def test_base_url():
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "http://example.com/foo/bar?x=1"
    assert ac._base_url() == "http://example.com"


def test_base_url_https():
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "https://target.org/admin"
    assert ac._base_url() == "https://target.org"


def test_get_url_params():
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "http://t.com/p?id=1&name=foo"
    params = ac._get_url_params()
    assert params == {"id": "1", "name": "foo"}


def test_get_url_params_empty():
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "http://t.com/p"
    assert ac._get_url_params() == {}


def test_extract_session_id():
    """Set-Cookie 解析."""
    cookie = "PHPSESSID=abc123def456; Path=/; HttpOnly"
    assert AttackChecklist._extract_session_id(cookie) == "abc123def456"


def test_extract_session_id_empty():
    assert AttackChecklist._extract_session_id("") == ""
    assert AttackChecklist._extract_session_id(None) == ""


def test_extract_session_id_no_equals():
    assert AttackChecklist._extract_session_id("garbage") == ""


# ============================================================
# _add 方法
# ============================================================

def test_add_truncates_evidence():
    """evidence 超过 200 字符要截断 (防止内存膨胀)."""
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.results = []
    long_evidence = "x" * 500
    ac._add("dim", "check", "target", "high", long_evidence)
    assert len(ac.results) == 1
    assert len(ac.results[0].evidence) == 200


# ============================================================
# run() 容错性
# ============================================================

def test_run_handles_network_error():
    """基线请求失败时不能崩溃, 要返回 error 结果."""
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "http://nonexistent.invalid/"
    ac.cookies = ""
    ac.results = []

    import requests
    ac.session = MagicMock()
    ac.session.get.side_effect = requests.ConnectionError("DNS failed")
    ac._baseline = None

    results = ac.run()
    assert len(results) >= 1
    assert results[0].dimension == "error"
    assert "DNS" in results[0].evidence or "failed" in results[0].evidence.lower() \
           or "error" in results[0].evidence.lower()


def test_run_with_mocked_baseline():
    """模拟一个带 Set-Cookie 的响应, 验证维度 14 (会话交互) 能跑."""
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "http://example.com/"
    ac.cookies = ""
    ac.results = []

    import requests
    ac.session = MagicMock(spec=requests.Session)
    ac.session.headers = {}  # Session.headers 是实例属性, 需手动设置
    ac._baseline = None

    # 模拟基线响应
    fake_resp = MagicMock()
    fake_resp.text = "<html><body>hello</body></html>"
    fake_resp.status_code = 200
    fake_resp.headers = {"Server": "nginx", "Set-Cookie": "session=abc; Path=/"}
    fake_resp.url = "http://example.com/"

    # 后续维度的请求也返回 fake_resp
    ac.session.get.return_value = fake_resp
    ac.session.options.return_value = fake_resp
    ac.session.request.return_value = fake_resp

    results = ac.run()
    # 至少应该有一些发现 (信息提取的 Server 头)
    assert isinstance(results, list)
    # 不应该崩溃


# ============================================================
# report_text
# ============================================================

def test_report_text_contains_summary():
    ac = AttackChecklist.__new__(AttackChecklist)
    ac.url = "http://t.com/"
    ac.results = [
        CheckResult(dimension="信息提取", check_name="Server头",
                    target="http://t.com", severity="low", evidence="Server: nginx"),
        CheckResult(dimension="认证分析", check_name="未授权访问",
                    target="http://t.com", severity="high", evidence="无需认证"),
    ]
    text = ac.report_text()
    assert "攻击清单报告" in text
    assert "http://t.com" in text
    assert "信息提取" in text
    assert "认证分析" in text
    assert "高危" in text or "高" in text


# ============================================================
# 导出测试
# ============================================================

def test_exported_from_traffic_package():
    """attack_checklist 必须在 traffic 包顶层导出."""
    from aiburp.traffic import AttackChecklist as Exported, CheckResult as ExportedCR
    assert Exported is AttackChecklist
    assert ExportedCR is CheckResult


# ============================================================
# Agent 集成
# ============================================================

def test_agent_has_new_actions():
    """Agent 必须注册 attack_checklist 和 full_audit."""
    from aiburp.agent import ActionParser
    assert "attack_checklist" in ActionParser.VALID_ACTIONS
    assert "full_audit" in ActionParser.VALID_ACTIONS
    assert ActionParser.validate({"action": "attack_checklist", "params": {}})
    assert ActionParser.validate({"action": "full_audit", "params": {}})


def test_agent_has_action_methods():
    from aiburp.agent import SecurityAgent
    assert hasattr(SecurityAgent, "_action_attack_checklist")
    assert hasattr(SecurityAgent, "_action_full_audit")
