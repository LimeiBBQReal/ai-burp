"""
OpSec 安全闸门测试 — verify_proxy 必须在无代理时拒绝运行.

这是红队第一原则的代码层保障: 绝不裸奔.
"""

import pytest
from unittest.mock import patch, MagicMock
from aiburp.agent import SecurityAgent


def _bare_agent():
    """构造一个绕过 LLM 初始化的 Agent (只测 OpSec 逻辑)."""
    a = SecurityAgent.__new__(SecurityAgent)
    a.project_id = "test"
    a._proxy_required = True
    a._proxy_verified = False
    a._real_ip = ""
    a.proxy_manager = None
    return a


def test_verify_proxy_rejects_when_no_proxy():
    """无代理时必须拒绝 (safe=False)."""
    a = _bare_agent()
    with patch.object(a, '_get_real_ip', return_value='1.2.3.4'):
        pv = a.verify_proxy()
    assert pv["safe"] is False
    assert pv["ok"] is False
    assert "代理未配置" in pv["error"] or "拒绝" in pv["error"]


def test_verify_proxy_rejects_when_proxy_equals_real():
    """代理出口 == 真实 IP 时必须拒绝 (说明在裸奔)."""
    a = _bare_agent()
    # 模拟代理出口和真实 IP 相同
    a.proxy_manager = MagicMock()
    a.proxy_manager.get_proxy.return_value = "socks5://127.0.0.1:1080"
    with patch.object(a, '_get_real_ip', return_value='1.2.3.4'), \
         patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {"origin": "1.2.3.4"}
        pv = a.verify_proxy()
    assert pv["safe"] is False
    assert pv["real_ip"] == "1.2.3.4"
    assert pv["proxy_ip"] == "1.2.3.4"
    assert "裸奔" in pv["error"]


def test_verify_proxy_passes_when_different_ip():
    """代理出口 ≠ 真实 IP 时通过."""
    a = _bare_agent()
    a.proxy_manager = MagicMock()
    a.proxy_manager.get_proxy.return_value = "socks5://127.0.0.1:1080"
    with patch.object(a, '_get_real_ip', return_value='1.2.3.4'), \
         patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {"origin": "104.28.166.32"}
        pv = a.verify_proxy()
    assert pv["safe"] is True
    assert pv["ok"] is True
    assert pv["real_ip"] == "1.2.3.4"
    assert pv["proxy_ip"] == "104.28.166.32"
    assert a._proxy_verified is True


def test_verify_proxy_handles_connection_failure():
    """代理连接失败时必须拒绝."""
    a = _bare_agent()
    a.proxy_manager = MagicMock()
    a.proxy_manager.get_proxy.return_value = "socks5://127.0.0.1:1080"
    with patch.object(a, '_get_real_ip', return_value='1.2.3.4'), \
         patch('requests.get', side_effect=Exception("Connection refused")):
        pv = a.verify_proxy()
    assert pv["safe"] is False
    assert "代理连接失败" in pv["error"]


def test_run_blocks_without_proxy():
    """run() 在 _proxy_required=True 且无代理时必须拒绝启动."""
    a = _bare_agent()
    a.llm = MagicMock()
    a.llm.is_available = True
    a.orchestrator = MagicMock()
    # 无 proxy_manager
    result = a.run("test")
    assert result["ok"] is False
    assert "OpSec" in result["error"] or "代理" in result["error"]


def test_real_ip_cached():
    """_get_real_ip 应缓存结果 (不重复请求)."""
    a = _bare_agent()
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {"origin": "5.6.7.8"}
        ip1 = a._get_real_ip()
        ip2 = a._get_real_ip()  # 第二次应走缓存
    assert ip1 == "5.6.7.8"
    assert ip2 == "5.6.7.8"
    # 只请求了一次 (第二次走缓存)
    assert mock_get.call_count == 1
