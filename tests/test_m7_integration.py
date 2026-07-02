"""
M7 CLI + Agent 集成测试.

覆盖:
    - CLI: traffic probe/scan/check 命令 (subprocess 调用)
    - Agent: VALID_ACTIONS 含 traffic_probe/scan
    - Agent: _action_traffic_probe/scan 执行
    - ActionParser: 解析 traffic action
"""

import pytest
import asyncio
import subprocess
import json
import sys


# ============================================================
# Agent 集成 (单元测试, 不走 subprocess)
# ============================================================

class TestAgentTrafficActions:

    def test_valid_actions_includes_traffic(self):
        """VALID_ACTIONS 含 traffic_probe / traffic_scan"""
        from aiburp.agent import ActionParser
        assert "traffic_probe" in ActionParser.VALID_ACTIONS
        assert "traffic_scan" in ActionParser.VALID_ACTIONS

    def test_action_parser_parses_traffic_probe_json(self):
        """ActionParser 能解析 traffic_probe JSON (markdown 代码块, LLM 实际输出格式)"""
        from aiburp.agent import ActionParser
        response = '```json\n{"action": "traffic_probe", "params": {"target": "10.0.0.1:6379"}}\n```'
        action = ActionParser.parse(response)
        assert action is not None
        assert action["action"] == "traffic_probe"
        assert action["params"]["target"] == "10.0.0.1:6379"

    def test_action_parser_parses_traffic_scan_json(self):
        """ActionParser 能解析 traffic_scan JSON (markdown 代码块)"""
        from aiburp.agent import ActionParser
        response = '```json\n{"action": "traffic_scan", "params": {"cidr": "10.0.0.0/24"}}\n```'
        action = ActionParser.parse(response)
        assert action is not None
        assert action["action"] == "traffic_scan"

    def test_action_validate_traffic_probe(self):
        """validate 接受 traffic_probe"""
        from aiburp.agent import ActionParser
        action = {"action": "traffic_probe", "params": {"target": "x:1"}}
        assert ActionParser.validate(action)

    def test_action_validate_traffic_scan(self):
        from aiburp.agent import ActionParser
        action = {"action": "traffic_scan", "params": {"cidr": "10.0.0.0/24"}}
        assert ActionParser.validate(action)

    def test_action_traffic_probe_closed_port(self):
        """_action_traffic_probe 对 closed port 不崩, 返回结构化结果"""
        from aiburp.agent import SecurityAgent
        # 不走 __init__ (避免 LLM 初始化)
        agent = SecurityAgent.__new__(SecurityAgent)
        agent.project_id = "test"
        result = agent._action_traffic_probe({"target": "127.0.0.1:6379", "timeout": 1})
        assert "ok" in result
        assert "data" in result
        assert "summary" in result
        assert result["data"]["protocol"] == "redis"  # 端口表路由

    def test_action_traffic_probe_missing_target(self):
        """缺 target 参数返回错误"""
        from aiburp.agent import SecurityAgent
        agent = SecurityAgent.__new__(SecurityAgent)
        agent.project_id = "test"
        result = agent._action_traffic_probe({})
        assert result["ok"] is False
        assert "target" in result["error"]

    def test_action_traffic_scan_closed_cidr(self):
        """_action_traffic_scan 对全 closed 网段返回摘要"""
        from aiburp.agent import SecurityAgent
        agent = SecurityAgent.__new__(SecurityAgent)
        agent.project_id = "test"
        result = agent._action_traffic_scan({
            "cidr": "127.0.0.1/32",
            "ports": [1, 2],
            "timeout": 0.5,
        })
        assert result["ok"] is True
        assert "summary" in result
        assert result["summary"]["open_count"] == 0
        assert result["total_open"] == 0

    def test_action_traffic_scan_missing_target(self):
        """缺 cidr/hosts 返回错误"""
        from aiburp.agent import SecurityAgent
        agent = SecurityAgent.__new__(SecurityAgent)
        agent.project_id = "test"
        result = agent._action_traffic_scan({})
        assert result["ok"] is False
        assert "cidr" in result["error"] or "hosts" in result["error"]


# ============================================================
# CLI 测试 (subprocess)
# ============================================================

class TestCliTrafficCommands:

    def _run_cli(self, *args, timeout=30):
        """运行 ide_cli 并返回 (returncode, stdout, stderr)"""
        cmd = [sys.executable, "-m", "aiburp.ide_cli", "traffic"] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def test_traffic_help(self):
        """traffic --help 显示三个子命令"""
        code, out, err = self._run_cli("--help")
        assert code == 0
        assert "probe" in out
        assert "scan" in out
        assert "check" in out

    def test_traffic_probe_help(self):
        code, out, err = self._run_cli("probe", "--help")
        assert code == 0
        assert "target" in out

    def test_traffic_probe_closed_port(self):
        """traffic probe closed port 输出 JSON"""
        code, out, err = self._run_cli("probe", "127.0.0.1:6379", "-t", "1")
        assert code == 0
        d = json.loads(out)
        assert d["ok"] is True  # CLI 命令成功 (即使 probe 失败)
        assert d["data"]["ok"] is False  # 但 probe 结果是失败
        assert d["data"]["protocol"] == "redis"

    def test_traffic_check_closed_port(self):
        """traffic check 输出 JSON"""
        code, out, err = self._run_cli("check", "127.0.0.1:6379", "-t", "1", timeout=30)
        assert code == 0
        d = json.loads(out)
        assert d["ok"] is True

    def test_traffic_scan_small_cidr(self):
        """traffic scan /32 输出 JSON"""
        code, out, err = self._run_cli(
            "scan", "127.0.0.1/32", "-p", "1,2,3", "-t", "0.5", timeout=30
        )
        assert code == 0
        d = json.loads(out)
        assert d["ok"] is True
        assert "summary" in d["data"]

    def test_traffic_scan_text_report(self):
        """traffic scan --text 输出人类报告"""
        code, out, err = self._run_cli(
            "scan", "127.0.0.1/32", "-p", "1", "-t", "0.5", "--text", timeout=20
        )
        assert code == 0
        d = json.loads(out)
        assert "report" in d["data"]
        assert "扫描报告" in d["data"]["report"]
