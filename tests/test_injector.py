"""
多通道注入引擎测试.

覆盖:
    - extract_params: URL query + 表单 + cookie 三源提取
    - _send_payload: 四通道 (GET/POST/COOKIE/HEADER) 发送
    - 检测: sqli error-based / xss reflection / ssrf metadata / idor / auth-bypass
    - scan_all: 端到端
    - OpSec: _action_inject 无代理拒绝
"""

import pytest
from unittest.mock import patch, MagicMock
from aiburp.traffic.injector import (
    MultiChannelInjector, InjectionFinding, ScanReport,
    XSS_CANARY, SQL_ERROR_PATTERNS,
)


def _mock_session():
    """构造一个 mock requests.Session."""
    s = MagicMock()
    s.cookies = MagicMock()
    s.cookies.keys.return_value = ["sessionid"]
    return s


# ============================================================
# 参数提取
# ============================================================

class TestExtractParams:
    def test_get_query_params(self):
        inj = MultiChannelInjector(_mock_session())
        params = inj.extract_params("http://t.com/page?id=1&name=test")
        assert "id" in params["GET"]
        assert "name" in params["GET"]

    def test_form_params_from_baseline(self):
        inj = MultiChannelInjector(_mock_session())
        baseline = MagicMock()
        baseline.text = '<form><input name="username"><input name="password"><input name="__VIEWSTATE" value="x"></form>'
        params = inj.extract_params("http://t.com/login", baseline)
        assert "username" in params["POST"]
        assert "password" in params["POST"]
        # __VIEWSTATE 是系统字段, 应该被过滤
        assert "__VIEWSTATE" not in params["POST"]

    def test_cookie_params(self):
        inj = MultiChannelInjector(_mock_session())
        params = inj.extract_params("http://t.com/page")
        assert "sessionid" in params["COOKIE"]

    def test_header_always_present(self):
        inj = MultiChannelInjector(_mock_session())
        params = inj.extract_params("http://t.com/page")
        assert "X-Forwarded-For" in params["HEADER"]
        assert "Referer" in params["HEADER"]

    def test_no_query(self):
        inj = MultiChannelInjector(_mock_session())
        params = inj.extract_params("http://t.com/page")
        assert params["GET"] == []


# ============================================================
# 四通道发送
# ============================================================

class TestSendPayload:
    def test_get_channel_injects_query(self):
        s = _mock_session()
        s.get.return_value = MagicMock(status_code=200, text="ok", headers={}, url="http://t.com")
        inj = MultiChannelInjector(s)
        resp = inj._send_payload("http://t.com/page?id=1", "GET", "id", "' OR 1=1",
                                  base_params={"id": "1"})
        assert s.get.called
        # payload 应该在 params 里
        call_kwargs = s.get.call_args.kwargs
        assert call_kwargs["params"]["id"] == "' OR 1=1"

    def test_post_channel_injects_body(self):
        s = _mock_session()
        s.post.return_value = MagicMock(status_code=200, text="ok", headers={}, url="http://t.com")
        inj = MultiChannelInjector(s)
        resp = inj._send_payload("http://t.com/login", "POST", "username", "admin'--",
                                  base_params={"username": ""})
        assert s.post.called
        call_kwargs = s.post.call_args.kwargs
        assert call_kwargs["data"]["username"] == "admin'--"

    def test_cookie_channel_injects_cookie(self):
        s = _mock_session()
        s.get.return_value = MagicMock(status_code=200, text="ok", headers={}, url="http://t.com")
        inj = MultiChannelInjector(s)
        resp = inj._send_payload("http://t.com/admin", "COOKIE", "role", "admin",
                                  base_cookies={"role": "user"})
        assert s.get.called
        call_kwargs = s.get.call_args.kwargs
        assert call_kwargs["cookies"]["role"] == "admin"

    def test_header_channel_injects_header(self):
        s = _mock_session()
        s.get.return_value = MagicMock(status_code=200, text="ok", headers={}, url="http://t.com")
        inj = MultiChannelInjector(s)
        resp = inj._send_payload("http://t.com/admin", "HEADER", "X-Forwarded-For", "127.0.0.1")
        assert s.get.called
        call_kwargs = s.get.call_args.kwargs
        assert call_kwargs["headers"]["X-Forwarded-For"] == "127.0.0.1"

    def test_connection_error_returns_error_dict(self):
        import requests
        s = _mock_session()
        s.get.side_effect = requests.ConnectionError("refused")
        inj = MultiChannelInjector(s)
        resp = inj._send_payload("http://t.com/x", "GET", "id", "'")
        assert resp["error"]
        assert resp["status"] == 0


# ============================================================
# 检测逻辑
# ============================================================

class TestDetection:
    def test_detect_sqli_mysql_error(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "You have an error in your SQL syntax near '", "status": 200, "error": None}
        result = inj._detect_sqli(resp, "'")
        assert result is not None
        assert "SQL" in result or "syntax" in result

    def test_detect_sqli_classic_asp_error(self):
        """经典 ASP 的 ADODB 错误 — store.aspx 场景."""
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "Microsoft JET Database error '80040e14'", "status": 500, "error": None}
        result = inj._detect_sqli(resp, "'")
        assert result is not None

    def test_detect_sqli_dotnet_exception(self):
        """store.aspx 实战: 500 + System.Data 异常 — 新增的检测."""
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "System.Data.SqlClient.SqlException: Incorrect syntax",
                "status": 500, "error": None}
        result = inj._detect_sqli(resp, "'")
        assert result is not None
        assert "SQL" in result or "异常" in result

    def test_detect_sqli_app_exception_500(self):
        """500 + 应用异常文本 (非标准 SQL 错误) — 新增检测."""
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "Server Error in '/' Application. Runtime Error.",
                "status": 500, "error": None}
        result = inj._detect_sqli(resp, "'")
        assert result is not None
        assert "异常" in result or "500" in result

    def test_detect_sqli_boolean_confirmed(self):
        """Boolean SQLi: AND 1=1≈基线, AND 1=2 差异大 → 确认."""
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_length = 1000
        # 真: 1010b (≈基线), 假: 200b (差异大)
        resp_true = {"length": 1010, "status": 200, "error": None}
        resp_false = {"length": 200, "status": 200, "error": None}
        result = inj._detect_sqli_boolean(resp_true, resp_false, "id")
        assert result is not None
        assert "Boolean" in result

    def test_detect_sqli_boolean_status_diff(self):
        """Boolean SQLi: 真=200 假=404 → 确认."""
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_length = 1000
        resp_true = {"length": 1000, "status": 200, "error": None}
        resp_false = {"length": 50, "status": 404, "error": None}
        result = inj._detect_sqli_boolean(resp_true, resp_false, "id")
        assert result is not None

    def test_detect_sqli_boolean_no_injection(self):
        """Boolean: 真≈假≈基线 → 无注入."""
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_length = 1000
        resp_true = {"length": 1000, "status": 200, "error": None}
        resp_false = {"length": 995, "status": 200, "error": None}
        result = inj._detect_sqli_boolean(resp_true, resp_false, "id")
        assert result is None

    def test_detect_sqli_no_error(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "<html>正常页面</html>", "status": 200, "error": None}
        result = inj._detect_sqli(resp, "'")
        assert result is None

    def test_detect_sqli_time_based(self):
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_time = 0.3
        resp = {"body": "<html>正常</html>", "status": 200, "error": None}
        # SLEEP payload, 延迟 4s (> 基线 + 2.5)
        result = inj._detect_sqli_time(resp, 4.0, "' AND SLEEP(3)--")
        assert result is not None
        assert "时间盲注" in result

    def test_detect_xss_reflection(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": f'<div>输入: <script>{XSS_CANARY}</script></div>', "status": 200, "error": None}
        result = inj._detect_xss(resp, f"<script>{XSS_CANARY}</script>")
        assert result is not None
        assert "反射" in result

    def test_detect_xss_no_reflection(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "<html>无反射</html>", "status": 200, "error": None}
        result = inj._detect_xss(resp, f"<script>{XSS_CANARY}</script>")
        assert result is None

    def test_detect_ssrf_metadata(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": '{"instance-id":"i-1234567890","ami-id":"ami-abc123"}',
                "status": 200, "error": None}
        result = inj._detect_ssrf(resp, "http://169.254.169.254/latest/meta-data/")
        assert result is not None
        assert "SSRF" in result

    def test_detect_ssrf_file_read(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
                "status": 200, "error": None}
        result = inj._detect_ssrf(resp, "file:///etc/passwd")
        assert result is not None

    def test_detect_idor_403_to_200(self):
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_status = 403
        inj._baseline_length = 100
        resp = {"status": 200, "length": 500, "error": None}
        result = inj._detect_idor(resp, "id", "100")
        assert result is not None
        assert "IDOR" in result

    def test_detect_auth_bypass_redirect(self):
        inj = MultiChannelInjector(_mock_session())
        resp = {"status": 302, "headers": {"Location": "/dashboard/welcome"},
                "body": "", "error": None}
        result = inj._detect_auth_bypass(resp, "' OR '1'='1'--")
        assert result is not None
        assert "认证绕过" in result


# ============================================================
# payload 选择
# ============================================================

class TestPayloadSelection:
    def test_sqli_payloads_nonempty(self):
        inj = MultiChannelInjector(_mock_session())
        ps = inj._get_payloads("sqli")
        assert len(ps) >= 4
        # 应该包含单引号探测
        assert "'" in ps

    def test_ssrf_has_metadata(self):
        inj = MultiChannelInjector(_mock_session())
        ps = inj._get_payloads("ssrf")
        assert any("169.254" in p for p in ps)

    def test_idor_values(self):
        inj = MultiChannelInjector(_mock_session())
        val = inj._idor_value("100", "__IDOR_INCREMENT__")
        assert val == "101"
        val = inj._idor_value("100", "__IDOR_DECREMENT__")
        assert val == "99"
        val = inj._idor_value("100", "__IDOR_ZERO__")
        assert val == "0"

    def test_auth_bypass_payloads(self):
        inj = MultiChannelInjector(_mock_session())
        ps = inj._get_payloads("auth-bypass")
        assert len(ps) >= 3
        assert any("OR" in p.upper() or "or" in p for p in ps)


# ============================================================
# scan_all 端到端 (mock)
# ============================================================

class TestScanAll:
    def test_scan_finds_sqli(self):
        """mock session 返回 SQL 错误 → scan_all 应报告 sqli."""
        s = _mock_session()
        # 基线正常
        baseline_resp = MagicMock(status_code=200, text="<html>正常</html>",
                                  headers={}, url="http://t.com/page?id=1")
        s.get.return_value = baseline_resp

        # 但带 payload 的请求返回 SQL 错误 — 通过 side_effect 区分
        def get_side_effect(url, **kwargs):
            params = kwargs.get("params", {})
            if params.get("id") and "'" in str(params["id"]):
                return MagicMock(status_code=500,
                                 text="You have an error in your SQL syntax",
                                 headers={}, url=url)
            return baseline_resp
        s.get.side_effect = get_side_effect

        inj = MultiChannelInjector(s, delay=0)
        report = inj.scan_all("http://t.com/page?id=1", vuln_types=["sqli"],
                              channels=["GET"])
        assert len(report.findings) >= 1
        assert any(f.vuln_type == "sqli" for f in report.findings)
        assert report.total_requests > 0

    def test_scan_no_findings_on_clean_target(self):
        s = _mock_session()
        s.get.return_value = MagicMock(status_code=200, text="<html>正常页面</html>",
                                       headers={}, url="http://t.com/page?id=1")
        inj = MultiChannelInjector(s, delay=0)
        report = inj.scan_all("http://t.com/page?id=1", vuln_types=["sqli"],
                              channels=["GET"])
        assert len(report.findings) == 0

    def test_scan_handles_baseline_error(self):
        s = _mock_session()
        s.get.side_effect = Exception("connection refused")
        inj = MultiChannelInjector(s, delay=0)
        report = inj.scan_all("http://t.com/page?id=1")
        assert len(report.errors) > 0
        assert report.total_requests == 0


# ============================================================
# 导出
# ============================================================

def test_exported_from_traffic():
    from aiburp.traffic import MultiChannelInjector as Exp, InjectionFinding as ExpF
    assert Exp is MultiChannelInjector
    assert ExpF is InjectionFinding


# ============================================================
# Agent OpSec — _action_inject 无代理拒绝
# ============================================================

class TestAgentInjectOpSec:
    def _bare_agent(self):
        from aiburp.agent import SecurityAgent
        a = SecurityAgent.__new__(SecurityAgent)
        a.project_id = "test"
        a._proxy_required = True
        a._proxy_verified = False
        a._real_ip = ""
        a._discovered = {}
        a.proxy_manager = None
        return a

    def test_inject_rejects_without_proxy(self):
        """无 proxy_manager 时 inject 必须拒绝 (OpSec)."""
        a = self._bare_agent()
        result = a._action_inject({"url": "http://t.com/page?id=1"})
        assert result["ok"] is False
        assert "OpSec" in result["error"] or "代理" in result["error"]

    def test_inject_registered_as_valid_action(self):
        from aiburp.agent import ActionParser
        assert "inject" in ActionParser.VALID_ACTIONS
        assert ActionParser.validate({"action": "inject", "params": {}})


# ============================================================
# 新功能: CSRF Token 预抓取
# ============================================================

class TestCSRFToken:
    def test_fetch_phpmyadmin_tokens(self):
        """phpMyAdmin 页面应能提取 token 和 set_session."""
        s = _mock_session()
        s.get.return_value = MagicMock(
            status_code=200,
            text='<form><input type="hidden" name="token" value="abc123" />'
                 '<input type="hidden" name="set_session" value="def456" />'
                 '<input type="hidden" name="server" value="1" /></form>',
        )
        inj = MultiChannelInjector(s)
        tokens = inj._fetch_csrf_tokens("http://t.com/pma/")
        assert "token" in tokens
        assert tokens["token"] == "abc123"
        assert "set_session" in tokens
        assert tokens["set_session"] == "def456"

    def test_fetch_aspnet_token(self):
        """ASP.NET __RequestVerificationToken."""
        s = _mock_session()
        s.get.return_value = MagicMock(
            status_code=200,
            text='<input name="__RequestVerificationToken" type="hidden" value="rvf123" />',
        )
        inj = MultiChannelInjector(s)
        tokens = inj._fetch_csrf_tokens("http://t.com/login")
        assert "__requestverificationtoken" in tokens or "token" in tokens

    def test_fetch_no_token(self):
        """无 CSRF token 的页面返回空 dict."""
        s = _mock_session()
        s.get.return_value = MagicMock(
            status_code=200,
            text='<html><body>hello</body></html>',
        )
        inj = MultiChannelInjector(s)
        tokens = inj._fetch_csrf_tokens("http://t.com/")
        assert tokens == {}


# ============================================================
# 新功能: HOST_INJECT 通道
# ============================================================

class TestHostInject:
    def test_detect_host_in_response_body(self):
        """注入的 Host 出现在响应体 → 缓存投毒."""
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "Generated by evil.attacker.com", "status": 200,
                "headers": {}, "error": None}
        result = inj._detect_host_injection(resp, "evil.attacker.com")
        assert result is not None
        assert "Host注入" in result

    def test_detect_host_in_redirect(self):
        """302 重定向到注入的 Host → 开放重定向+Host注入."""
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "",
                "status": 302,
                "headers": {"Location": "http://evil.attacker.com/admin"},
                "error": None}
        result = inj._detect_host_injection(resp, "evil.attacker.com")
        assert result is not None
        assert "重定向" in result

    def test_detect_host_no_injection(self):
        """Host 未出现在响应中 → 无注入."""
        inj = MultiChannelInjector(_mock_session())
        resp = {"body": "<html>正常</html>", "status": 200,
                "headers": {}, "error": None}
        result = inj._detect_host_injection(resp, "evil.attacker.com")
        assert result is None

    def test_host_inject_payloads(self):
        """host-inject 类型应有 payload."""
        inj = MultiChannelInjector(_mock_session())
        ps = inj._get_payloads("host-inject")
        assert len(ps) >= 3
        assert "127.0.0.1" in ps

    def test_host_inject_in_extract_params(self):
        """extract_params 应包含 HOST_INJECT 通道."""
        inj = MultiChannelInjector(_mock_session())
        params = inj.extract_params("http://t.com/page")
        assert "HOST_INJECT" in params
        assert "Host" in params["HOST_INJECT"]

    def test_default_channels_include_host_inject(self):
        """默认通道应包含 HOST_INJECT."""
        assert "HOST_INJECT" in MultiChannelInjector.DEFAULT_CHANNELS


# ============================================================
# 新功能: METHOD_OVERRIDE 通道
# ============================================================

class TestMethodOverride:
    def test_detect_method_override_status_change(self):
        """方法覆盖后状态码变化 → 可能绕过 ACL."""
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_status = 200
        resp = {"status": 201, "length": 500, "body": "", "headers": {}, "error": None}
        result = inj._detect_method_override(resp, "PUT")
        assert result is not None
        assert "方法覆盖" in result

    def test_detect_method_override_auth_bypass(self):
        """基线 403 → 方法覆盖后 200 → 认证绕过."""
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_status = 403
        resp = {"status": 200, "length": 500, "body": "", "headers": {}, "error": None}
        result = inj._detect_method_override(resp, "DELETE")
        assert result is not None
        assert "认证绕过" in result

    def test_detect_method_override_no_change(self):
        """方法覆盖无效果."""
        inj = MultiChannelInjector(_mock_session())
        inj._baseline_status = 200
        resp = {"status": 200, "length": 500, "body": "", "headers": {}, "error": None}
        result = inj._detect_method_override(resp, "PUT")
        assert result is None

    def test_method_override_payloads(self):
        """method-override 类型应有 PUT/DELETE 等."""
        inj = MultiChannelInjector(_mock_session())
        ps = inj._get_payloads("method-override")
        assert "PUT" in ps or "DELETE" in ps

    def test_method_override_in_extract_params(self):
        """extract_params 应包含 METHOD_OVERRIDE 通道."""
        inj = MultiChannelInjector(_mock_session())
        params = inj.extract_params("http://t.com/page")
        assert "METHOD_OVERRIDE" in params
        assert "X-HTTP-Method-Override" in params["METHOD_OVERRIDE"]

    def test_default_channels_include_method_override(self):
        """默认通道应包含 METHOD_OVERRIDE."""
        assert "METHOD_OVERRIDE" in MultiChannelInjector.DEFAULT_CHANNELS
