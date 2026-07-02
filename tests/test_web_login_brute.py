"""
web_login_brute.py 单元测试.

验证:
    1. CSRF token 提取
    2. 登录表单检测
    3. 成功/失败判定
    4. 拦截检测
    5. 爆破器基本流程
"""

import re
from unittest.mock import Mock, patch, MagicMock

import pytest

from aiburp.traffic.web_login_brute import (
    WebLoginBruteForcer,
    LoginFormInfo,
    extract_csrf_tokens,
    CSRF_TOKEN_NAMES,
    PMA_SUCCESS_PATTERNS,
    BLOCKED_PATTERNS,
)


# ============================================================
# 测试用 HTML 样本
# ============================================================

PMA_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
<form method="post" action="index.php?route=/&amp;ajax=1">
<input type="hidden" name="token" value="abc123token">
<input type="hidden" name="set_session" value="def456session">
<input type="hidden" name="server" value="1">
<input type="hidden" name="lang" value="en">
<input type="text" name="pma_username" id="input_username" required>
<input type="password" name="pma_password" id="input_password" required>
<button type="submit">Log in</button>
</form>
</body>
</html>"""

PMA_SUCCESS_HTML = """<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
<div id="serverinfo">Server: localhost</div>
<iframe src="navigation.php"></iframe>
<a href="index.php?route=/">Home</a>
</body>
</html>"""

PMA_FAIL_HTML = """<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
<form method="post">
<input type="text" name="pma_username" id="input_username">
<input type="password" name="pma_password">
<div class="alert alert-danger">Cannot log in to the MySQL server</div>
</form>
</body>
</html>"""

GENERIC_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<form method="post" action="/login">
<input type="hidden" name="_token" value="xyz789token">
<input type="text" name="email" placeholder="Email">
<input type="password" name="password" placeholder="Password">
<button type="submit">Sign In</button>
</form>
</body>
</html>"""

GENERIC_DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>Welcome back, Admin!</h1>
<a href="/logout">Logout</a>
</body>
</html>"""

BLOCKED_HTML = """<!DOCTYPE html>
<html>
<head><title>Rate Limit Exceeded</title></head>
<body>
<h1>Too many login attempts</h1>
<p>Please try again later.</p>
</body>
</html>"""


# ============================================================
# CSRF Token 提取测试
# ============================================================

class TestExtractCsrfTokens:
    def test_phpmyadmin_tokens(self):
        """提取 phpMyAdmin 的所有 token 字段"""
        tokens = extract_csrf_tokens(PMA_LOGIN_HTML)
        assert 'token' in tokens
        assert tokens['token'] == 'abc123token'
        assert 'set_session' in tokens
        assert tokens['set_session'] == 'def456session'
        assert 'server' in tokens
        assert tokens['server'] == '1'

    def test_generic_csrf(self):
        """提取通用 CSRF token"""
        tokens = extract_csrf_tokens(GENERIC_LOGIN_HTML)
        assert '_token' in tokens or 'token' in tokens

    def test_no_tokens(self):
        """无 token 的 HTML 返回空"""
        tokens = extract_csrf_tokens("<html><body>Hello</body></html>")
        assert tokens == {}

    def test_empty_html(self):
        """空 HTML"""
        tokens = extract_csrf_tokens("")
        assert tokens == {}


class TestDetectLoginForm:
    def test_detect_phpmyadmin(self, requests_mock):
        """检测 phpMyAdmin 登录表单"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = PMA_LOGIN_HTML
        mock_resp.url = "https://target.com/phpmyadmin/"
        mock_session.get.return_value = mock_resp
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session)
        form = brute.detect_login_form("https://target.com/phpmyadmin/")

        assert form.is_phpmyadmin is True
        assert form.username_field in ('pma_username', 'input_username')
        assert form.password_field in ('pma_password', 'input_password')
        assert len(form.token_fields) > 0

    def test_detect_generic(self, requests_mock):
        """检测通用登录表单"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = GENERIC_LOGIN_HTML
        mock_resp.url = "https://target.com/login"
        mock_session.get.return_value = mock_resp
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session)
        form = brute.detect_login_form("https://target.com/login")

        # 通用表单应该检测到 email 和 password 字段
        assert form.username_field == "email" or "email" in form.username_field

    def test_detect_connection_error(self):
        """连接错误时返回默认表单信息"""
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection error")
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session)
        form = brute.detect_login_form("https://target.com/")

        # 默认 action URL 应等于传入的 URL
        assert form.action_url == "https://target.com/"


# ============================================================
# 登录成功/失败判定测试
# ============================================================

class TestIsLoginSuccess:
    def test_pma_success(self):
        """phpMyAdmin 登录成功"""
        mock_resp = Mock()
        mock_resp.text = PMA_SUCCESS_HTML
        mock_resp.url = "https://target.com/phpmyadmin/index.php"
        mock_resp.status_code = 200
        mock_resp.headers = {}

        form_info = LoginFormInfo(is_phpmyadmin=True)
        success, detail = WebLoginBruteForcer._is_login_success(mock_resp, form_info)
        assert success is True, f"Should detect success: {detail}"

    def test_pma_fail(self):
        """phpMyAdmin 登录失败"""
        mock_resp = Mock()
        mock_resp.text = PMA_FAIL_HTML
        mock_resp.url = "https://target.com/phpmyadmin/"
        mock_resp.status_code = 200
        mock_resp.headers = {}

        form_info = LoginFormInfo(is_phpmyadmin=True)
        success, detail = WebLoginBruteForcer._is_login_success(mock_resp, form_info)
        assert success is False, f"Should detect failure: {detail}"

    def test_redirect_success(self):
        """302 重定向到 dashboard"""
        mock_resp = Mock()
        mock_resp.text = "<html><body>Redirecting...</body></html>"
        mock_resp.url = "https://target.com/dashboard"
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "/dashboard"}

        form_info = LoginFormInfo()
        success, detail = WebLoginBruteForcer._is_login_success(mock_resp, form_info)
        assert success is True

    def test_generic_success_body(self):
        """响应体包含 welcome/logout"""
        mock_resp = Mock()
        mock_resp.text = GENERIC_DASHBOARD_HTML
        mock_resp.url = "https://target.com/dashboard"
        mock_resp.status_code = 200
        mock_resp.headers = {}

        form_info = LoginFormInfo()
        success, detail = WebLoginBruteForcer._is_login_success(mock_resp, form_info)
        assert success is True

    def test_no_success(self):
        """普通页面, 非登录相关"""
        mock_resp = Mock()
        mock_resp.text = "<html><body>Page not found</body></html>"
        mock_resp.url = "https://target.com/404"
        mock_resp.status_code = 404
        mock_resp.headers = {}

        form_info = LoginFormInfo()
        success, detail = WebLoginBruteForcer._is_login_success(mock_resp, form_info)
        assert success is False


# ============================================================
# 拦截检测测试
# ============================================================

class TestIsBlocked:
    def test_rate_limit_429(self):
        """HTTP 429 拦截"""
        mock_resp = Mock()
        mock_resp.status_code = 429
        mock_resp.text = "Too Many Requests"
        blocked, detail = WebLoginBruteForcer._is_blocked(mock_resp)
        assert blocked is True
        assert "429" in detail

    def test_forbidden_403(self):
        """HTTP 403 拦截"""
        mock_resp = Mock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        blocked, detail = WebLoginBruteForcer._is_blocked(mock_resp)
        assert blocked is True

    def test_body_blocked_pattern(self):
        """响应体包含拦截关键词"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = BLOCKED_HTML
        blocked, detail = WebLoginBruteForcer._is_blocked(mock_resp)
        assert blocked is True

    def test_no_block(self):
        """正常响应"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Welcome</body></html>"
        blocked, detail = WebLoginBruteForcer._is_blocked(mock_resp)
        assert blocked is False


# ============================================================
# 爆破器核心流程测试
# ============================================================

class TestCrack:
    def test_crack_successful_login(self):
        """成功找到密码: 最后一个请求返回成功"""
        mock_session = Mock()

        # 第一个 GET 返回登录页 (CSRF token)
        login_resp = Mock()
        login_resp.text = PMA_LOGIN_HTML
        login_resp.url = "https://target.com/phpmyadmin/"

        # POST 请求: 第一次失败, 第二次成功
        fail_resp = Mock()
        fail_resp.text = PMA_FAIL_HTML
        fail_resp.url = "https://target.com/phpmyadmin/"
        fail_resp.status_code = 200
        fail_resp.headers = {}

        success_resp = Mock()
        success_resp.text = PMA_SUCCESS_HTML
        success_resp.url = "https://target.com/phpmyadmin/index.php"
        success_resp.status_code = 200
        success_resp.headers = {}

        # GET 返回登录页 (用于 CSRF 提取)
        mock_session.get.return_value = login_resp
        # POST: 第一次 fail, 第二次 success
        mock_session.post.side_effect = [fail_resp, success_resp]
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session, delay=0.01)
        report = brute.crack(
            "https://target.com/phpmyadmin/",
            usernames=["admin", "root"],
            passwords=["wrongpass", "correctpass"],
            stop_on_first=True,
        )

        assert len(report.successful) >= 1, "Should find at least one success"
        # 因为 stop_on_first=True, 应该在第二个组合 (root:correctpass) 成功

    def test_crack_no_success(self):
        """没有找到有效密码"""
        mock_session = Mock()

        login_resp = Mock()
        login_resp.text = PMA_LOGIN_HTML
        login_resp.url = "https://target.com/phpmyadmin/"

        fail_resp = Mock()
        fail_resp.text = PMA_FAIL_HTML
        fail_resp.url = "https://target.com/phpmyadmin/"
        fail_resp.status_code = 200
        fail_resp.headers = {}

        mock_session.get.return_value = login_resp
        mock_session.post.return_value = fail_resp  # 全部失败
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session, delay=0.01)
        report = brute.crack(
            "https://target.com/phpmyadmin/",
            usernames=["admin", "baduser"],
            passwords=["badpass1", "badpass2"],
            stop_on_first=True,
        )

        assert len(report.successful) == 0, "Should find no successes"
        assert report.total_attempts > 0, "Should have attempted some logins"

    def test_crack_max_attempts(self):
        """最大尝试次数限制"""
        mock_session = Mock()
        login_resp = Mock()
        login_resp.text = PMA_LOGIN_HTML
        login_resp.url = "https://target.com/phpmyadmin/"

        fail_resp = Mock()
        fail_resp.text = PMA_FAIL_HTML
        fail_resp.url = "https://target.com/phpmyadmin/"
        fail_resp.status_code = 200
        fail_resp.headers = {}

        mock_session.get.return_value = login_resp
        mock_session.post.return_value = fail_resp
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session, delay=0.01)
        report = brute.crack(
            "https://target.com/phpmyadmin/",
            usernames=["admin", "root", "user1", "user2"],
            passwords=["pass1", "pass2", "pass3"],
            max_attempts=4,  # 只尝试 4 次
            stop_on_first=False,
        )

        assert report.total_attempts <= 4, f"Should limit to 4 attempts (got {report.total_attempts})"

    def test_crack_blocked_stops(self):
        """被拦截后停止"""
        mock_session = Mock()

        login_resp = Mock()
        login_resp.text = PMA_LOGIN_HTML
        login_resp.url = "https://target.com/phpmyadmin/"

        blocked_resp = Mock()
        blocked_resp.text = BLOCKED_HTML
        blocked_resp.status_code = 429
        blocked_resp.headers = {}

        mock_session.get.return_value = login_resp
        mock_session.post.return_value = blocked_resp
        mock_session.cookies.get_dict.return_value = {}

        brute = WebLoginBruteForcer(mock_session, delay=0.01)
        report = brute.crack(
            "https://target.com/phpmyadmin/",
            usernames=["admin", "root"],
            passwords=["pass1", "pass2", "pass3"],
            max_attempts=100,
            stop_on_first=False,
        )

        assert report.blocked is True, "Should detect blocking"
        assert report.total_attempts < 10, "Should stop early after blocking"


# ============================================================
# 快捷函数测试
# ============================================================

class TestBrutePhpMyAdmin:
    def test_brute_phpmyadmin_import(self):
        """brute_phpmyadmin 快捷函数可导入且可调用"""
        from aiburp.traffic.web_login_brute import brute_phpmyadmin
        assert callable(brute_phpmyadmin)


# ============================================================
# fixtures for pytest
# ============================================================

@pytest.fixture
def requests_mock():
    """Mock requests library for tests that need it."""
    return True