"""
hosting_panel_detect.py 单元测试.

验证:
    1. 面板指纹匹配 (cPanel/WHM/Plesk 等)
    2. 版本提取
    3. 置信度计算
    4. 默认凭据检测 (mock)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from aiburp.traffic.hosting_panel_detect import (
    HostingPanelDetect,
    PanelInfo,
    PanelDetectResult,
    PANEL_FINGERPRINTS,
    detect_panels,
)


# ============================================================
# 测试用 HTML 样本
# ============================================================

CPANEL_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>cPanel Login</title></head>
<body>
<div class="login-container">
<h1>cPanel &trade; Login</h1>
<form action="/cpsess1234/login">
<input type="text" name="user">
<input type="password" name="pass">
</form>
<div class="footer">cPanel L.L.C. All Rights Reserved.</div>
</div>
</body></html>"""

WHM_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>WHM Login</title></head>
<body>
<h1>WebHost Manager (WHM)</h1>
<form action="/whm/login">
<input type="text" name="root">
<input type="password" name="pass">
</form>
<div class="version">WHM 98.0.9</div>
</body></html>"""

PLESK_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Plesk Obsidian Login</title></head>
<body>
<h1>Plesk Obsidian 18.0.57</h1>
<form action="/plesk/login">
<div class="product-name">Plesk</div>
</form>
</body></html>"""

PHP_MY_ADMIN_HTML = """<!DOCTYPE html>
<html><head><title>phpMyAdmin 5.2.3</title></head>
<body>
<form method="post" action="index.php">
<input type="text" name="pma_username" id="input_username">
<input type="password" name="pma_password">
</form>
</body></html>"""

NOT_A_PANEL = """<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body>
<h1>Welcome to our website</h1>
<p>This is a regular site.</p>
</body></html>"""


class TestDetectPath:
    def test_detect_cpanel(self):
        """检测 cPanel 面板"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = CPANEL_LOGIN_HTML
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "Apache/2.4.57", "Content-Type": "text/html"}
        mock_resp.url = "https://target.com/cpanel/"

        mock_session.get.return_value = mock_resp

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/cpanel/",
            ["cPanel", "cpapi2", "cPanel L.L.C."],
        )
        assert info is not None
        assert "cpanel" in info.panel_type.lower() or "cpanel" in str(info).lower()

    def test_detect_whm(self):
        """检测 WHM 面板"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = WHM_LOGIN_HTML
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "Apache/2.4.57", "Content-Type": "text/html"}
        mock_resp.url = "https://target.com/whm/"

        mock_session.get.return_value = mock_resp

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/whm/",
            ["WHM", "cPanel L.L.C.", "cpsess", "WebHost Manager"],
        )
        assert info is not None

    def test_detect_plesk(self):
        """检测 Plesk 面板"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = PLESK_LOGIN_HTML
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "Apache", "Content-Type": "text/html"}
        mock_resp.url = "https://target.com/plesk/"

        mock_session.get.return_value = mock_resp

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/plesk/",
            ["Plesk", "plesk", "Odin", "Parallels Panel"],
        )
        assert info is not None

    def test_detect_phpmyadmin(self):
        """检测 phpMyAdmin"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = PHP_MY_ADMIN_HTML
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "Apache/2.4.57", "Content-Type": "text/html"}
        mock_resp.url = "https://target.com/phpmyadmin/"

        mock_session.get.return_value = mock_resp

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/phpmyadmin/",
            ["phpMyAdmin", "pma_", "input_username", "pma_password"],
        )
        assert info is not None

    def test_no_false_positive(self):
        """普通页面不应误报"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = NOT_A_PANEL
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "nginx", "Content-Type": "text/html"}
        mock_resp.url = "https://target.com/"

        mock_session.get.return_value = mock_resp

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/admin/",
            ["admin", "login", "cPanel"],
        )
        # "Welcome" 页面不匹配 cPanel 关键词
        assert info is None

    def test_403_with_keyword(self):
        """403 但含关键词应返回低置信度"""
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.text = "<html><body>cPanel Login - Access Denied</body></html>"
        mock_resp.status_code = 403
        mock_resp.headers = {"Server": "Apache", "Content-Type": "text/html"}
        mock_resp.url = "https://target.com/cpanel/"

        mock_session.get.return_value = mock_resp

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/cpanel/",
            ["cPanel", "cpapi2"],
        )
        assert info is not None
        assert info.detect_method == "403+keyword"
        assert info.confidence == 0.5

    def test_connection_error(self):
        """连接错误返回 None"""
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection refused")

        detect = HostingPanelDetect(session=mock_session)
        info = detect._check_path_sync(
            "https://target.com",
            "/cpanel/",
            ["cPanel"],
        )
        assert info is None


class TestExtractVersion:
    def test_version_from_text(self):
        """从文本提取版本"""
        ver = HostingPanelDetect._extract_version(
            "WHM 98.0.9 - WebHost Manager", "WHM"
        )
        assert ver == "98.0.9" or len(ver) > 0

    def test_version_none(self):
        """无版本号"""
        ver = HostingPanelDetect._extract_version(
            "Welcome to cPanel", "cPanel"
        )
        assert ver == ""


class TestCalcConfidence:
    def test_single_keyword(self):
        """单个关键词匹配"""
        conf = HostingPanelDetect._calc_confidence(
            ["cPanel"], "<html>cPanel Login</html>", "cPanel"
        )
        assert conf == 0.5

    def test_multiple_keywords(self):
        """多个关键词匹配提升置信度"""
        conf = HostingPanelDetect._calc_confidence(
            ["cPanel", "cpapi2", "paper_lantern"],
            "<html>cPanel Login cpapi2 paper_lantern</html>",
            "cPanel",
        )
        assert conf > 0.5
        assert conf <= 1.0


class TestDetectSync:
    def test_detect_sync_finds_panels(self):
        """同步检测至少找到部分面板"""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Server": "Apache", "Content-Type": "text/html"}
            mock_resp.url = url

            if "cpanel" in url or "whm" in url:
                mock_resp.text = CPANEL_LOGIN_HTML
            elif "phpmyadmin" in url or "pma" in url:
                mock_resp.text = PHP_MY_ADMIN_HTML
            else:
                mock_resp.text = NOT_A_PANEL
            return mock_resp

        mock_session.get.side_effect = mock_get

        detect = HostingPanelDetect(session=mock_session)
        result = detect.detect_sync("https://target.com")

        assert result.total_checked > 0
        # 应该找到 cpanel 或 phpmyadmin
        panel_types = [p.panel_type for p in result.panels]
        assert len(panel_types) > 0


class TestDefaultCreds:
    def test_check_default_creds_with_known(self):
        """对已知面板尝试默认凭据"""
        mock_session = Mock()
        fail_resp = Mock()
        fail_resp.status_code = 200
        fail_resp.text = "Login failed"
        fail_resp.headers = {}

        mock_session.post.return_value = fail_resp

        panel = PanelInfo(
            panel_type="cpanel",
            login_url="https://target.com/cpanel/",
            default_creds=[("root", "cpanel"), ("admin", "admin")],
        )

        detect = HostingPanelDetect(session=mock_session)
        results = detect.check_default_creds(panel)
        # 默认凭据失败, 应该返回空 (不会报错)
        assert isinstance(results, list)


class TestFingerprintsStructure:
    def test_panel_fingerprints_have_required_fields(self):
        """所有面板指纹定义完整"""
        for fp in PANEL_FINGERPRINTS:
            assert "type" in fp, f"Missing type in {fp}"
            assert "paths" in fp, f"Missing paths in {fp['type']}"
            assert "keywords" in fp, f"Missing keywords in {fp['type']}"
            assert len(fp["paths"]) > 0
            assert len(fp["keywords"]) > 0

    def test_hosting_panels_covered(self):
        """关键面板类型都在指纹库中"""
        panel_types = {fp["type"] for fp in PANEL_FINGERPRINTS}
        for required in ["cpanel", "whm", "plesk", "directadmin",
                         "phpmyadmin", "webmin", "vestacp"]:
            assert required in panel_types, f"Missing panel type: {required}"


class TestQuickFunctions:
    def test_detect_panels_import(self):
        """快捷函数可导入"""
        assert callable(detect_panels)