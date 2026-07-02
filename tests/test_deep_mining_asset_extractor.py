"""
deep_mining / asset_extractor.py 单元测试
覆盖: CSS url()、HTML 标签提取、JS 路径、通用回退
"""
import pytest
from aiburp.deep_mining.asset_extractor import (
    AssetExtractor,
    extract_endpoints,
)


def _ends(out, suffix):
    return any(p.endswith(suffix) for p in out), out


class TestCssExtraction:
    def test_simple_url_function(self):
        body = """
        .bg { background: url('/img/bg.png'); }
        .icon { background-image: url("/icons/home.svg"); }
        """
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/css", url="https://x.com/")
        assert any(p.endswith("/img/bg.png") for p in out), out
        assert any(p.endswith("/icons/home.svg") for p in out), out

    def test_url_with_spaces(self):
        body = ".x { background: url(  '/a/b.jpg'  ); }"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/css")
        assert any(p.endswith("/a/b.jpg") for p in out), out

    def test_data_uri_does_not_crash(self):
        body = ".x { background: url(data:image/png;base64,AAAA); }"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/css")
        assert isinstance(out, list)

    def test_extension_fallback(self):
        """url 参数以 .css 结尾时也走 CSS 分支."""
        body = ".x { background: url('/y/bg.png'); }"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/plain", url="https://x.com/y.css")
        assert any(p.endswith("/y/bg.png") for p in out), out

    def test_cdn_url_kept_absolute(self):
        body = ".x { background: url('https://cdn.x.com/bg.png'); }"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/css")
        assert "https://cdn.x.com/bg.png" in out


class TestHtmlExtraction:
    def test_basic_tags(self):
        body = """
        <html>
        <head>
            <link rel="stylesheet" href="/static/main.css">
            <script src="/js/app.js"></script>
        </head>
        <body>
            <a href="/home">Home</a>
            <img src="/img/logo.png">
            <iframe src="/embed/widget"></iframe>
            <form action="/api/login" method="post"></form>
        </body>
        </html>
        """
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/html", url="https://x.com/")
        for suffix in [
            "/static/main.css",
            "/js/app.js",
            "/home",
            "/img/logo.png",
            "/embed/widget",
            "/api/login",
        ]:
            assert any(p.endswith(suffix) for p in out), f"missing {suffix} in {out}"

    def test_php_jsp_response_uses_html_extractor(self):
        """PHP/JSP 服务端输出 (含 HTML) 走 HTML 分支."""
        body = """
        <?php echo "hello"; ?>
        <html><body><a href="/admin">Admin</a></body></html>
        """
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/html", url="https://x.com/index.php")
        assert any(p.endswith("/admin") for p in out), out


class TestJsExtraction:
    def test_relative_path(self):
        # js_extractor 抓 fetch('') 模式, 不抓裸字符串赋值
        body = """
        fetch('/api/users');
        """
        ext = AssetExtractor()
        out = ext.extract(body, content_type="application/javascript", url="https://x.com/")
        assert any("/api/users" in p for p in out), out

    def test_quoted_paths(self):
        body = """const api = "/api/v1"; const img = '/img/x.png';"""
        ext = AssetExtractor()
        out = ext.extract(body, content_type="application/javascript")
        # 裸字符串 '/api/v1' 也能被 _API_PATH_PAT 抓到
        assert any("/api/v1" in p for p in out), out


class TestGenericExtraction:
    def test_generic_text_returns_list(self):
        """通用 fallback 不抛异常, 返回 list (可能为空)."""
        body = "see /api/foo for details"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/plain")
        # _PATH_RE 要求被 ['"\`] 包裹; 裸文本不会抽到
        # 但应不抛异常
        assert isinstance(out, list)

    def test_quoted_in_generic(self):
        body = "const a = '/api/foo'; const b = '/api/bar';"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/plain")
        # 通用 fallback 也会匹配带引号的路径
        assert any("/api/foo" in p for p in out) or \
               any("/api/bar" in p for p in out), out

    def test_empty_body(self):
        ext = AssetExtractor()
        assert ext.extract("", content_type="text/html") == []
        assert ext.extract(None, content_type="text/html") == []


class TestAbsoluteUrl:
    def test_absolute_url_kept(self):
        body = "fetch('https://api.other.com/x')"
        ext = AssetExtractor()
        out = ext.extract(body, content_type="application/javascript",
                          url="https://x.com/")
        assert any("api.other.com" in p for p in out), out

    def test_relative_url_joined(self):
        """HTML 抽取器只抽以 / 开头的相对路径 (避免对每个 a 标签做 urljoin)."""
        body = """<a href="/page/home.html">x</a>"""
        ext = AssetExtractor()
        out = ext.extract(body, content_type="text/html",
                          url="https://x.com/")
        # bs4 抽到的是原始 /page/home.html
        assert any(p.endswith("home.html") for p in out), out
        # 在 extract() 中按 url 做 urljoin -> https://x.com/page/home.html
        assert any("x.com/page/home.html" in p for p in out), out


class TestConvenienceFunction:
    def test_extract_endpoints(self):
        body = ".x { background: url('/a.png'); }"
        out = extract_endpoints(body, content_type="text/css")
        assert any(p.endswith("/a.png") for p in out), out
