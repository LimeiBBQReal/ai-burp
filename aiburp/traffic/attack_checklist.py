"""
攻击清单引擎 — 对任何目标执行完整方法论, 不遗漏任何维度.

设计哲学:
    不是"你提醒什么我做什么", 而是"拿到目标自动跑完整清单".
    流量分析不只看响应体, 还看请求结构/认证机制/接口语义.

每个目标的攻击清单 (14 个维度):

    1. 信息提取 — 从响应里榨取一切 (版本/框架/Cookie/API/注释/错误)
    2. 认证机制分析 — 怎么认证? 能不能绕过?
    3. 接口枚举 — JavaScript 里的所有 API 端点
    4. 参数发现 — 隐藏参数 / 可控参数 / 敏感参数
    5. 权限测试 — 未授权访问 / 水平越权 / 垂直越权
    6. 注入测试 — SQL/XSS/CMD/SSTI/LDAP/XPath (基于流量特征)
    7. CVE 匹配 — 从版本号匹配已知漏洞
    8. 配置文件探测 — .git/.env/web.config/wp-config/backup
    9. 方法/类型切换 — GET→POST→PUT + JSON→XML→form
    10. 目录/文件发现 — 不只是爆破, 还有 robots/sitemap/.well-known
    11. 业务逻辑 — IDOR/价格/竞争/状态机
    12. 响应差异分析 — 同接口不同参数的响应对比
    13. 请求结构分析 — 请求头/方法/路径/Host 注入面 (不只看响应)
    14. 会话交互分析 — Cookie 演化/重放/会话固定/令牌轮转

用法:
    engine = AttackChecklist(url)
    report = engine.run()  # 自动执行全部 12 个维度
"""

import re
import json
import hashlib
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class CheckResult:
    """单项检查结果"""
    dimension: str       # 信息提取/认证分析/接口枚举/...
    check_name: str      # 具体检查项
    target: str          # 检查的目标
    result: str = ""     # "vulnerable" / "info" / "clean" / "error"
    severity: str = "info"  # critical/high/medium/low/info
    evidence: str = ""   # 证据
    recommendation: str = ""  # 建议


class AttackChecklist:
    """
    攻击清单引擎.

    给一个 URL, 自动执行 12 个维度的完整检查.
    """

    def __init__(self, url: str, cookies: str = "", proxy: str = ""):
        self.url = url
        self.cookies = cookies
        self.results: List[CheckResult] = []

        import requests
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        if cookies:
            self.session.headers['Cookie'] = cookies
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        # 缓存基线响应
        self._baseline = None

    def run(self) -> List[CheckResult]:
        """执行全部 12 个维度"""
        self.results = []

        # 先拿基线响应
        try:
            self._baseline = self.session.get(self.url, timeout=10, allow_redirects=True)
        except Exception as e:
            self.results.append(CheckResult(
                dimension="error", check_name="baseline",
                target=self.url, result="error", evidence=str(e)[:100],
            ))
            return self.results

        # 执行全部维度
        self._dim1_info_extraction()
        self._dim2_auth_analysis()
        self._dim3_api_enumeration()
        self._dim4_param_discovery()
        self._dim5_access_control()
        self._dim6_injection_probes()
        self._dim7_cve_matching()
        self._dim8_config_files()
        self._dim9_method_type_switch()
        self._dim10_directory_discovery()
        self._dim11_business_logic()
        self._dim12_response_diff()
        # 扩展维度 (流量深层分析 — 不是只看响应体)
        self._dim13_request_structure()
        self._dim14_session_interaction()

        return self.results

    # ============================================================
    # 维度 1: 信息提取
    # ============================================================

    def _dim1_info_extraction(self):
        """从响应里榨取一切信息"""
        r = self._baseline
        body = r.text

        # 版本号提取
        versions = set()
        for pat in [r'(?i)version["\s:=]+([0-9]+\.[0-9]+\.[0-9]+)',
                    r'\?v=([0-9]+\.[0-9]+\.[0-9]+)',
                    r'(?i)powered by ([^<\r\n]+)',
                    r'(?i)generator.*?content="([^"]+)"']:
            versions.update(re.findall(pat, body))
        if versions:
            self._add("信息提取", "版本号", self.url, "info",
                      f"发现版本: {versions}", "匹配 CVE")

        # 技术栈
        server = r.headers.get('Server', '')
        powered = r.headers.get('X-Powered-By', '')
        if server:
            self._add("信息提取", "Server头", self.url, "low",
                      f"Server: {server}", f"检查 {server} 已知漏洞")
        if powered:
            self._add("信息提取", "X-Powered-By", self.url, "low",
                      f"X-Powered-By: {powered}", f"检查 {powered} 已知漏洞")

        # Cookie 分析
        set_cookie = r.headers.get('Set-Cookie', '')
        if set_cookie:
            # Cookie 安全标志
            issues = []
            if 'httponly' not in set_cookie.lower() and 'session' in set_cookie.lower():
                issues.append("Session Cookie 无 HttpOnly (XSS 可偷)")
            if 'secure' not in set_cookie.lower() and r.url.startswith('https'):
                issues.append("Cookie 无 Secure (HTTP 泄露)")
            if 'samesite' not in set_cookie.lower():
                issues.append("Cookie 无 SameSite (CSRF 可能)")
            if issues:
                self._add("信息提取", "Cookie安全", self.url, "medium",
                          "; ".join(issues))

        # HTML 注释
        comments = re.findall(r'<!--(.+?)-->', body, re.S)
        interesting = [c.strip()[:80] for c in comments
                      if any(kw in c.lower() for kw in ['todo','fixme','debug','password',
                                                          'secret','api','key','token','config'])]
        if interesting:
            self._add("信息提取", "HTML注释", self.url, "medium",
                      f"敏感注释: {interesting[:3]}")

        # 错误信息/堆栈跟踪
        error_pats = {
            'sql_error': [r'SQL syntax', r'mysql_', r'ORA-\d+', r'PostgreSQL.*ERROR'],
            'stack_trace': [r'Traceback', r'at\s+\w+\.\w+\(', r'Caused by:'],
            'debug_mode': [r'DEBUG\s*=\s*True', r'debug mode', r'Whoops!'],
            'path_leak': [r'/home/', r'C:\\\\', r'/var/www/', r'/usr/local/'],
        }
        for etype, pats in error_pats.items():
            for pat in pats:
                if re.search(pat, body, re.I):
                    self._add("信息提取", etype, self.url, "high",
                              f"发现 {etype}: {pat}")
                    break

        # 隐藏字段
        hidden = re.findall(r'type="hidden"[^>]*name="([^"]+)"', body)
        if hidden:
            self._add("信息提取", "隐藏字段", self.url, "info",
                      f"隐藏字段: {hidden}")

        # 框架指纹
        frameworks = {
            'ASP.NET': [r'__VIEWSTATE', r'__EVENTVALIDATION', r'asp\.net'],
            'Rails': [r'authenticity_token', r'csrf-token.*rails'],
            'Django': [r'csrftoken', r'django'],
            'Laravel': [r'laravel_session', r'XSRF-TOKEN'],
            'Spring': [r'JSESSIONID', r'spring'],
            'Express': [r'express', r'connect.sid'],
        }
        for fw, pats in frameworks.items():
            for pat in pats:
                if re.search(pat, body, re.I) or re.search(pat, str(r.headers), re.I):
                    self._add("信息提取", "框架指纹", self.url, "info",
                              f"检测到 {fw}")
                    break

        # 缺失安全头
        sec_headers = ['X-Content-Type-Options', 'X-Frame-Options',
                       'Strict-Transport-Security', 'Content-Security-Policy']
        missing = [h for h in sec_headers if h.lower() not in {k.lower() for k in r.headers}]
        if missing:
            self._add("信息提取", "安全头", self.url, "low",
                      f"缺失: {missing}")

    # ============================================================
    # 维度 2: 认证机制分析
    # ============================================================

    def _dim2_auth_analysis(self):
        """分析认证机制 — 能不能绕过?"""
        r = self._baseline

        # 认证类型
        auth_type = "unknown"
        if 'Authorization' in self.session.headers:
            auth_type = "header"
        cookies = r.headers.get('Set-Cookie', '')
        if 'session' in cookies.lower():
            auth_type = "session-cookie"
        if 'token' in cookies.lower() or 'jwt' in cookies.lower():
            auth_type = "token-cookie"
        www_auth = r.headers.get('WWW-Authenticate', '')
        if 'basic' in www_auth.lower():
            auth_type = "basic-auth"
        if 'bearer' in www_auth.lower():
            auth_type = "bearer"

        self._add("认证分析", "认证类型", self.url, "info",
                  f"认证方式: {auth_type}")

        # 未授权访问测试 — 去掉 Cookie 看能不能访问
        try:
            r2 = self.session.get(self.url, headers={'Cookie': ''}, timeout=8)
            if r2.status_code == 200 and r2.status_code == r.status_code:
                if len(r2.text) > 100 and len(r2.text) - len(r.text) < 500:
                    self._add("认证分析", "未授权访问", self.url, "high",
                              "去掉 Cookie 后仍返回 200 + 相似内容 — 可能无认证!",
                              "确认是否未登录可访问")
        except:
            pass

        # JWT 检测
        for cookie_part in cookies.split(';'):
            if 'eyJ' in cookie_part:
                self._add("认证分析", "JWT", self.url, "high",
                          f"Cookie 含 JWT: {cookie_part.strip()[:40]}",
                          "用 JWTTool 解码/伪造")

    # ============================================================
    # 维度 3: 接口枚举
    # ============================================================

    def _dim3_api_enumeration(self):
        """从 JavaScript / HTML 里提取所有 API 端点"""
        body = self._baseline.text
        endpoints = set()

        # JavaScript 里的 API 端点
        for pat in [r'["\']/(api/[^\s"\']+)["\']',
                    r'["\']([^"\']*/wp-json/[^\s"\']*)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                    r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)',
                    r'XMLHttpRequest.*?open\([\'"][A-Z]+[\'"],\s*["\']([^"\']+)']:
            endpoints.update(re.findall(pat, body))

        # HTML 里的链接
        for pat in [r'href="([^"]*(?:api|admin|upload|ajax|action|json)[^"]*)"',
                    r'src="([^"]*\.js)"']:
            endpoints.update(re.findall(pat, body, re.I))

        # JS 文件内容分析 (如果 JS 是内联的)
        js_blocks = re.findall(r'<script[^>]*>(.+?)</script>', body, re.S)
        for js in js_blocks:
            for pat in [r'["\']/(api/[^"\']+)["\']', r'url:\s*["\']([^"\']+)["\']']:
                endpoints.update(re.findall(pat, js))

        # 过滤 + 去重
        clean = {e for e in endpoints if len(e) > 2 and not e.startswith('http') and not e.startswith('//')}

        if clean:
            self._add("接口枚举", "API端点", self.url, "info",
                      f"发现 {len(clean)} 个端点: {list(clean)[:10]}")

        # WordPress REST API
        if 'wp-json' in body or 'wp-content' in body:
            try:
                r = self.session.get(f"{self._base_url()}/wp-json/", timeout=8)
                if r.status_code == 200:
                    routes = r.json().get('routes', {})
                    self._add("接口枚举", "WP REST API", self.url, "info",
                              f"WordPress REST API: {len(routes)} 个路由")
                    # 用户枚举
                    r2 = self.session.get(f"{self._base_url()}/wp-json/wp/v2/users", timeout=8)
                    if r2.status_code == 200:
                        users = r2.json()
                        names = [u.get('slug','?') for u in users]
                        self._add("接口枚举", "WP用户枚举", self.url, "high",
                                  f"用户: {names}", "可用于爆破/钓鱼")
            except:
                pass

    # ============================================================
    # 维度 4: 参数发现
    # ============================================================

    def _dim4_param_discovery(self):
        """发现隐藏参数和敏感参数"""
        body = self._baseline.text

        # 表单参数
        forms = re.findall(r'<form[^>]*>(.+?)</form>', body, re.S)
        all_params = set()
        for form in forms:
            inputs = re.findall(r'<input[^>]*name="([^"]+)"', form)
            all_params.update(inputs)
            selects = re.findall(r'<select[^>]*name="([^"]+)"', form)
            all_params.update(selects)

        # URL 参数
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.url)
        url_params = set(parse_qs(parsed.query).keys())
        all_params.update(url_params)

        if all_params:
            # 敏感参数检测
            sensitive = {}
            for p in all_params:
                p_lower = p.lower()
                if any(k in p_lower for k in ['id','uid','user']):
                    sensitive[p] = "IDOR 可能"
                elif any(k in p_lower for k in ['url','redirect','callback']):
                    sensitive[p] = "SSRF 可能"
                elif any(k in p_lower for k in ['file','path','page']):
                    sensitive[p] = "LFI 可能"
                elif any(k in p_lower for k in ['cmd','exec','command']):
                    sensitive[p] = "命令注入 可能"
                elif any(k in p_lower for k in ['price','amount','total']):
                    sensitive[p] = "价格篡改 可能"
                elif any(k in p_lower for k in ['role','admin','priv']):
                    sensitive[p] = "权限提升 可能"

            if sensitive:
                for param, risk in sensitive.items():
                    self._add("参数发现", risk, f"{self.url}?{param}=", "medium",
                              f"参数 {param}: {risk}")

            self._add("参数发现", "全部参数", self.url, "info",
                      f"参数: {all_params}")

    # ============================================================
    # 维度 5: 权限测试
    # ============================================================

    def _dim5_access_control(self):
        """未授权访问 / 越权测试"""
        r = self._baseline

        # 如果当前是 admin 页面, 去掉认证看能不能访问
        if 'admin' in self.url.lower():
            try:
                r2 = self.session.get(self.url, headers={'Cookie': ''}, timeout=8)
                if r2.status_code == 200 and 'login' not in r2.text.lower()[:500]:
                    self._add("权限测试", "admin未授权", self.url, "critical",
                              "admin 页面无需认证可访问!",
                              "立即修复: 添加认证检查")
            except:
                pass

        # HTTP 方法测试 — 是否支持 PUT/DELETE
        for method in ['PUT', 'DELETE', 'PATCH', 'OPTIONS']:
            try:
                r3 = self.session.request(method, self.url, timeout=5)
                if r3.status_code not in (405, 403, 501):
                    allow = r3.headers.get('Allow', '')
                    self._add("权限测试", f"HTTP {method}", self.url, "medium",
                              f"{method} 返回 {r3.status_code} (Allow: {allow})",
                              f"测试 {method} 能否修改/删除资源")
            except:
                pass

    # ============================================================
    # 维度 6: 注入探测
    # ============================================================

    def _dim6_injection_probes(self):
        """基于流量特征的注入探测 (轻量, 不发大量 payload)"""
        body = self._baseline.text
        url_params = self._get_url_params()

        for param, value in url_params.items():
            # 参数反射 → XSS 可能
            if value and str(value) in body:
                self._add("注入探测", "XSS反射", f"{param}={value}", "high",
                          f"参数 {param} 的值被反射到响应",
                          "注入 <script>alert(1)</script> 测试")

        # 单引号探测 SQLi
        for param in url_params:
            try:
                r = self.session.get(self.url, params={param: "'"}, timeout=5)
                if any(kw in r.text for kw in ['SQL syntax', 'mysql_', 'ORA-', 'PostgreSQL']):
                    self._add("注入探测", "SQLi迹象", f"{param}='", "high",
                              f"单引号触发 SQL 错误!",
                              "深入测试 UNION SELECT")
            except:
                pass

    # ============================================================
    # 维度 7: CVE 匹配
    # ============================================================

    def _dim7_cve_matching(self):
        """从版本号匹配已知 CVE"""
        body = self._baseline.text

        # 检测版本 → 匹配 CVE
        cve_db = {
            'phpmyadmin': {
                r'5\.2\.[0-3]': ['CVE-2023-3411 (XSS)', '检查版本是否受影响'],
            },
            'wordpress': {
                r'6\.[0-3]\.': ['CVE-2023-2745 (目录穿越)', '检查具体版本'],
                r'5\.[0-9]\.': ['多个已知漏洞', '升级到最新版'],
            },
            'blue iris': {
                r'5\.[0-8]\.': ['CVE-2022-21564 (认证绕过)', '尝试直接访问 /admin/'],
                r'5\.9\.[0-8]': ['CVE-2023-xxx (多个 RCE)', '检查具体子版本'],
            },
            'iis': {
                r'10\.0': ['CVE-2020-0688 (Exchange)', '检查是否为 Exchange'],
            },
            'apache': {
                r'2\.4\.[0-4][0-9]': ['CVE-2021-41773 (目录穿越)', '尝试 /.git/'],
            },
        }

        for product, versions in cve_db.items():
            if product.replace(' ', '') in body.lower().replace(' ', '') or \
               product in self._baseline.headers.get('Server','').lower():
                for ver_pat, cves in versions.items():
                    if re.search(ver_pat, body):
                        for cve in cves:
                            self._add("CVE匹配", product, self.url, "high",
                                      f"{product}: {cve}")

    # ============================================================
    # 维度 8: 配置文件探测
    # ============================================================

    def _dim8_config_files(self):
        """探测配置文件/备份/.git"""
        base = self._base_url()
        config_paths = [
            '.git/config', '.git/HEAD', '.env',
            'wp-config.php', 'wp-config.php.bak', 'wp-config.php~',
            'config.php', 'config.inc.php', 'configuration.php',
            'web.config', 'app.config', 'settings.py',
            'backup.sql', 'db.sql', 'dump.sql',
            '.htaccess', '.htpasswd',
            'robots.txt', 'sitemap.xml',
            'composer.json', 'package.json',
            'phpinfo.php', 'info.php', 'test.php',
            'debug.php', 'trace.axd', 'elmah.axd',
            'swagger.json', 'swagger-ui/', 'api-docs',
            'graphql', '/.well-known/security.txt',
        ]

        for path in config_paths:
            try:
                r = self.session.get(f"{base}/{path}", timeout=4, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    severity = "critical" if any(k in path for k in ['.git','.env','config','sql','backup']) else "low"
                    snippet = r.text[:80].replace('\n',' ').replace('\r','')
                    self._add("配置文件", path, f"{base}/{path}", severity,
                              f"200 ({len(r.text)}b): {snippet}",
                              f"分析 {path} 内容")
            except:
                pass

    # ============================================================
    # 维度 9: 方法/类型切换
    # ============================================================

    def _dim9_method_type_switch(self):
        """切换 HTTP 方法和 Content-Type 看响应变化"""
        # OPTIONS — 看支持哪些方法
        try:
            r = self.session.options(self.url, timeout=5)
            allow = r.headers.get('Allow', '')
            if allow:
                methods = [m.strip() for m in allow.split(',')]
                if 'PUT' in methods or 'DELETE' in methods:
                    self._add("方法切换", "OPTIONS", self.url, "medium",
                              f"支持: {methods}")
        except:
            pass

        # 切换 Content-Type 看是否返回不同内容
        try:
            r_json = self.session.get(self.url, headers={'Accept': 'application/json'}, timeout=5)
            r_xml = self.session.get(self.url, headers={'Accept': 'application/xml'}, timeout=5)
            if r_json.status_code == 200 and r_xml.status_code == 200:
                if abs(len(r_json.text) - len(r_xml.text)) > 500:
                    self._add("方法切换", "Accept切换", self.url, "info",
                              f"JSON ({len(r_json.text)}b) vs XML ({len(r_xml.text)}b) 差异大",
                              "分析不同格式是否有不同信息泄露")
        except:
            pass

    # ============================================================
    # 维度 10: 目录发现
    # ============================================================

    def _dim10_directory_discovery(self):
        """智能目录发现 (不只是爆破)"""
        base = self._base_url()
        smart_paths = [
            'robots.txt', 'sitemap.xml', '.well-known/security.txt',
            'admin', 'login', 'api', 'api/v1', 'api/v2',
            'swagger', 'swagger-ui', 'graphql',
            'backup', 'old', 'test', 'debug',
            'uploads', 'files', 'static', 'assets',
            'phpmyadmin', 'phpinfo.php',
            '.git', '.svn', '.hg',
            'web.config', 'crossdomain.xml',
            'server-status', 'server-info',
        ]

        found = []
        for path in smart_paths:
            try:
                r = self.session.get(f"{base}/{path}", timeout=3, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    found.append((path, r.status_code, r.headers.get('Location','')))
            except:
                pass

        for path, code, loc in found:
            severity = "high" if path in ['admin','phpmyadmin','backup','.git','phpinfo.php'] else "low"
            self._add("目录发现", path, f"{base}/{path}", severity,
                      f"{code}" + (f" → {loc[:30]}" if loc else ""))

    # ============================================================
    # 维度 11: 业务逻辑
    # ============================================================

    def _dim11_business_logic(self):
        """业务逻辑漏洞检测 (基于参数)"""
        params = self._get_url_params()

        for param, value in params.items():
            p_lower = param.lower()
            if value and str(value).isdigit():
                self._add("业务逻辑", "IDOR可能", f"{param}={value}", "medium",
                          f"参数 {param} 是数字 ({value}), 尝试 ±1 越权",
                          f"用 LogicVulnScanner.scan_url 测试")

    # ============================================================
    # 维度 12: 响应差异分析
    # ============================================================

    def _dim12_response_diff(self):
        """同接口不同参数的响应差异"""
        params = self._get_url_params()
        baseline_len = len(self._baseline.text)

        for param, value in params.items():
            # 正常值 vs 特殊值
            test_values = [str(value), str(value) + "9999", "0", "-1", ""]
            lengths = []
            for tv in test_values:
                try:
                    r = self.session.get(self.url, params={param: tv}, timeout=5)
                    lengths.append(len(r.text))
                except:
                    lengths.append(-1)

            # 如果不同值导致不同响应长度 → 可能存在注入
            valid = [l for l in lengths if l > 0]
            if valid and max(valid) - min(valid) > 100:
                self._add("响应差异", param, self.url, "medium",
                          f"参数 {param} 不同值 → 响应大小差异: {lengths}",
                          "分析差异原因 — 可能存在注入或越权")

    # ============================================================
    # 维度 13: 请求结构分析 (不只是看响应, 也看请求)
    # ============================================================

    def _dim13_request_structure(self):
        """分析请求本身的攻击面 — 头/方法/路径/Host 都是注入点."""
        r = self._baseline
        req_headers = r.request.headers if hasattr(r, 'request') and r.request else {}

        # Host 头注入 — Host 头能否被服务器信任用于内部路由?
        try:
            r_h = self.session.get(
                self.url,
                headers={'Host': 'evil.attacker.com', 'X-Forwarded-Host': 'evil.attacker.com'},
                timeout=5, allow_redirects=False,
            )
            # 如果响应里出现我们注入的 Host → 缓存投毒 / 密码重置投毒
            if 'evil.attacker.com' in r_h.text or 'evil.attacker.com' in str(r_h.headers):
                self._add("请求结构", "Host头注入", self.url, "high",
                          "注入的 Host 出现在响应 → 缓存投毒/重置投毒可能",
                          "测试密码重置链接是否使用 Host")
        except Exception:
            pass

        # X-Forwarded-For 认证绕过
        try:
            r_xff = self.session.get(
                self.url,
                headers={'X-Forwarded-For': '127.0.0.1',
                         'X-Real-IP': '127.0.0.1',
                         'X-Originating-IP': '127.0.0.1'},
                timeout=5,
            )
            # 如果带 XFF 的响应与基线长度差异大 → 可能存在 IP 信任绕过
            if abs(len(r_xff.text) - len(self._baseline.text)) > 500:
                self._add("请求结构", "XFF信任绕过", self.url, "high",
                          f"XFF=127.0.0.1 → 响应差异 {len(r_xff.text)} vs {len(self._baseline.text)}",
                          "测试带 XFF 能否访问受限接口/绕过限速")
        except Exception:
            pass

        # 路径规范化 — /admin vs //admin vs /./admin vs /admin;.js
        from urllib.parse import urlparse
        path = urlparse(self.url).path or '/'
        path_variants = [
            ('double-slash', '//' + path.lstrip('/')),
            ('dot-segment', '/.' + path.lstrip('/')),
            ('url-encode', '/%' + '2e' + path.lstrip('/')),
            ('path-traversal', '/..' + path),
            ('semicolon', path + ';.js'),
            ('case', '/' + path.lstrip('/').swapcase()),
        ]
        for name, variant in path_variants:
            try:
                base = self._base_url()
                rv = self.session.get(base + variant, timeout=4, allow_redirects=False)
                # 如果变体路径返回了和原路径相似的 200 → 路径归一化不一致 (WAF 绕过)
                if rv.status_code == 200 and abs(len(rv.text) - len(self._baseline.text)) < 200:
                    self._add("请求结构", f"路径归一化({name})", base + variant, "medium",
                              f"路径变体 {name} 仍返回 200 — 可绕过 WAF/ACL")
                    break
            except Exception:
                continue

        # HTTP 方法覆盖 — _method 参数或 X-HTTP-Method-Override
        for header in ['X-HTTP-Method-Override', 'X-Method-Override']:
            try:
                rm = self.session.get(
                    self.url,
                    headers={header: 'PUT'},
                    timeout=4,
                )
                if rm.status_code != self._baseline.status_code:
                    self._add("请求结构", "方法覆盖", self.url, "medium",
                              f"{header}: PUT → 状态码 {rm.status_code} (基线 {self._baseline.status_code})",
                              "测试能否通过头绕过方法限制")
                    break
            except Exception:
                continue

    # ============================================================
    # 维度 14: 会话交互分析 (Cookie/Token 的演化与重放)
    # ============================================================

    def _dim14_session_interaction(self):
        """分析会话令牌的轮转/固定/重放 — 流量的"交互"维度."""
        r1 = self._baseline
        cookie1 = r1.headers.get('Set-Cookie', '')

        if not cookie1:
            self._add("会话交互", "无Cookie", self.url, "info",
                      "响应未设置 Cookie — 静态资源或无状态 API")
            return

        # 会话固定检测 — 两次请求是否返回相同的 SessionID?
        try:
            r2 = self.session.get(self.url, timeout=5)
            cookie2 = r2.headers.get('Set-Cookie', '')
            sid1 = self._extract_session_id(cookie1)
            sid2 = self._extract_session_id(cookie2)
            if sid1 and sid2 and sid1 == sid2:
                self._add("会话交互", "会话固定", self.url, "high",
                          f"两次请求返回相同 SessionID ({sid1[:12]}...) — 会话固定可能",
                          "攻击者可强制设置受害者 SessionID")
            elif sid1 and sid2 and sid1 != sid2:
                self._add("会话交互", "会话轮转", self.url, "info",
                          "每次请求轮转 SessionID — 会话管理正常",
                          "")
        except Exception:
            pass

        # Cookie 属性深度分析
        issues = []
        for attr, label, risk in [
            ('httponly', 'HttpOnly', 'XSS 可偷取'),
            ('secure', 'Secure', 'HTTP 明文泄露'),
            ('samesite', 'SameSite', 'CSRF 可能'),
        ]:
            if attr not in cookie1.lower():
                # 只对 Session 类 Cookie 报警
                if 'session' in cookie1.lower() or 'token' in cookie1.lower() or 'auth' in cookie1.lower():
                    issues.append(f"Cookie 无 {label} ({risk})")
        if issues:
            self._add("会话交互", "Cookie属性", self.url, "medium",
                      "; ".join(issues))

        # 登录后回放检测 — 同一 Cookie 能否在不同上下文重放?
        # (这里只做轻量检测: 带 Cookie 访问 /api/me 类接口)
        if self.cookies:
            from urllib.parse import urlparse
            netloc = urlparse(self.url).netloc
            probe_paths = ['/api/me', '/api/user', '/api/profile', '/user/info', '/account']
            for p in probe_paths:
                try:
                    rp = self.session.get(
                        f"{self._base_url()}{p}",
                        timeout=4,
                    )
                    if rp.status_code == 200 and len(rp.text) > 50:
                        self._add("会话交互", "令牌重放", f"{self._base_url()}{p}", "medium",
                                  f"带 Cookie 访问 {p} 返回 200 ({len(rp.text)}b) — 令牌可跨接口重放",
                                  "测试该接口是否泄露其他用户数据 (越权)")
                        break
                except Exception:
                    continue

    # ============================================================
    # 工具方法
    # ============================================================

    def _add(self, dim, check, target, severity, evidence, rec=""):
        self.results.append(CheckResult(
            dimension=dim, check_name=check, target=target,
            severity=severity, evidence=evidence[:200], recommendation=rec,
        ))

    def _base_url(self) -> str:
        from urllib.parse import urlparse
        p = urlparse(self.url)
        return f"{p.scheme}://{p.netloc}"

    def _get_url_params(self) -> dict:
        from urllib.parse import urlparse, parse_qs
        return {k: v[0] if v else '' for k, v in parse_qs(urlparse(self.url).query).items()}

    @staticmethod
    def _extract_session_id(set_cookie: str) -> str:
        """从 Set-Cookie 头里提取 SessionID 值 (用于会话固定检测)."""
        if not set_cookie:
            return ""
        # Set-Cookie: name=value; Path=/; ...
        try:
            pair = set_cookie.split(';', 1)[0].strip()
            if '=' in pair:
                return pair.split('=', 1)[1]
        except Exception:
            pass
        return ""

    def report_text(self) -> str:
        """生成报告"""
        lines = [f"{'='*60}", f"攻击清单报告: {self.url}", f"{'='*60}"]
        lines.append(f"总检查项: {len(self.results)}")
        critical = sum(1 for r in self.results if r.severity == 'critical')
        high = sum(1 for r in self.results if r.severity == 'high')
        lines.append(f"严重: {critical} | 高危: {high}")
        lines.append(f"{'─'*60}")

        by_dim = {}
        for r in self.results:
            by_dim.setdefault(r.dimension, []).append(r)

        for dim, items in by_dim.items():
            lines.append(f"\n[{dim}] ({len(items)} 项):")
            for r in items:
                icon = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🟢','info':'🔵'}.get(r.severity,'⚪')
                lines.append(f"  {icon} {r.check_name}: {r.evidence[:60]}")
                if r.recommendation:
                    lines.append(f"     → {r.recommendation[:60]}")

        return "\n".join(lines)
