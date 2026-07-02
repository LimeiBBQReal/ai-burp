"""
AIHelper - AI 决策辅助模块

为 AI Agent 提供决策辅助，基于观察到的数据给出建议。

核心功能:
1. suggest_actions(view) - 基于页面结构建议操作
2. suggest_tests(request) - 基于参数建议测试类型
3. analyze_response(response) - 分析响应中的异常、敏感数据、技术提示
4. prioritize_requests(requests) - 按测试优先级排序请求

Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
"""

import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from .models import Request, Response, PageView, FormInfo, LinkInfo, ButtonInfo, InputInfo


# ============================================================
# 数据模型
# ============================================================

@dataclass
class ActionSuggestion:
    """操作建议"""
    action: str  # click, fill, submit, navigate
    selector: str = ""
    value: str = ""
    reason: str = ""
    priority: int = 0  # 0-100, 越高越优先
    
    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "selector": self.selector,
            "value": self.value,
            "reason": self.reason,
            "priority": self.priority,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class TestSuggestion:
    """测试建议"""
    test_type: str  # sqli, xss, idor, ssrf, lfi, etc.
    param: str
    reason: str = ""
    priority: int = 0  # 0-100
    payloads: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "test_type": self.test_type,
            "param": self.param,
            "reason": self.reason,
            "priority": self.priority,
            "payloads": self.payloads,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class ResponseAnalysis:
    """响应分析结果"""
    # 异常检测
    anomalies: List[str] = field(default_factory=list)
    
    # 敏感数据
    sensitive_data: List[Dict] = field(default_factory=list)
    
    # 技术提示
    tech_hints: List[Dict] = field(default_factory=list)
    
    # 安全头分析
    security_headers: Dict[str, Any] = field(default_factory=dict)
    
    # 整体风险评估
    risk_level: str = "low"  # critical, high, medium, low
    
    # 建议
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "anomalies": self.anomalies,
            "sensitive_data": self.sensitive_data,
            "tech_hints": self.tech_hints,
            "security_headers": self.security_headers,
            "risk_level": self.risk_level,
            "recommendations": self.recommendations,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class PrioritizedRequest:
    """带优先级的请求"""
    request: Request
    priority: int = 0  # 0-100
    reasons: List[str] = field(default_factory=list)
    suggested_tests: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request.id,
            "url": self.request.url,
            "method": self.request.method,
            "priority": self.priority,
            "reasons": self.reasons,
            "suggested_tests": self.suggested_tests,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


# ============================================================
# AIHelper 类
# ============================================================

class AIHelper:
    """
    AI 决策辅助
    
    为 AI Agent 提供基于观察数据的决策建议。
    
    核心方法:
    - suggest_actions(view): 基于页面结构建议操作
    - suggest_tests(request): 基于参数建议测试类型
    - analyze_response(response): 分析响应
    - prioritize_requests(requests): 按优先级排序请求
    """
    
    # 登录表单关键词
    LOGIN_KEYWORDS = ["login", "signin", "sign-in", "log-in", "auth", "authenticate"]
    
    # 注册表单关键词
    REGISTER_KEYWORDS = ["register", "signup", "sign-up", "create-account", "join"]
    
    # 搜索表单关键词
    SEARCH_KEYWORDS = ["search", "query", "find", "lookup"]
    
    # 管理员链接关键词
    ADMIN_KEYWORDS = ["admin", "dashboard", "manage", "control", "panel", "backend"]
    
    # 敏感页面关键词
    SENSITIVE_KEYWORDS = ["account", "profile", "settings", "password", "payment", "billing", "order"]
    
    # 参数名到漏洞类型的映射
    PARAM_VULN_MAPPING = {
        # ID 参数 -> IDOR, SQLi
        "id_params": {
            "keywords": ["id", "uid", "user_id", "pid", "product_id", "order_id", "account_id", "userid", "accountid"],
            "vulns": ["idor", "sqli"],
            "priority": 80,
        },
        # 文件参数 -> LFI, Path Traversal
        "file_params": {
            "keywords": ["file", "path", "filename", "filepath", "document", "attachment", "doc", "upload", "template"],
            "vulns": ["lfi", "path_traversal"],
            "priority": 90,
        },
        # URL 参数 -> SSRF, Open Redirect
        "url_params": {
            "keywords": ["url", "link", "redirect", "return", "next", "callback", "goto", "returnurl", "redirect_uri", "target"],
            "vulns": ["ssrf", "open_redirect"],
            "priority": 85,
        },
        # 搜索参数 -> SQLi, XSS
        "search_params": {
            "keywords": ["search", "query", "q", "keyword", "term", "filter", "s"],
            "vulns": ["sqli", "xss"],
            "priority": 75,
        },
        # 回调参数 -> XSS, JSONP Hijacking
        "callback_params": {
            "keywords": ["callback", "jsonp", "cb", "func", "handler"],
            "vulns": ["xss", "jsonp_hijacking"],
            "priority": 70,
        },
        # 管理员参数 -> Privilege Escalation
        "admin_params": {
            "keywords": ["admin", "role", "privilege", "isAdmin", "is_admin", "permission", "level", "type"],
            "vulns": ["privilege_escalation", "idor"],
            "priority": 95,
        },
        # 调试参数 -> Info Disclosure
        "debug_params": {
            "keywords": ["debug", "test", "dev", "verbose", "trace", "log", "mode"],
            "vulns": ["info_disclosure"],
            "priority": 60,
        },
        # 命令参数 -> Command Injection
        "cmd_params": {
            "keywords": ["cmd", "command", "exec", "run", "shell", "ping", "host", "ip"],
            "vulns": ["cmdi", "rce"],
            "priority": 95,
        },
        # 模板参数 -> SSTI
        "template_params": {
            "keywords": ["template", "tpl", "view", "render", "page", "layout"],
            "vulns": ["ssti"],
            "priority": 80,
        },
    }
    
    # 安全头列表
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-Permitted-Cross-Domain-Policies",
    ]
    
    # 技术栈检测模式
    TECH_PATTERNS = {
        # Web 服务器
        "Apache": [r"Apache", r"apache"],
        "Nginx": [r"nginx", r"Nginx"],
        "IIS": [r"Microsoft-IIS", r"IIS"],
        # 编程语言/框架
        "PHP": [r"\.php", r"PHP/", r"PHPSESSID"],
        "ASP.NET": [r"ASP\.NET", r"\.aspx", r"__VIEWSTATE"],
        "Java": [r"JSESSIONID", r"\.jsp", r"Servlet"],
        "Python": [r"Python", r"Django", r"Flask", r"Werkzeug"],
        "Ruby": [r"Ruby", r"Rails", r"Rack"],
        "Node.js": [r"Express", r"Node\.js", r"connect\.sid"],
        # CMS
        "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
        "Drupal": [r"Drupal", r"drupal"],
        "Joomla": [r"Joomla", r"joomla"],
        # JavaScript 框架
        "React": [r"react", r"__NEXT_DATA__", r"_next"],
        "Vue": [r"vue", r"__vue__"],
        "Angular": [r"ng-", r"angular"],
        # 数据库
        "MySQL": [r"mysql", r"MySQL"],
        "PostgreSQL": [r"postgres", r"PostgreSQL"],
        "MongoDB": [r"mongo", r"MongoDB"],
    }
    
    def __init__(self):
        """初始化 AIHelper"""
        pass

    # ==================== suggest_actions ====================
    
    def suggest_actions(self, view: PageView) -> List[ActionSuggestion]:
        """
        基于页面结构建议操作
        
        分析页面中的表单、链接、按钮，给出操作建议。
        
        识别:
        - 登录表单
        - 注册表单
        - 搜索表单
        - 管理员链接
        - 敏感页面链接
        
        Args:
            view: PageView 对象
            
        Returns:
            ActionSuggestion 列表，按优先级排序
        
        Requirements: 19.1, 19.5
        """
        suggestions = []
        
        # 1. 分析表单
        for form in view.forms:
            form_suggestions = self._analyze_form(form)
            suggestions.extend(form_suggestions)
        
        # 2. 分析链接
        for link in view.links:
            link_suggestions = self._analyze_link(link)
            suggestions.extend(link_suggestions)
        
        # 3. 分析按钮
        for button in view.buttons:
            button_suggestions = self._analyze_button(button)
            suggestions.extend(button_suggestions)
        
        # 4. 分析独立输入框
        for inp in view.inputs:
            input_suggestions = self._analyze_input(inp)
            suggestions.extend(input_suggestions)
        
        # 按优先级排序
        suggestions.sort(key=lambda s: s.priority, reverse=True)
        
        return suggestions
    
    def _analyze_form(self, form: FormInfo) -> List[ActionSuggestion]:
        """分析表单，生成操作建议"""
        suggestions = []
        
        action_lower = form.action.lower() if form.action else ""
        input_names = [inp.name.lower() for inp in form.inputs if inp.name]
        input_types = [inp.type.lower() for inp in form.inputs if inp.type]
        
        # 检测登录表单
        is_login = (
            any(kw in action_lower for kw in self.LOGIN_KEYWORDS) or
            ("password" in input_types or "password" in input_names) and
            ("username" in input_names or "email" in input_names or "user" in input_names or "login" in input_names)
        )
        
        if is_login:
            # 建议填写登录表单
            suggestions.append(ActionSuggestion(
                action="fill_form",
                selector=form.selector,
                reason="检测到登录表单 - 尝试登录以访问更多功能",
                priority=90,
            ))
            
            # 建议测试默认凭证
            suggestions.append(ActionSuggestion(
                action="test_default_creds",
                selector=form.selector,
                reason="登录表单 - 测试默认凭证 (admin:admin, test:test)",
                priority=85,
            ))
            
            # 建议测试 SQL 注入
            suggestions.append(ActionSuggestion(
                action="test_sqli",
                selector=form.selector,
                reason="登录表单 - 测试 SQL 注入绕过认证",
                priority=80,
            ))
        
        # 检测注册表单
        is_register = (
            any(kw in action_lower for kw in self.REGISTER_KEYWORDS) or
            ("password" in input_types and "email" in input_names and 
             ("confirm" in " ".join(input_names) or "register" in action_lower))
        )
        
        if is_register:
            suggestions.append(ActionSuggestion(
                action="fill_form",
                selector=form.selector,
                reason="检测到注册表单 - 创建测试账户",
                priority=75,
            ))
        
        # 检测搜索表单
        is_search = (
            any(kw in action_lower for kw in self.SEARCH_KEYWORDS) or
            any(kw in " ".join(input_names) for kw in self.SEARCH_KEYWORDS)
        )
        
        if is_search:
            suggestions.append(ActionSuggestion(
                action="test_xss",
                selector=form.selector,
                reason="检测到搜索表单 - 测试 XSS",
                priority=70,
            ))
            suggestions.append(ActionSuggestion(
                action="test_sqli",
                selector=form.selector,
                reason="检测到搜索表单 - 测试 SQL 注入",
                priority=70,
            ))
        
        # 检测文件上传
        has_file_input = "file" in input_types
        if has_file_input:
            suggestions.append(ActionSuggestion(
                action="test_file_upload",
                selector=form.selector,
                reason="检测到文件上传 - 测试文件上传漏洞",
                priority=85,
            ))
        
        # 通用表单建议
        if not suggestions and form.inputs:
            suggestions.append(ActionSuggestion(
                action="fill_form",
                selector=form.selector,
                reason=f"表单包含 {len(form.inputs)} 个输入字段",
                priority=50,
            ))
        
        return suggestions
    
    def _analyze_link(self, link: LinkInfo) -> List[ActionSuggestion]:
        """分析链接，生成操作建议"""
        suggestions = []
        
        href_lower = link.href.lower() if link.href else ""
        text_lower = link.text.lower() if link.text else ""
        combined = f"{href_lower} {text_lower}"
        
        # 检测管理员链接
        if any(kw in combined for kw in self.ADMIN_KEYWORDS):
            suggestions.append(ActionSuggestion(
                action="navigate",
                selector=link.selector,
                reason="检测到管理员/后台链接 - 可能存在未授权访问",
                priority=95,
            ))
        
        # 检测敏感页面链接
        if any(kw in combined for kw in self.SENSITIVE_KEYWORDS):
            suggestions.append(ActionSuggestion(
                action="navigate",
                selector=link.selector,
                reason="检测到敏感页面链接 - 可能包含敏感信息",
                priority=80,
            ))
        
        # 检测登录/注册链接
        if any(kw in combined for kw in self.LOGIN_KEYWORDS + self.REGISTER_KEYWORDS):
            suggestions.append(ActionSuggestion(
                action="navigate",
                selector=link.selector,
                reason="检测到认证相关链接",
                priority=70,
            ))
        
        # 检测 API 端点
        if "/api/" in href_lower or "/v1/" in href_lower or "/v2/" in href_lower:
            suggestions.append(ActionSuggestion(
                action="navigate",
                selector=link.selector,
                reason="检测到 API 端点链接",
                priority=75,
            ))
        
        # 检测可能的 IDOR
        if re.search(r'[?&](id|uid|user_id|pid)=\d+', href_lower):
            suggestions.append(ActionSuggestion(
                action="test_idor",
                selector=link.selector,
                reason="链接包含 ID 参数 - 可能存在 IDOR",
                priority=85,
            ))
        
        return suggestions
    
    def _analyze_button(self, button: ButtonInfo) -> List[ActionSuggestion]:
        """分析按钮，生成操作建议"""
        suggestions = []
        
        text_lower = button.text.lower() if button.text else ""
        
        # 检测删除按钮
        if any(kw in text_lower for kw in ["delete", "remove", "删除"]):
            suggestions.append(ActionSuggestion(
                action="click",
                selector=button.selector,
                reason="检测到删除按钮 - 测试 CSRF 和授权",
                priority=70,
            ))
        
        # 检测提交按钮
        if button.type == "submit" or any(kw in text_lower for kw in ["submit", "send", "提交"]):
            suggestions.append(ActionSuggestion(
                action="click",
                selector=button.selector,
                reason="提交按钮",
                priority=50,
            ))
        
        return suggestions
    
    def _analyze_input(self, inp: InputInfo) -> List[ActionSuggestion]:
        """分析独立输入框，生成操作建议"""
        suggestions = []
        
        name_lower = inp.name.lower() if inp.name else ""
        
        # 检测搜索输入框
        if any(kw in name_lower for kw in self.SEARCH_KEYWORDS):
            suggestions.append(ActionSuggestion(
                action="fill",
                selector=inp.selector,
                value="test",
                reason="搜索输入框 - 测试 XSS/SQLi",
                priority=65,
            ))
        
        return suggestions

    # ==================== suggest_tests ====================
    
    def suggest_tests(self, request: Request) -> List[TestSuggestion]:
        """
        基于参数建议测试类型
        
        分析请求中的参数，映射到可能的漏洞类型。
        
        映射规则:
        - id, uid, user_id -> IDOR, SQLi
        - file, path, filename -> LFI, Path Traversal
        - url, redirect, callback -> SSRF, Open Redirect
        - search, query, q -> SQLi, XSS
        - admin, role, privilege -> Privilege Escalation
        
        Args:
            request: Request 对象
            
        Returns:
            TestSuggestion 列表，按优先级排序
        
        Requirements: 19.2, 19.6
        """
        suggestions = []
        
        # 收集所有参数
        all_params = {}
        
        # URL 参数
        for name, value in request.params.items():
            all_params[name] = ("url", value)
        
        # Body 参数
        for name, value in request.body_params.items():
            all_params[name] = ("body", value)
        
        # 分析每个参数
        for param_name, (location, value) in all_params.items():
            param_suggestions = self._analyze_param_for_tests(param_name, value, location)
            suggestions.extend(param_suggestions)
        
        # 分析请求整体特征
        overall_suggestions = self._analyze_request_overall(request)
        suggestions.extend(overall_suggestions)
        
        # 去重并按优先级排序
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            key = (s.test_type, s.param)
            if key not in seen:
                seen.add(key)
                unique_suggestions.append(s)
        
        unique_suggestions.sort(key=lambda s: s.priority, reverse=True)
        
        return unique_suggestions
    
    def _analyze_param_for_tests(self, name: str, value: str, location: str) -> List[TestSuggestion]:
        """分析单个参数，生成测试建议"""
        suggestions = []
        name_lower = name.lower()
        
        # 遍历参数-漏洞映射
        for category, config in self.PARAM_VULN_MAPPING.items():
            if any(kw in name_lower for kw in config["keywords"]):
                for vuln in config["vulns"]:
                    suggestions.append(TestSuggestion(
                        test_type=vuln,
                        param=name,
                        reason=f"参数名 '{name}' 匹配 {category} 模式",
                        priority=config["priority"],
                        payloads=self._get_sample_payloads(vuln),
                    ))
        
        # 基于值模式的建议
        value_suggestions = self._analyze_value_for_tests(name, value)
        suggestions.extend(value_suggestions)
        
        return suggestions
    
    def _analyze_value_for_tests(self, name: str, value: str) -> List[TestSuggestion]:
        """基于参数值分析测试建议"""
        suggestions = []
        
        if not value:
            return suggestions
        
        # 数字 ID -> IDOR
        if re.match(r'^\d+$', value):
            suggestions.append(TestSuggestion(
                test_type="idor",
                param=name,
                reason=f"参数值 '{value}' 是数字 ID",
                priority=75,
                payloads=[str(int(value) + 1), str(int(value) - 1), "0", "-1"],
            ))
        
        # URL -> SSRF
        if re.match(r'^https?://', value, re.IGNORECASE):
            suggestions.append(TestSuggestion(
                test_type="ssrf",
                param=name,
                reason=f"参数值是 URL",
                priority=85,
                payloads=["http://127.0.0.1", "http://localhost", "http://169.254.169.254"],
            ))
        
        # 文件路径 -> LFI
        if re.match(r'^[./\\]|\.\./', value):
            suggestions.append(TestSuggestion(
                test_type="lfi",
                param=name,
                reason=f"参数值看起来像文件路径",
                priority=90,
                payloads=["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"],
            ))
        
        # Base64 -> 可能的敏感数据
        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) >= 4:
            suggestions.append(TestSuggestion(
                test_type="info_disclosure",
                param=name,
                reason=f"参数值可能是 Base64 编码",
                priority=50,
                payloads=[],
            ))
        
        # JWT -> JWT 攻击
        if re.match(r'^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$', value):
            suggestions.append(TestSuggestion(
                test_type="jwt_attack",
                param=name,
                reason=f"参数值是 JWT",
                priority=80,
                payloads=[],
            ))
        
        return suggestions
    
    def _analyze_request_overall(self, request: Request) -> List[TestSuggestion]:
        """分析请求整体特征"""
        suggestions = []
        
        # JSON 请求 -> Mass Assignment
        if request.is_json:
            suggestions.append(TestSuggestion(
                test_type="mass_assignment",
                param="*",
                reason="JSON 请求 - 测试 Mass Assignment",
                priority=60,
                payloads=[],
            ))
        
        # PUT/DELETE 方法 -> 测试授权
        if request.method in ["PUT", "DELETE", "PATCH"]:
            suggestions.append(TestSuggestion(
                test_type="authorization",
                param="*",
                reason=f"{request.method} 方法 - 测试授权",
                priority=70,
                payloads=[],
            ))
        
        # 包含敏感路径
        path_lower = request.path.lower()
        if any(kw in path_lower for kw in self.ADMIN_KEYWORDS):
            suggestions.append(TestSuggestion(
                test_type="authorization",
                param="*",
                reason="管理员路径 - 测试未授权访问",
                priority=90,
                payloads=[],
            ))
        
        return suggestions
    
    def _get_sample_payloads(self, vuln_type: str) -> List[str]:
        """获取漏洞类型的示例 payload"""
        payloads = {
            "sqli": ["'", "' OR '1'='1", "1' AND '1'='1", "1 UNION SELECT NULL--"],
            "xss": ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "javascript:alert(1)"],
            "idor": ["1", "2", "0", "-1", "admin"],
            "ssrf": ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"],
            "lfi": ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"],
            "path_traversal": ["../", "..\\", "....//", "..%2f"],
            "open_redirect": ["//evil.com", "https://evil.com", "/\\evil.com"],
            "cmdi": ["; id", "| id", "$(id)", "`id`"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
            "privilege_escalation": ["admin", "1", "true", "root"],
            "info_disclosure": ["debug=1", "test=1", "verbose=1"],
            "jsonp_hijacking": ["alert", "callback", "func"],
            "rce": ["; id", "| whoami", "$(whoami)"],
        }
        return payloads.get(vuln_type, [])

    # ==================== analyze_response ====================
    
    def analyze_response(self, response: Response) -> ResponseAnalysis:
        """
        分析响应中的异常、敏感数据、技术提示
        
        检测:
        - 异常: SQL 错误、路径泄露、堆栈跟踪、WAF 拦截
        - 敏感数据: 邮箱、API Key、密码、信用卡号
        - 技术提示: 服务器类型、框架、CMS
        - 安全头: CSP、X-Frame-Options 等
        
        Args:
            response: Response 对象
            
        Returns:
            ResponseAnalysis 对象
        
        Requirements: 19.3
        """
        analysis = ResponseAnalysis()
        
        # 1. 检测异常
        analysis.anomalies = self._detect_anomalies(response)
        
        # 2. 检测敏感数据
        analysis.sensitive_data = self._detect_sensitive_data(response)
        
        # 3. 检测技术提示
        analysis.tech_hints = self._detect_tech_hints(response)
        
        # 4. 分析安全头
        analysis.security_headers = self._analyze_security_headers(response)
        
        # 5. 计算风险等级
        analysis.risk_level = self._calculate_risk_level(analysis)
        
        # 6. 生成建议
        analysis.recommendations = self._generate_recommendations(analysis)
        
        return analysis
    
    def _detect_anomalies(self, response: Response) -> List[str]:
        """检测响应异常"""
        anomalies = []
        
        if not response.body:
            return anomalies
        
        body_lower = response.body.lower()
        
        # SQL 错误
        sql_patterns = [
            ("mysql", "MySQL 错误"),
            ("postgresql", "PostgreSQL 错误"),
            ("ora-", "Oracle 错误"),
            ("sqlite", "SQLite 错误"),
            ("sql syntax", "SQL 语法错误"),
            ("unclosed quotation", "SQL 引号未闭合"),
            ("you have an error in your sql", "SQL 错误"),
            ("warning: mysql", "MySQL 警告"),
            ("microsoft sql server", "MSSQL 错误"),
            ("odbc sql server driver", "ODBC SQL 错误"),
        ]
        for pattern, desc in sql_patterns:
            if pattern in body_lower:
                anomalies.append(f"sql_error: {desc}")
                break
        
        # 路径泄露
        path_patterns = [
            ("/var/www", "Linux Web 路径"),
            ("c:\\", "Windows 路径"),
            ("/home/", "Linux Home 路径"),
            ("\\inetpub", "IIS 路径"),
            ("/usr/", "Linux 系统路径"),
            ("\\windows\\", "Windows 系统路径"),
        ]
        for pattern, desc in path_patterns:
            if pattern in body_lower:
                anomalies.append(f"path_disclosure: {desc}")
                break
        
        # 堆栈跟踪
        stack_patterns = [
            ("traceback", "Python Traceback"),
            ("stack trace", "堆栈跟踪"),
            ("exception", "异常信息"),
            ("at line", "行号信息"),
            ("error in", "错误位置"),
            ("fatal error", "致命错误"),
        ]
        for pattern, desc in stack_patterns:
            if pattern in body_lower:
                anomalies.append(f"stack_trace: {desc}")
                break
        
        # WAF/防火墙拦截
        if response.status == 403:
            anomalies.append("blocked: HTTP 403 Forbidden")
        if any(kw in body_lower for kw in ["blocked", "forbidden", "access denied", "waf", "firewall"]):
            anomalies.append("blocked: 可能被 WAF 拦截")
        
        # 调试信息
        if any(kw in body_lower for kw in ["debug", "phpinfo", "server configuration"]):
            anomalies.append("debug_info: 调试信息泄露")
        
        return anomalies
    
    def _detect_sensitive_data(self, response: Response) -> List[Dict]:
        """检测敏感数据"""
        sensitive = []
        
        if not response.body:
            return sensitive
        
        # 邮箱
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.body)
        if emails:
            sensitive.append({
                "type": "email",
                "count": len(emails),
                "samples": emails[:3],
            })
        
        # API Key 模式
        api_keys = re.findall(
            r'(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})["\']?',
            response.body, re.IGNORECASE
        )
        if api_keys:
            sensitive.append({
                "type": "api_key",
                "count": len(api_keys),
                "samples": [f"{k[0]}={k[1][:8]}..." for k in api_keys[:3]],
            })
        
        # 密码字段
        passwords = re.findall(
            r'(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'<>]{4,})["\']?',
            response.body, re.IGNORECASE
        )
        if passwords:
            sensitive.append({
                "type": "password",
                "count": len(passwords),
                "samples": [f"{p[0]}=***" for p in passwords[:3]],
            })
        
        # 信用卡号 (简单模式)
        cc_numbers = re.findall(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', response.body)
        if cc_numbers:
            sensitive.append({
                "type": "credit_card",
                "count": len(cc_numbers),
                "samples": [f"{cc[:4]}****{cc[-4:]}" for cc in cc_numbers[:3]],
            })
        
        # 私钥
        if "-----BEGIN" in response.body and "PRIVATE KEY" in response.body:
            sensitive.append({
                "type": "private_key",
                "count": 1,
                "samples": ["Private Key Found"],
            })
        
        # AWS 凭证
        aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', response.body)
        if aws_keys:
            sensitive.append({
                "type": "aws_key",
                "count": len(aws_keys),
                "samples": [f"{k[:8]}..." for k in aws_keys[:3]],
            })
        
        return sensitive
    
    def _detect_tech_hints(self, response: Response) -> List[Dict]:
        """检测技术栈提示"""
        hints = []
        
        # 从 Header 检测
        headers_str = json.dumps(response.headers).lower()
        body_lower = response.body.lower() if response.body else ""
        combined = f"{headers_str} {body_lower}"
        
        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    # 尝试提取版本
                    version = self._extract_version(tech, combined)
                    hints.append({
                        "technology": tech,
                        "version": version,
                        "confidence": "high" if pattern in headers_str else "medium",
                    })
                    break
        
        # 从 Server header 检测
        server = response.headers.get("Server", "")
        if server:
            hints.append({
                "technology": "Server",
                "version": server,
                "confidence": "high",
            })
        
        # 从 X-Powered-By 检测
        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            hints.append({
                "technology": "X-Powered-By",
                "version": powered_by,
                "confidence": "high",
            })
        
        return hints
    
    def _extract_version(self, tech: str, text: str) -> Optional[str]:
        """尝试提取版本号"""
        patterns = {
            "Apache": r'Apache/(\d+\.\d+(?:\.\d+)?)',
            "Nginx": r'nginx/(\d+\.\d+(?:\.\d+)?)',
            "IIS": r'IIS/(\d+\.\d+)',
            "PHP": r'PHP/(\d+\.\d+(?:\.\d+)?)',
        }
        
        if tech in patterns:
            match = re.search(patterns[tech], text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _analyze_security_headers(self, response: Response) -> Dict[str, Any]:
        """分析安全头"""
        result = {
            "present": [],
            "missing": [],
            "issues": [],
        }
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        for header in self.SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in headers_lower:
                result["present"].append({
                    "header": header,
                    "value": headers_lower[header_lower],
                })
                
                # 检查具体问题
                value = headers_lower[header_lower]
                if header == "X-Frame-Options" and value.lower() not in ["deny", "sameorigin"]:
                    result["issues"].append(f"{header} 配置不安全: {value}")
                if header == "X-XSS-Protection" and value == "0":
                    result["issues"].append(f"{header} 已禁用")
            else:
                result["missing"].append(header)
        
        return result
    
    def _calculate_risk_level(self, analysis: ResponseAnalysis) -> str:
        """计算风险等级"""
        score = 0
        
        # 异常加分
        for anomaly in analysis.anomalies:
            if "sql_error" in anomaly:
                score += 40
            elif "path_disclosure" in anomaly:
                score += 20
            elif "stack_trace" in anomaly:
                score += 25
            elif "debug_info" in anomaly:
                score += 30
        
        # 敏感数据加分
        for data in analysis.sensitive_data:
            if data["type"] == "private_key":
                score += 50
            elif data["type"] == "aws_key":
                score += 45
            elif data["type"] == "password":
                score += 40
            elif data["type"] == "api_key":
                score += 35
            elif data["type"] == "credit_card":
                score += 45
            elif data["type"] == "email":
                score += 10
        
        # 缺失安全头加分
        missing_count = len(analysis.security_headers.get("missing", []))
        score += missing_count * 5
        
        # 安全头问题加分
        issues_count = len(analysis.security_headers.get("issues", []))
        score += issues_count * 10
        
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        return "low"
    
    def _generate_recommendations(self, analysis: ResponseAnalysis) -> List[str]:
        """生成建议"""
        recommendations = []
        
        # 基于异常的建议
        for anomaly in analysis.anomalies:
            if "sql_error" in anomaly:
                recommendations.append("🔥 发现 SQL 错误 - 立即测试 SQL 注入")
            elif "path_disclosure" in anomaly:
                recommendations.append("💡 发现路径泄露 - 可用于 LFI/路径遍历攻击")
            elif "stack_trace" in anomaly:
                recommendations.append("💡 发现堆栈跟踪 - 分析技术栈和潜在漏洞")
            elif "debug_info" in anomaly:
                recommendations.append("💡 发现调试信息 - 可能泄露敏感配置")
        
        # 基于敏感数据的建议
        for data in analysis.sensitive_data:
            if data["type"] == "private_key":
                recommendations.append("🚨 发现私钥泄露 - 严重安全问题!")
            elif data["type"] == "aws_key":
                recommendations.append("🚨 发现 AWS 凭证泄露 - 严重安全问题!")
            elif data["type"] == "password":
                recommendations.append("⚠️ 发现密码泄露 - 检查是否可利用")
            elif data["type"] == "api_key":
                recommendations.append("⚠️ 发现 API Key 泄露 - 测试是否有效")
        
        # 基于缺失安全头的建议
        missing = analysis.security_headers.get("missing", [])
        if "Content-Security-Policy" in missing:
            recommendations.append("💡 缺少 CSP - 可能存在 XSS 风险")
        if "X-Frame-Options" in missing:
            recommendations.append("💡 缺少 X-Frame-Options - 可能存在点击劫持风险")
        
        return recommendations

    # ==================== prioritize_requests ====================
    
    def prioritize_requests(self, requests: List[Request]) -> List[PrioritizedRequest]:
        """
        按测试优先级排序请求
        
        优先级因素:
        - 参数敏感度 (id, file, url, admin 等)
        - 请求方法 (PUT, DELETE 优先)
        - 路径敏感度 (admin, api 等)
        - 响应异常
        
        Args:
            requests: Request 列表
            
        Returns:
            PrioritizedRequest 列表，按优先级排序
        
        Requirements: 19.4
        """
        prioritized = []
        
        for request in requests:
            priority, reasons, suggested_tests = self._calculate_request_priority(request)
            
            prioritized.append(PrioritizedRequest(
                request=request,
                priority=priority,
                reasons=reasons,
                suggested_tests=suggested_tests,
            ))
        
        # 按优先级排序
        prioritized.sort(key=lambda p: p.priority, reverse=True)
        
        return prioritized
    
    def _calculate_request_priority(self, request: Request) -> Tuple[int, List[str], List[str]]:
        """计算单个请求的优先级"""
        priority = 0
        reasons = []
        suggested_tests = []
        
        # 1. 分析参数
        all_params = list(request.params.keys()) + list(request.body_params.keys())
        
        for param in all_params:
            param_lower = param.lower()
            
            for category, config in self.PARAM_VULN_MAPPING.items():
                if any(kw in param_lower for kw in config["keywords"]):
                    priority += config["priority"] // 2
                    reasons.append(f"参数 '{param}' 匹配 {category}")
                    suggested_tests.extend(config["vulns"])
                    break
        
        # 2. 分析请求方法
        if request.method in ["PUT", "DELETE", "PATCH"]:
            priority += 30
            reasons.append(f"{request.method} 方法 - 测试授权")
            suggested_tests.append("authorization")
        
        # 3. 分析路径
        path_lower = request.path.lower()
        
        if any(kw in path_lower for kw in self.ADMIN_KEYWORDS):
            priority += 40
            reasons.append("管理员路径")
            suggested_tests.append("authorization")
        
        if "/api/" in path_lower or "/v1/" in path_lower or "/v2/" in path_lower:
            priority += 20
            reasons.append("API 端点")
        
        if any(kw in path_lower for kw in self.SENSITIVE_KEYWORDS):
            priority += 25
            reasons.append("敏感路径")
        
        # 4. 分析响应 (如果有)
        if request.response:
            response = request.response
            
            # 检测异常
            response.detect_anomalies()
            if response.anomalies:
                priority += 30
                reasons.append(f"响应异常: {', '.join(response.anomalies[:2])}")
            
            # 错误响应
            if response.is_error:
                priority += 10
                reasons.append(f"错误响应: {response.status}")
        
        # 5. JSON 请求
        if request.is_json:
            priority += 15
            reasons.append("JSON 请求")
            suggested_tests.append("mass_assignment")
        
        # 限制最大优先级
        priority = min(priority, 100)
        
        # 去重
        suggested_tests = list(set(suggested_tests))
        
        return priority, reasons, suggested_tests
    
    # ==================== 辅助方法 ====================
    
    def to_dict(self) -> Dict:
        """转为字典"""
        return {
            "class": "AIHelper",
            "description": "AI 决策辅助模块",
            "methods": [
                "suggest_actions(view) - 基于页面结构建议操作",
                "suggest_tests(request) - 基于参数建议测试类型",
                "analyze_response(response) - 分析响应",
                "prioritize_requests(requests) - 按优先级排序请求",
            ],
        }
    
    def __repr__(self) -> str:
        return "AIHelper()"
