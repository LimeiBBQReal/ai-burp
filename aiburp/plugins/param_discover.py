"""
参数发现器 - 深度挖掘攻击面

核心功能:
1. JS 资产挖掘 - 提取 API 端点、密钥、敏感信息
2. HTTP 头参数分析 - 发现隐藏参数、调试头
3. 表单/链接提取 - 传统参数发现
4. 响应头分析 - 发现后端信息

灵感来源: katana, paramspider, LinkFinder
"""

import re
import requests
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class Endpoint:
    """发现的端点"""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    source: str = ""  # js, form, link, header
    confidence: str = "high"  # high, medium, low


@dataclass 
class JSSecret:
    """JS 中发现的敏感信息"""
    type: str  # api_key, token, password, aws, etc
    value: str
    context: str  # 上下文
    file: str  # 来源文件


@dataclass
class HeaderInfo:
    """HTTP 头信息"""
    name: str
    value: str
    category: str  # debug, security, backend, custom
    risk: str  # high, medium, low, info


@dataclass
class DiscoverResult:
    """发现结果"""
    url: str
    endpoints: List[Endpoint] = field(default_factory=list)
    js_secrets: List[JSSecret] = field(default_factory=list)
    headers: List[HeaderInfo] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    params_found: Set[str] = field(default_factory=set)
    # 新增
    graphql_endpoints: List[Dict] = field(default_factory=list)  # GraphQL 端点
    websocket_urls: List[str] = field(default_factory=list)  # WebSocket URL
    source_maps: List[Dict] = field(default_factory=list)  # Source Map 信息
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "endpoints": [{"url": e.url, "method": e.method, "params": e.params, "source": e.source} for e in self.endpoints],
            "js_secrets": [{"type": s.type, "value": s.value[:50] + "...", "file": s.file} for s in self.js_secrets],
            "headers": [{"name": h.name, "value": h.value, "category": h.category, "risk": h.risk} for h in self.headers],
            "js_files": self.js_files,
            "params_found": list(self.params_found),
            "graphql_endpoints": self.graphql_endpoints,
            "websocket_urls": self.websocket_urls,
            "source_maps": self.source_maps,
        }


class ParamDiscoverer:
    """参数发现器"""
    
    # JS 中的 API 端点模式
    JS_ENDPOINT_PATTERNS = [
        # REST API
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v[0-9]+/[^"\']+)["\']',
        r'["\'](/graphql[^"\']*)["\']',
        # 相对路径
        r'(?:url|path|endpoint|api)\s*[=:]\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\$\.(get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
        # 完整 URL
        r'https?://[^"\'`\s<>]+',
    ]
    
    # JS 中的敏感信息模式
    JS_SECRET_PATTERNS = {
        "api_key": [
            r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([^"\']{16,})["\']',
            r'["\']?apikey["\']?\s*[=:]\s*["\']([^"\']{16,})["\']',
        ],
        "token": [
            r'["\']?(?:access[_-]?)?token["\']?\s*[=:]\s*["\']([^"\']{20,})["\']',
            r'["\']?bearer["\']?\s*[=:]\s*["\']([^"\']{20,})["\']',
            r'["\']?jwt["\']?\s*[=:]\s*["\']([^"\']{20,})["\']',
        ],
        "aws": [
            r'AKIA[0-9A-Z]{16}',
            r'["\']?aws[_-]?(?:access[_-]?key|secret)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
        ],
        "password": [
            r'["\']?(?:password|passwd|pwd)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
        ],
        "private_key": [
            r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        ],
        "google_api": [
            r'AIza[0-9A-Za-z_-]{35}',
        ],
        "firebase": [
            r'["\']?(?:firebase|firebaseio)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
        ],
        "stripe": [
            r'sk_live_[0-9a-zA-Z]{24}',
            r'pk_live_[0-9a-zA-Z]{24}',
        ],
        "internal_ip": [
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        ],
        "internal_url": [
            r'https?://(?:localhost|127\.0\.0\.1|internal|intranet|dev[.-]|staging[.-])[^"\'`\s]*',
        ],
    }
    
    # 误报过滤 - UI 文本关键词 (这些不是真正的敏感信息泄露)
    FALSE_POSITIVE_KEYWORDS = [
        # 密码相关 UI 文本
        'forgot password', 'reset password', 'change password', 'new password',
        'confirm password', 'enter password', 'your password', 'password?',
        'mot de passe', 'contraseña', 'passwort',  # 多语言
        'show password', 'hide password', 'password strength',
        'use face', 'fingerprint', 'device password', 'or device',
        # Token 相关 UI 文本
        'token expired', 'invalid token', 'refresh token',
        # 通用 UI
        'please enter', 'please fill', 'this field', 'required field',
        'text', 'type=', 'input', 'placeholder', 'veuillez',
        # 单独的字段名
        'password...', 'PASSWORD',
    ]
    
    # 无效 URL 模式 (XML namespace、测试 URL 等)
    INVALID_URL_PATTERNS = [
        r'^https?://www\.w3\.org/',           # W3C namespace
        r'^https?://[a-z]$',                   # 单字母域名 (http://a)
        r'^https?://[a-z]/',                   # 单字母域名带路径
        r'^https?://example\.com',             # 示例域名
        r'^https?://test\.com',
        r'^https?://localhost:\d+$',           # 纯 localhost 无路径
        r'^https?://127\.0\.0\.1:\d+$',
        r'^\$\{',                              # 模板变量
        r'^https?://\$',
        r'^\+',                                # 字符串拼接
        r'^["\']',                             # 引号开头
        r'\.svg$',                             # SVG 文件
        r'\.png$', r'\.jpg$', r'\.gif$',       # 图片
        r'\.woff', r'\.ttf$',                  # 字体
        r'^clip-path$', r'^rect\(',            # CSS
        r'^responseURL$',                      # JS 变量名
        r'^mailto:', r'^tel:',                 # 非 HTTP
    ]
    
    # 有价值的 HTTP 响应头
    INTERESTING_HEADERS = {
        # 调试/开发头 (高风险)
        "X-Debug": ("debug", "high"),
        "X-Debug-Token": ("debug", "high"),
        "X-Debug-Token-Link": ("debug", "high"),
        "X-Powered-By": ("backend", "medium"),
        "X-AspNet-Version": ("backend", "medium"),
        "X-AspNetMvc-Version": ("backend", "medium"),
        "X-Runtime": ("backend", "low"),
        "X-Version": ("backend", "medium"),
        "X-Build": ("backend", "low"),
        # 后端信息
        "Server": ("backend", "info"),
        "X-Served-By": ("backend", "info"),
        "X-Backend-Server": ("backend", "medium"),
        "X-Upstream": ("backend", "medium"),
        "Via": ("backend", "info"),
        # 安全相关
        "X-Frame-Options": ("security", "info"),
        "X-XSS-Protection": ("security", "info"),
        "X-Content-Type-Options": ("security", "info"),
        "Content-Security-Policy": ("security", "info"),
        "Strict-Transport-Security": ("security", "info"),
        # 缓存/CDN
        "X-Cache": ("cdn", "info"),
        "X-Cache-Hit": ("cdn", "info"),
        "CF-RAY": ("cdn", "info"),
        "X-Amz-Cf-Id": ("cdn", "info"),
        # 自定义头 (可能泄露信息)
        "X-Request-Id": ("custom", "low"),
        "X-Correlation-Id": ("custom", "low"),
        "X-Trace-Id": ("custom", "low"),
    }
    
    # 隐藏参数候选 (用于参数爆破)
    HIDDEN_PARAMS = [
        # 调试参数
        "debug", "test", "dev", "staging", "verbose", "trace",
        # 认证绕过
        "admin", "is_admin", "isAdmin", "role", "user_role", "auth", "token",
        # IDOR
        "id", "uid", "user_id", "userId", "account", "account_id",
        # 功能开关
        "feature", "flag", "enable", "disable", "mode", "type",
        # 回调/重定向
        "callback", "redirect", "url", "next", "return", "goto", "dest",
        # 文件操作
        "file", "path", "filename", "template", "include", "page",
        # 命令执行
        "cmd", "exec", "command", "run", "query", "search",
        # 其他
        "action", "method", "func", "do", "op", "step",
    ]
    
    def __init__(self, timeout: int = 10, max_js: int = 20):
        self.timeout = timeout
        self.max_js = max_js
        # 编译无效 URL 正则
        self._invalid_url_re = [re.compile(p, re.IGNORECASE) for p in self.INVALID_URL_PATTERNS]
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
    
    def discover(self, url: str, depth: int = 1, analyze_js: bool = True) -> DiscoverResult:
        """
        发现参数和端点
        
        Args:
            url: 目标 URL
            depth: 爬取深度 (1=只分析当前页, 2=跟随链接)
            analyze_js: 是否分析 JS 文件
        """
        result = DiscoverResult(url=url)
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            html = resp.text
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            
            # 1. 分析响应头
            result.headers = self._analyze_headers(resp.headers)
            
            # 2. 提取表单
            result.forms = self._extract_forms(html, base_url)
            for form in result.forms:
                result.endpoints.append(Endpoint(
                    url=form["action"],
                    method=form["method"],
                    params=form["params"],
                    source="form"
                ))
                result.params_found.update(form["params"].keys())
            
            # 3. 提取链接中的参数
            links = self._extract_links(html, base_url)
            for link in links:
                parsed = urlparse(link)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    result.endpoints.append(Endpoint(
                        url=link.split("?")[0],
                        method="GET",
                        params={k: v[0] for k, v in params.items()},
                        source="link"
                    ))
                    result.params_found.update(params.keys())
            
            # 4. 提取并分析 JS 文件
            if analyze_js:
                js_files = self._extract_js_files(html, base_url)
                result.js_files = js_files[:self.max_js]
                
                for js_url in result.js_files:
                    js_result = self._analyze_js(js_url, base_url)
                    result.endpoints.extend(js_result["endpoints"])
                    result.js_secrets.extend(js_result["secrets"])
                    result.params_found.update(js_result["params"])
            
            # 5. 从 HTML 中提取内联 JS
            inline_js = self._extract_inline_js(html)
            for js_code in inline_js:
                js_result = self._analyze_js_code(js_code, url)
                result.endpoints.extend(js_result["endpoints"])
                result.js_secrets.extend(js_result["secrets"])
            
            # 6. 检测 GraphQL 端点
            result.graphql_endpoints = self._detect_graphql(base_url)
            
            # 7. 提取 WebSocket URL
            result.websocket_urls = self._extract_websocket_urls(html, result.js_files)
            
            # 8. 检测 Source Map
            if analyze_js:
                result.source_maps = self._detect_source_maps(result.js_files)
            
        except Exception as e:
            pass
        
        # 去重
        result.endpoints = self._dedupe_endpoints(result.endpoints)
        # 清洗参数 (解码 HTML 实体、去重)
        result.params_found = self._clean_params(result.params_found)
        
        return result
    
    def _clean_params(self, params: set) -> set:
        """清洗参数名 - 解码 HTML 实体、去重"""
        import html
        cleaned = set()
        for p in params:
            # 解码 HTML 实体 (amp; -> &)
            decoded = html.unescape(p)
            # 移除前缀 amp; (有些没被正确解码)
            if decoded.startswith('amp;'):
                decoded = decoded[4:]
            # 移除空白
            decoded = decoded.strip()
            # 过滤无效参数名
            if decoded and len(decoded) > 0 and not decoded.startswith(('(', '{', '[', '<')):
                cleaned.add(decoded)
        return cleaned

    
    def _analyze_headers(self, headers) -> List[HeaderInfo]:
        """分析响应头"""
        result = []
        
        for name, value in headers.items():
            # 检查已知的有价值头
            if name in self.INTERESTING_HEADERS:
                category, risk = self.INTERESTING_HEADERS[name]
                result.append(HeaderInfo(name=name, value=value, category=category, risk=risk))
            # 检查自定义 X- 头
            elif name.startswith("X-") and name not in self.INTERESTING_HEADERS:
                result.append(HeaderInfo(name=name, value=value, category="custom", risk="low"))
        
        return result
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """提取表单"""
        forms = []
        
        # 简单的表单提取
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            action = match.group(1)
            form_html = match.group(2)
            
            # 获取 method
            method_match = re.search(r'method=["\']([^"\']+)["\']', match.group(0), re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # 提取 input 参数
            params = {}
            for input_match in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE):
                name = input_match.group(1)
                # 尝试获取 value
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_match.group(0), re.IGNORECASE)
                value = value_match.group(1) if value_match else ""
                params[name] = value
            
            # textarea
            for ta_match in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE):
                params[ta_match.group(1)] = ""
            
            # select
            for sel_match in re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE):
                params[sel_match.group(1)] = ""
            
            if params:
                full_action = urljoin(base_url, action) if action else base_url
                forms.append({
                    "action": full_action,
                    "method": method,
                    "params": params
                })
        
        return forms
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """提取链接"""
        links = set()
        
        # href 链接
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            if not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                links.add(urljoin(base_url, href))
        
        # src 链接 (非 JS/CSS/图片)
        for match in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            if "?" in src and not any(ext in src.lower() for ext in [".js", ".css", ".png", ".jpg", ".gif", ".svg"]):
                links.add(urljoin(base_url, src))
        
        return list(links)
    
    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """提取 JS 文件 URL"""
        js_files = []
        
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            if not any(cdn in src.lower() for cdn in ["jquery", "bootstrap", "cdn.", "googleapis", "cloudflare"]):
                js_files.append(urljoin(base_url, src))
        
        return js_files
    
    def _extract_inline_js(self, html: str) -> List[str]:
        """提取内联 JS"""
        scripts = []
        for match in re.finditer(r'<script[^>]*>([^<]+)</script>', html, re.IGNORECASE | re.DOTALL):
            content = match.group(1).strip()
            if content and len(content) > 50:  # 忽略太短的
                scripts.append(content)
        return scripts
    
    def _analyze_js(self, js_url: str, base_url: str) -> Dict:
        """分析 JS 文件"""
        result = {"endpoints": [], "secrets": [], "params": set()}
        
        try:
            resp = self.session.get(js_url, timeout=self.timeout)
            if resp.status_code == 200:
                js_code = resp.text
                analysis = self._analyze_js_code(js_code, js_url)
                result["endpoints"] = analysis["endpoints"]
                result["secrets"] = analysis["secrets"]
                
                # 提取参数名
                for ep in analysis["endpoints"]:
                    result["params"].update(ep.params.keys())
        except:
            pass
        
        return result
    
    def _analyze_js_code(self, js_code: str, source: str) -> Dict:
        """分析 JS 代码"""
        result = {"endpoints": [], "secrets": []}
        
        # 1. 提取 API 端点
        for pattern in self.JS_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_code, re.IGNORECASE):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                if endpoint and len(endpoint) > 1:
                    # 过滤无效 URL
                    if self._is_invalid_url(endpoint):
                        continue
                    
                    # 提取 URL 中的参数
                    params = {}
                    if "?" in endpoint:
                        query = endpoint.split("?")[1]
                        for param in query.split("&"):
                            if "=" in param:
                                k, v = param.split("=", 1)
                                params[k] = v
                    
                    result["endpoints"].append(Endpoint(
                        url=endpoint.split("?")[0],
                        method="GET",
                        params=params,
                        source="js",
                        confidence="medium"
                    ))
        
        # 2. 提取敏感信息
        for secret_type, patterns in self.JS_SECRET_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, js_code, re.IGNORECASE):
                    value = match.group(1) if match.lastindex else match.group(0)
                    # 获取上下文
                    start = max(0, match.start() - 30)
                    end = min(len(js_code), match.end() + 30)
                    context = js_code[start:end].replace("\n", " ")
                    
                    # 过滤误报 (UI 文本)
                    if self._is_false_positive(value, context, secret_type):
                        continue
                    
                    result["secrets"].append(JSSecret(
                        type=secret_type,
                        value=value,
                        context=context,
                        file=source
                    ))
        
        return result
    
    def _is_invalid_url(self, url: str) -> bool:
        """检查是否为无效 URL"""
        if not url or len(url) < 5:
            return True
        for pattern in self._invalid_url_re:
            if pattern.search(url):
                return True
        return False
    
    def _is_false_positive(self, value: str, context: str, secret_type: str) -> bool:
        """检查是否为误报"""
        value_lower = value.lower()
        context_lower = context.lower()
        
        # 检查 UI 文本关键词
        for keyword in self.FALSE_POSITIVE_KEYWORDS:
            if keyword in value_lower or keyword in context_lower:
                return True
        
        # password 类型额外检查
        if secret_type == "password":
            # 排除明显的 UI 路径/变量名
            if any(x in value_lower for x in ['forgot', 'reset', 'change', 'login', 'signup', 'create', 'confirm', 'new_', 'old_', 'face', 'fingerprint', 'device']):
                return True
            # 排除纯大写 (通常是常量/标签)
            if value.isupper() and len(value) < 20:
                return True
            # 排除以 ... 结尾 (UI 占位符)
            if value.endswith('...') or value.endswith('..'):
                return True
            # 排除单词 Password/password
            if value_lower in ['password', 'password.', 'passwords']:
                return True
            # 排除太短的值 (可能是字段名)
            if len(value) < 8:
                return True
        
        # token 类型额外检查
        if secret_type == "token":
            # 排除代码片段
            if any(x in value for x in ['.concat', '.push', 'Promise', 'function', '=>', '()', '{}', 'return', 'await', 'async']):
                return True
            # 排除太短的值
            if len(value) < 16:
                return True
        
        return False
    
    def _dedupe_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """端点去重"""
        seen = set()
        unique = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique
    
    def _detect_graphql(self, base_url: str) -> List[Dict]:
        """检测 GraphQL 端点和 introspection"""
        graphql_paths = ['/graphql', '/api/graphql', '/gql', '/query', '/v1/graphql', '/api/v1/graphql']
        introspection_query = '{"query": "{ __schema { queryType { name } types { name } } }"}'
        found = []
        
        for path in graphql_paths:
            url = base_url.rstrip('/') + path
            try:
                # 先尝试 POST
                r = self.session.post(
                    url, 
                    data=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if r.status_code == 200:
                    has_introspection = '__schema' in r.text or 'queryType' in r.text
                    found.append({
                        'url': url,
                        'method': 'POST',
                        'introspection': has_introspection,
                        'status': r.status_code
                    })
                elif r.status_code in [400, 401, 403, 405]:
                    # 端点存在但可能需要认证或禁用了 introspection
                    if 'graphql' in r.text.lower() or 'query' in r.text.lower():
                        found.append({
                            'url': url,
                            'method': 'POST',
                            'introspection': False,
                            'status': r.status_code
                        })
            except:
                pass
        
        return found
    
    def _extract_websocket_urls(self, html: str, js_files: List[str]) -> List[str]:
        """从 HTML 和 JS 中提取 WebSocket URL"""
        ws_urls = set()
        
        # 从 HTML 提取
        ws_matches = re.findall(r'wss?://[^"\'`\s<>]+', html)
        ws_urls.update(ws_matches)
        
        # 从 JS 文件提取
        for js_url in js_files[:5]:  # 只检查前5个 JS
            try:
                r = self.session.get(js_url, timeout=self.timeout)
                if r.status_code == 200:
                    matches = re.findall(r'wss?://[^"\'`\s<>]+', r.text)
                    ws_urls.update(matches)
            except:
                pass
        
        # 过滤无效的
        valid = []
        for url in ws_urls:
            # 排除模板变量
            if '${' not in url and '{' not in url and len(url) > 10:
                valid.append(url)
        
        return list(valid)[:20]  # 最多返回20个
    
    def _detect_source_maps(self, js_files: List[str]) -> List[Dict]:
        """检测 Source Map 泄露"""
        found = []
        
        for js_url in js_files[:10]:  # 只检查前10个
            try:
                r = self.session.get(js_url, timeout=self.timeout)
                if r.status_code != 200:
                    continue
                
                # 检查 sourceMappingURL
                match = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', r.text)
                if match:
                    map_path = match.group(1)
                    
                    # 构建完整 URL
                    if map_path.startswith('http'):
                        map_url = map_path
                    elif map_path.startswith('//'):
                        map_url = 'https:' + map_path
                    elif map_path.startswith('/'):
                        parsed = urlparse(js_url)
                        map_url = f"{parsed.scheme}://{parsed.netloc}{map_path}"
                    else:
                        map_url = js_url.rsplit('/', 1)[0] + '/' + map_path
                    
                    # 检查 map 文件是否可访问
                    try:
                        mr = self.session.head(map_url, timeout=5)
                        accessible = mr.status_code == 200
                    except:
                        accessible = False
                    
                    found.append({
                        'js_file': js_url,
                        'map_url': map_url,
                        'accessible': accessible
                    })
            except:
                pass
        
        return found
    
    def probe_hidden_params(self, url: str, method: str = "GET", 
                           params: List[str] = None, threads: int = 5) -> List[str]:
        """
        探测隐藏参数
        
        通过响应差异检测隐藏参数
        """
        params = params or self.HIDDEN_PARAMS
        found = []
        
        # 获取基线响应
        try:
            if method == "GET":
                baseline = self.session.get(url, timeout=self.timeout)
            else:
                baseline = self.session.post(url, timeout=self.timeout)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except:
            return found
        
        def test_param(param):
            try:
                if method == "GET":
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}=test123"
                    resp = self.session.get(test_url, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data={param: "test123"}, timeout=self.timeout)
                
                # 检测差异
                if resp.status_code != baseline_status:
                    return param
                if abs(len(resp.text) - baseline_len) > 50:
                    return param
                # 检查参数是否在响应中反射
                if "test123" in resp.text:
                    return param
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(test_param, p): p for p in params}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        return found
    
    def report(self, result: DiscoverResult) -> str:
        """生成报告"""
        lines = ["=" * 60, "🔍 参数发现报告", "=" * 60, ""]
        lines.append(f"目标: {result.url}")
        lines.append("")
        
        # JS 敏感信息 (最重要)
        if result.js_secrets:
            lines.append("🔴 JS 敏感信息泄露:")
            for s in result.js_secrets:
                lines.append(f"  [{s.type}] {s.value[:50]}...")
                lines.append(f"    来源: {s.file}")
            lines.append("")
        
        # 有价值的响应头
        high_risk_headers = [h for h in result.headers if h.risk in ["high", "medium"]]
        if high_risk_headers:
            lines.append("🟠 有价值的响应头:")
            for h in high_risk_headers:
                lines.append(f"  [{h.risk}] {h.name}: {h.value}")
            lines.append("")
        
        # API 端点
        js_endpoints = [e for e in result.endpoints if e.source == "js"]
        if js_endpoints:
            lines.append(f"🔵 JS 中发现的 API 端点 ({len(js_endpoints)}):")
            for e in js_endpoints[:20]:
                params_str = f" ?{urlencode(e.params)}" if e.params else ""
                lines.append(f"  [{e.method}] {e.url}{params_str}")
            if len(js_endpoints) > 20:
                lines.append(f"  ... 还有 {len(js_endpoints) - 20} 个")
            lines.append("")
        
        # 表单
        if result.forms:
            lines.append(f"📝 表单 ({len(result.forms)}):")
            for f in result.forms:
                lines.append(f"  [{f['method']}] {f['action']}")
                lines.append(f"    参数: {list(f['params'].keys())}")
            lines.append("")
        
        # 发现的参数汇总
        if result.params_found:
            lines.append(f"📊 发现的参数 ({len(result.params_found)}):")
            lines.append(f"  {', '.join(sorted(result.params_found)[:30])}")
            lines.append("")
        
        # JS 文件
        if result.js_files:
            lines.append(f"📄 JS 文件 ({len(result.js_files)}):")
            for js in result.js_files[:10]:
                lines.append(f"  {js}")
            lines.append("")
        
        # GraphQL 端点
        if result.graphql_endpoints:
            lines.append("🟣 GraphQL 端点:")
            for gql in result.graphql_endpoints:
                intro = "✅ introspection 开启" if gql['introspection'] else "❌ introspection 关闭"
                lines.append(f"  [{gql['method']}] {gql['url']} ({intro})")
            lines.append("")
        
        # WebSocket URL
        if result.websocket_urls:
            lines.append(f"🔌 WebSocket URL ({len(result.websocket_urls)}):")
            for ws in result.websocket_urls[:10]:
                lines.append(f"  {ws}")
            lines.append("")
        
        # Source Map
        if result.source_maps:
            lines.append("🗺️ Source Map:")
            for sm in result.source_maps:
                status = "✅ 可访问" if sm['accessible'] else "❌ 不可访问"
                lines.append(f"  {sm['map_url'][:60]}... ({status})")
            lines.append("")
        
        lines.append("=" * 60)
        return "\n".join(lines)


# CLI 入口
if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("用法: python param_discover.py <url>")
        sys.exit(1)
    
    discoverer = ParamDiscoverer()
    result = discoverer.discover(sys.argv[1])
    print(discoverer.report(result))
