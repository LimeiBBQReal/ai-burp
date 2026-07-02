"""
流量深度分析插件

从拦截的流量中提取:
1. JS 文件中的 API 端点、参数名
2. HTML 中的隐藏表单字段、data-* 属性
3. JSON 响应中的键名
4. Cookie 中的参数
5. 注释中的敏感信息
6. 硬编码的 URL、路径

所有发现的资产自动加入待测试队列
"""

import re
import json
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin

from aiburp.plugins import AuxPlugin, PluginResult
from aiburp.core.history import History
from aiburp.core.models import Request


@dataclass
class ExtractedAsset:
    """提取的资产"""
    type: str  # endpoint, param, secret, comment
    value: str
    source: str  # js, html, json, cookie, header
    context: str = ""  # 上下文信息
    confidence: str = "medium"  # high, medium, low
    
    def __hash__(self):
        return hash((self.type, self.value, self.source))
    
    def __eq__(self, other):
        return self.type == other.type and self.value == other.value


@dataclass
class TrafficAnalysisResult:
    """流量分析结果"""
    # API 端点
    endpoints: List[Dict] = field(default_factory=list)
    
    # 参数 (来自各种来源)
    params_from_js: Set[str] = field(default_factory=set)
    params_from_html: Set[str] = field(default_factory=set)
    params_from_json: Set[str] = field(default_factory=set)
    params_from_url: Set[str] = field(default_factory=set)
    
    # 隐藏表单字段
    hidden_fields: List[Dict] = field(default_factory=list)
    
    # 敏感信息
    secrets: List[Dict] = field(default_factory=list)
    
    # 注释
    comments: List[str] = field(default_factory=list)
    
    # JS 文件
    js_files: List[str] = field(default_factory=list)
    
    @property
    def all_params(self) -> Set[str]:
        """所有参数"""
        return (self.params_from_js | self.params_from_html | 
                self.params_from_json | self.params_from_url)
    
    def to_dict(self) -> Dict:
        return {
            "endpoints": self.endpoints,
            "params": {
                "from_js": list(self.params_from_js),
                "from_html": list(self.params_from_html),
                "from_json": list(self.params_from_json),
                "from_url": list(self.params_from_url),
                "all": list(self.all_params),
            },
            "hidden_fields": self.hidden_fields,
            "secrets": self.secrets,
            "comments": self.comments[:20],  # 限制数量
            "js_files": self.js_files,
        }


class TrafficAnalyzer:
    """
    流量深度分析器
    
    从 History 中的流量提取所有可能的攻击面
    """
    
    # API 路径模式
    API_PATTERNS = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\'](/graphql[^"\']*)["\']',
        r'["\'](/ajax/[^"\']+)["\']',
        r'["\'](/ws/[^"\']+)["\']',
        r'["\']([^"\']*\.json)["\']',
        r'["\']([^"\']*\.xml)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\$\.(get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\s*\([^,]+,\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'path\s*[:=]\s*["\']([^"\']+)["\']',
        r'href\s*[:=]\s*["\']([^"\']+\.php[^"\']*)["\']',
        r'action\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    # 参数名模式 (JS)
    JS_PARAM_PATTERNS = [
        # 常见参数名
        r'["\'](\w*id)["\']',
        r'["\'](\w*Id)["\']',
        r'["\'](\w*ID)["\']',
        r'["\'](user\w*)["\']',
        r'["\'](pass\w*)["\']',
        r'["\'](token\w*)["\']',
        r'["\'](key\w*)["\']',
        r'["\'](secret\w*)["\']',
        r'["\'](api\w*)["\']',
        r'["\'](auth\w*)["\']',
        r'["\'](session\w*)["\']',
        r'["\'](cookie\w*)["\']',
        r'["\'](\w*name)["\']',
        r'["\'](\w*email)["\']',
        r'["\'](\w*phone)["\']',
        r'["\'](\w*address)["\']',
        r'["\'](\w*code)["\']',
        r'["\'](\w*type)["\']',
        r'["\'](\w*status)["\']',
        r'["\'](\w*action)["\']',
        r'["\'](\w*cmd)["\']',
        r'["\'](\w*command)["\']',
        r'["\'](\w*exec)["\']',
        r'["\'](\w*file)["\']',
        r'["\'](\w*path)["\']',
        r'["\'](\w*url)["\']',
        r'["\'](\w*redirect)["\']',
        r'["\'](\w*callback)["\']',
        r'["\'](\w*return)["\']',
        r'["\'](\w*next)["\']',
        r'["\'](\w*page)["\']',
        r'["\'](\w*limit)["\']',
        r'["\'](\w*offset)["\']',
        r'["\'](\w*sort)["\']',
        r'["\'](\w*order)["\']',
        r'["\'](\w*filter)["\']',
        r'["\'](\w*search)["\']',
        r'["\'](\w*query)["\']',
        r'["\'](\w*q)["\']',
        r'["\'](\w*data)["\']',
        r'["\'](\w*value)["\']',
        r'["\'](\w*content)["\']',
        r'["\'](\w*message)["\']',
        r'["\'](\w*text)["\']',
        r'["\'](\w*body)["\']',
        r'["\'](\w*payload)["\']',
        r'["\'](\w*input)["\']',
        r'["\'](\w*output)["\']',
        r'["\'](\w*result)["\']',
        r'["\'](\w*response)["\']',
        r'["\'](\w*request)["\']',
        # 对象属性访问
        r'\.(\w+)\s*=',
        r'\[["\']([\w_]+)["\']\]',
        # 函数参数 (分割处理)
        # r'function\s+\w+\s*\(([^)]+)\)',  # 移除，单独处理
    ]
    
    # 函数参数模式 (单独处理，需要分割)
    FUNC_PARAM_PATTERN = r'function\s+\w+\s*\(([^)]+)\)'
    
    # 敏感信息模式
    SECRET_PATTERNS = [
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
        (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'secret_key'),
        (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
        (r'["\']?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'token'),
        (r'["\']?auth["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'auth'),
        (r'Bearer\s+([A-Za-z0-9\-_]+\.?[A-Za-z0-9\-_]*\.?[A-Za-z0-9\-_]*)', 'bearer_token'),
        (r'Basic\s+([A-Za-z0-9+/=]+)', 'basic_auth'),
        (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?', 'aws_key'),
        (r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'aws_secret'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'private_key'),
        (r'ghp_[A-Za-z0-9]{36}', 'github_token'),
        (r'sk-[A-Za-z0-9]{48}', 'openai_key'),
    ]
    
    def __init__(self, history: History = None, base_url: str = ""):
        self.history = history
        self.base_url = base_url
        self.result = TrafficAnalysisResult()
    
    def analyze_all(self) -> TrafficAnalysisResult:
        """分析 History 中的所有流量"""
        if not self.history:
            return self.result
        
        requests = self.history.list(limit=1000)
        
        for req in requests:
            self.analyze_request(req)
        
        return self.result
    
    def analyze_request(self, request: Request):
        """分析单个请求"""
        # 提取 URL 参数
        self._extract_url_params(request.url)
        
        # 提取 Body 参数
        content_type = ""
        if hasattr(request, 'content_type'):
            content_type = request.content_type
        elif hasattr(request, 'headers') and request.headers:
            content_type = request.headers.get('Content-Type', '')
        
        if request.body:
            self._extract_body_params(request.body, content_type)
        
        # 分析响应
        if request.response:
            resp = request.response
            body = ""
            resp_content_type = ""
            
            # 获取响应体 (兼容两种 Response 类型)
            if hasattr(resp, 'body') and resp.body:
                body = resp.body
            
            # 获取 content_type (兼容两种 Response 类型)
            if hasattr(resp, 'content_type'):
                resp_content_type = resp.content_type.lower() if resp.content_type else ""
            elif hasattr(resp, 'headers') and resp.headers:
                resp_content_type = resp.headers.get('Content-Type', '').lower()
            
            if body:
                # 根据 content_type 或 URL 判断类型
                if 'javascript' in resp_content_type or request.url.endswith('.js'):
                    self._analyze_js(body, request.url)
                elif 'html' in resp_content_type or '<html' in body.lower()[:500]:
                    self._analyze_html(body, request.url)
                elif 'json' in resp_content_type or (body.strip().startswith('{') or body.strip().startswith('[')):
                    self._analyze_json(body)
                else:
                    # 未知类型，尝试 HTML 分析 (很多页面没有正确的 content-type)
                    if '<' in body and '>' in body:
                        self._analyze_html(body, request.url)
                
                # 通用分析
                self._extract_secrets(body)
                self._extract_comments(body)
    
    def analyze_response(self, body: str, content_type: str = "", url: str = "") -> TrafficAnalysisResult:
        """分析单个响应体"""
        content_type = content_type.lower()
        
        if 'javascript' in content_type or url.endswith('.js'):
            self._analyze_js(body, url)
        elif 'html' in content_type:
            self._analyze_html(body, url)
        elif 'json' in content_type:
            self._analyze_json(body)
        
        self._extract_secrets(body)
        self._extract_comments(body)
        
        return self.result
    
    def _extract_url_params(self, url: str):
        """从 URL 提取参数"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params.keys():
            self.result.params_from_url.add(param)
    
    def _extract_body_params(self, body: str, content_type: str):
        """从请求体提取参数"""
        content_type = content_type.lower()
        
        if 'json' in content_type:
            try:
                data = json.loads(body)
                self._extract_json_keys(data, self.result.params_from_json)
            except:
                pass
        elif 'form' in content_type or '=' in body:
            params = parse_qs(body)
            for param in params.keys():
                self.result.params_from_url.add(param)
    
    def _analyze_js(self, content: str, source_url: str = ""):
        """分析 JS 内容"""
        # 提取 API 端点
        for pattern in self.API_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[-1]  # 取最后一个分组
                if match and len(match) > 1 and not match.startswith('data:'):
                    # 过滤无效路径
                    if match.startswith('/') or match.startswith('http'):
                        endpoint = {
                            "path": match,
                            "source": source_url or "js",
                            "type": "api",
                        }
                        if endpoint not in self.result.endpoints:
                            self.result.endpoints.append(endpoint)
        
        # 提取参数名
        for pattern in self.JS_PARAM_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str) and len(match) > 1 and len(match) < 30:
                    # 过滤常见的非参数词
                    if match.lower() not in ['function', 'return', 'const', 'let', 'var', 
                                              'true', 'false', 'null', 'undefined', 'this',
                                              'new', 'class', 'export', 'import', 'from',
                                              'if', 'else', 'for', 'while', 'switch', 'case',
                                              'break', 'continue', 'try', 'catch', 'finally',
                                              'throw', 'typeof', 'instanceof', 'delete', 'void',
                                              'document', 'window', 'console', 'alert', 'event']:
                        self.result.params_from_js.add(match)
        
        # 函数参数 (单独处理，需要分割)
        func_matches = re.findall(self.FUNC_PARAM_PATTERN, content, re.IGNORECASE)
        for params_str in func_matches:
            # 分割参数
            params = [p.strip() for p in params_str.split(',')]
            for param in params:
                # 清理参数名 (去掉默认值等)
                param = param.split('=')[0].strip()
                if param and len(param) > 1 and len(param) < 30:
                    if param.lower() not in ['function', 'return', 'const', 'let', 'var']:
                        self.result.params_from_js.add(param)
        
        # 只记录真正的 JS 文件
        if source_url and source_url.endswith('.js') and source_url not in self.result.js_files:
            self.result.js_files.append(source_url)
    
    def _analyze_html(self, content: str, source_url: str = ""):
        """分析 HTML 内容"""
        # 提取表单字段
        form_patterns = [
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
            r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>',
            r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>',
        ]
        
        for pattern in form_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.result.params_from_html.add(match)
        
        # 提取隐藏字段
        hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*>'
        hidden_pattern2 = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\'][^>]*>'
        
        for pattern in [hidden_pattern, hidden_pattern2]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for name, value in matches:
                self.result.hidden_fields.append({
                    "name": name,
                    "value": value,
                    "source": source_url,
                })
        
        # 提取 data-* 属性
        data_pattern = r'data-([a-z0-9\-]+)=["\']([^"\']*)["\']'
        matches = re.findall(data_pattern, content, re.IGNORECASE)
        for name, value in matches:
            self.result.params_from_html.add(name)
            if value and len(value) < 100:
                self.result.params_from_html.add(f"data-{name}")
        
        # 提取内联 JS
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        for script in scripts:
            if script.strip():
                self._analyze_js(script, source_url)
        
        # 提取外部 JS 文件
        js_src_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        js_files = re.findall(js_src_pattern, content, re.IGNORECASE)
        for js_file in js_files:
            if js_file not in self.result.js_files:
                # 转换为绝对 URL
                if self.base_url and not js_file.startswith('http'):
                    js_file = urljoin(self.base_url, js_file)
                self.result.js_files.append(js_file)
        
        # 提取链接中的参数
        href_pattern = r'href=["\']([^"\']*\?[^"\']+)["\']'
        hrefs = re.findall(href_pattern, content, re.IGNORECASE)
        for href in hrefs:
            self._extract_url_params(href)
    
    def _analyze_json(self, content: str):
        """分析 JSON 内容"""
        try:
            data = json.loads(content)
            self._extract_json_keys(data, self.result.params_from_json)
        except:
            pass
    
    def _extract_json_keys(self, data: Any, target: Set[str], prefix: str = ""):
        """递归提取 JSON 键名"""
        if isinstance(data, dict):
            for key, value in data.items():
                target.add(key)
                self._extract_json_keys(value, target, f"{prefix}.{key}" if prefix else key)
        elif isinstance(data, list) and data:
            self._extract_json_keys(data[0], target, prefix)
    
    def _extract_secrets(self, content: str):
        """提取敏感信息"""
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:  # 过滤太短的
                    self.result.secrets.append({
                        "type": secret_type,
                        "value": match[:50] + "..." if len(match) > 50 else match,
                        "full_length": len(match),
                    })
    
    def _extract_comments(self, content: str):
        """提取注释"""
        # HTML 注释
        html_comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        for comment in html_comments:
            comment = comment.strip()
            if comment and len(comment) > 5 and len(comment) < 500:
                self.result.comments.append(f"HTML: {comment[:100]}")
        
        # JS 注释
        js_comments = re.findall(r'//\s*(.+)$', content, re.MULTILINE)
        for comment in js_comments:
            comment = comment.strip()
            if comment and len(comment) > 5 and len(comment) < 200:
                # 过滤常见的无用注释
                if not any(x in comment.lower() for x in ['copyright', 'license', 'eslint', 'jshint']):
                    self.result.comments.append(f"JS: {comment[:100]}")
        
        # 多行 JS 注释
        js_block_comments = re.findall(r'/\*(.*?)\*/', content, re.DOTALL)
        for comment in js_block_comments:
            comment = comment.strip()
            if comment and len(comment) > 10 and len(comment) < 500:
                if not any(x in comment.lower() for x in ['copyright', 'license', '@param', '@return']):
                    self.result.comments.append(f"JS Block: {comment[:100]}")


class TrafficAnalyzerPlugin(AuxPlugin):
    """流量分析插件"""
    
    name = "traffic_analyzer"
    description = "深度分析流量，提取 JS 中的 API、HTML 中的隐藏参数、JSON 键名等"
    
    def __init__(self, history: History = None):
        self.history = history
    
    def execute(self, base_url: str = "", **kwargs) -> PluginResult:
        """
        执行流量分析
        
        Args:
            base_url: 基础 URL (用于解析相对路径)
        
        Returns:
            PluginResult with extracted assets
        """
        try:
            analyzer = TrafficAnalyzer(self.history, base_url)
            result = analyzer.analyze_all()
            
            return PluginResult(
                success=True,
                data=result.to_dict(),
            )
        except Exception as e:
            return PluginResult(success=False, error=str(e))


# 便捷函数
def analyze_traffic(history: History, base_url: str = "") -> TrafficAnalysisResult:
    """分析 History 中的所有流量"""
    analyzer = TrafficAnalyzer(history, base_url)
    return analyzer.analyze_all()


def analyze_response(body: str, content_type: str = "", url: str = "") -> TrafficAnalysisResult:
    """分析单个响应"""
    analyzer = TrafficAnalyzer()
    return analyzer.analyze_response(body, content_type, url)


def extract_js_assets(js_content: str, source_url: str = "") -> TrafficAnalysisResult:
    """从 JS 内容提取资产"""
    analyzer = TrafficAnalyzer()
    analyzer._analyze_js(js_content, source_url)
    return analyzer.result
