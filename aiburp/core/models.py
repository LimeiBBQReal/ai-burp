"""
AIBURP 数据模型

所有数据结构都设计为 JSON 友好，方便 AI 解析
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode


@dataclass
class Request:
    """
    HTTP 请求
    
    设计原则：
    - 完整保存原始数据
    - 提供便捷的参数访问
    - JSON 序列化友好
    """
    
    # 基本信息
    method: str = "GET"
    url: str = ""
    
    # 头和体
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    
    # 元数据
    id: Optional[int] = None
    timestamp: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    # 关联的响应
    response: Optional['Response'] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    # ==================== 属性访问 ====================
    
    @property
    def host(self) -> str:
        """提取 host"""
        parsed = urlparse(self.url)
        return parsed.netloc or self.headers.get("Host", "")
    
    @property
    def path(self) -> str:
        """提取路径"""
        parsed = urlparse(self.url)
        return parsed.path or "/"
    
    @property
    def query_string(self) -> str:
        """提取查询字符串"""
        parsed = urlparse(self.url)
        return parsed.query
    
    @property
    def params(self) -> Dict[str, str]:
        """
        提取 URL 参数
        返回 {name: value}，多值只取第一个
        """
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        return {k: v[0] if v else "" for k, v in qs.items()}
    
    @property
    def param_names(self) -> List[str]:
        """参数名列表"""
        return list(self.params.keys())
    
    @property
    def body_params(self) -> Dict[str, Any]:
        """
        解析 body 参数
        支持 form-urlencoded 和 JSON
        """
        if not self.body:
            return {}
        
        content_type = self.headers.get("Content-Type", "").lower()
        
        # JSON
        if "json" in content_type:
            try:
                data = json.loads(self.body)
                if isinstance(data, dict):
                    return data
            except:
                pass
        
        # Form
        if "form" in content_type or "=" in self.body:
            try:
                qs = parse_qs(self.body)
                return {k: v[0] if v else "" for k, v in qs.items()}
            except:
                pass
        
        return {}
    
    @property
    def json_body(self) -> Optional[Dict]:
        """
        JSON Body (仅当 Content-Type 为 JSON 时)
        """
        if not self.body:
            return None
        
        content_type = self.headers.get("Content-Type", "").lower()
        if "json" in content_type:
            try:
                data = json.loads(self.body)
                if isinstance(data, dict):
                    return data
            except:
                pass
        return None
    
    @property
    def all_params(self) -> Dict[str, Any]:
        """所有参数（URL + Body）"""
        result = dict(self.params)
        result.update(self.body_params)
        return result
    
    @property
    def all_param_names(self) -> List[str]:
        """所有参数名"""
        return list(self.all_params.keys())
    
    @property
    def cookies(self) -> Dict[str, str]:
        """解析 Cookie"""
        cookie_str = self.headers.get("Cookie", "")
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies
    
    @property
    def content_type(self) -> str:
        """Content-Type"""
        return self.headers.get("Content-Type", "")
    
    @property
    def is_json(self) -> bool:
        """是否是 JSON 请求"""
        return "json" in self.content_type.lower()
    
    @property
    def is_form(self) -> bool:
        """是否是表单请求"""
        return "form" in self.content_type.lower()
    
    @property
    def fingerprint(self) -> str:
        """
        请求指纹（用于去重）
        基于 method + host + path + 参数名
        """
        parts = [
            self.method,
            self.host,
            self.path,
            ",".join(sorted(self.all_param_names)),
        ]
        return hashlib.md5("|".join(parts).encode()).hexdigest()[:16]
    
    # ==================== 修改方法 ====================
    
    def with_param(self, name: str, value: str) -> 'Request':
        """
        返回修改了参数的新请求
        不修改原请求
        """
        new_req = Request(
            method=self.method,
            url=self.url,
            headers=dict(self.headers),
            body=self.body,
            id=self.id,
            timestamp=self.timestamp,
            tags=list(self.tags),
            notes=self.notes,
        )
        
        # URL 参数
        if name in self.params:
            parsed = urlparse(self.url)
            qs = parse_qs(parsed.query)
            qs[name] = [value]
            new_query = urlencode(qs, doseq=True)
            new_req.url = parsed._replace(query=new_query).geturl()
        
        # Body 参数
        elif name in self.body_params:
            if self.is_json:
                data = json.loads(self.body)
                data[name] = value
                new_req.body = json.dumps(data)
            else:
                qs = parse_qs(self.body)
                qs[name] = [value]
                new_req.body = urlencode(qs, doseq=True)
        
        return new_req
    
    def with_header(self, name: str, value: str) -> 'Request':
        """返回修改了 header 的新请求"""
        new_req = Request(
            method=self.method,
            url=self.url,
            headers=dict(self.headers),
            body=self.body,
            id=self.id,
            timestamp=self.timestamp,
            tags=list(self.tags),
            notes=self.notes,
        )
        new_req.headers[name] = value
        return new_req
    
    # ==================== 序列化 ====================
    
    def to_dict(self) -> Dict:
        """转为字典（给 AI 看）"""
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "params": self.params,
            "body_params": self.body_params,
            "headers": self.headers,
            "body": self.body,
            "cookies": self.cookies,
            "content_type": self.content_type,
            "timestamp": self.timestamp,
            "tags": self.tags,
            "notes": self.notes,
            "response": self.response.to_dict() if self.response else None,
        }
    
    def to_json(self) -> str:
        """转为 JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    def to_raw(self) -> str:
        """转为原始 HTTP 格式"""
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        
        lines = [f"{self.method} {path} HTTP/1.1"]
        
        # 确保有 Host
        headers = dict(self.headers)
        if "Host" not in headers:
            headers["Host"] = self.host
        
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        
        lines.append("")
        if self.body:
            lines.append(self.body)
        
        return "\r\n".join(lines)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Request':
        """从字典创建"""
        resp_data = data.pop("response", None)
        # 移除计算属性
        for key in ["host", "path", "params", "body_params", "cookies", "content_type"]:
            data.pop(key, None)
        
        req = cls(**data)
        if resp_data:
            req.response = Response.from_dict(resp_data)
        return req
    
    @classmethod
    def from_raw(cls, raw: str, base_url: str = "") -> 'Request':
        """从原始 HTTP 格式解析"""
        lines = raw.replace("\r\n", "\n").split("\n")
        
        # 请求行
        first_line = lines[0]
        parts = first_line.split(" ")
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "/"
        
        # 头
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        
        # Body
        body = "\n".join(lines[body_start:]) if body_start else ""
        
        # URL
        host = headers.get("Host", "")
        if base_url:
            url = base_url.rstrip("/") + path
        elif host:
            url = f"https://{host}{path}"
        else:
            url = path
        
        return cls(method=method, url=url, headers=headers, body=body)
    
    def __str__(self) -> str:
        return f"[{self.method}] {self.url}"


@dataclass
class Response:
    """
    HTTP 响应
    """
    
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    time_ms: float = 0
    
    # 工具检测到的异常（辅助 AI，不做决策）
    anomalies: List[str] = field(default_factory=list)
    
    @property
    def length(self) -> int:
        """响应长度"""
        return len(self.body.encode('utf-8', errors='ignore'))
    
    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")
    
    @property
    def is_json(self) -> bool:
        return "json" in self.content_type.lower()
    
    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower()
    
    @property
    def is_redirect(self) -> bool:
        return self.status in [301, 302, 303, 307, 308]
    
    @property
    def is_error(self) -> bool:
        return self.status >= 400
    
    @property
    def is_server_error(self) -> bool:
        return self.status >= 500
    
    def detect_anomalies(self) -> List[str]:
        """
        检测响应异常
        
        检测类型:
        - SQL 错误
        - 路径泄露
        - 堆栈跟踪
        - WAF 拦截
        - 敏感信息泄露
        
        Returns:
            检测到的异常列表
        """
        import re
        
        # 清空之前的异常
        self.anomalies = []
        
        body_lower = self.body.lower()
        
        # SQL 错误
        sql_patterns = [
            ("mysql", "mysql_error"),
            ("postgresql", "postgresql_error"),
            ("ora-", "oracle_error"),
            ("sqlite", "sqlite_error"),
            ("sql syntax", "sql_error"),
            ("unclosed quotation", "sql_error"),
            ("you have an error in your sql", "sql_error"),
            ("warning: mysql", "mysql_error"),
            ("microsoft sql server", "mssql_error"),
            ("odbc sql server driver", "mssql_error"),
        ]
        for pattern, anomaly in sql_patterns:
            if pattern in body_lower:
                if anomaly not in self.anomalies:
                    self.anomalies.append(anomaly)
        
        # 路径泄露
        path_patterns = ["/var/www", "c:\\", "/home/", "\\inetpub", "/usr/", "\\windows\\"]
        if any(p in body_lower for p in path_patterns):
            self.anomalies.append("path_disclosure")
        
        # 堆栈跟踪
        stack_patterns = ["traceback", "stack trace", "exception", "at line", "error in"]
        if any(p in body_lower for p in stack_patterns):
            self.anomalies.append("stack_trace")
        
        # WAF 拦截
        if self.status == 403 or "blocked" in body_lower or "forbidden" in body_lower:
            self.anomalies.append("blocked")
        
        # 敏感信息 - 邮箱
        if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", self.body):
            self.anomalies.append("email_disclosure")
        
        # 敏感信息 - API Key 模式
        if re.search(r"(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}", self.body, re.IGNORECASE):
            self.anomalies.append("api_key_disclosure")
        
        # 敏感信息 - 密码字段
        if re.search(r"(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]+", self.body, re.IGNORECASE):
            self.anomalies.append("password_disclosure")
        
        return self.anomalies
    
    def to_dict(self) -> Dict:
        return {
            "status": self.status,
            "length": self.length,
            "time_ms": self.time_ms,
            "headers": self.headers,
            "body": self.body,
            "content_type": self.content_type,
            "anomalies": self.anomalies,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Response':
        # 移除计算属性
        for key in ["length", "content_type"]:
            data.pop(key, None)
        return cls(**data)
    
    def __str__(self) -> str:
        anomaly_str = f" [{','.join(self.anomalies)}]" if self.anomalies else ""
        return f"[{self.status}] {self.length}b {self.time_ms:.0f}ms{anomaly_str}"


@dataclass
class Finding:
    """
    漏洞发现
    """
    
    id: str = ""
    type: str = ""  # sqli, xss, ssrf, etc.
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: str = "possible"  # confirmed, likely, possible
    
    title: str = ""
    description: str = ""
    
    # 影响范围
    url: str = ""
    method: str = ""
    param: str = ""
    
    # 证据
    payload: str = ""
    request: str = ""  # 原始请求
    response: str = ""  # 原始响应
    evidence: str = ""  # 关键证据（如错误信息）
    
    # 建议
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # 时间线
    timeline: List[Dict] = field(default_factory=list)
    
    # 元数据
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.id:
            self.id = f"VULN-{hashlib.md5(f'{self.url}{self.param}{self.type}'.encode()).hexdigest()[:8].upper()}"
    
    def add_timeline(self, action: str):
        """添加时间线记录"""
        self.timeline.append({
            "time": datetime.now().isoformat(),
            "action": action,
        })
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Finding':
        return cls(**data)
    
    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.type}: {self.title}"


# ============================================================
# PageView 及相关数据模型 (v2)
# ============================================================

@dataclass
class InputInfo:
    """输入框信息"""
    name: str = ""
    type: str = "text"
    selector: str = ""
    value: Optional[str] = None
    placeholder: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "type": self.type,
            "selector": self.selector,
            "value": self.value,
            "placeholder": self.placeholder,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class ButtonInfo:
    """按钮信息"""
    text: str = ""
    selector: str = ""
    type: str = "button"  # button, submit, reset
    
    def to_dict(self) -> Dict:
        return {
            "text": self.text,
            "selector": self.selector,
            "type": self.type,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class LinkInfo:
    """链接信息"""
    text: str = ""
    href: str = ""
    selector: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "text": self.text,
            "href": self.href,
            "selector": self.selector,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class FormInfo:
    """表单信息"""
    action: str = ""
    method: str = "GET"
    selector: str = ""
    inputs: List[InputInfo] = field(default_factory=list)
    submit_button: Optional[ButtonInfo] = None
    
    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "method": self.method,
            "selector": self.selector,
            "inputs": [i.to_dict() for i in self.inputs],
            "submit_button": self.submit_button.to_dict() if self.submit_button else None,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class PageView:
    """
    页面视图 (AI 友好)
    
    包含截图和简化 DOM，供 AI 分析页面结构
    """
    screenshot: str = ""  # base64 PNG
    title: str = ""
    url: str = ""
    forms: List[FormInfo] = field(default_factory=list)
    links: List[LinkInfo] = field(default_factory=list)
    buttons: List[ButtonInfo] = field(default_factory=list)
    inputs: List[InputInfo] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "screenshot": self.screenshot[:100] + "..." if len(self.screenshot) > 100 else self.screenshot,
            "title": self.title,
            "url": self.url,
            "forms": [f.to_dict() for f in self.forms],
            "links": [l.to_dict() for l in self.links],
            "buttons": [b.to_dict() for b in self.buttons],
            "inputs": [i.to_dict() for i in self.inputs],
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @property
    def all_selectors(self) -> List[str]:
        """获取所有元素的选择器"""
        selectors = []
        for form in self.forms:
            selectors.append(form.selector)
            for inp in form.inputs:
                selectors.append(inp.selector)
            if form.submit_button:
                selectors.append(form.submit_button.selector)
        for link in self.links:
            selectors.append(link.selector)
        for button in self.buttons:
            selectors.append(button.selector)
        for inp in self.inputs:
            selectors.append(inp.selector)
        return [s for s in selectors if s]  # 过滤空选择器
    
    def __str__(self) -> str:
        return f"PageView({self.title}, {len(self.forms)} forms, {len(self.links)} links, {len(self.buttons)} buttons)"
