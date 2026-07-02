"""
AIBURP Proxy - MITM 代理模块

基于 mitmproxy 实现，所有流量自动记录到 History

核心功能:
- 拦截 HTTP/HTTPS 流量
- 自动记录到 History
- 支持请求/响应修改
- 支持拦截规则
- 支持 WebSocket

使用方式:
    proxy = Proxy(history, port=8080)
    proxy.start()  # 启动代理
    # 配置浏览器代理到 127.0.0.1:8080
    # 所有流量自动记录到 history
    proxy.stop()   # 停止代理
"""

import json
import threading
import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime

from .models import Request, Response
from .history import History


@dataclass
class InterceptRule:
    """拦截规则"""
    name: str
    enabled: bool = True
    
    # 匹配条件 (正则)
    host_pattern: str = ""
    path_pattern: str = ""
    method: str = ""  # GET, POST, etc.
    content_type: str = ""
    
    # 动作
    action: str = "record"  # record, drop, modify, intercept
    
    # 修改规则 (action=modify 时)
    modify_request: Optional[Callable] = None
    modify_response: Optional[Callable] = None
    
    # 标签
    tags: List[str] = field(default_factory=list)
    
    def matches(self, request: Request) -> bool:
        """检查请求是否匹配规则"""
        if not self.enabled:
            return False
        
        if self.host_pattern:
            if not re.search(self.host_pattern, request.host, re.I):
                return False
        
        if self.path_pattern:
            if not re.search(self.path_pattern, request.path, re.I):
                return False
        
        if self.method:
            if request.method.upper() != self.method.upper():
                return False
        
        if self.content_type:
            if self.content_type.lower() not in request.content_type.lower():
                return False
        
        return True


@dataclass
class ProxyConfig:
    """代理配置"""
    host: str = "127.0.0.1"
    port: int = 8080
    
    # SSL
    ssl_insecure: bool = True  # 忽略证书错误
    
    # 过滤
    include_hosts: List[str] = field(default_factory=list)  # 只记录这些 host
    exclude_hosts: List[str] = field(default_factory=list)  # 排除这些 host
    exclude_extensions: List[str] = field(default_factory=lambda: [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", 
        ".woff", ".woff2", ".ttf", ".eot", ".svg", ".mp4", ".webp"
    ])
    
    # 记录
    record_request_body: bool = True
    record_response_body: bool = True
    max_body_size: int = 1024 * 1024  # 1MB
    
    # 默认标签
    default_tags: List[str] = field(default_factory=lambda: ["proxy"])


class Proxy:
    """
    MITM 代理
    
    所有流量自动记录到 History + TrafficJournal，供 AI 分析
    
    使用示例:
        history = History(project="target")
        proxy = Proxy(history)
        
        # 添加拦截规则
        proxy.add_rule(InterceptRule(
            name="api_only",
            path_pattern=r"/api/",
            tags=["api"]
        ))
        
        # 启动
        proxy.start()
        
        # 查看流量
        requests = history.list(tags=["proxy"])
    """
    
    def __init__(self, history: History, config: Optional[ProxyConfig] = None,
                 journal: Optional['TrafficJournal'] = None):
        self.history = history
        self.config = config or ProxyConfig()
        self.rules: List[InterceptRule] = []
        self.journal = journal  # V4 TrafficJournal (可选)
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._server = None
        
        # 统计
        self.stats = {
            "requests": 0,
            "recorded": 0,
            "dropped": 0,
            "modified": 0,
            "errors": 0,
            "start_time": None,
        }
        
        # 回调
        self._on_request: Optional[Callable] = None
        self._on_response: Optional[Callable] = None
        
        # 拦截队列 (用于手动拦截)
        self._intercept_queue: List[Dict] = []
    
    # ==================== 规则管理 ====================
    
    def add_rule(self, rule: InterceptRule):
        """添加拦截规则"""
        self.rules.append(rule)
    
    def remove_rule(self, name: str):
        """移除规则"""
        self.rules = [r for r in self.rules if r.name != name]
    
    def clear_rules(self):
        """清空规则"""
        self.rules = []
    
    def enable_rule(self, name: str):
        """启用规则"""
        for rule in self.rules:
            if rule.name == name:
                rule.enabled = True
    
    def disable_rule(self, name: str):
        """禁用规则"""
        for rule in self.rules:
            if rule.name == name:
                rule.enabled = False
    
    # ==================== 回调设置 ====================
    
    def on_request(self, callback: Callable[[Request], Optional[Request]]):
        """
        设置请求回调
        
        callback 返回:
        - Request: 修改后的请求
        - None: 不修改
        """
        self._on_request = callback
    
    def on_response(self, callback: Callable[[Request, Response], Optional[Response]]):
        """
        设置响应回调
        
        callback 返回:
        - Response: 修改后的响应
        - None: 不修改
        """
        self._on_response = callback
    
    # ==================== 核心逻辑 ====================
    
    def _should_record(self, request: Request) -> bool:
        """判断是否应该记录"""
        # 检查 host 过滤
        if self.config.include_hosts:
            if not any(h in request.host for h in self.config.include_hosts):
                return False
        
        if self.config.exclude_hosts:
            if any(h in request.host for h in self.config.exclude_hosts):
                return False
        
        # 检查扩展名过滤
        path_lower = request.path.lower()
        for ext in self.config.exclude_extensions:
            if path_lower.endswith(ext):
                return False
        
        return True
    
    def _get_matching_rules(self, request: Request) -> List[InterceptRule]:
        """获取匹配的规则"""
        return [r for r in self.rules if r.matches(request)]
    
    def _process_request(self, request: Request) -> Optional[Request]:
        """
        处理请求
        
        返回:
        - Request: 处理后的请求 (可能被修改)
        - None: 丢弃请求
        """
        self.stats["requests"] += 1
        
        # 检查是否应该记录
        if not self._should_record(request):
            return request
        
        # 获取匹配规则
        matching_rules = self._get_matching_rules(request)
        
        # 收集标签
        tags = list(self.config.default_tags)
        for rule in matching_rules:
            tags.extend(rule.tags)
        request.tags = list(set(tags))
        
        # 处理规则动作
        for rule in matching_rules:
            if rule.action == "drop":
                self.stats["dropped"] += 1
                return None
            
            elif rule.action == "modify" and rule.modify_request:
                request = rule.modify_request(request)
                self.stats["modified"] += 1
            
            elif rule.action == "intercept":
                # 加入拦截队列，等待手动处理
                self._intercept_queue.append({
                    "type": "request",
                    "request": request,
                    "rule": rule.name,
                    "timestamp": datetime.now().isoformat(),
                })
        
        # 调用用户回调
        if self._on_request:
            result = self._on_request(request)
            if result:
                request = result
        
        return request
    
    def _process_response(self, request: Request, response: Response) -> Response:
        """处理响应"""
        # 获取匹配规则
        matching_rules = self._get_matching_rules(request)
        
        # 处理规则动作
        for rule in matching_rules:
            if rule.action == "modify" and rule.modify_response:
                response = rule.modify_response(response)
        
        # 调用用户回调
        if self._on_response:
            result = self._on_response(request, response)
            if result:
                response = result
        
        # 记录到 History
        if self._should_record(request):
            request.response = response
            self.history.add(request)
            self.stats["recorded"] += 1
            
            # 同时记录到 TrafficJournal (V4)
            if self.journal is not None:
                self._record_to_journal(request, response)
        
        return response
    
    def _record_to_journal(self, request: Request, response: Response):
        """记录请求/响应到 TrafficJournal."""
        if not self.journal:
            return
        
        try:
            # 延迟导入避免循环依赖
            from ..traffic.traffic_journal import TrafficJournal as TJ
            if not isinstance(self.journal, TJ):
                return
            
            # 构建请求摘要
            body_snippet = (request.body[:500] if request.body else "")
            resp_body = (response.body[:2000] if hasattr(response, 'body') and response.body else "")
            body_snippet = (request.body[:500] if request.body else "")
            resp_body = (response.body[:2000] if hasattr(response, 'body') and response.body else "")
            
            entry = self.journal.record_http(
                method=request.method,
                url=request.url,
                status=response.status if hasattr(response, 'status') else 0,
                length=len(resp_body) if resp_body else 0,
                body=resp_body[:500] if resp_body else "",
                headers=dict(response.headers) if hasattr(response, 'headers') else {},
                source="proxy",
                elapsed_ms=response.time_ms if hasattr(response, 'time_ms') else 0,
            )
            
            # 敏感数据检测 → journal finding
            if resp_body:
                sensitive = self._detect_sensitive(resp_body, request.url)
                for s in sensitive:
                    self.journal.record_finding(
                        vuln_type=s["type"],
                        target=request.url,
                        evidence=s["evidence"][:200],
                        severity=s["severity"],
                        source="proxy_sensor",
                    )
        except Exception:
            pass
    
    @staticmethod
    def _detect_sensitive(body: str, url: str) -> List[Dict]:
        """检测响应中的敏感数据."""
        findings = []
        body_lower = body.lower()
        
        # JWT token
        jwt_matches = re.findall(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', body)
        for jwt in jwt_matches[:3]:
            findings.append({
                "type": "jwt-token",
                "evidence": jwt[:80],
                "severity": "high",
            })
        
        # AWS Key
        aws_matches = re.findall(r'AKIA[A-Z0-9]{16}', body)
        for aws in aws_matches[:3]:
            findings.append({
                "type": "aws-key",
                "evidence": aws[:20],
                "severity": "critical",
            })
        
        # 密码泄露
        if re.search(r'(password|passwd|pwd)\s*[:=]\s*["\']?[^"\'\s]+', body_lower):
            findings.append({
                "type": "credential-leak",
                "evidence": "password field in response body",
                "severity": "high",
            })
        
        # 内网 IP
        internal_ips = re.findall(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', body)
        if internal_ips:
            findings.append({
                "type": "internal-ip",
                "evidence": internal_ips[0],
                "severity": "medium",
            })
        
        # 堆栈跟踪
        if re.search(r'(Stack Trace|at\s+\w+\.\w+|File\s+\".*?\.php\".*?line\s+\d+)', body):
            findings.append({
                "type": "stack-trace",
                "evidence": "stack trace detected in response",
                "severity": "medium",
            })
        
        return findings
    
    # ==================== 启动/停止 ====================
    
    def start(self, blocking: bool = False):
        """
        启动代理
        
        Args:
            blocking: 是否阻塞当前线程
        """
        if self._running:
            return {"success": False, "error": "Proxy already running"}
        
        self._running = True
        self.stats["start_time"] = datetime.now().isoformat()
        
        if blocking:
            self._run_proxy()
        else:
            self._thread = threading.Thread(target=self._run_proxy, daemon=True)
            self._thread.start()
            time.sleep(0.5)  # 等待启动
        
        return {
            "success": True,
            "host": self.config.host,
            "port": self.config.port,
            "message": f"Proxy started on {self.config.host}:{self.config.port}"
        }
    
    def stop(self):
        """停止代理"""
        self._running = False
        
        if self._server:
            try:
                self._server.shutdown()
            except:
                pass
        
        if self._thread:
            self._thread.join(timeout=2)
        
        return {
            "success": True,
            "stats": self.get_stats(),
            "message": "Proxy stopped"
        }
    
    def _run_proxy(self):
        """运行代理服务器"""
        try:
            # 尝试使用 mitmproxy
            self._run_mitmproxy()
        except ImportError:
            # 回退到简单 HTTP 代理
            self._run_simple_proxy()
    
    def _run_mitmproxy(self):
        """使用 mitmproxy 运行"""
        from mitmproxy import options
        from mitmproxy.tools import dump
        from mitmproxy import http
        
        class Addon:
            def __init__(self, proxy: 'Proxy'):
                self.proxy = proxy
            
            def request(self, flow: http.HTTPFlow):
                # 转换为 Request
                req = Request(
                    method=flow.request.method,
                    url=flow.request.pretty_url,
                    headers=dict(flow.request.headers),
                    body=flow.request.get_text() or "",
                )
                
                # 处理请求
                result = self.proxy._process_request(req)
                
                if result is None:
                    # 丢弃请求
                    flow.kill()
                elif result != req:
                    # 修改请求
                    flow.request.method = result.method
                    flow.request.url = result.url
                    flow.request.headers = result.headers
                    if result.body:
                        flow.request.set_text(result.body)
                
                # 保存原始请求用于响应处理
                flow.metadata["aiburp_request"] = result
            
            def response(self, flow: http.HTTPFlow):
                req = flow.metadata.get("aiburp_request")
                if not req:
                    return
                
                # 转换为 Response
                resp = Response(
                    status=flow.response.status_code,
                    headers=dict(flow.response.headers),
                    body=flow.response.get_text() or "",
                    time_ms=(flow.response.timestamp_end - flow.request.timestamp_start) * 1000,
                )
                
                # 处理响应
                result = self.proxy._process_response(req, resp)
                
                if result != resp:
                    # 修改响应
                    flow.response.status_code = result.status
                    flow.response.headers = result.headers
                    if result.body:
                        flow.response.set_text(result.body)
        
        opts = options.Options(
            listen_host=self.config.host,
            listen_port=self.config.port,
            ssl_insecure=self.config.ssl_insecure,
        )
        
        master = dump.DumpMaster(opts)
        master.addons.add(Addon(self))
        
        self._server = master
        
        try:
            master.run()
        except KeyboardInterrupt:
            pass
        finally:
            master.shutdown()
    
    def _run_simple_proxy(self):
        """简单 HTTP 代理 (不支持 HTTPS)"""
        import socket
        import select
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.config.host, self.config.port))
        server.listen(100)
        server.settimeout(1)
        
        self._server = server
        
        while self._running:
            try:
                client, addr = server.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                self.stats["errors"] += 1
        
        server.close()
    
    def _handle_client(self, client: 'socket.socket'):
        """处理客户端连接"""
        import socket
        
        try:
            # 接收请求
            data = b""
            while True:
                chunk = client.recv(4096)
                data += chunk
                if len(chunk) < 4096:
                    break
            
            if not data:
                return
            
            raw = data.decode('utf-8', errors='ignore')
            
            # 解析请求
            lines = raw.split('\r\n')
            first_line = lines[0]
            parts = first_line.split(' ')
            
            if len(parts) < 2:
                return
            
            method = parts[0]
            url = parts[1]
            
            # CONNECT 方法 (HTTPS)
            if method == 'CONNECT':
                client.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                # 简单代理不支持 HTTPS 解密
                return
            
            # 解析 headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line:
                    body_start = i + 1
                    break
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            
            body = '\r\n'.join(lines[body_start:]) if body_start else ''
            
            # 创建 Request
            req = Request(
                method=method,
                url=url,
                headers=headers,
                body=body,
            )
            
            # 处理请求
            result = self._process_request(req)
            if result is None:
                client.close()
                return
            
            # 转发请求
            from urllib.parse import urlparse
            parsed = urlparse(result.url)
            host = parsed.netloc
            port = 80
            if ':' in host:
                host, port = host.split(':')
                port = int(port)
            
            # 连接目标服务器
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.connect((host, port))
            
            # 发送请求
            target.send(result.to_raw().encode())
            
            # 接收响应
            response_data = b""
            start_time = time.time()
            while True:
                chunk = target.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            end_time = time.time()
            
            target.close()
            
            # 解析响应
            resp_raw = response_data.decode('utf-8', errors='ignore')
            resp_lines = resp_raw.split('\r\n')
            
            status = 0
            if resp_lines:
                status_parts = resp_lines[0].split(' ')
                if len(status_parts) >= 2:
                    try:
                        status = int(status_parts[1])
                    except:
                        pass
            
            resp_headers = {}
            resp_body_start = 0
            for i, line in enumerate(resp_lines[1:], 1):
                if not line:
                    resp_body_start = i + 1
                    break
                if ':' in line:
                    k, v = line.split(':', 1)
                    resp_headers[k.strip()] = v.strip()
            
            resp_body = '\r\n'.join(resp_lines[resp_body_start:]) if resp_body_start else ''
            
            resp = Response(
                status=status,
                headers=resp_headers,
                body=resp_body,
                time_ms=(end_time - start_time) * 1000,
            )
            
            # 处理响应
            self._process_response(result, resp)
            
            # 返回给客户端
            client.send(response_data)
            
        except Exception as e:
            self.stats["errors"] += 1
        finally:
            try:
                client.close()
            except:
                pass
    
    # ==================== 状态查询 ====================
    
    def is_running(self) -> bool:
        """是否运行中"""
        return self._running
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            "running": self._running,
            "host": self.config.host,
            "port": self.config.port,
            **self.stats,
        }
    
    def get_intercept_queue(self) -> List[Dict]:
        """获取拦截队列"""
        return list(self._intercept_queue)
    
    def release_intercepted(self, index: int, modified: Optional[Request] = None):
        """释放拦截的请求"""
        if 0 <= index < len(self._intercept_queue):
            item = self._intercept_queue.pop(index)
            # TODO: 实现请求释放逻辑
            return {"success": True, "released": item}
        return {"success": False, "error": "Invalid index"}
    
    def drop_intercepted(self, index: int):
        """丢弃拦截的请求"""
        if 0 <= index < len(self._intercept_queue):
            item = self._intercept_queue.pop(index)
            return {"success": True, "dropped": item}
        return {"success": False, "error": "Invalid index"}
    
    # ==================== 便捷方法 ====================
    
    def scope(self, hosts: List[str]):
        """
        设置作用域 (只记录这些 host)
        
        proxy.scope(["target.com", "api.target.com"])
        """
        self.config.include_hosts = hosts
        return self
    
    def exclude(self, hosts: List[str]):
        """
        排除 host
        
        proxy.exclude(["google.com", "facebook.com"])
        """
        self.config.exclude_hosts.extend(hosts)
        return self
    
    def to_dict(self) -> Dict:
        """转为字典 (给 AI 看)"""
        return {
            "running": self._running,
            "config": {
                "host": self.config.host,
                "port": self.config.port,
                "include_hosts": self.config.include_hosts,
                "exclude_hosts": self.config.exclude_hosts,
            },
            "rules": [
                {
                    "name": r.name,
                    "enabled": r.enabled,
                    "host_pattern": r.host_pattern,
                    "path_pattern": r.path_pattern,
                    "action": r.action,
                    "tags": r.tags,
                }
                for r in self.rules
            ],
            "stats": self.get_stats(),
            "intercept_queue_size": len(self._intercept_queue),
        }
    
    def to_json(self) -> str:
        """转为 JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


# ==================== 便捷函数 ====================

def create_proxy(history: History, port: int = 8080, **kwargs) -> Proxy:
    """
    创建代理
    
    proxy = create_proxy(history, port=8080)
    proxy.scope(["target.com"])
    proxy.start()
    """
    config = ProxyConfig(port=port, **kwargs)
    return Proxy(history, config)
