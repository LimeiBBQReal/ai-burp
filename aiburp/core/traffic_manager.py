"""
AIBURP TrafficManager - 流量查询模块

提供便捷的流量查询接口，帮助 AI 筛选请求。

Requirements:
- 4.1: recent(n) - 获取最近 n 条请求
- 4.2: find(**filters) - 查找单个请求
- 4.3: filter(**filters) - 过滤请求
- 4.4: 支持 path (regex), method, host, content_type, tags 过滤
- 4.5: clear() - 清空历史
"""

import re
from typing import Dict, List, Optional, Any

from .models import Request, Response
from .history import History


class TrafficManager:
    """
    流量查询管理器
    
    提供便捷的流量查询接口，帮助 AI 筛选请求。
    
    用法:
        traffic = TrafficManager(history)
        
        # 获取最近请求
        recent = traffic.recent(10)
        
        # 查找单个请求
        req = traffic.find(method="POST", path="/api/login")
        
        # 过滤请求
        requests = traffic.filter(host="example.com", method="GET")
        
        # 清空历史
        traffic.clear()
    """
    
    def __init__(self, history: History):
        """
        初始化 TrafficManager
        
        Args:
            history: History 实例，用于存储和查询请求
        """
        self.history = history
    
    def recent(self, n: int = 10) -> List[Request]:
        """
        获取最近 n 条请求
        
        Args:
            n: 返回的请求数量，默认 10
        
        Returns:
            最近 n 条请求列表，按时间倒序
        
        Requirements: 4.1
        """
        return self.history.list(limit=n)
    
    def find(
        self,
        path: str = None,
        method: str = None,
        host: str = None,
        content_type: str = None,
        tags: List[str] = None,
        status: int = None,
        has_params: bool = None,
    ) -> Optional[Request]:
        """
        查找单个匹配的请求
        
        Args:
            path: 路径匹配 (支持正则表达式)
            method: HTTP 方法 (GET, POST, etc.)
            host: 主机名
            content_type: Content-Type 匹配
            tags: 标签列表
            status: 响应状态码
            has_params: 是否有参数
        
        Returns:
            第一个匹配的请求，如果没有匹配则返回 None
        
        Requirements: 4.2
        """
        results = self.filter(
            path=path,
            method=method,
            host=host,
            content_type=content_type,
            tags=tags,
            status=status,
            has_params=has_params,
            limit=1,
        )
        return results[0] if results else None
    
    def filter(
        self,
        path: str = None,
        method: str = None,
        host: str = None,
        content_type: str = None,
        tags: List[str] = None,
        status: int = None,
        has_params: bool = None,
        limit: int = 100,
    ) -> List[Request]:
        """
        过滤请求
        
        Args:
            path: 路径匹配 (支持正则表达式)
            method: HTTP 方法 (GET, POST, etc.)
            host: 主机名
            content_type: Content-Type 匹配
            tags: 标签列表
            status: 响应状态码
            has_params: 是否有参数
            limit: 返回数量限制
        
        Returns:
            匹配的请求列表
        
        Requirements: 4.3, 4.4
        """
        # 先从 History 获取基本过滤结果
        # History.list 支持 host, method, path, has_params, tags, status
        requests = self.history.list(
            host=host,
            method=method,
            has_params=has_params,
            tags=tags,
            status=status,
            limit=limit * 10,  # 获取更多以便后续过滤
        )
        
        # 应用额外的过滤条件
        filtered = []
        
        for req in requests:
            # 路径正则匹配
            if path is not None:
                try:
                    if not re.search(path, req.path):
                        continue
                except re.error:
                    # 如果正则无效，使用简单包含匹配
                    if path not in req.path:
                        continue
            
            # Content-Type 匹配
            if content_type is not None:
                req_content_type = req.headers.get("Content-Type", "")
                if content_type.lower() not in req_content_type.lower():
                    continue
            
            filtered.append(req)
            
            # 达到限制数量后停止
            if len(filtered) >= limit:
                break
        
        return filtered
    
    def clear(self):
        """
        清空所有历史请求
        
        Requirements: 4.5
        """
        self.history.clear()
    
    # ==================== 便捷方法 ====================
    
    def by_host(self, host: str, limit: int = 100) -> List[Request]:
        """
        按主机名过滤
        
        Args:
            host: 主机名
            limit: 返回数量限制
        
        Returns:
            匹配的请求列表
        """
        return self.filter(host=host, limit=limit)
    
    def by_method(self, method: str, limit: int = 100) -> List[Request]:
        """
        按 HTTP 方法过滤
        
        Args:
            method: HTTP 方法
            limit: 返回数量限制
        
        Returns:
            匹配的请求列表
        """
        return self.filter(method=method, limit=limit)
    
    def by_path(self, path: str, limit: int = 100) -> List[Request]:
        """
        按路径过滤 (支持正则)
        
        Args:
            path: 路径模式 (正则表达式)
            limit: 返回数量限制
        
        Returns:
            匹配的请求列表
        """
        return self.filter(path=path, limit=limit)
    
    def by_content_type(self, content_type: str, limit: int = 100) -> List[Request]:
        """
        按 Content-Type 过滤
        
        Args:
            content_type: Content-Type 匹配字符串
            limit: 返回数量限制
        
        Returns:
            匹配的请求列表
        """
        return self.filter(content_type=content_type, limit=limit)
    
    def by_tags(self, tags: List[str], limit: int = 100) -> List[Request]:
        """
        按标签过滤
        
        Args:
            tags: 标签列表
            limit: 返回数量限制
        
        Returns:
            匹配的请求列表
        """
        return self.filter(tags=tags, limit=limit)
    
    def with_params(self, limit: int = 100) -> List[Request]:
        """
        获取有参数的请求
        
        Args:
            limit: 返回数量限制
        
        Returns:
            有参数的请求列表
        """
        return self.filter(has_params=True, limit=limit)
    
    def without_params(self, limit: int = 100) -> List[Request]:
        """
        获取没有参数的请求
        
        Args:
            limit: 返回数量限制
        
        Returns:
            没有参数的请求列表
        """
        return self.filter(has_params=False, limit=limit)
    
    def json_requests(self, limit: int = 100) -> List[Request]:
        """
        获取 JSON 请求
        
        Args:
            limit: 返回数量限制
        
        Returns:
            Content-Type 包含 json 的请求列表
        """
        return self.filter(content_type="json", limit=limit)
    
    def form_requests(self, limit: int = 100) -> List[Request]:
        """
        获取表单请求
        
        Args:
            limit: 返回数量限制
        
        Returns:
            Content-Type 包含 form 的请求列表
        """
        return self.filter(content_type="form", limit=limit)
    
    def errors(self, limit: int = 100) -> List[Request]:
        """
        获取错误响应的请求 (4xx, 5xx)
        
        Args:
            limit: 返回数量限制
        
        Returns:
            响应状态码 >= 400 的请求列表
        """
        # 获取所有请求，然后过滤错误响应
        all_requests = self.history.list(limit=limit * 10)
        errors = []
        
        for req in all_requests:
            if req.response and req.response.status >= 400:
                errors.append(req)
                if len(errors) >= limit:
                    break
        
        return errors
    
    def successful(self, limit: int = 100) -> List[Request]:
        """
        获取成功响应的请求 (2xx)
        
        Args:
            limit: 返回数量限制
        
        Returns:
            响应状态码 2xx 的请求列表
        """
        # 获取所有请求，然后过滤成功响应
        all_requests = self.history.list(limit=limit * 10)
        successful = []
        
        for req in all_requests:
            if req.response and 200 <= req.response.status < 300:
                successful.append(req)
                if len(successful) >= limit:
                    break
        
        return successful
    
    # ==================== 统计方法 ====================
    
    def count(self, host: str = None) -> int:
        """
        统计请求数量
        
        Args:
            host: 可选的主机名过滤
        
        Returns:
            请求数量
        """
        return self.history.count(host=host)
    
    def hosts(self) -> List[str]:
        """
        获取所有主机名
        
        Returns:
            主机名列表
        """
        return self.history.hosts()
    
    def summary(self) -> Dict:
        """
        获取流量摘要
        
        Returns:
            包含统计信息的字典
        """
        return self.history.summary()
    
    def stats(self) -> Dict:
        """
        获取详细统计
        
        Returns:
            包含详细统计信息的字典
        """
        return self.history.stats()
