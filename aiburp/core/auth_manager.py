"""
认证/会话管理模块

功能:
- Cookie 管理 (自动保存/加载)
- Token 管理 (JWT/Bearer 自动刷新)
- 多账户支持 (测试越权)
- OAuth 流程支持
- 请求自动注入认证信息
"""

import json
import time
import base64
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import requests

from .models import Request


@dataclass
class Account:
    """账户信息"""
    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)  # Authorization 等
    tokens: Dict[str, str] = field(default_factory=dict)  # access_token, refresh_token
    token_expiry: Optional[float] = None  # Unix timestamp
    role: str = ""  # admin, user, guest
    properties: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "cookies": self.cookies,
            "headers": self.headers,
            "tokens": self.tokens,
            "token_expiry": self.token_expiry,
            "role": self.role,
            "properties": self.properties,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "Account":
        return cls(
            name=data.get("name", ""),
            cookies=data.get("cookies", {}),
            headers=data.get("headers", {}),
            tokens=data.get("tokens", {}),
            token_expiry=data.get("token_expiry"),
            role=data.get("role", ""),
            properties=data.get("properties", {}),
        )


class AuthManager:
    """
    认证管理器
    
    用法:
        auth = AuthManager()
        
        # 添加账户
        auth.add_account("admin", cookies={"session": "xxx"})
        auth.add_account("user", headers={"Authorization": "Bearer xxx"})
        
        # 切换账户
        auth.switch("admin")
        
        # 注入认证到请求
        request = auth.inject(request)
        
        # 登录
        auth.login("https://target.com/login", username="test", password="test")
        
        # 保存/加载
        auth.save("auth.json")
        auth.load("auth.json")
    """
    
    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or Path.home() / ".aiburp"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.accounts: Dict[str, Account] = {}
        self.current_account: Optional[str] = None
        
        # Token 刷新回调
        self._refresh_callbacks: Dict[str, Callable] = {}
    
    # ==================== 账户管理 ====================
    
    def add_account(
        self,
        name: str,
        cookies: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        tokens: Dict[str, str] = None,
        role: str = "",
    ) -> Account:
        """
        添加账户
        
        Args:
            name: 账户名
            cookies: Cookie 字典
            headers: 请求头字典 (如 Authorization)
            tokens: Token 字典 (access_token, refresh_token)
            role: 角色 (admin, user, guest)
        
        Returns:
            Account 对象
        """
        account = Account(
            name=name,
            cookies=cookies or {},
            headers=headers or {},
            tokens=tokens or {},
            role=role,
        )
        
        self.accounts[name] = account
        
        # 如果是第一个账户，自动设为当前
        if self.current_account is None:
            self.current_account = name
        
        return account
    
    def remove_account(self, name: str):
        """删除账户"""
        if name in self.accounts:
            del self.accounts[name]
            if self.current_account == name:
                self.current_account = next(iter(self.accounts), None)
    
    def get_account(self, name: str = None) -> Optional[Account]:
        """获取账户"""
        name = name or self.current_account
        return self.accounts.get(name)
    
    def switch(self, name: str) -> bool:
        """切换当前账户"""
        if name in self.accounts:
            self.current_account = name
            return True
        return False
    
    def list_accounts(self) -> List[Dict]:
        """列出所有账户"""
        return [
            {
                "name": acc.name,
                "role": acc.role,
                "has_cookies": bool(acc.cookies),
                "has_tokens": bool(acc.tokens),
                "is_current": acc.name == self.current_account,
            }
            for acc in self.accounts.values()
        ]
    
    # ==================== 认证注入 ====================
    
    def inject(self, request: Request, account_name: str = None) -> Request:
        """
        注入认证信息到请求
        
        Args:
            request: 原始请求
            account_name: 账户名 (默认使用当前账户)
        
        Returns:
            注入后的请求
        """
        account = self.get_account(account_name)
        if not account:
            return request
        
        # 检查 Token 是否过期
        if account.token_expiry and time.time() > account.token_expiry:
            self._try_refresh_token(account)
        
        # 注入 Cookie
        if account.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in account.cookies.items()])
            existing = request.headers.get("Cookie", "")
            if existing:
                request.headers["Cookie"] = f"{existing}; {cookie_str}"
            else:
                request.headers["Cookie"] = cookie_str
        
        # 注入 Headers
        for key, value in account.headers.items():
            request.headers[key] = value
        
        # 注入 Bearer Token
        if "access_token" in account.tokens and "Authorization" not in request.headers:
            request.headers["Authorization"] = f"Bearer {account.tokens['access_token']}"
        
        return request
    
    def inject_for_all(self, request: Request) -> List[Request]:
        """
        为所有账户生成请求 (用于越权测试)
        
        Args:
            request: 原始请求
        
        Returns:
            每个账户的请求列表
        """
        requests = []
        for name in self.accounts:
            req_copy = Request(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                body=request.body,
            )
            req_copy = self.inject(req_copy, name)
            req_copy.notes = f"Account: {name}"
            requests.append(req_copy)
        return requests
    
    # ==================== 登录 ====================
    
    def login(
        self,
        url: str,
        username: str = None,
        password: str = None,
        data: Dict = None,
        method: str = "POST",
        account_name: str = None,
    ) -> bool:
        """
        执行登录
        
        Args:
            url: 登录 URL
            username: 用户名
            password: 密码
            data: 自定义表单数据
            method: 请求方法
            account_name: 保存到的账户名
        
        Returns:
            是否成功
        """
        # 构建登录数据
        if data is None:
            data = {}
            if username:
                data["username"] = username
            if password:
                data["password"] = password
        
        try:
            session = requests.Session()
            
            if method.upper() == "POST":
                resp = session.post(url, data=data, allow_redirects=True, timeout=30)
            else:
                resp = session.get(url, params=data, allow_redirects=True, timeout=30)
            
            # 检查是否成功 (简单判断)
            if resp.status_code in [200, 302]:
                # 提取 Cookie
                cookies = dict(session.cookies)
                
                if cookies:
                    name = account_name or username or "default"
                    self.add_account(name, cookies=cookies)
                    return True
            
            return False
        
        except Exception:
            return False
    
    def login_json(
        self,
        url: str,
        data: Dict,
        token_path: str = "access_token",
        refresh_path: str = "refresh_token",
        account_name: str = None,
    ) -> bool:
        """
        JSON API 登录
        
        Args:
            url: 登录 API URL
            data: JSON 数据
            token_path: access_token 在响应中的路径
            refresh_path: refresh_token 在响应中的路径
            account_name: 账户名
        
        Returns:
            是否成功
        """
        try:
            resp = requests.post(
                url,
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if resp.status_code == 200:
                result = resp.json()
                
                # 提取 Token
                access_token = self._get_nested(result, token_path)
                refresh_token = self._get_nested(result, refresh_path)
                
                if access_token:
                    name = account_name or "default"
                    tokens = {"access_token": access_token}
                    if refresh_token:
                        tokens["refresh_token"] = refresh_token
                    
                    # 解析 JWT 过期时间
                    expiry = self._parse_jwt_expiry(access_token)
                    
                    account = self.add_account(name, tokens=tokens)
                    account.token_expiry = expiry
                    
                    return True
            
            return False
        
        except Exception:
            return False
    
    # ==================== Token 管理 ====================
    
    def set_refresh_callback(self, account_name: str, callback: Callable):
        """设置 Token 刷新回调"""
        self._refresh_callbacks[account_name] = callback
    
    def _try_refresh_token(self, account: Account) -> bool:
        """尝试刷新 Token"""
        # 使用回调
        if account.name in self._refresh_callbacks:
            try:
                new_tokens = self._refresh_callbacks[account.name](account)
                if new_tokens:
                    account.tokens.update(new_tokens)
                    if "access_token" in new_tokens:
                        account.token_expiry = self._parse_jwt_expiry(new_tokens["access_token"])
                    return True
            except:
                pass
        
        # 默认刷新逻辑 (如果有 refresh_token)
        if "refresh_token" in account.tokens:
            # 需要知道刷新 URL，这里跳过
            pass
        
        return False
    
    def _parse_jwt_expiry(self, token: str) -> Optional[float]:
        """解析 JWT 过期时间"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            
            # 解码 payload
            payload = parts[1]
            # 补齐 padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            
            exp = data.get("exp")
            if exp:
                return float(exp)
        except:
            pass
        
        return None
    
    # ==================== Cookie 管理 ====================
    
    def update_cookies(self, account_name: str, cookies: Dict[str, str]):
        """更新 Cookie"""
        account = self.get_account(account_name)
        if account:
            account.cookies.update(cookies)
    
    def clear_cookies(self, account_name: str = None):
        """清除 Cookie"""
        if account_name:
            account = self.get_account(account_name)
            if account:
                account.cookies.clear()
        else:
            for account in self.accounts.values():
                account.cookies.clear()
    
    def extract_cookies_from_response(self, response_headers: Dict, account_name: str = None):
        """从响应头提取 Cookie"""
        account = self.get_account(account_name)
        if not account:
            return
        
        set_cookie = response_headers.get("Set-Cookie", "")
        if not set_cookie:
            return
        
        # 解析 Set-Cookie
        for cookie in set_cookie.split(","):
            parts = cookie.strip().split(";")[0]
            if "=" in parts:
                key, value = parts.split("=", 1)
                account.cookies[key.strip()] = value.strip()
    
    # ==================== 持久化 ====================
    
    def save(self, file_path: str = None):
        """保存到文件"""
        file_path = file_path or str(self.data_dir / "auth.json")
        
        data = {
            "current_account": self.current_account,
            "accounts": {name: acc.to_dict() for name, acc in self.accounts.items()},
        }
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def load(self, file_path: str = None):
        """从文件加载"""
        file_path = file_path or str(self.data_dir / "auth.json")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self.current_account = data.get("current_account")
            self.accounts = {
                name: Account.from_dict(acc_data)
                for name, acc_data in data.get("accounts", {}).items()
            }
        except FileNotFoundError:
            pass
    
    # ==================== 工具方法 ====================
    
    @staticmethod
    def _get_nested(data: Dict, path: str) -> Any:
        """获取嵌套字典值"""
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    def to_json_for_ai(self) -> str:
        """返回 JSON 格式 (给 AI 看)"""
        return json.dumps({
            "current_account": self.current_account,
            "accounts": self.list_accounts(),
        }, indent=2, ensure_ascii=False)
