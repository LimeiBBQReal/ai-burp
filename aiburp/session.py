"""
AI-Burp 认证会话管理模块 v1.0.0

功能:
1. 保存/加载认证会话 (Cookie/Token/Headers)
2. 自动登录并保存会话
3. 从浏览器/Burp 导入 Cookie
4. 会话有效性检测
5. 多会话管理

用法:
    # CLI
    aiburp auth login https://target.com/login -u admin -p pass --save session1
    aiburp auth import-cookie "PHPSESSID=xxx" --save session2
    aiburp auth list
    aiburp request GET https://target.com/api --session session1
    
    # Python API
    from aiburp.session import SessionManager
    
    sm = SessionManager("project1")
    sm.login("https://target.com/login", "admin", "pass", save_as="session1")
    sm.import_cookie("PHPSESSID=xxx; token=yyy", save_as="session2")
    
    session = sm.load("session1")
    burp = Burp(cookies=session.cookies, headers=session.headers)
"""

import os
import json
import time
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .sync_wrapper import SyncBurp as Burp


@dataclass
class Session:
    """认证会话"""
    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    token: str = ""
    token_type: str = ""  # bearer, basic, custom
    created_at: str = ""
    updated_at: str = ""
    login_url: str = ""
    check_url: str = ""  # 用于验证会话有效性的 URL
    valid: bool = True
    notes: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Session':
        return cls(**data)
    
    def get_auth_header(self) -> Dict[str, str]:
        """获取认证头"""
        headers = dict(self.headers)
        if self.token:
            if self.token_type == "bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            elif self.token_type == "basic":
                headers["Authorization"] = f"Basic {self.token}"
            else:
                headers["Authorization"] = self.token
        return headers
    
    def get_cookie_string(self) -> str:
        """获取 Cookie 字符串"""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


class SessionManager:
    """
    会话管理器
    
    用法:
        sm = SessionManager("project1")
        
        # 登录并保存
        sm.login("https://target.com/login", "admin", "pass", save_as="admin")
        
        # 导入 Cookie
        sm.import_cookie("PHPSESSID=xxx", save_as="session1")
        
        # 加载会话
        session = sm.load("admin")
        
        # 使用会话
        burp = Burp()
        burp.set_session(session)
        burp.get("https://target.com/api/users")
    """
    
    def __init__(self, project: str = "default"):
        self.project = project
        self.sessions_dir = Path.home() / ".aiburp" / project / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.burp = Burp(project=project, delay=0.5)
    
    def _session_path(self, name: str) -> Path:
        """获取会话文件路径"""
        return self.sessions_dir / f"{name}.json"
    
    def save(self, session: Session) -> bool:
        """保存会话"""
        try:
            session.updated_at = datetime.now().isoformat()
            path = self._session_path(session.name)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ 保存会话失败: {e}")
            return False
    
    def load(self, name: str) -> Optional[Session]:
        """加载会话"""
        path = self._session_path(name)
        if not path.exists():
            print(f"❌ 会话不存在: {name}")
            return None
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return Session.from_dict(data)
        except Exception as e:
            print(f"❌ 加载会话失败: {e}")
            return None
    
    def delete(self, name: str) -> bool:
        """删除会话"""
        path = self._session_path(name)
        if path.exists():
            path.unlink()
            return True
        return False
    
    def list_sessions(self) -> List[Session]:
        """列出所有会话"""
        sessions = []
        for path in self.sessions_dir.glob("*.json"):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                sessions.append(Session.from_dict(data))
            except:
                pass
        return sessions
    
    def import_cookie(
        self, 
        cookie_string: str, 
        save_as: str,
        headers: Dict[str, str] = None
    ) -> Session:
        """
        从 Cookie 字符串导入
        
        Args:
            cookie_string: Cookie 字符串 (如 "PHPSESSID=xxx; token=yyy")
            save_as: 保存名称
            headers: 额外的 HTTP 头
        
        Returns:
            Session 对象
        """
        cookies = {}
        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                cookies[key.strip()] = value.strip()
        
        session = Session(
            name=save_as,
            cookies=cookies,
            headers=headers or {},
            notes="Imported from cookie string"
        )
        
        self.save(session)
        print(f"✅ 已导入 {len(cookies)} 个 Cookie，保存为: {save_as}")
        return session
    
    def import_from_burp(self, file_path: str, save_as: str) -> Optional[Session]:
        """
        从 Burp Suite 导出的 Cookie 文件导入
        
        支持格式:
        - Netscape Cookie 格式
        - JSON 格式
        """
        path = Path(file_path)
        if not path.exists():
            print(f"❌ 文件不存在: {file_path}")
            return None
        
        cookies = {}
        content = path.read_text(encoding='utf-8')
        
        # 尝试 JSON 格式
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if "name" in item and "value" in item:
                        cookies[item["name"]] = item["value"]
            elif isinstance(data, dict):
                cookies = data
        except json.JSONDecodeError:
            # Netscape Cookie 格式
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split("\t")
                    if len(parts) >= 7:
                        cookies[parts[5]] = parts[6]
        
        if not cookies:
            print("❌ 未能解析任何 Cookie")
            return None
        
        session = Session(
            name=save_as,
            cookies=cookies,
            notes=f"Imported from {file_path}"
        )
        
        self.save(session)
        print(f"✅ 已导入 {len(cookies)} 个 Cookie，保存为: {save_as}")
        return session
    
    def import_token(
        self, 
        token: str, 
        save_as: str,
        token_type: str = "bearer"
    ) -> Session:
        """
        导入 Token
        
        Args:
            token: Token 值
            save_as: 保存名称
            token_type: Token 类型 (bearer/basic/custom)
        """
        session = Session(
            name=save_as,
            token=token,
            token_type=token_type,
            notes=f"Imported {token_type} token"
        )
        
        self.save(session)
        print(f"✅ 已导入 {token_type} Token，保存为: {save_as}")
        return session
    
    def login(
        self,
        login_url: str,
        username: str,
        password: str,
        save_as: str,
        username_field: str = None,
        password_field: str = None,
        extra_data: Dict[str, str] = None,
        check_url: str = None,
        success_indicator: str = None,
        failure_indicator: str = None
    ) -> Optional[Session]:
        """
        自动登录并保存会话
        
        Args:
            login_url: 登录页面 URL
            username: 用户名
            password: 密码
            save_as: 保存名称
            username_field: 用户名字段名 (自动检测)
            password_field: 密码字段名 (自动检测)
            extra_data: 额外的表单数据
            check_url: 验证登录成功的 URL
            success_indicator: 登录成功的标志字符串
            failure_indicator: 登录失败的标志字符串
        
        Returns:
            Session 对象，失败返回 None
        """
        print(f"🔐 尝试登录: {login_url}")
        
        # 1. 获取登录页面，检测表单字段
        r = self.burp.get(login_url)
        if not r.ok:
            print(f"❌ 无法访问登录页面: {r.error}")
            return None
        
        # 自动检测表单字段
        if not username_field or not password_field:
            detected = self._detect_login_fields(r.body)
            username_field = username_field or detected.get("username", "username")
            password_field = password_field or detected.get("password", "password")
            print(f"📝 检测到字段: {username_field}, {password_field}")
        
        # 2. 构建登录数据
        login_data = {
            username_field: username,
            password_field: password
        }
        if extra_data:
            login_data.update(extra_data)
        
        # 检测 CSRF Token
        csrf_token = self._detect_csrf_token(r.body)
        if csrf_token:
            login_data[csrf_token["name"]] = csrf_token["value"]
            print(f"🔑 检测到 CSRF Token: {csrf_token['name']}")
        
        # 3. 发送登录请求
        login_r = self.burp.post(login_url, data=login_data)
        
        # 4. 检查登录结果
        success = False
        
        # 检查失败标志
        if failure_indicator and failure_indicator.lower() in login_r.body.lower():
            print(f"❌ 登录失败: 检测到失败标志 '{failure_indicator}'")
            return None
        
        # 检查成功标志
        if success_indicator:
            if success_indicator.lower() in login_r.body.lower():
                success = True
        else:
            # 默认检查: 重定向或 Set-Cookie
            if login_r.status in [301, 302, 303, 307, 308]:
                success = True
            elif "set-cookie" in str(login_r.headers).lower():
                success = True
            elif login_r.status == 200 and len(login_r.body) > 0:
                # 检查常见失败标志
                fail_signs = ["invalid", "incorrect", "failed", "error", "wrong", "denied"]
                if not any(sign in login_r.body.lower() for sign in fail_signs):
                    success = True
        
        if not success:
            print("❌ 登录可能失败 (未检测到成功标志)")
            print(f"   状态码: {login_r.status}, 响应长度: {login_r.length}b")
            return None
        
        # 5. 提取 Cookie
        cookies = self._extract_cookies(login_r.headers)
        if not cookies:
            print("⚠️ 未获取到 Cookie，尝试从响应头提取...")
            # 尝试从 Set-Cookie 头提取
            set_cookie = login_r.headers.get("set-cookie", "")
            if set_cookie:
                cookies = self._parse_set_cookie(set_cookie)
        
        if not cookies:
            print("❌ 登录后未获取到 Cookie")
            return None
        
        print(f"✅ 登录成功! 获取到 {len(cookies)} 个 Cookie")
        
        # 6. 创建并保存会话
        session = Session(
            name=save_as,
            cookies=cookies,
            login_url=login_url,
            check_url=check_url or login_url,
            notes=f"Auto login as {username}"
        )
        
        self.save(session)
        print(f"💾 会话已保存: {save_as}")
        
        # 7. 验证会话有效性
        if check_url:
            if self.check_validity(session):
                print("✅ 会话验证通过")
            else:
                print("⚠️ 会话验证失败，Cookie 可能无效")
        
        return session
    
    def check_validity(self, session: Session, check_url: str = None) -> bool:
        """
        检测会话有效性
        
        Args:
            session: 会话对象
            check_url: 验证 URL (默认使用 session.check_url)
        
        Returns:
            True 如果会话有效
        """
        url = check_url or session.check_url
        if not url:
            print("⚠️ 未指定验证 URL")
            return True  # 无法验证，假设有效
        
        # 使用会话 Cookie 发送请求
        headers = {"Cookie": session.get_cookie_string()}
        headers.update(session.get_auth_header())
        
        r = self.burp.get(url, headers=headers)
        
        # 检查是否被重定向到登录页
        if r.status in [301, 302, 303, 307, 308]:
            location = r.headers.get("location", "").lower()
            if "login" in location or "signin" in location or "auth" in location:
                session.valid = False
                return False
        
        # 检查是否返回 401/403
        if r.status in [401, 403]:
            session.valid = False
            return False
        
        # 检查响应内容
        login_signs = ["please login", "please sign in", "session expired", "not authenticated"]
        if any(sign in r.body.lower() for sign in login_signs):
            session.valid = False
            return False
        
        session.valid = True
        return True
    
    def _detect_login_fields(self, html: str) -> Dict[str, str]:
        """检测登录表单字段名"""
        result = {}
        
        # 常见用户名字段
        username_patterns = [
            r'name=["\']?(username|user|login|email|account|userid|user_id|uname|loginname)["\']?',
            r'id=["\']?(username|user|login|email|account)["\']?',
            r'type=["\']?email["\']?[^>]*name=["\']?([^"\'>\s]+)["\']?',
        ]
        
        # 常见密码字段
        password_patterns = [
            r'name=["\']?(password|pass|pwd|passwd|secret)["\']?',
            r'type=["\']?password["\']?[^>]*name=["\']?([^"\'>\s]+)["\']?',
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                result["username"] = match.group(1) if match.lastindex else match.group(0).split("=")[1].strip("\"'")
                break
        
        for pattern in password_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                result["password"] = match.group(1) if match.lastindex else match.group(0).split("=")[1].strip("\"'")
                break
        
        return result
    
    def _detect_csrf_token(self, html: str) -> Optional[Dict[str, str]]:
        """检测 CSRF Token"""
        # 常见 CSRF Token 模式
        patterns = [
            r'name=["\']?(csrf_token|_token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|_csrf)["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?(csrf|token|_token)["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'<meta\s+name=["\']?csrf-token["\']?\s+content=["\']?([^"\'>\s]+)["\']?',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                if match.lastindex == 2:
                    return {"name": match.group(1), "value": match.group(2)}
                elif match.lastindex == 1:
                    return {"name": "csrf-token", "value": match.group(1)}
        
        return None
    
    def _extract_cookies(self, headers: Dict[str, str]) -> Dict[str, str]:
        """从响应头提取 Cookie"""
        cookies = {}
        
        # httpx 返回的 headers 可能是多值的
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                cookies.update(self._parse_set_cookie(value))
        
        return cookies
    
    def _parse_set_cookie(self, set_cookie: str) -> Dict[str, str]:
        """解析 Set-Cookie 头"""
        cookies = {}
        
        # 处理多个 Cookie (可能用逗号分隔，但要注意 expires 中也有逗号)
        # 简单处理: 按分号分割第一部分
        parts = set_cookie.split(",")
        
        for part in parts:
            # 取第一个分号前的部分 (name=value)
            cookie_part = part.split(";")[0].strip()
            if "=" in cookie_part:
                name, value = cookie_part.split("=", 1)
                name = name.strip()
                # 跳过 Cookie 属性
                if name.lower() not in ["path", "domain", "expires", "max-age", "secure", "httponly", "samesite"]:
                    cookies[name] = value.strip()
        
        return cookies
    
    def refresh(self, session_name: str) -> Optional[Session]:
        """
        刷新会话 (重新登录)
        
        需要会话中保存了 login_url
        """
        session = self.load(session_name)
        if not session:
            return None
        
        if not session.login_url:
            print("❌ 会话未保存登录信息，无法刷新")
            return None
        
        print(f"🔄 刷新会话: {session_name}")
        # 这里需要保存的用户名密码，但出于安全考虑不保存
        # 用户需要重新调用 login()
        print("⚠️ 请使用 login() 方法重新登录")
        return None
    
    def export(self, session_name: str, format: str = "cookie") -> str:
        """
        导出会话
        
        Args:
            session_name: 会话名称
            format: 导出格式 (cookie/curl/python/burp)
        
        Returns:
            导出的字符串
        """
        session = self.load(session_name)
        if not session:
            return ""
        
        if format == "cookie":
            return session.get_cookie_string()
        
        elif format == "curl":
            cookie_str = session.get_cookie_string()
            auth_headers = session.get_auth_header()
            parts = [f"-b '{cookie_str}'"]
            for k, v in auth_headers.items():
                parts.append(f"-H '{k}: {v}'")
            return " ".join(parts)
        
        elif format == "python":
            lines = [
                "import requests",
                "",
                "session = requests.Session()",
                f"session.cookies.update({session.cookies})",
            ]
            if session.token:
                lines.append(f"session.headers['Authorization'] = '{session.get_auth_header().get('Authorization', '')}'")
            return "\n".join(lines)
        
        elif format == "burp":
            # Burp Suite Cookie Jar 格式
            lines = []
            for name, value in session.cookies.items():
                lines.append(f"{name}\t{value}")
            return "\n".join(lines)
        
        return ""