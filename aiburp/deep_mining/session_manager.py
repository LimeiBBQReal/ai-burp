"""
aiburp/deep_mining/session_manager.py
Session 隔离管理 — 防止 cookie 串号, 支持匿名/多用户对比.
"""
import threading
from typing import Dict, Optional
import requests
import urllib3

urllib3.disable_warnings()


class SessionManager:
    """
    多个命名 session, 互不串 cookie.

    常用命名:
      - "anon"    匿名, 无登录态
      - "user_A"  普通用户 A
      - "user_B"  普通用户 B (对比 IDOR 用)
      - "admin"   管理员

    用法:
        sm = SessionManager()
        s = sm.get_or_create("anon", proxy={"http": "...", "https": "..."})
        s.get("https://target/")
    """

    def __init__(self):
        self._sessions: Dict[str, requests.Session] = {}
        self._lock = threading.Lock()

    def get_or_create(self, name: str,
                      proxy: Optional[dict] = None,
                      headers: Optional[dict] = None) -> requests.Session:
        """获取或创建命名 session."""
        with self._lock:
            if name not in self._sessions:
                s = requests.Session()
                s.trust_env = False
                s.verify = False
                if proxy:
                    s.proxies.update(proxy)
                if headers:
                    s.headers.update(headers)
                self._sessions[name] = s
            return self._sessions[name]

    def has_session(self, name: str) -> bool:
        return name in self._sessions

    def drop_session(self, name: str) -> bool:
        """销毁命名 session, 释放 cookie."""
        with self._lock:
            s = self._sessions.pop(name, None)
            if s is not None:
                s.close()
                return True
            return False

    def login(self, name: str, login_url: str, creds: Dict[str, str],
              method: str = "POST",
              success_check: Optional[callable] = None) -> bool:
        """
        自动登录并保留 cookie.

        Args:
            name: session 名
            login_url: 登录接口 URL
            creds: {"username": "...", "password": "..."}
            method: POST / GET
            success_check: 可选 callable(response) -> bool,
                          默认检查 302 + Set-Cookie 包含 session

        Returns:
            是否登录成功
        """
        s = self.get_or_create(name)

        try:
            if method.upper() == "POST":
                r = s.post(login_url, data=creds, timeout=10,
                           allow_redirects=True)
            else:
                r = s.get(login_url, params=creds, timeout=10,
                           allow_redirects=True)

            if success_check is not None:
                return bool(success_check(r))

            cookies = r.headers.get("Set-Cookie", "") or ""
            return (r.status_code in (200, 302)
                    and any(tok in cookies.lower()
                            for tok in ("session", "sessid", "token", "auth")))

        except Exception:
            return False

    def cookies_of(self, name: str) -> Dict[str, str]:
        s = self._sessions.get(name)
        return dict(s.cookies) if s else {}

    def snapshot(self) -> Dict[str, Dict[str, str]]:
        """导出所有 session 的 cookie, 调试用."""
        return {name: dict(s.cookies) for name, s in self._sessions.items()}

    def close_all(self):
        with self._lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()