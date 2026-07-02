"""
GitHub 泄露搜索 — 在 GitHub 上搜索目标相关的代码/密钥泄露.

红队高频发现:
    - 开发者把 API key 推到了 GitHub
    - .git 目录暴露在 Web 上
    - 内部代码仓库泄露到公开 GitHub
    - 配置文件含数据库密码

数据源:
    1. GitHub Code Search API (需要 GitHub Token)
    2. GitHub Dorking (不用 Token, 用网页搜索)

支持的搜索:
    - 域名: "target.com" (找含目标域名的代码)
    - 密钥: "target.com" + "password/secret/api_key/token"
    - 配置: "target.com" + "config/.env/database.yml"
"""

import asyncio
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class GithubLeak:
    """GitHub 泄露发现"""
    repo: str               # 仓库名
    file: str               # 文件路径
    url: str                # GitHub URL
    snippet: str = ""       # 匹配的代码片段
    leak_type: str = ""     # leak 类型 (api_key/password/config/token)
    severity: str = "medium"  # high / medium / low


class GithubLeakScanner:
    """
    GitHub 泄露扫描器.

    用法:
        scanner = GithubLeakScanner()
        leaks = await scanner.search_domain("target.com")
        leaks = await scanner.search_keyword("target.com", "password")
    """

    # 泄露关键词模式
    LEAK_PATTERNS = {
        "api_key": [
            r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})',
            r'(?i)AKIA[A-Z0-9]{16}',  # AWS
            r'(?i)sk-[A-Za-z0-9]{20,}',  # OpenAI
            r'(?i)ghp_[A-Za-z0-9]{36}',  # GitHub PAT
            r'(?i)glpat-[A-Za-z0-9\-]{20}',  # GitLab PAT
        ],
        "password": [
            r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^\s"\']{4,})',
            r'(?i)(mysql|postgres|redis)://\w+:(\S+)@',
        ],
        "token": [
            r'(?i)(token|bearer|jwt)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-.]{20,})',
            r'(?i)eyJ[A-Za-z0-9_\-.]{10,}\.[A-Za-z0-9_\-.]{10,}',  # JWT
        ],
        "config": [
            r'(?i)(database|db|host|port)["\']?\s*[:=]\s*["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(?i)(DATABASE_URL|DB_HOST|REDIS_URL)\s*=\s*(.+)',
            r'(?i)(private[_-]?key|BEGIN RSA PRIVATE)',
        ],
    }

    # GitHub Dork 查询模板
    DORKS = [
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" secret',
        '"{domain}" token',
        '"{domain}" config',
        '"{domain}" .env',
        '"{domain}" database.yml',
        '"{domain}" authorizers',
        'extension:env "{domain}"',
        'extension:yml "{domain}" password',
        'extension:json "{domain}" key',
        'extension:pem "{domain}"',
        'filename:.env "{domain}"',
        'filename:config.php "{domain}"',
        'filename:wp-config.php "{domain}"',
    ]

    def __init__(self, github_token: Optional[str] = None):
        """
        Args:
            github_token: GitHub Personal Access Token (提高速率限制)
                         无 token 也能用, 但速率受限 (10 次/分钟)
        """
        import os
        self.token = github_token or os.environ.get("GITHUB_TOKEN", "")

    async def search_domain(self, domain: str, max_results: int = 50) -> List[GithubLeak]:
        """
        搜索域名相关的所有泄露.

        执行多个 Dork 查询, 合并去重.
        """
        all_leaks: Dict[str, GithubLeak] = {}

        for dork_template in self.DORKS:
            query = dork_template.format(domain=domain)
            leaks = await self._search_code(query, max_results=5)
            for leak in leaks:
                key = f"{leak.repo}:{leak.file}"
                if key not in all_leaks:
                    all_leaks[key] = leak

            if len(all_leaks) >= max_results:
                break

        return list(all_leaks.values())

    async def search_keyword(self, keyword: str, leak_type: str = "",
                              max_results: int = 20) -> List[GithubLeak]:
        """
        搜索特定关键词的泄露.

        Args:
            keyword: 搜索关键词 (如 "target.com password")
            leak_type: 限定泄露类型 (api_key/password/token/config)
        """
        return await self._search_code(keyword, max_results=max_results, leak_type=leak_type)

    async def _search_code(self, query: str, max_results: int = 10,
                           leak_type: str = "") -> List[GithubLeak]:
        """GitHub Code Search API"""
        import requests

        def _search():
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.token:
                headers["Authorization"] = f"token {self.token}"

            try:
                r = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": min(max_results, 30)},
                    headers=headers,
                    timeout=15,
                )

                if r.status_code == 200:
                    items = r.json().get("items", [])
                    leaks = []
                    for item in items[:max_results]:
                        repo = item.get("repository", {}).get("full_name", "")
                        file_path = item.get("path", "")
                        html_url = item.get("html_url", "")

                        # 获取文件内容片段 (raw)
                        raw_url = item.get("html_url", "").replace(
                            "github.com", "raw.githubusercontent.com"
                        ).replace("/blob/", "/")

                        # 尝试获取内容
                        snippet = ""
                        detected_type = leak_type or "unknown"
                        try:
                            raw_r = requests.get(
                                raw_url.replace("raw.githubusercontent.com",
                                               "github.com").replace("/raw/", "/") +
                                "?raw=true",
                                headers=headers, timeout=10,
                            )
                            if raw_r.status_code == 200:
                                content = raw_r.text[:5000]
                                snippet = content[:200]
                                # 自动检测泄露类型
                                detected_type = self._detect_leak_type(content)
                        except Exception:
                            pass

                        leaks.append(GithubLeak(
                            repo=repo,
                            file=file_path,
                            url=html_url,
                            snippet=snippet,
                            leak_type=detected_type,
                            severity=self._assess_severity(detected_type, snippet),
                        ))
                    return leaks

                elif r.status_code == 403:
                    # Rate limit
                    return []
            except Exception:
                pass
            return []

        return await asyncio.to_thread(_search)

    def _detect_leak_type(self, content: str) -> str:
        """自动检测内容里的泄露类型"""
        for leak_type, patterns in self.LEAK_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, content):
                    return leak_type
        return "unknown"

    def _assess_severity(self, leak_type: str, snippet: str) -> str:
        """评估严重度"""
        if leak_type in ("api_key", "password") and "=" in snippet:
            return "high"
        if leak_type in ("token", "config"):
            return "medium"
        return "low"
