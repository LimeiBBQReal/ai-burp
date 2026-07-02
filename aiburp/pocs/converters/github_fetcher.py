"""
GitHub POC 搜索器

从 GitHub 搜索 CVE 相关的 POC 代码

使用方式:
    fetcher = GitHubPOCFetcher(token="your_github_token")
    
    # 搜索 POC
    results = fetcher.search("CVE-2024-1234")
    
    # 获取代码内容
    code = fetcher.get_file_content(results[0])
"""

import requests
import base64
import re
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class GitHubPOCResult:
    """GitHub POC 搜索结果"""
    repo: str
    path: str
    url: str
    language: str
    score: float
    preview: str = ""
    
    def __str__(self):
        return f"[{self.language}] {self.repo}/{self.path}"


class GitHubPOCFetcher:
    """GitHub POC 搜索器"""
    
    def __init__(self, token: str = None):
        """
        初始化
        
        Args:
            token: GitHub Personal Access Token (可选，但有 rate limit)
        """
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
        
        self.api_base = "https://api.github.com"
    
    def search(self, cve: str, language: str = "python", max_results: int = 10) -> List[GitHubPOCResult]:
        """
        搜索 CVE 相关的 POC
        
        Args:
            cve: CVE 编号 (如 CVE-2024-1234)
            language: 编程语言过滤
            max_results: 最大结果数
        
        Returns:
            POC 搜索结果列表
        """
        results = []
        
        # 构建搜索查询
        query = f"{cve} language:{language}"
        
        try:
            resp = requests.get(
                f"{self.api_base}/search/code",
                params={"q": query, "per_page": max_results},
                headers=self.headers,
                timeout=30
            )
            
            if resp.status_code == 403:
                print("GitHub API rate limit exceeded. Please provide a token.")
                return results
            
            if resp.status_code != 200:
                print(f"GitHub API error: {resp.status_code}")
                return results
            
            data = resp.json()
            
            for item in data.get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                
                # 过滤掉明显不是 POC 的文件
                if self._is_likely_poc(path, repo):
                    results.append(GitHubPOCResult(
                        repo=repo,
                        path=path,
                        url=item.get("html_url", ""),
                        language=language,
                        score=item.get("score", 0)
                    ))
        
        except Exception as e:
            print(f"搜索失败: {e}")
        
        return results
    
    def _is_likely_poc(self, path: str, repo: str) -> bool:
        """判断是否可能是 POC 文件"""
        # 排除文档和配置文件
        exclude_patterns = [
            r'README', r'CHANGELOG', r'LICENSE', r'\.md$',
            r'test_', r'_test\.', r'spec\.', r'\.json$',
            r'requirements\.txt', r'setup\.py', r'\.yml$', r'\.yaml$'
        ]
        
        for pattern in exclude_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return False
        
        # 包含 POC 相关关键词
        include_patterns = [
            r'poc', r'exploit', r'exp\.', r'attack',
            r'CVE-\d{4}-\d+', r'vuln', r'payload'
        ]
        
        for pattern in include_patterns:
            if re.search(pattern, path, re.IGNORECASE) or re.search(pattern, repo, re.IGNORECASE):
                return True
        
        # Python 文件默认包含
        if path.endswith('.py'):
            return True
        
        return False
    
    def get_file_content(self, result: GitHubPOCResult) -> Optional[str]:
        """
        获取文件内容
        
        Args:
            result: 搜索结果
        
        Returns:
            文件内容
        """
        try:
            resp = requests.get(
                f"{self.api_base}/repos/{result.repo}/contents/{result.path}",
                headers=self.headers,
                timeout=30
            )
            
            if resp.status_code != 200:
                return None
            
            data = resp.json()
            content = data.get("content", "")
            
            if content:
                return base64.b64decode(content).decode('utf-8', errors='ignore')
        
        except Exception as e:
            print(f"获取内容失败: {e}")
        
        return None
    
    def search_poc_repos(self, cve: str, max_results: int = 5) -> List[Dict]:
        """
        搜索专门的 POC 仓库
        
        Args:
            cve: CVE 编号
            max_results: 最大结果数
        
        Returns:
            仓库列表
        """
        results = []
        
        try:
            resp = requests.get(
                f"{self.api_base}/search/repositories",
                params={"q": cve, "per_page": max_results, "sort": "stars"},
                headers=self.headers,
                timeout=30
            )
            
            if resp.status_code != 200:
                return results
            
            data = resp.json()
            
            for item in data.get("items", []):
                results.append({
                    "name": item.get("full_name"),
                    "url": item.get("html_url"),
                    "description": item.get("description", ""),
                    "stars": item.get("stargazers_count", 0),
                    "language": item.get("language", ""),
                    "updated": item.get("updated_at", "")
                })
        
        except Exception as e:
            print(f"搜索仓库失败: {e}")
        
        return results
    
    def analyze_poc(self, code: str) -> Dict:
        """
        分析 POC 代码结构
        
        Args:
            code: POC 代码
        
        Returns:
            分析结果
        """
        analysis = {
            "language": "python",
            "has_requests": False,
            "has_argparse": False,
            "target_param": None,
            "http_methods": [],
            "endpoints": [],
            "payloads": []
        }
        
        # 检测 requests 库
        if "import requests" in code or "from requests" in code:
            analysis["has_requests"] = True
        
        # 检测 argparse
        if "argparse" in code:
            analysis["has_argparse"] = True
        
        # 提取 HTTP 方法
        methods = re.findall(r'requests\.(get|post|put|delete|patch|head|options)\s*\(', code, re.IGNORECASE)
        analysis["http_methods"] = list(set(methods))
        
        # 提取 URL 端点
        endpoints = re.findall(r'["\']/([\w/\-\.]+)["\']', code)
        analysis["endpoints"] = list(set(endpoints))[:10]
        
        # 提取可能的 payload
        payloads = re.findall(r'payload\s*=\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        analysis["payloads"] = payloads[:5]
        
        return analysis
    
    def suggest_conversion(self, code: str) -> str:
        """
        生成转换建议
        
        Args:
            code: POC 代码
        
        Returns:
            转换建议
        """
        analysis = self.analyze_poc(code)
        
        suggestions = []
        
        if not analysis["has_requests"]:
            suggestions.append("- 需要添加 requests 库导入")
        
        if analysis["has_argparse"]:
            suggestions.append("- 需要移除 argparse，改为函数参数")
        
        if analysis["http_methods"]:
            suggestions.append(f"- HTTP 方法: {', '.join(analysis['http_methods'])}")
        
        if analysis["endpoints"]:
            suggestions.append(f"- 端点: {', '.join(analysis['endpoints'][:3])}")
        
        suggestions.append("- 需要适配为 POCResult 返回格式")
        suggestions.append("- 需要添加 POCInfo 注册信息")
        
        return "\n".join(suggestions)


# 命令行入口
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python github_fetcher.py <CVE-XXXX-XXXX> [token]")
        sys.exit(1)
    
    cve = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    fetcher = GitHubPOCFetcher(token=token)
    
    print(f"搜索 {cve} 相关 POC...")
    print()
    
    # 搜索仓库
    print("=== POC 仓库 ===")
    repos = fetcher.search_poc_repos(cve)
    for repo in repos:
        print(f"⭐ {repo['stars']} | {repo['name']}")
        print(f"   {repo['description'][:60]}..." if repo['description'] else "")
        print(f"   {repo['url']}")
        print()
    
    # 搜索代码
    print("=== Python POC 文件 ===")
    results = fetcher.search(cve, language="python")
    for result in results:
        print(f"📄 {result}")
        print(f"   {result.url}")
        print()
