"""
AI-Burp 通用工具模块

包含:
1. HTTP 头对比分析
2. GitHub 密钥扫描
3. 参数发现
"""

import re
import requests
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field


# ============================================================
# HTTP Headers Compare
# ============================================================

INTERESTING_HEADERS = [
    'Server', 'X-Powered-By', 'X-Frame-Options', 'X-Content-Type-Options',
    'Content-Security-Policy', 'Strict-Transport-Security', 'X-XSS-Protection',
    'Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
    'Set-Cookie', 'X-Request-Id', 'X-Runtime', 'X-Debug-Token',
]

DEBUG_INDICATORS = ['debug', 'dev', 'test', 'staging', 'development']


@dataclass
class HeadersResult:
    """HTTP 头对比结果"""
    targets: Dict[str, Dict] = field(default_factory=dict)
    unique_headers: Dict[str, List[str]] = field(default_factory=dict)
    debug_findings: List[Tuple[str, str, str]] = field(default_factory=list)


def compare_headers(targets: List[Tuple[str, str]], timeout: int = 10) -> HeadersResult:
    """
    对比多个目标的 HTTP 头
    
    Args:
        targets: [(url, name), ...] 目标列表
        timeout: 超时时间
    
    Returns:
        HeadersResult 对象
    
    Example:
        targets = [
            ("https://example.com", "Main"),
            ("https://api.example.com", "API"),
        ]
        result = compare_headers(targets)
    """
    result = HeadersResult()
    
    for url, name in targets:
        try:
            r = requests.get(url, verify=False, timeout=timeout, allow_redirects=False)
            result.targets[name] = {
                'url': url,
                'status': r.status_code,
                'headers': dict(r.headers)
            }
            
            # 检查 debug 指标
            for h, v in r.headers.items():
                for indicator in DEBUG_INDICATORS:
                    if indicator in h.lower() or indicator in str(v).lower():
                        result.debug_findings.append((name, h, v[:100]))
        except Exception as e:
            result.targets[name] = {'url': url, 'error': str(e)}
    
    # 找出独特的 headers
    all_headers = set()
    for name, data in result.targets.items():
        if 'headers' in data:
            all_headers.update(data['headers'].keys())
    
    for header in all_headers:
        sites = [name for name, data in result.targets.items() 
                if 'headers' in data and header.lower() in [k.lower() for k in data['headers'].keys()]]
        if 0 < len(sites) < len(result.targets):
            result.unique_headers[header] = sites
    
    return result


# ============================================================
# GitHub Secrets Scanner
# ============================================================

SECRET_PATTERNS = [
    (r'SECRET_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', 'Django SECRET_KEY'),
    (r'API_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', 'API Key'),
    (r'PASSWORD\s*=\s*[\'"]([^\'"]+)[\'"]', 'Password'),
    (r'DB_PASSWORD\s*=\s*[\'"]([^\'"]+)[\'"]', 'DB Password'),
    (r'AWS_SECRET_ACCESS_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', 'AWS Secret'),
    (r'STRIPE_SECRET_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', 'Stripe Secret'),
    (r'PAYPAL_SECRET\s*=\s*[\'"]([^\'"]+)[\'"]', 'PayPal Secret'),
    (r'PRIVATE_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', 'Private Key'),
    (r'JWT_SECRET\s*=\s*[\'"]([^\'"]+)[\'"]', 'JWT Secret'),
]

SENSITIVE_FILES = [
    "settings.py", ".env", ".env.example", "config.py",
    "config/database.php", "config/app.php", ".gitignore",
    "docker-compose.yml", "Dockerfile", "requirements.txt",
    "backend/settings.py", "src/settings.py", "app/settings.py",
]


@dataclass
class SecretFinding:
    """密钥发现"""
    repo: str
    file: str
    secret_type: str
    value: str


def scan_github_repo(repo: str, branch: str = "main", timeout: int = 10) -> List[SecretFinding]:
    """
    扫描 GitHub 仓库中的密钥
    
    Args:
        repo: 仓库名，如 "user/repo"
        branch: 分支名
        timeout: 超时时间
    
    Returns:
        SecretFinding 列表
    """
    findings = []
    
    # 检查仓库是否存在
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}", timeout=timeout)
        if r.status_code != 200:
            return findings
        
        data = r.json()
        branch = data.get('default_branch', branch)
    except:
        return findings
    
    # 扫描敏感文件
    for f in SENSITIVE_FILES:
        try:
            url = f"https://raw.githubusercontent.com/{repo}/{branch}/{f}"
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                for pattern, name in SECRET_PATTERNS:
                    matches = re.findall(pattern, r.text, re.IGNORECASE)
                    for match in matches:
                        findings.append(SecretFinding(
                            repo=repo, file=f, secret_type=name, value=match[:50]
                        ))
        except:
            pass
    
    return findings


def scan_github_repos(repos: List[str]) -> List[SecretFinding]:
    """批量扫描多个仓库"""
    all_findings = []
    for repo in repos:
        findings = scan_github_repo(repo)
        all_findings.extend(findings)
    return all_findings


# ============================================================
# Parameter Discovery
# ============================================================

@dataclass
class FormInfo:
    """表单信息"""
    url: str
    inputs: List[str] = field(default_factory=list)
    hidden: List[Tuple[str, str]] = field(default_factory=list)
    selects: List[str] = field(default_factory=list)
    csrf_token: Optional[str] = None


def discover_params(url: str, timeout: int = 10) -> FormInfo:
    """
    发现页面中的参数和表单
    
    Args:
        url: 目标 URL
        timeout: 超时时间
    
    Returns:
        FormInfo 对象
    """
    result = FormInfo(url=url)
    
    try:
        r = requests.get(url, verify=False, timeout=timeout)
        
        # 查找表单字段
        forms = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE)
        for form in forms:
            # Input 字段
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form, re.I)
            result.inputs.extend(inputs)
            
            # Hidden 字段
            hidden = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                form, re.I
            )
            result.hidden.extend(hidden)
            
            # Select 字段
            selects = re.findall(r'<select[^>]*name=["\']([^"\']+)["\']', form, re.I)
            result.selects.extend(selects)
        
        # 去重
        result.inputs = list(set(result.inputs))
        result.selects = list(set(result.selects))
        
        # CSRF Token
        csrf_patterns = [
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
        ]
        for pattern in csrf_patterns:
            match = re.search(pattern, r.text, re.I)
            if match:
                result.csrf_token = match.group(1)
                break
        
    except Exception:
        pass
    
    return result


def discover_hidden_apis(base_url: str, timeout: int = 5) -> List[Tuple[str, int, int]]:
    """
    发现隐藏的 API 端点
    
    Args:
        base_url: 基础 URL
        timeout: 超时时间
    
    Returns:
        [(path, status_code, size), ...] 列表
    """
    hidden_paths = [
        "/api/v1/", "/api/v2/", "/api/internal/", "/api/admin/",
        "/api/debug/", "/api/test/", "/api/config/", "/api/settings/",
        "/_api/", "/internal/", "/debug/", "/metrics/", "/health/",
        "/status/", "/info/", "/version/", "/swagger/", "/graphql/",
        "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
    ]
    
    found = []
    base_url = base_url.rstrip('/')
    
    for path in hidden_paths:
        try:
            r = requests.get(base_url + path, verify=False, timeout=timeout, allow_redirects=False)
            if r.status_code not in [404, 403, 302, 301]:
                found.append((path, r.status_code, len(r.content)))
        except:
            pass
    
    return found
