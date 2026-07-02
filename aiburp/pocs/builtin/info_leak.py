"""
L1 内置 POC: 信息泄露类

包含:
- phpinfo 泄露
- .git 目录泄露
- .env 文件泄露
- 备份文件泄露
- 配置文件泄露
- 源码泄露
"""

import requests
import re
from urllib.parse import urljoin
from ..poc_manager import POCInfo, POCResult, POCLevel, Severity


def check_phpinfo(url: str, **kwargs) -> POCResult:
    """检测 phpinfo 泄露"""
    paths = [
        "/phpinfo.php", "/info.php", "/php_info.php",
        "/test.php", "/i.php", "/pi.php",
        "/php.php", "/temp.php", "/p.php"
    ]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200 and "PHP Version" in resp.text:
                # 提取版本
                version_match = re.search(r'PHP Version\s*</td><td[^>]*>([^<]+)', resp.text)
                version = version_match.group(1) if version_match else "unknown"
                
                return POCResult(
                    poc_id="info-leak-phpinfo",
                    name="phpinfo 信息泄露",
                    vulnerable=True,
                    severity=Severity.MEDIUM,
                    evidence=f"路径: {path}, PHP版本: {version}",
                    details={"path": path, "php_version": version}
                )
        except:
            continue
    
    return POCResult(
        poc_id="info-leak-phpinfo",
        name="phpinfo 信息泄露",
        vulnerable=False
    )


def check_git_leak(url: str, **kwargs) -> POCResult:
    """检测 .git 目录泄露"""
    paths = ["/.git/config", "/.git/HEAD", "/.git/index"]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200:
                if path == "/.git/config" and "[core]" in resp.text:
                    return POCResult(
                        poc_id="info-leak-git",
                        name=".git 源码泄露",
                        vulnerable=True,
                        severity=Severity.CRITICAL,
                        evidence=f"路径: {path}",
                        details={"path": path, "content_preview": resp.text[:200]}
                    )
                elif path == "/.git/HEAD" and "ref:" in resp.text:
                    return POCResult(
                        poc_id="info-leak-git",
                        name=".git 源码泄露",
                        vulnerable=True,
                        severity=Severity.CRITICAL,
                        evidence=f"路径: {path}, 内容: {resp.text.strip()}",
                        details={"path": path}
                    )
        except:
            continue
    
    return POCResult(
        poc_id="info-leak-git",
        name=".git 源码泄露",
        vulnerable=False
    )


def check_env_leak(url: str, **kwargs) -> POCResult:
    """检测 .env 文件泄露"""
    paths = ["/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup"]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200 and len(resp.text) > 10:
                # 检查是否包含敏感信息
                sensitive_patterns = [
                    r'DB_PASSWORD\s*=', r'API_KEY\s*=', r'SECRET\s*=',
                    r'AWS_', r'MYSQL_', r'REDIS_', r'APP_KEY\s*='
                ]
                for pattern in sensitive_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return POCResult(
                            poc_id="info-leak-env",
                            name=".env 配置泄露",
                            vulnerable=True,
                            severity=Severity.CRITICAL,
                            evidence=f"路径: {path}",
                            details={"path": path, "size": len(resp.text)}
                        )
        except:
            continue
    
    return POCResult(
        poc_id="info-leak-env",
        name=".env 配置泄露",
        vulnerable=False
    )


def check_backup_files(url: str, **kwargs) -> POCResult:
    """检测备份文件泄露"""
    # 常见备份文件
    paths = [
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
        "/database.sql", "/dump.sql", "/data.sql",
        "/www.zip", "/web.zip", "/site.zip", "/html.zip",
        "/backup.rar", "/backup.7z",
        "/.backup", "/old/", "/bak/",
    ]
    
    # 根据域名生成备份文件名
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.replace(".", "_").replace(":", "_")
    paths.extend([
        f"/{domain}.zip", f"/{domain}.sql", f"/{domain}.tar.gz",
        f"/{parsed.netloc}.zip", f"/{parsed.netloc}.sql"
    ])
    
    for path in paths:
        try:
            resp = requests.head(urljoin(url, path), timeout=10, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                content_length = resp.headers.get('Content-Length', '0')
                content_type = resp.headers.get('Content-Type', '')
                
                # 检查是否是真实文件
                if int(content_length) > 1000 or 'zip' in content_type or 'sql' in content_type:
                    return POCResult(
                        poc_id="info-leak-backup",
                        name="备份文件泄露",
                        vulnerable=True,
                        severity=Severity.HIGH,
                        evidence=f"路径: {path}, 大小: {content_length}",
                        details={"path": path, "size": content_length, "type": content_type}
                    )
        except:
            continue
    
    return POCResult(
        poc_id="info-leak-backup",
        name="备份文件泄露",
        vulnerable=False
    )


def check_svn_leak(url: str, **kwargs) -> POCResult:
    """检测 .svn 目录泄露"""
    paths = ["/.svn/entries", "/.svn/wc.db"]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200:
                if path == "/.svn/entries" and ("dir" in resp.text or resp.text.startswith("8") or resp.text.startswith("9") or resp.text.startswith("10")):
                    return POCResult(
                        poc_id="info-leak-svn",
                        name=".svn 源码泄露",
                        vulnerable=True,
                        severity=Severity.CRITICAL,
                        evidence=f"路径: {path}",
                        details={"path": path}
                    )
                elif path == "/.svn/wc.db" and resp.content[:16] == b'SQLite format 3\x00':
                    return POCResult(
                        poc_id="info-leak-svn",
                        name=".svn 源码泄露",
                        vulnerable=True,
                        severity=Severity.CRITICAL,
                        evidence=f"路径: {path} (SQLite 数据库)",
                        details={"path": path}
                    )
        except:
            continue
    
    return POCResult(
        poc_id="info-leak-svn",
        name=".svn 源码泄露",
        vulnerable=False
    )


def check_ds_store(url: str, **kwargs) -> POCResult:
    """检测 .DS_Store 泄露"""
    try:
        resp = requests.get(urljoin(url, "/.DS_Store"), timeout=10, verify=False)
        if resp.status_code == 200 and resp.content[:8] == b'\x00\x00\x00\x01Bud1':
            return POCResult(
                poc_id="info-leak-ds-store",
                name=".DS_Store 目录结构泄露",
                vulnerable=True,
                severity=Severity.LOW,
                evidence="发现 .DS_Store 文件",
                details={"size": len(resp.content)}
            )
    except:
        pass
    
    return POCResult(
        poc_id="info-leak-ds-store",
        name=".DS_Store 目录结构泄露",
        vulnerable=False
    )


def check_web_config(url: str, **kwargs) -> POCResult:
    """检测 web.config 泄露"""
    paths = ["/web.config", "/Web.config", "/WEB.CONFIG"]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200 and "<configuration>" in resp.text:
                # 检查敏感信息
                has_conn_string = "connectionString" in resp.text
                has_app_settings = "appSettings" in resp.text
                
                return POCResult(
                    poc_id="info-leak-webconfig",
                    name="web.config 配置泄露",
                    vulnerable=True,
                    severity=Severity.HIGH if has_conn_string else Severity.MEDIUM,
                    evidence=f"路径: {path}",
                    details={
                        "path": path,
                        "has_connection_string": has_conn_string,
                        "has_app_settings": has_app_settings
                    }
                )
        except:
            continue
    
    return POCResult(
        poc_id="info-leak-webconfig",
        name="web.config 配置泄露",
        vulnerable=False
    )


def check_htaccess(url: str, **kwargs) -> POCResult:
    """检测 .htaccess 泄露"""
    try:
        resp = requests.get(urljoin(url, "/.htaccess"), timeout=10, verify=False)
        if resp.status_code == 200 and len(resp.text) > 5:
            # 检查是否是真实的 htaccess
            htaccess_patterns = ["RewriteEngine", "RewriteRule", "RewriteCond", "Options", "DirectoryIndex", "AuthType"]
            for pattern in htaccess_patterns:
                if pattern in resp.text:
                    return POCResult(
                        poc_id="info-leak-htaccess",
                        name=".htaccess 配置泄露",
                        vulnerable=True,
                        severity=Severity.MEDIUM,
                        evidence=f"发现 .htaccess 文件",
                        details={"content_preview": resp.text[:300]}
                    )
    except:
        pass
    
    return POCResult(
        poc_id="info-leak-htaccess",
        name=".htaccess 配置泄露",
        vulnerable=False
    )


# 注册所有 POC
POCS = [
    POCInfo(
        id="info-leak-phpinfo",
        name="phpinfo 信息泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["info-leak", "php", "config"],
        description="检测 phpinfo() 页面泄露，可能暴露服务器配置信息",
        check_func=check_phpinfo
    ),
    POCInfo(
        id="info-leak-git",
        name=".git 源码泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.CRITICAL,
        tags=["info-leak", "git", "source-code"],
        description="检测 .git 目录泄露，可导致完整源码泄露",
        check_func=check_git_leak
    ),
    POCInfo(
        id="info-leak-env",
        name=".env 配置泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.CRITICAL,
        tags=["info-leak", "env", "config", "credentials"],
        description="检测 .env 文件泄露，可能包含数据库密码、API密钥等",
        check_func=check_env_leak
    ),
    POCInfo(
        id="info-leak-backup",
        name="备份文件泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.HIGH,
        tags=["info-leak", "backup", "source-code"],
        description="检测备份文件泄露 (zip/sql/tar.gz)",
        check_func=check_backup_files
    ),
    POCInfo(
        id="info-leak-svn",
        name=".svn 源码泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.CRITICAL,
        tags=["info-leak", "svn", "source-code"],
        description="检测 .svn 目录泄露，可导致完整源码泄露",
        check_func=check_svn_leak
    ),
    POCInfo(
        id="info-leak-ds-store",
        name=".DS_Store 目录结构泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.LOW,
        tags=["info-leak", "macos"],
        description="检测 macOS .DS_Store 文件泄露，可暴露目录结构",
        check_func=check_ds_store
    ),
    POCInfo(
        id="info-leak-webconfig",
        name="web.config 配置泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.HIGH,
        tags=["info-leak", "asp", "iis", "config"],
        description="检测 ASP.NET web.config 泄露，可能包含数据库连接字符串",
        check_func=check_web_config
    ),
    POCInfo(
        id="info-leak-htaccess",
        name=".htaccess 配置泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["info-leak", "apache", "config"],
        description="检测 Apache .htaccess 文件泄露",
        check_func=check_htaccess
    ),
]
