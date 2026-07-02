"""
L1 内置 POC: 配置错误类

包含:
- 目录遍历
- 默认凭据
- 调试模式
- 安全头缺失
- 管理后台暴露
"""

import requests
import re
from urllib.parse import urljoin
from ..poc_manager import POCInfo, POCResult, POCLevel, Severity


def check_directory_listing(url: str, **kwargs) -> POCResult:
    """检测目录遍历"""
    paths = ["/", "/images/", "/uploads/", "/files/", "/static/", "/assets/", "/css/", "/js/"]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200:
                # 检测目录列表特征
                patterns = [
                    r'Index of /',
                    r'<title>Index of',
                    r'Directory listing for',
                    r'Parent Directory</a>',
                    r'\[To Parent Directory\]',
                    r'<h1>Index of'
                ]
                for pattern in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return POCResult(
                            poc_id="misconfig-dir-listing",
                            name="目录遍历",
                            vulnerable=True,
                            severity=Severity.MEDIUM,
                            evidence=f"路径: {path}",
                            details={"path": path}
                        )
        except:
            continue
    
    return POCResult(
        poc_id="misconfig-dir-listing",
        name="目录遍历",
        vulnerable=False
    )


def check_debug_mode(url: str, **kwargs) -> POCResult:
    """检测调试模式"""
    findings = []
    
    # Django Debug
    try:
        resp = requests.get(urljoin(url, "/nonexistent_page_12345/"), timeout=10, verify=False)
        if "You're seeing this error because you have <code>DEBUG = True</code>" in resp.text:
            findings.append(("Django DEBUG=True", resp.text[:200]))
    except:
        pass
    
    # Laravel Debug
    try:
        resp = requests.get(urljoin(url, "/"), timeout=10, verify=False)
        if "Whoops! There was an error" in resp.text or "Laravel" in resp.text and "Exception" in resp.text:
            findings.append(("Laravel Debug Mode", ""))
    except:
        pass
    
    # PHP errors
    try:
        resp = requests.get(urljoin(url, "/?id='"), timeout=10, verify=False)
        php_errors = ["Fatal error:", "Parse error:", "Warning:", "Notice:", "on line"]
        for err in php_errors:
            if err in resp.text:
                findings.append(("PHP Error Display", err))
                break
    except:
        pass
    
    # ASP.NET errors
    try:
        resp = requests.get(urljoin(url, "/"), timeout=10, verify=False)
        if "Server Error in" in resp.text and "Application" in resp.text:
            findings.append(("ASP.NET Error Display", ""))
    except:
        pass
    
    if findings:
        return POCResult(
            poc_id="misconfig-debug-mode",
            name="调试模式开启",
            vulnerable=True,
            severity=Severity.MEDIUM,
            evidence=", ".join([f[0] for f in findings]),
            details={"findings": findings}
        )
    
    return POCResult(
        poc_id="misconfig-debug-mode",
        name="调试模式开启",
        vulnerable=False
    )


def check_security_headers(url: str, **kwargs) -> POCResult:
    """检测安全头缺失"""
    try:
        resp = requests.get(url, timeout=10, verify=False)
        headers = resp.headers
        
        missing = []
        
        # 检查关键安全头
        security_headers = {
            "X-Frame-Options": "点击劫持防护",
            "X-Content-Type-Options": "MIME 类型嗅探防护",
            "X-XSS-Protection": "XSS 过滤器",
            "Content-Security-Policy": "内容安全策略",
            "Strict-Transport-Security": "HTTPS 强制"
        }
        
        for header, desc in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing.append(f"{header} ({desc})")
        
        if len(missing) >= 3:  # 缺少3个以上才报告
            return POCResult(
                poc_id="misconfig-security-headers",
                name="安全头缺失",
                vulnerable=True,
                severity=Severity.LOW,
                evidence=f"缺少: {', '.join(missing[:3])}...",
                details={"missing_headers": missing}
            )
    except:
        pass
    
    return POCResult(
        poc_id="misconfig-security-headers",
        name="安全头缺失",
        vulnerable=False
    )


def check_admin_panel(url: str, **kwargs) -> POCResult:
    """检测管理后台暴露"""
    admin_paths = [
        "/admin/", "/admin/login", "/administrator/",
        "/wp-admin/", "/wp-login.php",
        "/manager/", "/manage/", "/backend/",
        "/admin.php", "/admin.asp", "/admin.aspx",
        "/phpmyadmin/", "/pma/", "/myadmin/",
        "/cpanel/", "/webmail/",
        "/console/", "/dashboard/",
        "/_admin/", "/site-admin/",
        "/admincp/", "/admin_area/",
    ]
    
    found = []
    
    for path in admin_paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=5, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 401, 403]:
                # 200 或重定向到登录页都算发现
                if resp.status_code == 200:
                    found.append((path, "可访问"))
                elif resp.status_code in [301, 302]:
                    found.append((path, "重定向"))
                elif resp.status_code == 401:
                    found.append((path, "需要认证"))
                elif resp.status_code == 403:
                    found.append((path, "禁止访问"))
        except:
            continue
    
    if found:
        accessible = [f for f in found if f[1] == "可访问"]
        if accessible:
            return POCResult(
                poc_id="misconfig-admin-panel",
                name="管理后台暴露",
                vulnerable=True,
                severity=Severity.MEDIUM,
                evidence=f"发现: {accessible[0][0]}",
                details={"found_paths": found}
            )
    
    return POCResult(
        poc_id="misconfig-admin-panel",
        name="管理后台暴露",
        vulnerable=False
    )


def check_default_credentials(url: str, **kwargs) -> POCResult:
    """检测默认凭据"""
    # 常见默认凭据
    default_creds = [
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "password"),
        ("root", "root"),
        ("test", "test"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
    ]
    
    # 常见登录端点
    login_endpoints = [
        ("/admin/login", "username", "password"),
        ("/login", "username", "password"),
        ("/user/login", "email", "password"),
        ("/api/login", "username", "password"),
    ]
    
    # 这里只做简单检测，不实际尝试登录（避免账户锁定）
    # 实际使用时需要谨慎
    
    return POCResult(
        poc_id="misconfig-default-creds",
        name="默认凭据检测",
        vulnerable=False,
        details={"note": "需要手动测试默认凭据"}
    )


def check_cors_misconfig(url: str, **kwargs) -> POCResult:
    """检测 CORS 配置错误"""
    try:
        # 测试任意 Origin
        headers = {"Origin": "https://evil.com"}
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == "*":
            return POCResult(
                poc_id="misconfig-cors",
                name="CORS 配置错误",
                vulnerable=True,
                severity=Severity.MEDIUM,
                evidence="Access-Control-Allow-Origin: *",
                details={"acao": acao, "acac": acac}
            )
        elif acao == "https://evil.com":
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            return POCResult(
                poc_id="misconfig-cors",
                name="CORS 配置错误",
                vulnerable=True,
                severity=severity,
                evidence=f"反射 Origin: {acao}, Credentials: {acac}",
                details={"acao": acao, "acac": acac}
            )
    except:
        pass
    
    return POCResult(
        poc_id="misconfig-cors",
        name="CORS 配置错误",
        vulnerable=False
    )


def check_server_info(url: str, **kwargs) -> POCResult:
    """检测服务器信息泄露"""
    try:
        resp = requests.get(url, timeout=10, verify=False)
        headers = resp.headers
        
        info = {}
        
        # Server 头
        if "Server" in headers:
            info["server"] = headers["Server"]
        
        # X-Powered-By
        if "X-Powered-By" in headers:
            info["powered_by"] = headers["X-Powered-By"]
        
        # X-AspNet-Version
        if "X-AspNet-Version" in headers:
            info["aspnet_version"] = headers["X-AspNet-Version"]
        
        # X-AspNetMvc-Version
        if "X-AspNetMvc-Version" in headers:
            info["aspnetmvc_version"] = headers["X-AspNetMvc-Version"]
        
        if info:
            return POCResult(
                poc_id="misconfig-server-info",
                name="服务器信息泄露",
                vulnerable=True,
                severity=Severity.INFO,
                evidence=", ".join([f"{k}={v}" for k, v in info.items()]),
                details=info
            )
    except:
        pass
    
    return POCResult(
        poc_id="misconfig-server-info",
        name="服务器信息泄露",
        vulnerable=False
    )


# 注册所有 POC
POCS = [
    POCInfo(
        id="misconfig-dir-listing",
        name="目录遍历",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["misconfig", "directory-listing"],
        description="检测目录遍历漏洞，可能暴露敏感文件",
        check_func=check_directory_listing
    ),
    POCInfo(
        id="misconfig-debug-mode",
        name="调试模式开启",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["misconfig", "debug", "error"],
        description="检测调试模式是否开启，可能泄露敏感信息",
        check_func=check_debug_mode
    ),
    POCInfo(
        id="misconfig-security-headers",
        name="安全头缺失",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.LOW,
        tags=["misconfig", "headers", "security"],
        description="检测关键安全头是否缺失",
        check_func=check_security_headers
    ),
    POCInfo(
        id="misconfig-admin-panel",
        name="管理后台暴露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["misconfig", "admin", "exposure"],
        description="检测管理后台是否暴露在公网",
        check_func=check_admin_panel
    ),
    POCInfo(
        id="misconfig-default-creds",
        name="默认凭据检测",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.HIGH,
        tags=["misconfig", "credentials", "default"],
        description="检测是否使用默认凭据",
        check_func=check_default_credentials
    ),
    POCInfo(
        id="misconfig-cors",
        name="CORS 配置错误",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["misconfig", "cors", "security"],
        description="检测 CORS 配置是否存在安全问题",
        check_func=check_cors_misconfig
    ),
    POCInfo(
        id="misconfig-server-info",
        name="服务器信息泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.INFO,
        tags=["misconfig", "info", "headers"],
        description="检测服务器版本信息泄露",
        check_func=check_server_info
    ),
]
