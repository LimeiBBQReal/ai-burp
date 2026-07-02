"""
L1 内置 POC: CMS 漏洞类

包含:
- WordPress 常见漏洞
- Drupal 常见漏洞
- Joomla 常见漏洞
- 其他 CMS
"""

import requests
import re
from urllib.parse import urljoin
from ..poc_manager import POCInfo, POCResult, POCLevel, Severity


# ==================== WordPress ====================

def check_wp_version(url: str, **kwargs) -> POCResult:
    """检测 WordPress 版本"""
    version = None
    
    # 方法1: readme.html
    try:
        resp = requests.get(urljoin(url, "/readme.html"), timeout=10, verify=False)
        if resp.status_code == 200 and "WordPress" in resp.text:
            match = re.search(r'Version\s*([\d.]+)', resp.text)
            if match:
                version = match.group(1)
    except:
        pass
    
    # 方法2: wp-links-opml.php
    if not version:
        try:
            resp = requests.get(urljoin(url, "/wp-links-opml.php"), timeout=10, verify=False)
            if resp.status_code == 200:
                match = re.search(r'generator="WordPress/([\d.]+)"', resp.text)
                if match:
                    version = match.group(1)
        except:
            pass
    
    # 方法3: feed
    if not version:
        try:
            resp = requests.get(urljoin(url, "/feed/"), timeout=10, verify=False)
            if resp.status_code == 200:
                match = re.search(r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>', resp.text)
                if match:
                    version = match.group(1)
        except:
            pass
    
    if version:
        # 检查是否是老版本 (简单判断)
        try:
            major = int(version.split('.')[0])
            minor = int(version.split('.')[1]) if len(version.split('.')) > 1 else 0
            is_old = major < 6 or (major == 6 and minor < 4)
        except:
            is_old = False
        
        return POCResult(
            poc_id="cms-wp-version",
            name="WordPress 版本检测",
            vulnerable=is_old,
            severity=Severity.MEDIUM if is_old else Severity.INFO,
            evidence=f"WordPress {version}" + (" (老版本)" if is_old else ""),
            details={"version": version, "is_old": is_old}
        )
    
    return POCResult(
        poc_id="cms-wp-version",
        name="WordPress 版本检测",
        vulnerable=False
    )


def check_wp_xmlrpc(url: str, **kwargs) -> POCResult:
    """检测 WordPress XML-RPC"""
    try:
        # 检查 xmlrpc.php 是否存在
        resp = requests.post(
            urljoin(url, "/xmlrpc.php"),
            data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
            headers={"Content-Type": "application/xml"},
            timeout=10,
            verify=False
        )
        
        if resp.status_code == 200 and "methodResponse" in resp.text:
            # 检查危险方法
            dangerous_methods = ["wp.getUsersBlogs", "wp.getUsers", "pingback.ping"]
            found_methods = []
            
            for method in dangerous_methods:
                if method in resp.text:
                    found_methods.append(method)
            
            return POCResult(
                poc_id="cms-wp-xmlrpc",
                name="WordPress XML-RPC 暴露",
                vulnerable=True,
                severity=Severity.MEDIUM,
                evidence=f"发现方法: {', '.join(found_methods[:3])}",
                details={"methods": found_methods}
            )
    except:
        pass
    
    return POCResult(
        poc_id="cms-wp-xmlrpc",
        name="WordPress XML-RPC 暴露",
        vulnerable=False
    )


def check_wp_user_enum(url: str, **kwargs) -> POCResult:
    """检测 WordPress 用户枚举"""
    users = []
    
    # 方法1: author 参数
    for i in range(1, 6):
        try:
            resp = requests.get(
                urljoin(url, f"/?author={i}"),
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            if resp.status_code in [301, 302]:
                location = resp.headers.get("Location", "")
                match = re.search(r'/author/([^/]+)/', location)
                if match:
                    users.append(match.group(1))
        except:
            continue
    
    # 方法2: REST API
    try:
        resp = requests.get(urljoin(url, "/wp-json/wp/v2/users"), timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            for user in data:
                if "slug" in user:
                    users.append(user["slug"])
    except:
        pass
    
    users = list(set(users))
    
    if users:
        return POCResult(
            poc_id="cms-wp-user-enum",
            name="WordPress 用户枚举",
            vulnerable=True,
            severity=Severity.LOW,
            evidence=f"发现用户: {', '.join(users[:5])}",
            details={"users": users}
        )
    
    return POCResult(
        poc_id="cms-wp-user-enum",
        name="WordPress 用户枚举",
        vulnerable=False
    )


def check_wp_debug_log(url: str, **kwargs) -> POCResult:
    """检测 WordPress debug.log 泄露"""
    try:
        resp = requests.get(urljoin(url, "/wp-content/debug.log"), timeout=10, verify=False)
        if resp.status_code == 200 and len(resp.text) > 100:
            # 检查是否是真实的 debug log
            if "PHP" in resp.text or "WordPress" in resp.text or "Error" in resp.text:
                return POCResult(
                    poc_id="cms-wp-debug-log",
                    name="WordPress debug.log 泄露",
                    vulnerable=True,
                    severity=Severity.HIGH,
                    evidence=f"文件大小: {len(resp.text)} bytes",
                    details={"size": len(resp.text), "preview": resp.text[:200]}
                )
    except:
        pass
    
    return POCResult(
        poc_id="cms-wp-debug-log",
        name="WordPress debug.log 泄露",
        vulnerable=False
    )


# ==================== Drupal ====================

def check_drupal_version(url: str, **kwargs) -> POCResult:
    """检测 Drupal 版本"""
    version = None
    
    # 方法1: CHANGELOG.txt
    try:
        resp = requests.get(urljoin(url, "/CHANGELOG.txt"), timeout=10, verify=False)
        if resp.status_code == 200 and "Drupal" in resp.text:
            match = re.search(r'Drupal\s+([\d.]+)', resp.text)
            if match:
                version = match.group(1)
    except:
        pass
    
    # 方法2: core/CHANGELOG.txt (Drupal 8+)
    if not version:
        try:
            resp = requests.get(urljoin(url, "/core/CHANGELOG.txt"), timeout=10, verify=False)
            if resp.status_code == 200:
                match = re.search(r'Drupal\s+([\d.]+)', resp.text)
                if match:
                    version = match.group(1)
        except:
            pass
    
    if version:
        # 检查是否是老版本
        try:
            major = int(version.split('.')[0])
            is_old = major < 10
        except:
            is_old = False
        
        return POCResult(
            poc_id="cms-drupal-version",
            name="Drupal 版本检测",
            vulnerable=is_old,
            severity=Severity.MEDIUM if is_old else Severity.INFO,
            evidence=f"Drupal {version}" + (" (老版本)" if is_old else ""),
            details={"version": version, "is_old": is_old}
        )
    
    return POCResult(
        poc_id="cms-drupal-version",
        name="Drupal 版本检测",
        vulnerable=False
    )


# ==================== Joomla ====================

def check_joomla_version(url: str, **kwargs) -> POCResult:
    """检测 Joomla 版本"""
    version = None
    
    # 方法1: administrator/manifests/files/joomla.xml
    try:
        resp = requests.get(urljoin(url, "/administrator/manifests/files/joomla.xml"), timeout=10, verify=False)
        if resp.status_code == 200:
            match = re.search(r'<version>([\d.]+)</version>', resp.text)
            if match:
                version = match.group(1)
    except:
        pass
    
    # 方法2: language/en-GB/en-GB.xml
    if not version:
        try:
            resp = requests.get(urljoin(url, "/language/en-GB/en-GB.xml"), timeout=10, verify=False)
            if resp.status_code == 200:
                match = re.search(r'<version>([\d.]+)</version>', resp.text)
                if match:
                    version = match.group(1)
        except:
            pass
    
    if version:
        try:
            major = int(version.split('.')[0])
            is_old = major < 5
        except:
            is_old = False
        
        return POCResult(
            poc_id="cms-joomla-version",
            name="Joomla 版本检测",
            vulnerable=is_old,
            severity=Severity.MEDIUM if is_old else Severity.INFO,
            evidence=f"Joomla {version}" + (" (老版本)" if is_old else ""),
            details={"version": version, "is_old": is_old}
        )
    
    return POCResult(
        poc_id="cms-joomla-version",
        name="Joomla 版本检测",
        vulnerable=False
    )


# ==================== 其他 CMS ====================

def check_moodle_version(url: str, **kwargs) -> POCResult:
    """检测 Moodle 版本"""
    version = None
    
    paths = ["/lib/upgrade.txt", "/INSTALL.txt", "/README.txt"]
    
    for path in paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=10, verify=False)
            if resp.status_code == 200 and "Moodle" in resp.text:
                match = re.search(r'Moodle\s+([\d.]+)', resp.text)
                if match:
                    version = match.group(1)
                    break
        except:
            continue
    
    if version:
        try:
            parts = version.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            is_old = major < 4 or (major == 4 and minor < 3)
        except:
            is_old = False
        
        return POCResult(
            poc_id="cms-moodle-version",
            name="Moodle 版本检测",
            vulnerable=is_old,
            severity=Severity.MEDIUM if is_old else Severity.INFO,
            evidence=f"Moodle {version}" + (" (老版本)" if is_old else ""),
            details={"version": version, "is_old": is_old}
        )
    
    return POCResult(
        poc_id="cms-moodle-version",
        name="Moodle 版本检测",
        vulnerable=False
    )


def check_whmcs_exposure(url: str, **kwargs) -> POCResult:
    """检测 WHMCS 敏感文件暴露"""
    findings = []
    
    sensitive_paths = [
        ("/admin/login.php", "管理后台"),
        ("/configuration.php", "配置文件"),
        ("/crons/cron.php", "Cron 脚本"),
        ("/crons/domainsync.php", "域名同步脚本"),
        ("/downloads/", "下载目录"),
    ]
    
    for path, desc in sensitive_paths:
        try:
            resp = requests.get(urljoin(url, path), timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                findings.append((path, desc))
        except:
            continue
    
    if findings:
        return POCResult(
            poc_id="cms-whmcs-exposure",
            name="WHMCS 敏感文件暴露",
            vulnerable=True,
            severity=Severity.MEDIUM,
            evidence=f"发现: {findings[0][0]} ({findings[0][1]})",
            details={"findings": findings}
        )
    
    return POCResult(
        poc_id="cms-whmcs-exposure",
        name="WHMCS 敏感文件暴露",
        vulnerable=False
    )


# 注册所有 POC
POCS = [
    # WordPress
    POCInfo(
        id="cms-wp-version",
        name="WordPress 版本检测",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.INFO,
        tags=["cms", "wordpress", "version"],
        description="检测 WordPress 版本，识别老版本",
        check_func=check_wp_version
    ),
    POCInfo(
        id="cms-wp-xmlrpc",
        name="WordPress XML-RPC 暴露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["cms", "wordpress", "xmlrpc"],
        description="检测 WordPress XML-RPC 接口是否暴露",
        check_func=check_wp_xmlrpc
    ),
    POCInfo(
        id="cms-wp-user-enum",
        name="WordPress 用户枚举",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.LOW,
        tags=["cms", "wordpress", "user-enum"],
        description="检测 WordPress 用户枚举漏洞",
        check_func=check_wp_user_enum
    ),
    POCInfo(
        id="cms-wp-debug-log",
        name="WordPress debug.log 泄露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.HIGH,
        tags=["cms", "wordpress", "info-leak"],
        description="检测 WordPress debug.log 文件泄露",
        check_func=check_wp_debug_log
    ),
    
    # Drupal
    POCInfo(
        id="cms-drupal-version",
        name="Drupal 版本检测",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.INFO,
        tags=["cms", "drupal", "version"],
        description="检测 Drupal 版本，识别老版本",
        check_func=check_drupal_version
    ),
    
    # Joomla
    POCInfo(
        id="cms-joomla-version",
        name="Joomla 版本检测",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.INFO,
        tags=["cms", "joomla", "version"],
        description="检测 Joomla 版本，识别老版本",
        check_func=check_joomla_version
    ),
    
    # Moodle
    POCInfo(
        id="cms-moodle-version",
        name="Moodle 版本检测",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.INFO,
        tags=["cms", "moodle", "version"],
        description="检测 Moodle 版本，识别老版本",
        check_func=check_moodle_version
    ),
    
    # WHMCS
    POCInfo(
        id="cms-whmcs-exposure",
        name="WHMCS 敏感文件暴露",
        level=POCLevel.L1_BUILTIN,
        severity=Severity.MEDIUM,
        tags=["cms", "whmcs", "exposure"],
        description="检测 WHMCS 敏感文件是否暴露",
        check_func=check_whmcs_exposure
    ),
]
