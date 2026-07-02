#!/usr/bin/env python3
"""
HTTP Headers 对比分析脚本
分析同一站点不同路径的 HTTP 头差异
"""
import sys
import os
import json
import warnings
import urllib3

urllib3.disable_warnings()
warnings.filterwarnings('ignore')

import requests

def get_headers(url, method='GET', timeout=15):
    """获取 HTTP 响应头"""
    try:
        if method == 'GET':
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        elif method == 'POST':
            r = requests.post(url, timeout=timeout, verify=False, allow_redirects=False)
        elif method == 'OPTIONS':
            r = requests.options(url, timeout=timeout, verify=False, allow_redirects=False)
        elif method == 'HEAD':
            r = requests.head(url, timeout=timeout, verify=False, allow_redirects=False)
        else:
            r = requests.request(method, url, timeout=timeout, verify=False, allow_redirects=False)
        
        return {
            'status': r.status_code,
            'headers': dict(r.headers),
            'size': len(r.content) if method != 'HEAD' else 0,
        }
    except Exception as e:
        return {'error': str(e)}


def compare_headers(base_url, paths):
    """对比多个路径的 HTTP 头"""
    results = {}
    all_headers = set()
    
    print(f"\n{'='*70}")
    print(f"🔍 HTTP Headers 对比分析: {base_url}")
    print(f"{'='*70}\n")
    
    # 收集所有路径的头
    for path in paths:
        url = base_url.rstrip('/') + path
        print(f"📡 {path}...", end=" ")
        
        result = get_headers(url)
        results[path] = result
        
        if 'headers' in result:
            all_headers.update(result['headers'].keys())
            print(f"✅ {result['status']}")
        else:
            print(f"❌ {result.get('error', 'Unknown error')}")
    
    # 分析差异
    print(f"\n{'='*70}")
    print("📊 Headers 差异分析")
    print(f"{'='*70}\n")
    
    # 找出所有路径都有的头
    common_headers = {}
    varying_headers = {}
    unique_headers = {}
    
    for header in sorted(all_headers):
        values = {}
        for path, result in results.items():
            if 'headers' in result:
                # 不区分大小写查找
                for h, v in result['headers'].items():
                    if h.lower() == header.lower():
                        values[path] = v
                        break
        
        if len(values) == len([r for r in results.values() if 'headers' in r]):
            # 所有路径都有这个头
            unique_values = set(values.values())
            if len(unique_values) == 1:
                common_headers[header] = list(unique_values)[0]
            else:
                varying_headers[header] = values
        elif len(values) > 0:
            unique_headers[header] = values
    
    # 输出结果
    print("🟢 所有路径相同的 Headers:")
    print("-" * 50)
    for h, v in sorted(common_headers.items()):
        v_display = v[:60] + "..." if len(str(v)) > 60 else v
        print(f"  {h}: {v_display}")
    
    print(f"\n🟡 不同路径值不同的 Headers:")
    print("-" * 50)
    for h, values in sorted(varying_headers.items()):
        print(f"  {h}:")
        for path, v in values.items():
            v_display = v[:50] + "..." if len(str(v)) > 50 else v
            print(f"    {path}: {v_display}")
    
    print(f"\n🔴 仅部分路径有的 Headers:")
    print("-" * 50)
    for h, values in sorted(unique_headers.items()):
        print(f"  {h}:")
        for path, v in values.items():
            v_display = v[:50] + "..." if len(str(v)) > 50 else v
            print(f"    {path}: {v_display}")
    
    # 安全头分析
    print(f"\n{'='*70}")
    print("🔒 安全头分析")
    print(f"{'='*70}\n")
    
    security_headers = [
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Referrer-Policy',
        'Permissions-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
    ]
    
    for path, result in results.items():
        if 'headers' not in result:
            continue
        print(f"\n📄 {path}:")
        headers_lower = {k.lower(): v for k, v in result['headers'].items()}
        for sh in security_headers:
            if sh.lower() in headers_lower:
                print(f"  ✅ {sh}: {headers_lower[sh.lower()][:50]}...")
            else:
                print(f"  ❌ {sh}: Missing")
    
    return {
        'common': common_headers,
        'varying': varying_headers,
        'unique': unique_headers,
    }


def main():
    # Moodle 站点测试
    moodle_paths = [
        '/',
        '/login/index.php',
        '/lib/db/install.xml',
        '/webservice/rest/server.php',
        '/admin/',
        '/course/',
        '/user/',
        '/mod/',
        '/theme/',
        '/pluginfile.php/1/theme_adaptable/favicon/1640795195/hbl%20favicon.jpg',
    ]
    
    print("\n" + "="*70)
    print("🎯 Training.heritageibt.com (Moodle) Headers 分析")
    print("="*70)
    
    moodle_result = compare_headers('https://training.heritageibt.com', moodle_paths)
    
    # Platform 站点测试
    platform_paths = [
        '/',
        '/api/',
        '/api/v1/',
        '/health',
        '/swagger',
    ]
    
    print("\n" + "="*70)
    print("🎯 Platform.heritageibt.com Headers 分析")
    print("="*70)
    
    platform_result = compare_headers('https://platform.heritageibt.com', platform_paths)
    
    # Secure 站点测试
    secure_paths = [
        '/',
        '/web/',
        '/api/',
        '/login',
    ]
    
    print("\n" + "="*70)
    print("🎯 Secure.heritageibt.com (Banking) Headers 分析")
    print("="*70)
    
    secure_result = compare_headers('https://secure.heritageibt.com', secure_paths)
    
    # 测试不同 HTTP 方法
    print("\n" + "="*70)
    print("🎯 HTTP 方法差异分析 (training.heritageibt.com)")
    print("="*70 + "\n")
    
    methods = ['GET', 'POST', 'OPTIONS', 'HEAD', 'PUT', 'DELETE', 'PATCH']
    url = 'https://training.heritageibt.com/login/index.php'
    
    for method in methods:
        result = get_headers(url, method=method)
        if 'headers' in result:
            allow = result['headers'].get('Allow', 'N/A')
            server = result['headers'].get('Server', 'N/A')
            print(f"  {method:8} -> {result['status']} | Allow: {allow} | Server: {server}")
        else:
            print(f"  {method:8} -> Error: {result.get('error', 'Unknown')}")


if __name__ == "__main__":
    main()
