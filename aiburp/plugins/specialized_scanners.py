"""
AI-Burp Specialized Scanners
各种专项漏洞扫描逻辑 (IDOR, Header Injection, API Testing, etc.)
"""

import json
import time
import re
import urllib.parse
from typing import Dict, List, Optional, Any
from ..constants import SQL_ERRORS, WAF_SIGNATURES

def test_header_injection(burp, url, headers, cookie=None, types=None):
    """HTTP 头注入测试"""
    if types is None:
        types = ["sqli"]
    
    lines = ["=" * 50, "🔧 HTTP 头注入测试", "=" * 50, ""]
    baseline = burp.get(url)
    lines.append(f"📊 基线: [{baseline.status}] {baseline.length}b {baseline.time_ms:.0f}ms\n")
    
    payload_map = {
        "sqli": ["'", "' OR '1'='1", "1' AND SLEEP(3)--", "\" OR \"1\"=\"1"],
        "xss": ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"],
        "ssrf": ["http://127.0.0.1", "http://169.254.169.254/"],
        "cmdi": ["; sleep 3", "| id", "$(whoami)"],
    }
    
    findings = []
    for header in headers:
        lines.append(f"🔍 测试头: {header}")
        for vuln_type in types:
            for payload in payload_map.get(vuln_type, []):
                r = burp.request("GET", url, headers={header: payload})
                if r.error or r.time_ms > baseline.time_ms + 2500 or payload in r.body:
                    findings.append({"header": header, "payload": payload, "type": vuln_type})
                    lines.append(f"   ⚠️ [{vuln_type}] {payload[:30]}... → Detected")
                time.sleep(burp.delay)
    return "\n".join(lines)

def test_idor(burp, url, range_str="1-100", wordlist=None, diff_threshold=50):
    """IDOR 枚举测试"""
    marker = "§"
    if marker not in url: return "❌ URL 中需要包含 § 标记枚举点"
    
    test_values = []
    if range_str:
        start, end = map(int, range_str.split("-"))
        test_values = [str(i) for i in range(start, end + 1)]
    
    baseline_url = url.replace(marker, test_values[0])
    baseline = burp.get(baseline_url)
    
    found = []
    for val in test_values:
        r = burp.get(url.replace(marker, val))
        if r.status == 200 and (baseline.status != 200 or abs(r.length - baseline.length) > diff_threshold):
            found.append({"value": val, "status": r.status, "length": r.length})
        time.sleep(burp.delay * 0.1)
    return f"Found {len(found)} potential IDORs"

def test_api_json(burp, url, body, param, method="POST", headers=None):
    """JSON API 参数测试 (支持嵌套)"""
    try:
        json_data = json.loads(body)
    except: return "❌ JSON 解析错误"
    
    custom_headers = {"Content-Type": "application/json"}
    if headers: 
        for h in headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    baseline = burp.request(method, url, headers=custom_headers, data=body)
    payloads = ["'", "\"", "' OR '1'='1", "1' AND SLEEP(3)--"]
    
    findings = []
    for payload in payloads:
        test_data = json.loads(body)
        _set_nested_value(test_data, param, payload)
        r = burp.request(method, url, headers=custom_headers, data=json.dumps(test_data))
        if r.error or r.time_ms > baseline.time_ms + 2500:
            findings.append({"payload": payload, "status": r.status})
    return f"API Test Done, Found {len(findings)} anomalies"

def _get_nested_value(data, key):
    keys = key.split(".")
    value = data
    for k in keys:
        if isinstance(value, dict) and k in value: value = value[k]
        else: return None
    return value

def _set_nested_value(data, key, value):
    keys = key.split(".")
    obj = data
    for k in keys[:-1]:
        if isinstance(obj, dict) and k in obj: obj = obj[k]
        else: return
    if isinstance(obj, dict): obj[keys[-1]] = value
