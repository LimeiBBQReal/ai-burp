"""JS 签名/加密函数识别与 AST 启发式分析.

分析目标:
  1. 前端请求签名逻辑 (timestamp + sign / MD5(param+key) 等)
  2. 反爬 Token 生成
  3. API 端点隐藏参数规律

工作流:
  1. 从 urls.data.enc 中筛选 .js 文件
  2. 对每个 JS 做下载 + 正则/AST 启发式分析
  3. 输出签名模式指纹 + 关键代码片段

输出:
  out/js_signatures.data.enc + key.enc
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from _common import _read_encrypted, write_encrypted, http_get

# 签名模式正则库
SIGN_PATTERNS = {
    "md5_sign": {
        "pattern": re.compile(r'(?:md5|MD5)\s*\(\s*([^)]+)\s*\)', re.I),
        "description": "MD5(param + key) 签名",
        "severity": "high",
    },
    "sha256_hmac": {
        "pattern": re.compile(r'(?:hmac|SHA256|sha256)\s*\(\s*([^)]+)\s*\)', re.I),
        "description": "HMAC-SHA256 签名",
        "severity": "high",
    },
    "timestamp_param": {
        "pattern": re.compile(r'(?:timestamp|_t|ts|time)\s*[:=]\s*(Date\.now\(\)|new Date|parseInt)', re.I),
        "description": "时间戳参数生成",
        "severity": "medium",
    },
    "sign_param": {
        "pattern": re.compile(r'(?:sign|signature|_sign)\s*[:=]\s*', re.I),
        "description": "sign/signature 参数赋值",
        "severity": "high",
    },
    "base64_encode": {
        "pattern": re.compile(r'(?:btoa|atob|base64|Base64|encodeURIComponent)\s*\(', re.I),
        "description": "Base64/URL 编码",
        "severity": "medium",
    },
    "aes_encrypt": {
        "pattern": re.compile(r'(?:AES|aes|CryptoJS|crypto\.subtle)\s*\.', re.I),
        "description": "AES 加密",
        "severity": "high",
    },
    "param_sort": {
        "pattern": re.compile(r'(?:params|data|args)\s*\.sort|\.sort\(\s*\(\s*\)', re.I),
        "description": "参数排序 (签名前准备)",
        "severity": "medium",
    },
    "append_secret": {
        "pattern": re.compile(r'(?:secret|key|token|salt|appkey)\s*[\+\&]', re.I),
        "description": "密钥/盐值拼接",
        "severity": "high",
    },
    "xor_obfuscate": {
        "pattern": re.compile(r'\^\s*(?:0x[0-9a-fA-F]+|\d+)', re.I),
        "description": "XOR 混淆",
        "severity": "medium",
    },
    "api_endpoint": {
        "pattern": re.compile(r'["\'](/(?:api|v[0-9]+|gateway)/[^"\']*)["\']', re.I),
        "description": "API 端点路径",
        "severity": "info",
    },
}


def analyze_js_content(js_url: str, content: str) -> dict[str, Any]:
    """分析 JS 内容的签名特征."""
    result = {
        "url": js_url,
        "size": len(content),
        "patterns": {},
        "endpoints": set(),
        "suspicious_snippets": [],
        "risk_score": 0,
    }

    for sign_name, sign_info in SIGN_PATTERNS.items():
        matches = sign_info["pattern"].findall(content)
        if matches:
            # 去重并限制数量
            unique_matches = list(set(matches[:5]))
            result["patterns"][sign_name] = {
                "description": sign_info["description"],
                "severity": sign_info["severity"],
                "count": len(matches),
                "samples": unique_matches,
            }
            # 根据 severity 增加风险分
            if sign_info["severity"] == "high":
                result["risk_score"] += 3
            elif sign_info["severity"] == "medium":
                result["risk_score"] += 1

    # 提取 API 端点
    api_matches = re.findall(
        r"""["'](/[a-zA-Z0-9_\-/]+(?:api|v\d+|auth|login|sign|upload|pay|order)[a-zA-Z0-9_\-/]*)["']""",
        content,
        re.I,
    )
    if api_matches:
        result["endpoints"] = sorted(set(api_matches[:20]))

    # 提取可疑代码片段 (只保留前 80 字符)
    for pattern_name, sign_info in SIGN_PATTERNS.items():
        if sign_info["severity"] == "high":
            for match in sign_info["pattern"].finditer(content):
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                snippet = content[start:end].replace("\n", "\\n").strip()
                result["suspicious_snippets"].append(snippet[:120])
                if len(result["suspicious_snippets"]) >= 10:
                    break
            if len(result["suspicious_snippets"]) >= 10:
                break

    result["suspicious_snippets"] = result["suspicious_snippets"][:10]
    return result


def fetch_and_analyze(js_url: str) -> dict[str, Any] | None:
    """下载并分析一个 JS 文件."""
    r = http_get(js_url, timeout=10)
    if not r or r.status_code != 200:
        return {"url": js_url, "status": r.status_code if r else 0, "error": "fetch_failed"}

    content = r.text
    if len(content) < 100:
        return {"url": js_url, "status": r.status_code, "error": "too_small"}

    result = analyze_js_content(js_url, content)
    result["status"] = r.status_code
    return result


def main() -> int:
    print("[js-sign] 读取 urls", file=sys.stderr)
    udata = _read_encrypted("urls")
    target = udata.get("target", "")
    print(f"[js-sign] 目标: {target}", file=sys.stderr)

    all_urls = udata.get("urls", [])
    js_urls = sorted(set(
        u for u in all_urls
        if any(u.lower().split("?")[0].endswith(ext) for ext in (".js", ".mjs"))
    ))

    if not js_urls:
        print("[js-sign] 未发现 JS 文件", file=sys.stderr)
        write_encrypted("js_signatures", {
            "target": target,
            "files_scanned": 0,
            "signatures": [],
            "elapsed_s": 0,
        })
        return 0

    print(f"[js-sign] JS 文件: {len(js_urls)}", file=sys.stderr)

    t0 = time.time()
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(fetch_and_analyze, u): u for u in js_urls[:50]}
        for fut in as_completed(futs):
            r = fut.result()
            if r and r.get("status") == 200 and r.get("risk_score", 0) > 0:
                results.append(r)
                patterns_str = ", ".join(r.get("patterns", {}).keys())
                print(f"  [SIG] {r['url'][:80]}: score={r['risk_score']} "
                      f"patterns=[{patterns_str}]", file=sys.stderr)
            elif r and r.get("status") == 200:
                print(f"  [--] {r['url'][:80]}: no sig patterns", file=sys.stderr)

    elapsed = time.time() - t0

    # 合并所有发现的端点
    all_endpoints: set[str] = set()
    all_pattern_types: dict[str, int] = {}
    for r in results:
        all_endpoints.update(r.get("endpoints", []))
        for pname, pinfo in r.get("patterns", {}).items():
            all_pattern_types[pname] = all_pattern_types.get(pname, 0) + pinfo["count"]

    print(f"\n[js-sign] 扫描 {len(js_urls)} 文件, {len(results)} 含签名模式", file=sys.stderr)
    print(f"[js-sign] 发现端点: {len(all_endpoints)}, 模式类型: {all_pattern_types}", file=sys.stderr)

    # 转换 set → list 以便 JSON 序列化
    for r in results:
        r["endpoints"] = sorted(r.get("endpoints", []))

    write_encrypted("js_signatures", {
        "target": target,
        "files_scanned": len(js_urls),
        "files_with_signatures": len(results),
        "risk_summary": {
            "total_risk_score": sum(r.get("risk_score", 0) for r in results),
            "pattern_frequency": all_pattern_types,
        },
        "endpoints_discovered": sorted(all_endpoints),
        "details": results,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
