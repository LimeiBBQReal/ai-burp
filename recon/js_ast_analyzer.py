"""JS AST 深度分析器 — 真正的语法级分析.

能力:
  1. 函数调用图构建 (谁调用了谁)
  2. 字符串常量提取 (API 端点、密钥)
  3. 控制流平坦化检测 (OLLVM 风格)
  4. 混淆模式识别 (eval, atob, 十六进制字符串)

优先使用 esprima (Node.js), 不可用时回退到正则启发式.

输出: out/js_ast_detail.data.enc + key.enc
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from _common import _read_encrypted, write_encrypted, http_get

ROOT = Path(__file__).resolve().parent

# 混淆模式
OBFUSCATION_PATTERNS = {
    "eval_call": re.compile(r'\beval\s*\(', re.I),
    "atob_call": re.compile(r'\batob\s*\(', re.I),
    "btoa_call": re.compile(r'\bbtoa\s*\(', re.I),
    "function_constructor": re.compile(r'new\s+Function\s*\(', re.I),
    "hex_string": re.compile(r'\\x[0-9a-fA-F]{2}'),
    "unicode_escape": re.compile(r'\\u[0-9a-fA-F]{4}'),
    "string_concat_obfuscation": re.compile(r'(\+\s*["\']\w+["\']\s*){3,}'),
    "control_flow_flattening": re.compile(r'switch\s*\(\s*\w+\s*\)\s*\{[^}]*case\s+\d+:', re.S),
    "dead_code_injection": re.compile(r'if\s*\(\s*(?:false|0|!1|null)\s*\)', re.I),
    "variable_renaming": re.compile(r'\b(?:_0x[0-9a-f]{4,}|a-zA-Z_\$\{?\w*\}?)\b'),
    "packed_code": re.compile(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k', re.I),
}

# API 端点模式
API_PATTERNS = [
    re.compile(r"""["'](\/(?:api|v[0-9]+|graphql|rest|gateway|svc|service)\/[^"']{3,100})["']""", re.I),
    re.compile(r"""["']https?:\/\/[^"']{3,80}\/(?:api|v[0-9]+|graphql)[^"']{0,50}["']""", re.I),
    re.compile(r"""(?:url|endpoint|path|uri|route)\s*[:=]\s*["']([^"']{5,100})["']""", re.I),
]

# 密钥/Token 模式
SECRET_PATTERNS = {
    "jwt_token": re.compile(r'\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\b'),
    "api_key": re.compile(r"""(?:api[_-]?key|apikey|app[_-]?key)\s*[:=]\s*["']([a-zA-Z0-9_-]{16,64})["']""", re.I),
    "secret": re.compile(r"""(?:secret|password|passwd|token)\s*[:=]\s*["']([^"']{8,64})["']""", re.I),
    "aws_key": re.compile(r'(?:AKIA[0-9A-Z]{16}|aws[_-]?access[_-]?key[_-]?id)', re.I),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
}


def _check_esprima_available() -> bool:
    """检查 Node.js esprima 是否可用."""
    try:
        result = subprocess.run(
            ["node", "-e", "require('esprima')"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _analyze_with_esprima(js_content: str) -> dict[str, Any] | None:
    """使用 esprima 做真正的 AST 分析."""
    # 创建临时分析脚本
    analyzer_script = ROOT / "_esprima_analyzer.js"

    if not analyzer_script.exists():
        analyzer_script.write_text("""/* eslint-disable */
const esprima = require('esprima');

function analyze(code) {
    const result = {
        functions: [],
        calls: [],
        strings: [],
        complexity: 0,
        hasEval: false,
        hasFunctionConstructor: false,
    };

    try {
        const ast = esprima.parseScript(code, { tolerant: true, range: true });

        function walk(node, depth) {
            if (!node || typeof node !== 'object') return;

            if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') {
                const name = node.id ? node.id.name : '(anonymous)';
                result.functions.push({
                    name: name,
                    params: node.params.map(p => p.name || p.type),
                    range: node.range,
                });
            }

            if (node.type === 'CallExpression') {
                let callee = '';
                if (node.callee.type === 'Identifier') {
                    callee = node.callee.name;
                } else if (node.callee.type === 'MemberExpression') {
                    callee = node.callee.property ? node.callee.property.name : '';
                }
                if (callee) {
                    result.calls.push(callee);
                    if (callee === 'eval') result.hasEval = true;
                    if (callee === 'Function') result.hasFunctionConstructor = true;
                }
            }

            if (node.type === 'Literal' && typeof node.value === 'string') {
                if (node.value.length > 3 && node.value.length < 200) {
                    result.strings.push(node.value);
                }
            }

            for (const key in node) {
                if (key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(c => walk(c, depth + 1));
                } else if (child && typeof child === 'object' && child.type) {
                    walk(child, depth + 1);
                }
            }
        }

        walk(ast, 0);
        result.complexity = result.functions.length + result.calls.length;
    } catch (e) {
        result.error = e.message;
    }

    return result;
}

const fs = require('fs');
const code = fs.readFileSync(0, 'utf-8');
const result = analyze(code);
console.log(JSON.stringify(result));
""", encoding="utf-8")

    try:
        proc = subprocess.run(
            ["node", str(analyzer_script)],
            input=js_content,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
    except Exception:
        pass
    return None


def _analyze_with_regex(js_content: str) -> dict[str, Any]:
    """正则启发式分析 (esprima 不可用时的回退)."""
    result = {
        "functions": [],
        "calls": [],
        "strings": [],
        "complexity": 0,
        "hasEval": False,
        "hasFunctionConstructor": False,
    }

    # 提取函数定义
    func_matches = re.findall(
        r'function\s+(\w+)\s*\(([^)]*)\)',
        js_content,
    )
    for name, params in func_matches[:50]:
        result["functions"].append({
            "name": name,
            "params": [p.strip() for p in params.split(",") if p.strip()],
        })

    # 提取函数调用
    call_matches = re.findall(r'(\w+)\s*\(', js_content)
    result["calls"] = list(set(call_matches))[:100]
    result["hasEval"] = "eval" in result["calls"]
    result["hasFunctionConstructor"] = "Function" in result["calls"]

    # 提取字符串
    str_matches = re.findall(r"""["']([^"']{5,100})["']""", js_content)
    result["strings"] = list(set(str_matches))[:50]

    result["complexity"] = len(result["functions"]) + len(result["calls"])
    return result


def analyze_js(js_url: str, js_content: str) -> dict[str, Any]:
    """分析 JS 文件, 优先 esprima, 回退正则."""
    result = {
        "url": js_url,
        "size": len(js_content),
        "ast_method": "none",
        "ast_result": None,
        "obfuscation": {},
        "endpoints": [],
        "secrets": {},
        "risk_score": 0,
    }

    # 尝试 esprima
    esprima_result = _analyze_with_esprima(js_content)
    if esprima_result and not esprima_result.get("error"):
        result["ast_method"] = "esprima"
        result["ast_result"] = esprima_result
        result["risk_score"] += min(esprima_result.get("complexity", 0) // 10, 5)
        if esprima_result.get("hasEval"):
            result["risk_score"] += 3
        if esprima_result.get("hasFunctionConstructor"):
            result["risk_score"] += 2
    else:
        # 回退正则
        result["ast_method"] = "regex"
        result["ast_result"] = _analyze_with_regex(js_content)

    # 混淆检测
    for ob_name, ob_pattern in OBFUSCATION_PATTERNS.items():
        matches = ob_pattern.findall(js_content)
        if matches:
            result["obfuscation"][ob_name] = len(matches)
            if ob_name in ("eval_call", "function_constructor", "packed_code"):
                result["risk_score"] += 2
            elif ob_name == "control_flow_flattening":
                result["risk_score"] += 3

    # API 端点提取
    for api_pat in API_PATTERNS:
        api_matches = api_pat.findall(js_content)
        if api_matches:
            result["endpoints"].extend(api_matches[:10])
    result["endpoints"] = sorted(set(result["endpoints"]))[:20]

    # 密钥检测
    for sec_name, sec_pattern in SECRET_PATTERNS.items():
        sec_matches = sec_pattern.findall(js_content)
        if sec_matches:
            result["secrets"][sec_name] = len(sec_matches)
            result["risk_score"] += 5  # 密钥泄露高危

    return result


def fetch_and_analyze(js_url: str) -> dict[str, Any] | None:
    """下载并分析 JS."""
    r = http_get(js_url, timeout=10)
    if not r or r.status_code != 200:
        return {"url": js_url, "status": r.status_code if r else 0, "error": "fetch_failed"}

    content = r.text
    if len(content) < 200:
        return {"url": js_url, "status": r.status_code, "error": "too_small"}

    result = analyze_js(js_url, content)
    result["status"] = r.status_code
    return result


def main() -> int:
    print("[js-ast] 读取 urls", file=sys.stderr)
    udata = _read_encrypted("urls")
    target = udata.get("target", "")
    print(f"[js-ast] 目标: {target}", file=sys.stderr)

    # 检查 esprima 可用性
    esprima_ok = _check_esprima_available()
    print(f"[js-ast] esprima 可用: {esprima_ok}", file=sys.stderr)

    all_urls = udata.get("urls", [])
    js_urls = sorted(set(
        u for u in all_urls
        if any(u.lower().split("?")[0].endswith(ext) for ext in (".js", ".mjs"))
    ))

    if not js_urls:
        print("[js-ast] 未发现 JS 文件", file=sys.stderr)
        write_encrypted("js_ast_detail", {
            "target": target,
            "files_scanned": 0,
            "results": [],
            "elapsed_s": 0,
        })
        return 0

    print(f"[js-ast] JS 文件: {len(js_urls)}", file=sys.stderr)

    t0 = time.time()
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(fetch_and_analyze, u): u for u in js_urls[:30]}
        for fut in as_completed(futs):
            r = fut.result()
            if r and r.get("status") == 200:
                results.append(r)
                method = r.get("ast_method", "?")
                score = r.get("risk_score", 0)
                ob_count = len(r.get("obfuscation", {}))
                ep_count = len(r.get("endpoints", []))
                sec_count = len(r.get("secrets", {}))
                print(f"  [{method}] {r['url'][:70]}: "
                      f"score={score} obf={ob_count} ep={ep_count} sec={sec_count}",
                      file=sys.stderr)

    elapsed = time.time() - t0

    # 汇总
    total_risk = sum(r.get("risk_score", 0) for r in results)
    all_endpoints = set()
    all_obfuscations: dict[str, int] = {}
    all_secrets: dict[str, int] = {}
    for r in results:
        all_endpoints.update(r.get("endpoints", []))
        for k, v in r.get("obfuscation", {}).items():
            all_obfuscations[k] = all_obfuscations.get(k, 0) + v
        for k, v in r.get("secrets", {}).items():
            all_secrets[k] = all_secrets.get(k, 0) + v

    print(f"\n[js-ast] 扫描 {len(results)} 文件, 总风险: {total_risk}", file=sys.stderr)
    print(f"[js-ast] 端点: {len(all_endpoints)}, 混淆: {all_obfuscations}, 密钥: {all_secrets}",
          file=sys.stderr)

    write_encrypted("js_ast_detail", {
        "target": target,
        "files_scanned": len(js_urls),
        "files_analyzed": len(results),
        "ast_method": "esprima" if esprima_ok else "regex_fallback",
        "total_risk_score": total_risk,
        "endpoints_discovered": sorted(all_endpoints),
        "obfuscation_summary": all_obfuscations,
        "secrets_summary": all_secrets,
        "details": results,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
