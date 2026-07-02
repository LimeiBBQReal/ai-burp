"""
AI-Burp 全局常量与模式定义
集中管理所有的 WAF 指纹、数据库错误和敏感信息正则
"""

import re

# ============================================================
#                      1. 数据库错误模式
# ============================================================
SQL_ERRORS = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"Warning.*mysqli_",
        r"You have an error in your SQL syntax",
        r"MySqlException",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"pg_query",
        r"PSQLException",
    ],
    "mssql": [
        r"Microsoft.*ODBC",
        r"SQL Server",
        r"Driver.* SQL",
        r"OLE DB.* SQL Server",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"Oracle error",
        r"OracleException",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
    ],
    "syntax": [
        r"syntax error",
        r"unclosed quotation",
    ]
}

# ============================================================
#                      2. WAF / 拦截模式
# ============================================================
WAF_SIGNATURES = {
    "cloudflare": [r"cloudflare", r"CF-RAY"],
    "akamai": [r"AkamaiGhost", r"akamai"],
    "sucuri": [r"Sucuri/Cloudproxy"],
    "imperva": [r"incapsula", r"visid_incap"],
    "aws_waf": [r"awselb/2.0"],
    "generic": [r"forbidden", r"blocked", r"access denied", r"request rejected"],
}

# ============================================================
#                      3. 敏感信息泄露模式
# ============================================================
SENSITIVE_PATTERNS = {
    # email 正则含 [a-z0-9._+-]* 量词, 在无 @ 的长文本上会灾难性回溯 (ReDoS).
    # 调用方 (IntentAnalyzer) 会先做 '@' in text 前置检查再跑此正则,
    # 这里只保证 "有 @ 时" 的匹配准确性.
    "email": r"[a-zA-Z0-9][a-zA-Z0-9._+-]{1,64}@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,6}",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    # JWT: 要求三段都是 base64url 且每段 >= 10 字符 (避免 ey.x.y 误匹配)
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "private_key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "path_disclosure": [r"/var/www", r"c:\\", r"/home/", r"\\inetpub", r"/usr/", r"\\windows\\"],
}

# ============================================================
#                      4. 语义画像关键词
# ============================================================
INTENT_KEYWORDS = {
    "AUTH": [r"\blogin\b", r"\bauth\b", r"sign[_-]?in", r"\bpwd\b", r"password", r"\btoken\b", r"session"],
    "FILE": [r"download", r"upload", r"\bfile\b", r"\bpath\b", r"\btemp\b", r"\bpdf\b", r"image", r"export"],
    # DB: 短词 (id/data) 加词边界, 避免匹配 video/provide/consider
    "DB": [r"\bid\b", r"uuid", r"query", r"search", r"\blist\b", r"find", r"\bdata\b"],
    "ADMIN": [r"\badmin\b", r"manage", r"\bconfig\b", r"\bsetting\b", r"\broot\b", r"\bsystem\b"],
    "REDIRECT": [r"\burl\b", r"redirect", r"callback", r"\bnext\b", r"goto", r"\breturn\b"],
    # CMD: run/exec 加词边界, 避免 running/executive
    "CMD": [r"\bexec\b", r"\brun\b", r"\bping\b", r"shell", r"command", r"\bcalc\b"],
}

# ============================================================
# 5. 多协议语义标签 (V4 IntentAnalyzer 扩展)
# ============================================================
# 协议/服务 -> 攻击意图标签的映射.
# 用于 TrafficResponse 的 protocol/banner/tags 推断攻击价值.

# 高危未授权服务 (确认存在 = 直接 RCE 路径)
HIGH_VALUE_SERVICES = {
    "redis", "docker", "kubelet", "mongodb", "memcached",
    "elasticsearch", "consul", "etcd", "zookeeper",
    "snmp",            # M4: 默认 community = 内网全景泄露
    "mysql",           # M5: 弱口令 -> UDF RCE / 数据导出
    "rmi",             # M5: 反序列化 RCE (ysoserial)
    "smb",             # M5: EternalBlue / 空会话 / 横向移动
}

# 服务 -> 典型攻击向量 (供 suggest_next_steps 推荐)
SERVICE_ATTACK_VECTORS = {
    "redis": [
        ("check_unauth", "Redis 未授权检测 (PING+INFO+CONFIG)"),
        ("dump_ssh_key", "写 SSH authorized_keys"),
        ("slaveof_rce", "主从复制 RCE (SLAVEOF + module load)"),
        ("write_webshell", "写 webshell 到 web 目录"),
        ("write_cron", "写 cron 反弹 shell"),
    ],
    "docker": [
        ("check_unauth", "Docker API 未授权检测 (/version+/containers)"),
        ("priv_container_rce", "创建特权容器挂载宿主机 (确定性 RCE)"),
        ("container_escape", "容器逃逸检测"),
    ],
    "kubelet": [
        ("check_unauth", "Kubelet 10250/10255 未授权检测"),
        ("exec_in_pod", "POST /run 在容器内执行命令 (RCE)"),
        ("dump_pod_secrets", "读取 Pod 环境变量里的 K8s Secret"),
        ("service_account_token", "窃取 ServiceAccount Token 访问 K8s API"),
    ],
    "ssh": [
        ("weak_creds", "弱口令爆破 (root/admin/user)"),
        ("known_exploit", "已知 CVE 检测 (CVE-2024-6387 等)"),
    ],
    "mysql": [
        ("check_unauth", "MySQL 弱口令爆破 (root/admin + 常见密码)"),
        ("udf_rce", "UDF 提权 RCE (上传 lib_mysqludf_sys)"),
        ("dump_database", "数据库数据导出"),
        ("write_webshell", "写 webshell 到 web 目录 (into outfile)"),
        ("read_files", "读取敏感文件 (load_file)"),
    ],
    "mssql": [
        ("weak_creds", "弱口令爆破 (sa)"),
        ("xp_cmdshell", "xp_cmdshell 命令执行"),
    ],
    "mongodb": [
        ("check_unauth", "未授权访问检测 (默认无密码)"),
        ("dump_data", "数据库数据导出"),
    ],
    "ftp": [
        ("anonymous", "匿名登录检测"),
        ("bounce_scan", "FTP bounce 端口扫描"),
    ],
    "smtp": [
        ("open_relay", "开放中继检测"),
        ("user_enum", "用户名枚举 (VRFY/EXPN)"),
    ],
    "snmp": [
        ("check_unauth", "SNMP 默认 community 检测 (public/private/cisco)"),
        ("dump_full_tree", "完整 MIB 树导出 (路由表/ARP/进程)"),
        ("weak_communities", "弱 community 字典爆破"),
        ("snmp_rce_check", "SNMP RCE 漏洞检测 (CVE-2017-6736 等)"),
    ],
    "rmi": [
        ("check_deserial", "RMI 反序列化风险检测 (ysoserial 入口)"),
        ("ysoserial_exploit", "用 ysoserial RMI payload 验证 RCE"),
        ("jmx_check", "JMX 接口检测 (CVE-2015-8103)"),
    ],
    "smb": [
        ("check_null_session", "空会话枚举 (用户/共享/域信息)"),
        ("check_unauth", "弱口令爆破 (Administrator/guest)"),
        ("ms17_010", "EternalBlue (MS17-010) RCE 检测"),
        ("pass_the_hash", "Pass-the-Hash 横向移动"),
        ("share_enum", "共享目录枚举 + 敏感文件搜索"),
    ],
}

# 协议 -> 默认风险等级 (供 smart_probe 排序)
PROTOCOL_RISK = {
    "redis": 10, "docker": 10, "kubelet": 10,  # 直接 RCE
    "mongodb": 8, "elasticsearch": 8,          # 数据泄露 + 可能 RCE
    "mysql": 7, "mssql": 7,                    # 数据 + 可能 RCE
    "ssh": 6, "ftp": 5, "smtp": 4,             # 横向移动
    "dns": 5,                                  # 信息泄露 + 隧道
    "ws": 5,                                   # CSWSH + 注入
    "http": 3, "https": 3,                     # 需进一步分析
    "tcp": 2,                                  # 未知, 需指纹
}
