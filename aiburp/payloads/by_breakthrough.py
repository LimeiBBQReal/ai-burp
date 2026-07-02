"""
突破口 payload_category → MultiChannelInjector vuln_type 映射.

不另建 payload 库, 不另写检测器,
只做一层翻译, 直接复用 MultiChannelInjector.scan_all()。

修复记录:
- redirect_open → 加 redirect_open vuln_type 支持 (Injector 已有 _detect_open_redirect)
- 保持向后兼容, 老调用方依然拿空 list 表示走专用验证
"""

# payload_category → injector vuln_type 列表
# 空 list = 不适用 injector, 走 _verify_special 专用验证
# 非空 list = 直接喂给 MultiChannelInjector.scan_all(vuln_types=...)
CATEGORY_TO_VULNTYPES = {
    # 路径/资源 ID → IDOR (改值测试)
    "idor": ["idor"],
    # SQL 注入
    "sqli_reflection": ["sqli"],
    "sqli_blind": ["sqli"],
    # XSS
    "xss_reflected": ["xss"],
    "xss_stored": [],                # 存储型 XSS injector 不具备, 走专用
    # SSRF
    "ssrf": ["ssrf"],
    # 文件读取/路径遍历
    "lfi": ["lfi"],
    "path_traversal": ["lfi"],
    # 命令/SSTI
    "cmdi": ["cmdi"],
    "ssti": ["ssti"],
    # 开放重定向 — 新增
    "redirect_open": ["redirect"],
    # JWT/上传/未授权/爆破 — 专用通道, 不用 injector
    "jwt_none": [],
    "jwt_weak_secret": [],
    "upload_bypass": [],
    "unauth_bypass": [],
    "auth_brute": [],
    "cors_misconfig": [],
    "api_discovery": [],
    "graphql_introspect": [],
    "no_auth_check": [],
}


def get_vuln_types(category: str) -> list:
    """
    payload_category → vuln_types 列表 (供 MultiChannelInjector.scan_all 用).

    返回空列表表示该类别不适用 injector, 需走专用验证方法.
    """
    return CATEGORY_TO_VULNTYPES.get(category, [])


# 兼容旧接口 (单数 + 单值)
CATEGORY_TO_VULNTYPE = {
    cat: (vts[0] if vts else None)
    for cat, vts in CATEGORY_TO_VULNTYPES.items()
}
