"""
针对性字典生成器 — 从域名/公司名生成密码组合.

对 phpMyAdmin 12 站同源场景, 传统通用字典 (rockyou.txt) 效率极低.
本模块利用目标属性生成精准的候选密码集:

    域名自体 → 域名+年份 → 域名+特殊字符 → 域名+年份+特殊字符
    → 大写变体 → 常见弱密码融合

典型产出: 200~500 条/域名, 但命中率远高于通用字典.
"""

import re
import itertools
from typing import List, Optional


# ============================================================
# 常见弱密码 Top 50 (融合)
# ============================================================

COMMON_WEAK_PASSWORDS = [
    "admin", "password", "1234567890", "root", "admin123",
    "root123", "admin1", "password1", "root1", "toor",
    "admin1234", "root1234", "changeme", "letmein", "passw0rd",
    "administrator", "Admin@123", "Root@123", "p@ssw0rd",
    "P@ssw0rd", "admin2024", "root2024", "Admin123!", "Root123!",
    "admin@123", "root@123", "Admin_123", "Root_123",
    "qwerty123", "12345678", "11111111", "00000000",
    "test123", "test@123", "demo123", "demo@123",
    "adminadmin", "rootroot", "pass123", "pass@123",
    "welcome1", "Welcome1", "Welcome@1", "Welcome123",
    "server", "server123", "Server@123", "hosting", "hosting123",
]

# 年份扩展
YEARS = ["2023", "2024", "2025", "2026", "2025!", "2026!"]

# 季节/月份风格
SEASONAL = ["Spring", "Summer", "Fall", "Winter",
            "spring", "summer", "fall", "winter",
            "January", "February", "March", "April",
            "May", "June", "July", "August"]

# 特殊字符集
SPECIAL = ["!", "@", "#", "$", "%", "&"]


class TargetedDictGenerator:
    """
    针对性字典生成器.

    用法:
        gen = TargetedDictGenerator()
        passwords = gen.from_domain("blastzone.org")
        # -> ["blastzone", "Blastzone", "BLASTZONE", "blastzone2025!", ...]

    也支持从公司名生成:
        passwords = gen.from_company("BlastZone Web Hosting")
    """

    @staticmethod
    def _extract_base(domain: str) -> str:
        """从域名提取核心名称: blastzone.org -> blastzone, www.example.com -> example"""
        name = domain.lower().strip()
        # 去掉 www.
        name = re.sub(r"^www\.", "", name)
        # 去掉 TLD (.com/.org/.net 等)
        name = re.sub(r"\.[a-z]{2,}(\.[a-z]{2,})?$", "", name)
        # 去掉连字符 (保留但也用作变体)
        return name

    @staticmethod
    def _extract_parts(domain: str) -> List[str]:
        """从域名提取可能的分段: blastzonewebhosting -> [blastzone, web, hosting]"""
        name = TargetedDictGenerator._extract_base(domain)
        # 如果有连字符, 按连字符拆分
        if "-" in name:
            return name.split("-")
        # 尝试按驼峰拆分 (如果包含大写字母)
        parts = re.findall(r"[a-z]+|[A-Z][a-z]*", name)
        if len(parts) > 1:
            return parts
        # 如果名称很长(>12), 尝试按常见前缀拆分
        if len(name) > 12:
            prefixes = ["admin", "web", "host", "server", "cloud",
                        "mail", "vpn", "dev", "test", "api", "app",
                        "panel", "billing", "support", "portal", "client"]
            for p in prefixes:
                if name.startswith(p) and len(name) > len(p) + 2:
                    return [p, name[len(p):]]
        return [name]

    @staticmethod
    def _capitalize(s: str) -> str:
        """首字母大写"""
        if not s:
            return s
        return s[0].upper() + s[1:]

    @staticmethod
    def _leet(s: str) -> str:
        """简单的 leet 变体: a->@, e->3, o->0, s->5, i->1"""
        result = s
        result = result.replace("a", "@").replace("A", "@")
        result = result.replace("e", "3").replace("E", "3")
        result = result.replace("o", "0").replace("O", "0")
        result = result.replace("s", "5").replace("S", "5")
        result = result.replace("i", "1").replace("I", "1")
        return result

    @classmethod
    def _base_variants(cls, base: str) -> List[str]:
        """对一个核心词生成各种大小写变体"""
        variants = set()
        variants.add(base.lower())
        variants.add(base.upper())
        variants.add(cls._capitalize(base.lower()))
        # 首字母大写 + 其余保持
        if len(base) > 1:
            variants.add(base[0].upper() + base[1:])
        # 全部小写
        variants.add(base.lower())
        return list(variants)

    @classmethod
    def from_domain(cls, domain: str, extend_common: bool = True,
                    include_leet: bool = False, top_n: int = 500) -> List[str]:
        """
        从域名生成针对性密码列表.

        Args:
            domain: 目标域名 (如 "blastzone.org")
            extend_common: 是否融合常见弱密码
            include_leet: 是否包含 leet 变体 (会增加数量)
            top_n: 返回前 N 条 (按相关性排序)

        Returns:
            去重密码列表
        """
        base = cls._extract_base(domain)
        parts = cls._extract_parts(domain)

        candidates: set = set()

        # 1. 基础变体
        for variant in cls._base_variants(base):
            candidates.add(variant)

        # 2. 各部分变体 + 组合
        for part in parts:
            for variant in cls._base_variants(part):
                candidates.add(variant)

        # 3. 各部分组合 (如果有多段)
        if len(parts) > 1:
            for p1, p2 in itertools.permutations(parts, 2):
                candidates.add(p1 + p2)
                candidates.add(cls._capitalize(p1) + p2)
                candidates.add(p1 + cls._capitalize(p2))
                candidates.add(cls._capitalize(p1) + cls._capitalize(p2))

        # 4. +年份
        for c in list(candidates):
            for y in YEARS:
                candidates.add(c + y)
                candidates.add(y + c)

        # 5. +特殊字符
        for c in list(candidates):
            for s in SPECIAL:
                candidates.add(c + s)
                candidates.add(s + c)

        # 6. +年份+特殊字符 (最常被用户使用的模式)
        for c in list(candidates):
            if any(y in c for y in YEARS):
                for s in SPECIAL:
                    candidates.add(c + s)

        # 7. 季节性变体
        for base_v in cls._base_variants(base):
            for season in SEASONAL:
                candidates.add(base_v + season)
                candidates.add(season + base_v)

        # 8. leet 变体 (可选)
        if include_leet:
            leet_candidates = set()
            for c in list(candidates):
                if len(c) <= 25:  # 避免太长
                    leet_candidates.add(cls._leet(c))
            candidates.update(leet_candidates)

        # 9. 融合常见弱密码
        if extend_common:
            candidates.update(COMMON_WEAK_PASSWORDS)

        # 10. 去重 + 排序 (长度优先, 典型的短密码更常见)
        result = sorted(candidates, key=lambda x: (len(x), x))
        return result[:top_n]

    @classmethod
    def from_company(cls, company: str, extend_common: bool = True,
                     top_n: int = 200) -> List[str]:
        """
        从公司名生成密码列表.

        Args:
            company: 公司名 (如 "BlastZone Web Hosting")
            extend_common: 是否融合常见弱密码
            top_n: 返回前 N 条
        """
        # 清理公司名: 只保留字母数字
        company_clean = re.sub(r"[^a-zA-Z0-9]", "", company).lower()
        # 按空格/特殊字符分词
        words = re.findall(r"[a-zA-Z0-9]+", company)

        candidates: set = set()

        # 整个名称的变体
        for variant in cls._base_variants(company_clean):
            candidates.add(variant)

        # 各单词的变体
        for word in words:
            word_lower = word.lower()
            if len(word_lower) >= 3:  # 忽略太短的词
                for v in cls._base_variants(word_lower):
                    candidates.add(v)

        # 单词组合
        if len(words) >= 2:
            for w1, w2 in itertools.permutations(words, 2):
                w1l, w2l = w1.lower(), w2.lower()
                candidates.add(w1l + w2l)
                candidates.add(cls._capitalize(w1l) + w2l)
                candidates.add(cls._capitalize(w1l) + cls._capitalize(w2l))

        # +年份 + 特殊字符 (同域名逻辑)
        for c in list(candidates):
            for y in YEARS:
                candidates.add(c + y)
            for s in SPECIAL:
                candidates.add(c + s)

        if extend_common:
            candidates.update(COMMON_WEAK_PASSWORDS)

        result = sorted(candidates, key=lambda x: (len(x), x))
        return result[:top_n]

    @classmethod
    def from_domain_list(cls, domains: List[str], top_n: int = 500) -> List[str]:
        """
        从多个域名联合生成密码列表 (12 站同源场景).

        这些域名共享同一个主机 (blastzonewebhosting.com),
        因此密码可能跨站复用.

        Args:
            domains: 域名列表
            top_n: 返回前 N 条
        """
        all_passwords: set = set()
        for domain in domains:
            pwds = cls.from_domain(domain, extend_common=False, top_n=top_n)
            all_passwords.update(pwds)

        # 最后融合一次常见密码
        all_passwords.update(COMMON_WEAK_PASSWORDS)
        # 按 1)常见词优先 2)长度 排序
        def sort_key(p):
            score = 0
            if p in COMMON_WEAK_PASSWORDS:
                score = -100  # 常见词排最前
            return (score, len(p), p)
        result = sorted(all_passwords, key=sort_key)
        return result[:top_n]

    @classmethod
    def guess_usernames(cls, domain: str) -> List[str]:
        """
        从域名猜测可能的管理员用户名.

        phpMyAdmin 常见用户名:
            - admin, root, blastzone (域名前缀)
            - 域名前缀+admin, admin@域名前缀
        """
        base = cls._extract_base(domain)
        # 去掉可能的 "webhosting" / "hosting" 后缀
        base_short = re.sub(r"(web)?hosting$", "", base) or base

        usernames = set()
        usernames.add("admin")
        usernames.add("root")
        usernames.add("administrator")
        usernames.add(base)
        usernames.add(base_short)
        usernames.add(base + "_admin")
        usernames.add(base_short + "_admin")
        usernames.add("admin@" + base)
        usernames.add("admin_" + base)
        # 如果是共享主机, 客户常用用户名模式
        usernames.add(base_short + "user")
        usernames.add(base_short + "1")
        usernames.add(base_short + "123")

        result = sorted(usernames, key=lambda x: (len(x), x))
        return result


# ============================================================
# 快捷函数
# ============================================================

def generate_dict(domain: str, top_n: int = 500) -> List[str]:
    """从域名生成针对性字典的快捷函数."""
    return TargetedDictGenerator.from_domain(domain, top_n=top_n)


def generate_usernames(domain: str) -> List[str]:
    """从域名猜测用户名的快捷函数."""
    return TargetedDictGenerator.guess_usernames(domain)


def generate_multi_dict(domains: List[str], top_n: int = 500) -> List[str]:
    """从多个域名联合生成字典的快捷函数."""
    return TargetedDictGenerator.from_domain_list(domains, top_n=top_n)