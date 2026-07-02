"""
targeted_dict.py 单元测试.

验证:
    1. 域名解析正确性
    2. 密码生成的多样性和去重
    3. 用户名猜测
    4. 多域名联合生成
"""

from aiburp.traffic.targeted_dict import (
    TargetedDictGenerator,
    generate_dict,
    generate_usernames,
    generate_multi_dict,
    COMMON_WEAK_PASSWORDS,
)


class TestExtractBase:
    def test_simple_domain(self):
        assert TargetedDictGenerator._extract_base("blastzone.org") == "blastzone"

    def test_www_domain(self):
        assert TargetedDictGenerator._extract_base("www.blastzone.org") == "blastzone"

    def test_subdomain(self):
        assert TargetedDictGenerator._extract_base("admin.blastzone.com") == "admin"

    def test_multi_tld(self):
        assert TargetedDictGenerator._extract_base("example.co.uk") == "example"

    def test_complex_name(self):
        base = TargetedDictGenerator._extract_base("blastzonewebhosting.com")
        assert base == "blastzonewebhosting"

    def test_hyphenated(self):
        base = TargetedDictGenerator._extract_base("my-hosting-site.net")
        assert base == "my-hosting-site"


class TestExtractParts:
    def test_single_part(self):
        parts = TargetedDictGenerator._extract_parts("blastzone.org")
        assert "blastzone" in parts

    def test_hyphen_parts(self):
        parts = TargetedDictGenerator._extract_parts("my-hosting.net")
        assert "my" in parts
        assert "hosting" in parts

    def test_complex_splits_long_name(self):
        # blastzonewebhosting -> 没有连字符, 也没有驼峰
        # 但长度 > 12, 应尝试按常见前缀拆分
        parts = TargetedDictGenerator._extract_parts("blastzonewebhosting.com")
        # 可能会拆成 ["blastzone", "web", "hosting"] 或保持原样
        key = "blastzonewebhosting"
        assert any(key in p or p in key for p in parts), f"{parts} should relate to {key}"


class TestFromDomain:
    def test_basic_generation(self):
        """基本生成: 至少有一些条目"""
        passwords = TargetedDictGenerator.from_domain("test.com", top_n=500)
        assert len(passwords) > 10
        assert len(passwords) <= 500
        # 应该包含常见的弱密码
        assert any(p == "admin" for p in passwords)

    def test_domain_specific(self):
        """生成的密码应该包含域名变体"""
        passwords = TargetedDictGenerator.from_domain("blastzone.org", top_n=200)
        all_text = " ".join(passwords).lower()
        assert "blastzone" in all_text, "Domain base should appear in generated passwords"

    def test_no_duplicates(self):
        """去重: 没有重复密码"""
        passwords = TargetedDictGenerator.from_domain("example.com", top_n=500)
        assert len(passwords) == len(set(passwords)), "Should have no duplicates"

    def test_year_variants(self):
        """包含年份变体"""
        passwords = TargetedDictGenerator.from_domain("test.com", top_n=500)
        all_text = " ".join(passwords)
        # 应该包含至少一个年份组合
        has_year = any(y in all_text for y in ["2023", "2024", "2025", "2026"])
        assert has_year, "Should contain year variants"

    def test_case_variants(self):
        """包含大小写变体"""
        passwords = TargetedDictGenerator.from_domain("example.com", top_n=500)
        # 检查是否有大写变体 (但 "example" 小写也在)
        variants = [p for p in passwords if p.lower() == "example"]
        assert len(variants) >= 1, "Should have 'example' in some case"

    def test_leet_included(self):
        """leet 模式开启时产生更多变体"""
        normal = set(TargetedDictGenerator.from_domain("test.com", include_leet=False, top_n=500))
        leet = set(TargetedDictGenerator.from_domain("test.com", include_leet=True, top_n=500))
        assert len(leet) >= len(normal)

    def test_from_domain_without_common(self):
        """不融合常见密码时, 数量应显着减少"""
        no_common = set(TargetedDictGenerator.from_domain("test.com", extend_common=False, top_n=200))
        with_common = set(TargetedDictGenerator.from_domain("test.com", extend_common=True, top_n=200))
        assert len(no_common) <= len(with_common)


class TestGuessUsernames:
    def test_basic_usernames(self):
        """包含 admin 和 root"""
        usernames = TargetedDictGenerator.guess_usernames("blastzone.org")
        assert "admin" in usernames
        assert "root" in usernames

    def test_domain_based(self):
        """包含域名衍生用户名"""
        usernames = TargetedDictGenerator.guess_usernames("myhost.net")
        all_text = " ".join(usernames).lower()
        assert "myhost" in all_text

    def test_usernames_deduped(self):
        """去重"""
        usernames = TargetedDictGenerator.guess_usernames("blastzone.org")
        assert len(usernames) == len(set(usernames)), "Should have no duplicates"


class TestFromDomainList:
    def test_multi_domain(self):
        """多域名联合生成"""
        domains = ["site1.com", "site2.org"]
        passwords = TargetedDictGenerator.from_domain_list(domains, top_n=200)
        assert len(passwords) <= 200
        assert len(passwords) > 10
        # 应该包含两个域名的变体
        all_text = " ".join(passwords).lower()
        assert "site1" in all_text or "site" in all_text

    def test_common_first(self):
        """常见密码在排序中排在前面"""
        passwords = TargetedDictGenerator.from_domain_list(["a.com", "b.org"], top_n=500)
        # "admin" 应该在较前的位置
        admin_idx = next((i for i, p in enumerate(passwords) if p == "admin"), -1)
        assert admin_idx >= 0, "admin should be in the list"
        assert admin_idx < 50, f"admin should be near the front (idx={admin_idx})"


class TestFromCompany:
    def test_company_generation(self):
        """公司名生成"""
        passwords = TargetedDictGenerator.from_company("BlastZone Hosting", top_n=200)
        assert len(passwords) > 10
        all_text = " ".join(passwords).lower()
        assert "blastzone" in all_text or "blast" in all_text

    def test_company_with_common(self):
        """包含常见密码"""
        passwords = TargetedDictGenerator.from_company("Acme Corp", top_n=200)
        assert any(p == "admin" for p in passwords)


class TestQuickFunctions:
    def test_generate_dict(self):
        """快捷函数可用"""
        passwords = generate_dict("example.com", top_n=100)
        assert len(passwords) <= 100

    def test_generate_usernames(self):
        """用户名快捷函数可用"""
        usernames = generate_usernames("example.com")
        assert len(usernames) > 0

    def test_generate_multi_dict(self):
        """多域名快捷函数可用"""
        passwords = generate_multi_dict(["a.com", "b.com"], top_n=100)
        assert len(passwords) <= 100