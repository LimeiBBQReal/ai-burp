"""
deep_mining / url_template.py 单元测试
覆盖: 模板替换、聚类、统计
"""
import pytest
from aiburp.deep_mining.url_template import (
    url_to_template,
    cluster_urls,
    representatives,
    cluster_stats,
)


class TestUrlToTemplate:
    def test_plain_path_unchanged(self):
        assert url_to_template("/api/users") == "/api/users"

    def test_numeric_id_replaced(self):
        assert url_to_template("/api/users/123") == "/api/users/{N}"
        assert url_to_template("/api/users/123/orders/456") == \
               "/api/users/{N}/orders/{N}"

    def test_uuid_replaced(self):
        u = "/api/users/abc12345-1234-5678-9012-abcdef012345"
        assert url_to_template(u) == "/api/users/{S}"

    def test_hex_replaced(self):
        # 长 hex 优先匹配 _SLUG_PAT -> {S}; 短 hex 才匹配 _HEX_PAT -> {H}
        # _SLUG_PAT 要求 16+ 字符的 [a-f0-9]
        # _HEX_PAT 要求 8+ 字符的 [0-9a-f]
        # 二者重叠, 实际: 16+ 字符的纯 hex 串走 {S}, 8-15 字符走 {H}
        # 这里测 8 字符 hex 走 {H}
        assert url_to_template("/assets/deadbe12") == "/assets/{H}"
        # 16 字符走 {S} (slug)
        assert url_to_template("/assets/deadbeef12345678") == "/assets/{S}"

    def test_query_string_replaced(self):
        assert url_to_template("/api/x?page=2&q=hello") == \
               "/api/x?page={Q}&q={Q}"

    def test_query_param_without_value_kept(self):
        assert url_to_template("/api/x?flag") == "/api/x?flag"

    def test_full_url_with_scheme(self):
        assert url_to_template("https://x.com/a/123") == \
               "https://x.com/a/{N}"

    def test_garbage_url_returns_safely(self):
        assert url_to_template("") == ""
        out = url_to_template(None) if False else ""
        assert url_to_template("not a url?///") is not None

    def test_id_at_end_of_path(self):
        assert url_to_template("/users/42") == "/users/{N}"

    def test_uuid_priority_over_hex(self):
        # UUID 必须先于 HEX 匹配 (否则会被 HEX 吞掉)
        u = "/r/12345678-1234-5678-9012-123456789abc"
        assert url_to_template(u) == "/r/{S}"


class TestClusterUrls:
    def test_basic_clustering(self):
        urls = [
            "/api/users/1",
            "/api/users/2",
            "/api/users/3",
            "/api/posts/10",
        ]
        clusters = cluster_urls(urls)
        assert len(clusters) == 2
        assert clusters["/api/users/{N}"][0] == "/api/users/1"
        assert len(clusters["/api/users/{N}"]) == 3
        assert clusters["/api/posts/{N}"][0] == "/api/posts/10"

    def test_empty_input(self):
        assert cluster_urls([]) == {}

    def test_mixed_template(self):
        urls = [
            "/x/1",
            "/x/abc",
            "/x/2",
        ]
        clusters = cluster_urls(urls)
        # /x/{N} 出现 2 次, /x/abc 单独特立
        assert any(len(v) == 2 for v in clusters.values())
        assert any(len(v) == 1 for v in clusters.values())


class TestRepresentatives:
    def test_one_per_cluster(self):
        clusters = {
            "/a/{N}": ["/a/1", "/a/2", "/a/3"],
            "/b/{N}": ["/b/1", "/b/2"],
        }
        reps = representatives(clusters, max_per_cluster=1)
        assert len(reps) == 2
        assert reps[0] == "/a/1"
        assert reps[1] == "/b/1"

    def test_multiple_per_cluster(self):
        clusters = {"/a/{N}": ["/a/1", "/a/2", "/a/3"]}
        reps = representatives(clusters, max_per_cluster=2)
        assert reps == ["/a/1", "/a/2"]


class TestClusterStats:
    def test_basic_stats(self):
        clusters = {
            "/a/{N}": ["/a/1", "/a/2", "/a/3"],
            "/b/{N}": ["/b/1", "/b/2"],
        }
        s = cluster_stats(clusters)
        assert s["total_urls"] == 5
        assert s["templates"] == 2
        assert s["avg_per_template"] == 2.5
        assert s["max_per_template"] == 3

    def test_empty_stats(self):
        s = cluster_stats({})
        assert s["total_urls"] == 0
        assert s["templates"] == 0
        assert s["avg_per_template"] == 0
        assert s["max_per_template"] == 0
