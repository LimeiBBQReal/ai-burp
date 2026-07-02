"""
AI-Burp V3 智能层测试
"""

import pytest
from aiburp import KnowledgeBase, VulnerabilityChainer


class TestKnowledgeBase:
    """知识库测试"""
    
    def test_add_and_get_by_type(self):
        """添加和按类型获取"""
        kb = KnowledgeBase("test_intel")
        kb.assets.clear()  # 清空之前的数据
        kb._seen_values.clear()
        
        kb.add("sqli", "SQL error found", "https://example.com/api?id=1")
        
        results = kb.get_by_type("sqli")
        assert len(results) > 0
        assert results[0].value == "SQL error found"
    
    def test_query(self):
        """关键字查询"""
        kb = KnowledgeBase("test_intel2")
        kb.assets.clear()
        kb._seen_values.clear()
        
        kb.add("xss", "reflected script", "https://example.com/search")
        kb.add("sqli", "mysql error", "https://example.com/api")
        
        results = kb.query("script")
        assert len(results) == 1
        assert results[0].type == "xss"
    
    def test_dedup(self):
        """去重"""
        kb = KnowledgeBase("test_intel3")
        kb.assets.clear()
        kb._seen_values.clear()
        
        kb.add("sqli", "same_value", "url1")
        kb.add("sqli", "same_value", "url2")  # 重复
        
        assert len(kb.assets) == 1


class TestVulnerabilityChainer:
    """漏洞链分析测试"""
    
    def test_suggest_next_steps_empty(self):
        """空发现列表"""
        kb = KnowledgeBase("test_chainer")
        chainer = VulnerabilityChainer(kb)
        
        suggestions = chainer.suggest_next_steps([])
        assert isinstance(suggestions, list)
    
    def test_chain_with_internal_ip(self):
        """有内网 IP 时的建议"""
        kb = KnowledgeBase("test_chainer2")
        kb.assets.clear()
        kb._seen_values.clear()
        
        kb.add("internal_ip", "192.168.1.1", "https://example.com/api")
        chainer = VulnerabilityChainer(kb)
        
        # 模拟 SSRF 发现
        class MockFinding:
            vuln_type = "ssrf"
            def __str__(self):
                return "ssrf vulnerability"
        
        findings = [MockFinding()]
        suggestions = chainer.suggest_next_steps(findings)
        
        # 应该有建议
        assert len(suggestions) > 0
        # 检查是否包含 SSRF 相关建议
        actions = [s.get("action", "") for s in suggestions]
        assert any("ssrf" in a or "chain" in a for a in actions)
