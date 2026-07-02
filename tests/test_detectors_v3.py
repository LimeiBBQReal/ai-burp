"""
AI-Burp V3 检测器测试
"""

import pytest
from aiburp import AsyncVulnScanner, Finding, AsyncBurp


class TestFinding:
    """Finding 对象测试"""
    
    def test_finding_creation(self):
        """创建 Finding"""
        f = Finding(
            vuln_type="sqli",
            confidence="high",
            evidence="SQL syntax error",
            payload="' OR 1=1--"
        )
        assert f.vuln_type == "sqli"
        assert f.confidence == "high"
    
    def test_finding_str(self):
        """字符串表示"""
        f = Finding(
            vuln_type="xss",
            confidence="medium",
            evidence="reflected",
            payload="<script>"
        )
        s = str(f)
        assert "xss" in s.lower()
        assert "MEDIUM" in s


class TestAsyncVulnScanner:
    """异步漏洞扫描器测试"""
    
    @pytest.mark.asyncio
    async def test_scanner_init(self):
        """扫描器初始化"""
        async with AsyncBurp() as burp:
            scanner = AsyncVulnScanner(burp)
            assert scanner is not None
            assert hasattr(scanner, 'scan_all')
