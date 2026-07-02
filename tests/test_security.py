"""
V4 安全测试: 工具自身的漏洞防护.

这组测试专门固化 review 中发现的"工具自己被攻击"的防护:
    - R-1: nuclei 模板代码注入 (生成代码 RCE)
    - B10: Redis RESP 命令注入
    - I1: email 正则 ReDoS
    - S3: nuclei negative matcher 拒绝转换
    - S2: nuclei severity 非法值降级
"""

import os
import time
import yaml
import tempfile
import json

import pytest

from aiburp.pocs.converters.nuclei2py import NucleiConverter
from aiburp.traffic.adapters import RedisAdapter
from aiburp.burp import IntentAnalyzer
from aiburp.traffic import TrafficResponse


class TestNucleiCodeInjection:
    """R-1: nuclei 模板内容注入到生成代码"""

    def _convert(self, tpl_dict):
        p = os.path.join(tempfile.mkdtemp(), "t.yaml")
        with open(p, "w") as f:
            yaml.safe_dump(tpl_dict, f)
        return NucleiConverter().convert_file(p)

    def test_triple_quote_in_name_escaped(self):
        """name 含 \"\"\" 闭合 docstring 必须被中和"""
        code = self._convert({
            "id": "x",
            "info": {
                "name": 'a"""injected"""b',
                "severity": "high",
                "description": "d",
                "tags": [],
            },
            "http": [{"method": "GET", "path": ["{{BaseURL}}"],
                      "matchers": [{"type": "word", "words": ["x"]}]}],
        })
        # 生成的代码必须能编译 (注入被中和, 不破坏语法)
        compile(code, "<gen>", "exec")

    def test_code_in_name_not_executed(self, tmp_path):
        """name 含 import os; os.system 不应出现在可执行位置"""
        marker = tmp_path / "injection_marker.txt"
        # 构造写文件的注入 payload
        payload = f'open(r"{marker}","w").write("pwned")'
        code = self._convert({
            "id": "x",
            "info": {
                "name": f'a"""={payload}="""b',
                "severity": "high",
                "description": "d",
                "tags": [],
            },
            "http": [{"method": "GET", "path": ["{{BaseURL}}"],
                      "matchers": [{"type": "word", "words": ["x"]}]}],
        })
        # exec 模块级代码 (提供假全局避免 import 错误中断)
        try:
            ns = {"__name__": "test"}
            exec(code, ns)
        except Exception:
            pass  # 相对 import 失败没关系, 关键看 marker
        # marker 文件不应被创建
        assert not marker.exists(), "代码注入成功! marker 文件被创建"

    def test_description_injection_in_docstring_safe(self):
        """description 在 docstring 里, 即使含 ; 也不执行"""
        code = self._convert({
            "id": "x",
            "info": {
                "name": "normal",
                "severity": "high",
                "description": 'd"""=__import__("os")="""',
                "tags": [],
            },
            "http": [{"method": "GET", "path": ["{{BaseURL}}"],
                      "matchers": [{"type": "word", "words": ["x"]}]}],
        })
        compile(code, "<gen>", "exec")  # 语法必须合法

    def test_tags_field_not_raw_inserted(self):
        """tags 字段用 repr() 包裹, 不是裸插入"""
        code = self._convert({
            "id": "x",
            "info": {"name": "n", "severity": "high",
                     "description": "d", "tags": ["a", "b'c"]},
            "http": [{"method": "GET", "path": ["{{BaseURL}}"],
                      "matchers": [{"type": "word", "words": ["x"]}]}],
        })
        compile(code, "<gen>", "exec")


class TestRedisRespInjection:
    """B10: RESP 命令注入防护"""

    def test_list_with_newline_rejected(self):
        """list 参数含真换行必须拒绝"""
        adapter = RedisAdapter(timeout=1)
        with pytest.raises(ValueError, match="换行"):
            adapter._encode_command(["GET", "key\r\nFLUSHALL"])

    def test_list_with_lf_rejected(self):
        adapter = RedisAdapter(timeout=1)
        with pytest.raises(ValueError):
            adapter._encode_command(["GET", "k\nFLUSHALL"])

    def test_str_command_safe_via_split(self):
        """str 命令含换行 -> split 吃掉, FLUSHALL 变多余参数 (Redis 报错, 安全)"""
        adapter = RedisAdapter(timeout=1)
        # 不抛异常
        result = adapter._encode_command("GET k\nFLUSHALL")
        # 编码后 FLUSHALL 是 GET 的第 3 个参数, 不是独立命令
        assert b"FLUSHALL" in result
        # RESP 是单帧 (*3), 不会让 Redis 执行 FLUSHALL
        assert result.startswith(b"*3")

    def test_normal_command_works(self):
        adapter = RedisAdapter(timeout=1)
        result = adapter._encode_command("GET key")
        assert result == b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"

    def test_empty_command_returns_empty(self):
        adapter = RedisAdapter(timeout=1)
        assert adapter._encode_command("") == b""
        assert adapter._encode_command(None) == b""


class TestRegexDoS:
    """I1: email 正则 ReDoS 防护"""

    def test_pure_long_text_fast(self):
        """纯 x 长文本分析必须快 (< 100ms, 修复前 197ms/次)"""
        resp = TrafficResponse(protocol="http", text="x" * 10000, url="https://x.com", tags=[])
        t0 = time.time()
        for _ in range(100):  # 100 次 (1000 次太慢)
            IntentAnalyzer.analyze_response(resp)
        elapsed = (time.time() - t0) * 1000
        # 修复后约 0.24ms/次, 100 次 < 100ms; 留 5x 余量
        assert elapsed < 500, f"ReDoS 回归? 100 次耗时 {elapsed:.0f}ms"

    def test_large_text_100kb(self):
        """100KB 文本不卡死"""
        resp = TrafficResponse(protocol="http", text="x" * 100000, tags=[])
        t0 = time.time()
        IntentAnalyzer.analyze_response(resp)
        elapsed = (time.time() - t0) * 1000
        assert elapsed < 100, f"100KB 耗时 {elapsed:.0f}ms"

    def test_real_email_still_detected(self):
        """修复后真 email 仍能匹配"""
        resp = TrafficResponse(
            protocol="http", text="contact admin@target.com today", tags=[]
        )
        tags = IntentAnalyzer.analyze_response(resp)
        assert "LEAK-EMAIL" in tags


class TestNucleiSeverityAndMatchers:
    """S2 + S3: severity 降级 + negative matcher 拒绝"""

    def test_unknown_severity_downgraded(self):
        """S2: severity=unknown 降级 INFO 不崩"""
        code = self._convert_simple({"severity": "unknown"})
        assert "Severity.INFO" in code
        assert "Severity.UNKNOWN" not in code
        compile(code, "<gen>", "exec")

    def test_normal_severity_preserved(self):
        for sev in ["info", "low", "medium", "high", "critical"]:
            code = self._convert_simple({"severity": sev})
            assert f"Severity.{sev.upper()}" in code

    def test_negative_matcher_rejected(self):
        """S3: negative matcher 拒绝转换 (语义反转)"""
        p = os.path.join(tempfile.mkdtemp(), "n.yaml")
        with open(p, "w") as f:
            yaml.safe_dump({
                "id": "neg",
                "info": {"name": "N", "severity": "high", "tags": []},
                "http": [{"method": "GET", "path": ["{{BaseURL}}"],
                          "matchers": [{"type": "word", "words": ["x"],
                                        "negative": True}]}],
            }, f)
        can, reason = NucleiConverter().can_convert(p)
        assert can is False
        assert "Negative" in reason or "negative" in reason

    def _convert_simple(self, info_overrides):
        """转一个最简模板, info 字段可覆盖"""
        info = {"name": "T", "severity": "high", "description": "d", "tags": []}
        info.update(info_overrides)
        p = os.path.join(tempfile.mkdtemp(), "s.yaml")
        with open(p, "w") as f:
            yaml.safe_dump({
                "id": "test",
                "info": info,
                "http": [{"method": "GET", "path": ["{{BaseURL}}"],
                          "matchers": [{"type": "word", "words": ["x"]}]}],
            }, f)
        return NucleiConverter().convert_file(p)
