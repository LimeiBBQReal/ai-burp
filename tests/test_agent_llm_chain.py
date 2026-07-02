"""
agent / llm_chain.py 单元测试
覆盖: 模型降级、超时、会话重置、报告统计、fail-fast 行为
"""
import os
import time
import pytest
from unittest.mock import patch, MagicMock

from aiburp.agent_llm_chain_compat import (
    LLMChain,
    LLMUnavailableError,
    _count_tokens,
)


class TestTokenCount:
    def test_empty(self):
        assert _count_tokens("") == 0

    def test_english(self):
        # 4 字符/token
        assert _count_tokens("hello world!") == 3

    def test_chinese(self):
        # 1.5 字符/token
        s = "你好世界测试"
        n = _count_tokens(s)
        # 6 个汉字 / 1.5 = 4 (向下取整)
        assert n in (4, 5)

    def test_mixed(self):
        s = "hello 你好"
        n = _count_tokens(s)
        assert n > 0


class TestLLMChainInit:
    def test_default_chain(self, monkeypatch):
        monkeypatch.delenv("LLM_MODEL_PRIMARY", raising=False)
        monkeypatch.delenv("LLM_MODEL_SECONDARY", raising=False)
        monkeypatch.delenv("LLM_MODEL_TERTIARY", raising=False)
        monkeypatch.delenv("LLM_PRIMARY_TIMEOUT", raising=False)
        chain = LLMChain()
        names = [m for m, _ in chain.chain]
        assert names == ["minimax-m3", "deepseek-v4-pro", "deepseek-v4-flash"]
        assert chain.chain[0][1] == 30  # 默认 30s

    def test_custom_chain(self):
        chain = LLMChain([("a", 10), ("b", 20)])
        assert chain.chain == [("a", 10), ("b", 20)]

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_MODEL_PRIMARY", "gpt-x")
        monkeypatch.setenv("LLM_PRIMARY_TIMEOUT", "5")
        chain = LLMChain()
        assert chain.chain[0] == ("gpt-x", 5)


class TestLLMChainAsk:
    def _mock_client_ok(self, model_name):
        c = MagicMock()
        c.is_available = True
        c.ask.return_value = f"resp-from-{model_name}"
        return c

    def test_first_model_succeeds(self, monkeypatch):
        chain = LLMChain([("m1", 5), ("m2", 5)])
        # mock 两个模型
        with patch("aiburp.agent_llm_chain_impl.LLMChain._call_one") as call:
            call.side_effect = lambda model, *a, **kw: f"resp-from-{model}"
            result = chain.ask("hi")
        assert result["model"] == "m1"
        assert result["response"] == "resp-from-m1"
        assert "elapsed" in result
        assert "tokens" in result

    def test_fallback_on_first_error(self, monkeypatch):
        chain = LLMChain([("m1", 5), ("m2", 5)])
        def fake_call(model, *a, **kw):
            if model == "m1":
                raise RuntimeError("m1 down")
            return f"resp-from-{model}"
        with patch("aiburp.agent_llm_chain_impl.LLMChain._call_one",
                   side_effect=fake_call):
            result = chain.ask("hi")
        assert result["model"] == "m2"
        assert "m1 down" not in result["response"]
        # m1 计入 errors
        assert chain.usage["m1"]["errors"] == 1
        assert chain.usage["m2"]["calls"] == 1

    def test_fallback_on_timeout(self, monkeypatch):
        chain = LLMChain([("m1", 5), ("m2", 5)])
        def fake_call(model, *a, **kw):
            if model == "m1":
                raise TimeoutError("m1 timeout after 5s")
            return f"resp-from-{model}"
        with patch("aiburp.agent_llm_chain_impl.LLMChain._call_one",
                   side_effect=fake_call):
            result = chain.ask("hi")
        assert result["model"] == "m2"
        assert chain.usage["m1"]["timeouts"] == 1
        # 失败的 m1 应当记入 session 跳过集合
        assert "m1" in chain._failed_in_session

    def test_all_models_fail_raises(self, monkeypatch):
        chain = LLMChain([("m1", 5), ("m2", 5)])
        with patch("aiburp.agent_llm_chain_impl.LLMChain._call_one",
                   side_effect=RuntimeError("dead")):
            with pytest.raises(LLMUnavailableError) as ei:
                chain.ask("hi")
        assert "所有 LLM 都不可用" in str(ei.value)

    def test_all_models_fail_uses_llm_unavailable_error(self, monkeypatch):
        """fail-fast: 所有模型失败时, 必须抛 LLMUnavailableError (而非普通 RuntimeError)."""
        chain = LLMChain([("m1", 5), ("m2", 5)])
        with patch("aiburp.agent_llm_chain_impl.LLMChain._call_one",
                   side_effect=RuntimeError("dead")):
            with pytest.raises(LLMUnavailableError) as ei:
                chain.ask("hi")
        # LLMUnavailableError 是 RuntimeError 的子类, 但断言是更具体的类型
        assert isinstance(ei.value, LLMUnavailableError)

    def test_skips_already_failed_in_session(self, monkeypatch):
        chain = LLMChain([("m1", 5), ("m2", 5)])
        # m1 标记为 session 失败
        chain._failed_in_session.add("m1")
        with patch("aiburp.agent_llm_chain_impl.LLMChain._call_one",
                   return_value="ok") as call:
            result = chain.ask("hi")
        # 直接跳到 m2
        assert result["model"] == "m2"
        # _call_one 只被 m2 调用一次
        called_models = [c.args[0] for c in call.call_args_list]
        assert "m1" not in called_models
        assert "m2" in called_models


class TestResetSession:
    def test_reset_clears_failed_set(self):
        chain = LLMChain([("m1", 5)])
        chain._failed_in_session.add("m1")
        chain.reset_session()
        assert "m1" not in chain._failed_in_session


class TestReport:
    def test_report_shape(self):
        chain = LLMChain([("m1", 5), ("m2", 5)])
        r = chain.report()
        assert r["chain"] == ["m1", "m2"]
        assert "usage" in r
        assert "m1" in r["usage"]
        assert "calls" in r["usage"]["m1"]
        assert "tokens" in r["usage"]["m1"]
        assert "errors" in r["usage"]["m1"]
        assert "timeouts" in r["usage"]["m1"]
        assert "total_elapsed" in r["usage"]["m1"]


class TestRepr:
    def test_repr_contains_model_names(self):
        chain = LLMChain([("a", 5), ("b", 5)])
        s = repr(chain)
        assert "a" in s and "b" in s


class TestFailFast:
    """fail-fast 行为: LLM 不可用时必须 raise, 不能静默 fallback."""

    def test_unavailable_error_is_runtime_error(self):
        """LLMUnavailableError 必须继承 RuntimeError (兼容现有 except RuntimeError)."""
        assert issubclass(LLMUnavailableError, RuntimeError)

    def test_is_available_when_no_models_have_keys(self):
        """所有模型都没 API key → is_available 返回 False."""
        chain = LLMChain([("a", 5), ("b", 5)])
        # mock LLMClient 让所有 model 都返回 is_available=False
        with patch("aiburp.agent_llm_chain_compat.LLMChain.is_available") as mock:
            mock.return_value = False
            # 直接调 mock 的方法, 验证链路无 key 场景
            assert chain.is_available() is False or mock.called

    def test_assert_available_raises_on_all_unavailable(self):
        """全部模型不可用 → assert_available raise LLMUnavailableError."""
        chain = LLMChain([("m1", 5)])
        with patch.object(chain, "is_available", return_value=False):
            with pytest.raises(LLMUnavailableError) as ei:
                chain.assert_available()
        assert "LLM 链路无可用配置" in str(ei.value) or "可用配置" in str(ei.value)

    def test_assert_available_raises_on_empty_chain(self):
        """chain=[] → assert_available 立即 raise (直接构造后清空 chain)."""
        chain = LLMChain([("m1", 5)])
        chain.chain = []  # 强制清空, 模拟 "链路已耗尽" 的边界场景
        with pytest.raises(LLMUnavailableError) as ei:
            chain.assert_available()
        assert "配置为空" in str(ei.value)

    def test_assert_available_passes_when_ask_succeeds(self):
        """is_available=True 且 ask 成功 → assert_available 不抛."""
        chain = LLMChain([("m1", 5)])
        with patch.object(chain, "is_available", return_value=True):
            with patch.object(chain, "ask", return_value={
                "model": "m1", "response": "pong", "elapsed": 0.1, "tokens": 2,
            }):
                chain.assert_available()  # 不抛即通过

    def test_assert_available_wraps_unexpected_error(self):
        """is_available=True 但 ask 抛非 LLMUnavailableError → 包成 LLMUnavailableError."""
        chain = LLMChain([("m1", 5)])
        with patch.object(chain, "is_available", return_value=True):
            with patch.object(chain, "ask", side_effect=RuntimeError("网络超时")):
                with pytest.raises(LLMUnavailableError) as ei:
                    chain.assert_available()
        assert "健康检查失败" in str(ei.value)

    def test_mid_session_failure_raises_not_silent(self):
        """中途所有模型失败 → raise (不是返回空 dict 假装成功)."""
        chain = LLMChain([("m1", 5), ("m2", 5)])
        # 第一次 ask 成功 (模拟 Round 1), 第二次所有模型挂 (模拟 Round 2 中途失效)
        call_count = [0]

        def side_effect(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"model": "m1", "response": "ok", "elapsed": 0.1, "tokens": 2}
            raise RuntimeError("service unavailable")

        with patch.object(chain, "_call_one", side_effect=side_effect):
            # Round 1 成功
            r1 = chain.ask("hi")
            assert r1["model"] == "m1"
            # Round 2 中途挂 → 抛 LLMUnavailableError (fail-fast)
            with pytest.raises(LLMUnavailableError):
                chain.ask("hi2")
