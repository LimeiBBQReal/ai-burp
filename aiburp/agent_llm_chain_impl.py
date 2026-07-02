"""
aiburp/agent_llm_chain_impl.py
模型降级链 — 主模型 → 备模型 → 兜底模型, 任一成功即返回.

环境变量:
  LLM_MODEL_PRIMARY     默认 minimax-m3
  LLM_MODEL_SECONDARY   默认 deepseek-v4-pro
  LLM_MODEL_TERTIARY    默认 deepseek-v4-flash
  LLM_PRIMARY_TIMEOUT   默认 30 (秒)

用法:
    from aiburp.agent_llm_chain_compat import LLMChain
    chain = LLMChain()
    result = chain.ask("hello")  # {"model": ..., "response": ..., "elapsed": ...}

注意: 模块放在 aiburp/ 顶层 (而不是 aiburp/agent/) 是因为项目同时存在
aiburp/agent.py (file) 和 aiburp/agent/ (dir, 已被 agent.py 占用为单文件),
Python 会把单文件 agent.py 优先于 agent/ 包, 导致 llm_chain.py 不可导入.

Fail-fast 行为:
  - ask() 在所有模型都不可用时 raise LLMUnavailableError
  - is_available() 仅在至少有 1 个模型看起来可用 (有 API key 等) 时返回 True
  - assert_available() 主动 ping 主模型 (短 prompt), 失败时 raise LLMUnavailableError
  - 上层 (mining_loop / pipeline) 必须捕获或向上传播, 不得静默 fallback
"""
import os
import time
import logging
from typing import Optional, Dict, List, Tuple

log = logging.getLogger("aiburp.llm_chain")


class LLMUnavailableError(RuntimeError):
    """
    LLM 整体不可用时抛出 — 链路上所有模型都尝试失败,
    或根本没有可用配置 (缺 API key / 网络不通 / 鉴权拒绝).

    Fail-fast 信号: 上层应捕获后中止整个 pipeline,
    而不是静默 fallback 到启发式.
    """


def _count_tokens(s: str) -> int:
    """极简 token 估算: 英文按 4 字符/token, 中文按 1.5 字符/token."""
    if not s:
        return 0
    zh = sum(1 for c in s if "\u4e00" <= c <= "\u9fff")
    other = len(s) - zh
    return int(zh / 1.5 + other / 4)


class LLMChain:
    """
    模型降级链 (主 → 备 → 兜底), 每个模型有独立超时.

    与 LLMClient 的区别:
      - LLMClient 在单个 provider 内做 key 轮换
      - LLMChain 在多个 model 间做能力降级 (主模型挂了换更轻量的)
    """

    def __init__(self, chain: Optional[List[Tuple[str, int]]] = None):
        """
        chain: [(model_name, timeout_seconds), ...]
               默认从环境变量读取, 按主/备/兜底顺序.
        """
        if chain:
            self.chain = list(chain)
        else:
            self.chain = [
                (os.getenv("LLM_MODEL_PRIMARY", "minimax-m3"),
                 int(os.getenv("LLM_PRIMARY_TIMEOUT", "30"))),
                (os.getenv("LLM_MODEL_SECONDARY", "deepseek-v4-pro"), 60),
                (os.getenv("LLM_MODEL_TERTIARY", "deepseek-v4-flash"), 60),
            ]
        self.usage: Dict[str, Dict[str, int]] = {
            m: {"calls": 0, "tokens": 0, "errors": 0, "timeouts": 0,
                "total_elapsed": 0.0}
            for m, _ in self.chain
        }
        self._failed_in_session: set = set()  # 本轮已确认挂掉的 model, 跳过

    def ask(self, prompt: str, system: str = "",
            temperature: float = 0.7, max_tokens: int = 4096) -> Dict:
        """
        按 chain 顺序尝试, 任一成功立即返回.
        全失败抛 LLMUnavailableError (fail-fast 信号).

        Returns:
            {"model": str, "response": str, "elapsed": float, "tokens": int}

        Raises:
            LLMUnavailableError: 链路上所有模型都失败 / 全部超时
        """
        last_err = None
        for model, timeout in self.chain:
            if model in self._failed_in_session:
                continue
            t0 = time.time()
            try:
                resp = self._call_one(model, prompt, system, timeout,
                                      temperature, max_tokens)
                elapsed = time.time() - t0
                tokens = _count_tokens(prompt) + _count_tokens(resp)
                self.usage[model]["calls"] += 1
                self.usage[model]["tokens"] += tokens
                self.usage[model]["total_elapsed"] += elapsed
                log.info(f"[LLMChain] {model} OK ({elapsed:.1f}s, ~{tokens} tokens)")
                return {"model": model, "response": resp,
                        "elapsed": elapsed, "tokens": tokens}
            except TimeoutError as e:
                elapsed = time.time() - t0
                self.usage[model]["timeouts"] += 1
                self.usage[model]["total_elapsed"] += elapsed
                self._failed_in_session.add(model)
                log.warning(f"[LLMChain] {model} 超时 ({timeout}s)")
                last_err = f"timeout after {timeout}s"
            except Exception as e:
                elapsed = time.time() - t0
                self.usage[model]["errors"] += 1
                self.usage[model]["total_elapsed"] += elapsed
                log.warning(f"[LLMChain] {model} 失败: {str(e)[:120]}")
                last_err = str(e)
        raise LLMUnavailableError(
            f"所有 LLM 都不可用 ({len(self.chain)} 个): {last_err}"
        )

    def is_available(self) -> bool:
        """
        静态检查: 是否至少有 1 个模型在配置上看起来可用.
        不发起实际调用, 只看 API key 是否存在等.

        Returns:
            True: 至少 1 个模型有 API key 配置
            False: 全部模型都缺配置 (此时构造 chain 也无意义)
        """
        try:
            for model, _ in self.chain:
                if model in self._failed_in_session:
                    continue
                # 检查 aiburp.agent.LLMClient 在该 model 下能否构造 + is_available
                import importlib
                mod = importlib.import_module("aiburp.agent")
                LLMClient = mod.LLMClient
                os.environ["AIBURP_LLM_MODEL"] = model
                client = LLMClient()
                if client.is_available:
                    return True
            return False
        except Exception as e:
            log.warning(f"[LLMChain] is_available 检查异常: {str(e)[:120]}")
            return False

    def assert_available(self) -> None:
        """
        主动健康检查: 用 1 个超短 prompt 试 ping 链路上的模型.
        失败立即 raise LLMUnavailableError (供 pipeline 启动前预检).

        注意: 一旦 assert_available 成功, 后续 ask() 会经过正常的 fallback 链.
        """
        if not self.chain:
            raise LLMUnavailableError("LLMChain 配置为空 (chain=[])")

        # 先静态检查
        if not self.is_available():
            raise LLMUnavailableError(
                f"LLM 链路无可用配置: {[m for m, _ in self.chain]}"
            )

        # 再主动 ping (用最短 prompt)
        ping_prompt = "ping"
        try:
            self.ask(ping_prompt, max_tokens=4)
            log.info("[LLMChain] assert_available: 健康检查通过")
        except LLMUnavailableError:
            # 已经是 fail-fast 异常, 直接抛
            raise
        except Exception as e:
            raise LLMUnavailableError(
                f"LLM 健康检查失败: {str(e)[:120]}"
            ) from e

    def _call_one(self, model: str, prompt: str, system: str,
                  timeout: int, temperature: float,
                  max_tokens: int) -> str:
        """单模型调用, 异常向上抛."""
        import importlib
        mod = importlib.import_module("aiburp.agent")
        LLMClient = mod.LLMClient

        os.environ["AIBURP_LLM_MODEL"] = model

        client = LLMClient()
        if not client.is_available:
            raise RuntimeError(f"{model} 无可用配置 (缺 API key)")

        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError(f"{model} 调用超过 {timeout}s")

        if hasattr(signal, "SIGALRM"):
            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(timeout)
            try:
                resp = client.ask(prompt, system_prompt=system or None)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            return resp
        else:
            return client.ask(prompt, system_prompt=system or None)

    def reset_session(self):
        """新一轮开始, 允许重新尝试失败的 model (比如临时网络抖动恢复)."""
        self._failed_in_session.clear()

    def report(self) -> Dict:
        """返回各 model 的使用统计."""
        return {
            "chain": [m for m, _ in self.chain],
            "usage": self.usage,
        }

    def __repr__(self):
        return f"<LLMChain chain={[m for m, _ in self.chain]}>"