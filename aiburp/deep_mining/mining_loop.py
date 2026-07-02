"""
aiburp/deep_mining/mining_loop.py
深度挖掘主循环 — 串联 Layer 1.5-7 + LLM 决策, 3 轮收敛.

Fail-Fast 设计:
  - 启动时调用 decider.assert_available() 预检 LLM
  - 每轮 round 开始前再调一次, 防止中途 LLM 失效
  - 任一调用失败 → raise LLMUnavailableError 中止整个 deep_mining
  - 不允许静默 fallback (用户要求的安全冗余)

工作流:
  Round 1:
    - layer 1.5 url_template: 模板聚类
    - layer 2 html_parser: 解析 phase2 已发请求的 HTML
    - layer 3 asset_extractor: JS / CSS / 模板输出抽 endpoint
    - layer 4 header_parser: Link / Allow / CORS
    - layer 5 active_probe: robots/sitemap/.well-known
    - layer 6 hidden_param: 隐藏参数推测
    - LLM Round 1: 聚类 + 打 value

  Round 2:
    - 根据 LLM 决策方向, 发 1-2 个探测包
    - LLM Round 2: 是否继续 + 方向

  Round 3:
    - 最后一次发包
    - LLM Round 3: 收敛 + 最终 high 清单

 收敛条件 (任一):
   - LLM 决策 continue=False
   - 连续 2 轮无新 high
   - 已达 3 轮
   - 单轮 new URL 数 < 5
"""
import json
import logging
import hashlib
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .url_template import url_to_template, cluster_urls
from .html_parser import parse_html
from .asset_extractor import AssetExtractor
from .header_parser import parse_response_headers, is_spa_hint
from .active_probe import probe_active_sync
from .hidden_param import infer_hidden_params
from .llm_decider import LLMDecider
from ..agent_llm_chain_compat import LLMUnavailableError

log = logging.getLogger("aiburp.deep_mining")


CACHE_DIR = Path(__file__).parent / ".cache"


def _safe_name(target: str) -> str:
    """target -> 文件名安全字符串."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)


def _cache_path(target: str) -> Path:
    return CACHE_DIR / f"{_safe_name(target)}.json"


def _save_cache(target: str, result: Dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = _cache_path(target)
    p.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                 encoding="utf-8")
    log.info(f"[DeepMining] 缓存已保存: {p}")


def _load_cache(target: str) -> Optional[Dict]:
    p = _cache_path(target)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _inventory_hash(urls: List[str]) -> str:
    h = hashlib.md5()
    for u in sorted(set(urls)):
        h.update(u.encode())
        h.update(b"\n")
    return h.hexdigest()[:16]


class DeepMiningLoop:
    MAX_ROUNDS = 3
    MAX_NEW_URLS_PER_ROUND = 50
    MAX_LOGINS_PER_TARGET = 5

    EXTERNAL_JS_SKIP_PATTERNS = [
        re.compile(p, re.IGNORECASE) for p in [
            r"(jquery|lodash|underscore|react|vue|angular|bootstrap)",
            r"(analytics|tracking|ga\.|gtag|sentry|mixpanel|datadog)",
            r"(fontawesome|material-icons|font-)",
            r"\.min\.js$",
            r"(polyfill|normalize|reset)",
        ]
    ]

    EXTERNAL_JS_INTERESTING = [
        re.compile(p, re.IGNORECASE) for p in [
            r"(app|bundle|main|chunk|runtime)\.[a-z0-9]+\.js$",
            r"(api|client|http|service|fetch)",
            r"/chunks?/",
        ]
    ]

    def __init__(self, target: str, session_manager, llm_chain,
                 proxy: Optional[Dict] = None,
                 js_phase2_enabled: bool = True,
                 traffic_entries: Optional[List[Dict]] = None):
        """
        Args:
            target: 目标域名 (e.g. "fershop.net")
            session_manager: SessionManager 实例
            llm_chain: LLMChain 实例 (硬依赖, 不可为 None)
            proxy: {"http": "...", "https": "..."}
            js_phase2_enabled: 是否启用外部 JS 智能抓取 (默认 True)
            traffic_entries: phase2_trafficify 已写好的 TrafficJournal entries

        Raises:
            ValueError: llm_chain 为 None
            LLMUnavailableError: 构造时 LLM 不可用 (fail-fast)
        """
        if llm_chain is None:
            raise ValueError(
                "DeepMiningLoop 需要 LLMChain 实例 (Phase ②.5 是 LLM 驱动的, "
                "LLM 不可用应中止整个 pipeline, 不能 fallback)."
            )
        self.target = target
        self.sm = session_manager
        self.llm = llm_chain
        self.proxy = proxy or {}
        self.js_phase2 = js_phase2_enabled
        self.traffic_entries = traffic_entries or []
        self.decider = LLMDecider(llm_chain)
        self.logins_done = 0
        self.anon_session = self.sm.get_or_create("anon", proxy=self.proxy)
        self._cache_data: Dict = {}

    def run(self, initial_candidates: List[str]) -> Dict:
        """
        主入口.

        Returns:
            {
              "final_high_list": [...],
              "must_probe": [...],
              "all_clusters": [...],
              "llm_usage": {...},
              "rounds_run": int,
              "history": [...],
              "layer_signals": {...},
              "new_assets": [...],  # 本次挖出的新 URL (供 phase2 复用)
            }
        """
        inv_hash = _inventory_hash(initial_candidates)
        cache = _load_cache(self.target)
        if cache and cache.get("inventory_hash") == inv_hash:
            log.info(f"[DeepMining] 缓存命中: {self.target}")
            return cache["result"]

        # === Fail-Fast: 启动时预检 LLM ===
        # 若 LLM 不可用, 立即 raise, 不进入 3 轮循环
        log.info("[DeepMining] 预检 LLM 可用性...")
        self.decider.assert_available()
        log.info("[DeepMining] LLM 可用, 进入 3 轮决策")

        candidates = list(dict.fromkeys(initial_candidates))
        history = []
        all_clusters = []
        accumulated_high: List[str] = []
        new_assets: List[str] = []
        prev_high_count = 0
        rounds_no_new_high = 0

        for round_n in range(1, self.MAX_ROUNDS + 1):
            log.info(f"[DeepMining] Round {round_n}/{self.MAX_ROUNDS}, "
                     f"candidates={len(candidates)}")

            # === Fail-Fast: 每轮开始前再确认 LLM, 防止中途失效 ===
            try:
                if not self.decider.llm.is_available():
                    raise LLMUnavailableError(
                        f"Round {round_n} 启动前 LLM 已标记不可用"
                    )
            except LLMUnavailableError:
                raise
            except Exception as e:
                raise LLMUnavailableError(
                    f"Round {round_n} LLM 健康检查异常: {str(e)[:120]}"
                ) from e

            layer_signals = self._run_all_layers(candidates)
            new_assets_this_round = layer_signals.pop("new_assets", [])
            new_assets.extend(new_assets_this_round)

            if round_n == 1:
                decision = self.decider.decide_round_1(candidates,
                                                        layer_signals)
            elif round_n == 2:
                decision = self.decider.decide_round_2(
                    history[-1]["decision"] if history else {},
                    new_assets_this_round,
                    accumulated_high,
                    len(candidates),
                )
            else:
                decision = self.decider.decide_round_3(
                    history[-1]["decision"] if history else {},
                    accumulated_high,
                    len(candidates),
                )

            history.append({"round": round_n, "decision": decision,
                            "layer_signals_summary": {
                                k: v for k, v in layer_signals.items()
                                if k != "new_assets"
                            }})

            if "clusters" in decision:
                all_clusters.extend(decision["clusters"])

            for cluster in decision.get("clusters", []):
                if cluster.get("value") == "high":
                    canonical = cluster.get("canonical")
                    if canonical and canonical not in accumulated_high:
                        accumulated_high.append(canonical)

            accumulated_high = list(dict.fromkeys(
                accumulated_high + decision.get("must_probe", [])
            ))

            if self._should_stop(decision, accumulated_high,
                                  prev_high_count, rounds_no_new_high,
                                  new_assets_this_round):
                log.info(f"[DeepMining] 收敛于 round {round_n}")
                break

            if len(accumulated_high) == prev_high_count:
                rounds_no_new_high += 1
            else:
                rounds_no_new_high = 0
            prev_high_count = len(accumulated_high)

            executed = self._execute_decision(decision, candidates,
                                              layer_signals)
            if executed:
                executed = executed[:self.MAX_NEW_URLS_PER_ROUND]
                candidates.extend(executed)
                new_assets.extend(executed)

        result = {
            "final_high_list": accumulated_high,
            "must_probe": history[-1]["decision"].get("must_probe", []) if history else [],
            "all_clusters": all_clusters,
            "llm_usage": self.llm.report(),
            "rounds_run": len(history),
            "history": history,
            "new_assets": list(dict.fromkeys(new_assets)),
            "target": self.target,
        }

        _save_cache(self.target, {
            "inventory_hash": inv_hash,
            "saved_at": time.time(),
            "result": result,
        })

        return result

    # ---------- 内部 layer 执行 ----------

    def _run_all_layers(self, candidates: List[str]) -> Dict:
        """并行执行 Layer 2-6, 收集信号."""
        signals: Dict = {
            "form_count": 0,
            "asset_count": 0,
            "header_link_count": 0,
            "active_probe_count": 0,
            "hidden_param_count": 0,
            "new_assets": [],
            "context": "",
        }

        for entry in self.traffic_entries[:30]:
            url = entry.get("url", "")
            body = entry.get("body", "") or entry.get("response_body", "")
            content_type = entry.get("content_type", "")
            headers = entry.get("headers", {}) or {}

            if "html" in content_type.lower() or "<html" in body[:200].lower():
                parsed = parse_html(body, url)
                signals["form_count"] += len(parsed.forms)

                if parsed.forms:
                    for f in parsed.forms[:5]:
                        signals["new_assets"].append(f.get("action"))

                if is_spa_hint(headers, body):
                    for s in parsed.scripts[:5]:
                        signals["new_assets"].append(s)
                    signals["context"] += f" [SPA hint: {url}]"

            extractor = AssetExtractor()
            ext = extractor.extract(body, content_type, url)
            signals["asset_count"] += len(ext)
            signals["new_assets"].extend(ext)

            hdr_parsed = parse_response_headers(headers)
            signals["header_link_count"] += len(hdr_parsed.get("links", []))
            for link in hdr_parsed.get("links", []):
                href = link.get("href", "")
                if href.startswith("/"):
                    signals["new_assets"].append(urljoin(url, href))

        seen = set()
        deduped = []
        for a in signals["new_assets"]:
            if a and a not in seen:
                seen.add(a)
                deduped.append(a)
        signals["new_assets"] = deduped

        base_url = self._guess_base_url()
        if base_url:
            try:
                probe = probe_active_sync(self.anon_session, base_url)
                discovered = probe.get("discovered_urls", [])
                signals["active_probe_count"] = len(discovered)
                signals["new_assets"].extend(discovered)
            except Exception as e:
                log.warning(f"[DeepMining] active_probe 失败: {e}")

        for url in candidates[:20]:
            from urllib.parse import urlparse, parse_qs
            q = urlparse(url).query
            known = {k: v[0] for k, v in parse_qs(q).items()}
            hidden = infer_hidden_params(url, known)
            signals["hidden_param_count"] += len(hidden)
            for h in hidden[:3]:
                sep = "&" if "?" in url else "?"
                signals["new_assets"].append(
                    f"{url}{sep}{h['name']}={h['value']}"
                )

        return signals

    def _execute_decision(self, decision: Dict, candidates: List[str],
                           layer_signals: Dict) -> List[str]:
        """根据 LLM 决策, 实际发包 / 抽 endpoint / 跳过."""
        executed = []

        if not decision.get("continue", True):
            return []

        direction = decision.get("next_direction", "新 URL")

        if direction in ("新 URL", "停止", None):
            return []

        if direction == "第三方 JS":
            js_urls = self._fetch_external_js(candidates)
            executed.extend(js_urls)

        elif direction == "隐藏参数":
            for url in candidates[:5]:
                from urllib.parse import urlparse, parse_qs
                q = urlparse(url).query
                known = {k: v[0] for k, v in parse_qs(q).items()}
                hidden = infer_hidden_params(url, known)
                for h in hidden[:3]:
                    sep = "&" if "?" in url else "?"
                    executed.append(f"{url}{sep}{h['name']}={h['value']}")

        elif direction == "登录后接口":
            if self.logins_done >= self.MAX_LOGINS_PER_TARGET:
                log.warning("[DeepMining] 已达登录上限, 跳过登录态挖掘")
            else:
                login_url = next((u for u in candidates
                                  if "/login" in u.lower()), None)
                if login_url:
                    creds = {"username": "test", "password": "test"}
                    ok = self.sm.login("user_test", login_url, creds)
                    if ok:
                        self.logins_done += 1
                        test_session = self.sm.get_or_create("user_test")
                        try:
                            r = test_session.get(self._guess_base_url(),
                                                  timeout=8)
                            parsed = parse_html(r.text, r.url)
                            for f in parsed.forms[:3]:
                                if f.get("action"):
                                    executed.append(f["action"])
                            ext = AssetExtractor().extract(
                                r.text, r.headers.get("Content-Type", ""), r.url
                            )
                            executed.extend(ext[:10])
                        except Exception as e:
                            log.warning(f"[DeepMining] 登录后接口挖掘失败: {e}")

        return list(dict.fromkeys(executed))

    def _fetch_external_js(self, candidates: List[str]) -> List[str]:
        """智能抓取外部 JS (Phase 2)."""
        if not self.js_phase2:
            return []

        js_urls = set()
        for entry in self.traffic_entries[:10]:
            scripts = entry.get("scripts", []) or []
            body = entry.get("body", "")
            if not scripts and "<script" in body:
                parsed = parse_html(body, entry.get("url", ""))
                scripts = parsed.scripts
            for s in scripts:
                if not s or not s.startswith(("http", "/")):
                    continue
                if s.startswith("/"):
                    s = urljoin(entry.get("url", ""), s)
                if any(p.search(s) for p in self.EXTERNAL_JS_SKIP_PATTERNS):
                    continue
                if any(p.search(s) for p in self.EXTERNAL_JS_INTERESTING):
                    js_urls.add(s)

        js_urls = list(js_urls)[:5]
        if not js_urls:
            return []

        log.info(f"[DeepMining] 智能抓取 {len(js_urls)} 个外部 JS")
        executed = []
        for js_url in js_urls:
            try:
                r = self.anon_session.get(js_url, timeout=8)
                if r.status_code == 200:
                    extracted = AssetExtractor().extract(
                        r.text, "javascript", js_url
                    )
                    executed.extend(extracted[:20])
            except Exception as e:
                log.warning(f"[DeepMining] 抓 JS 失败 {js_url}: {e}")

        return executed

    def _guess_base_url(self) -> str:
        """从 candidates / traffic 推断 base_url."""
        # 优先用 traffic_entries 里的第一条 http URL 推断
        for entry in self.traffic_entries:
            u = entry.get("url", "") if isinstance(entry, dict) else ""
            if u and u.startswith("http"):
                p = urlparse(u)
                return f"{p.scheme}://{p.netloc}"
        return f"https://{self.target}"

    def _should_stop(self, decision: Dict, accumulated_high: List[str],
                     prev_high_count: int, rounds_no_new_high: int,
                     new_assets_this_round: List[str]) -> bool:
        if decision.get("continue") is False:
            return True
        if decision.get("stop_reason") in ("converged", "low_value",
                                            "max_rounds", "account_lock_risk"):
            return True
        if rounds_no_new_high >= 2:
            return True
        if len(new_assets_this_round) < 5 and len(accumulated_high) >= 3:
            return True
        return False