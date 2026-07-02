"""
纯 HTTP 节点探测 (去浏览器化版)

替代 test_dola_cap.py, 用纯 requests 代替 CloakBrowser:
  - 速度: ~2s/节点 (vs 浏览器版 ~40s/节点)
  - 内存: ~5MB/节点 (vs 浏览器版 ~300MB/节点)
  - 并发: 可同时探测 20-30 个节点

两种 cookie 获取模式:
  --cookie-mode get    纯 HTTP: 先 GET dola.com 拿 Set-Cookie (完全无浏览器)
  --cookie-mode browser 浏览器: 用 CloakBrowser 拿 cookie (更可靠, 但慢)

判断标准 (与 test_dola_cap 一致):
  CAPABLE  - conv_id 成功 (纯 HTTP 提交 /chat/completion)
  BLOCKED  - GET 失败 / 非 200 (IP 页面封禁)
  NO_CONV  - submit 200 但无 conv_id
"""
import sys
import time
import json
import uuid
import re
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple
from curl_cffi import requests  # 用 curl_cffi 替代 requests (Chrome TLS 指纹)
import yaml
from mini_clash import MiniClash
from dola_constants import (
    DOLA_CHAT_URL, CHAT_URL_TPL, BOT_ID,
    ABILITY_TYPE_VIDEO, BLOCK_TEXT, MODEL_SEEDANCE,
)

PROMPT = "generate a 5-second video of ocean waves on a beach, cinematic"
OUT_JSON = r"F:\CodexDEV\qwen2API\dola_capability_http.json"


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def build_body(prompt=PROMPT):
    """构造 /chat/completion T2V 请求体"""
    now_ms = int(time.time() * 1000)
    chat_ability = json.dumps({
        "ability_type": ABILITY_TYPE_VIDEO,
        "ability_param": {"style": "cinematic", "ratio": "16:9",
                          "model": MODEL_SEEDANCE, "duration": 5}
    }, ensure_ascii=False)
    return {
        "client_meta": {"local_conversation_id": f"local_{now_ms}",
                        "conversation_id": "", "bot_id": BOT_ID,
                        "last_section_id": "", "last_message_index": None},
        "messages": [{
            "local_message_id": str(uuid.uuid4()),
            "content_block": [{
                "block_type": BLOCK_TEXT,
                "content": {"text_block": {"text": prompt, "icon_url": "",
                                            "icon_url_dark": "", "summary": ""},
                            "pc_event_block": ""},
                "block_id": str(uuid.uuid4()), "parent_id": "",
                "meta_info": [], "append_fields": [],
            }],
            "message_status": 0,
            "ext": {"chat_ability": chat_ability},
        }],
        "option": {
            "create_time_ms": now_ms, "unique_key": str(uuid.uuid4()),
            "need_create_conversation": True, "is_audio": False,
            "need_deep_think": 0, "scene_type": 0,
            "conversation_init_option": {"need_ack_conversation": True},
            "sse_recv_event_options": {"support_chunk_delta": True},
            "recovery_option": {"is_recovery": False,
                                "req_create_time_sec": int(time.time()),
                                "append_sse_event_scene": 0},
        },
        "ext": {
            "use_deep_think": "0", "sub_conv_firstmet_type": "1",
            "collection_id": "",
            "conversation_init_option": "{\"need_ack_conversation\":true}",
            "commerce_credit_config_enable": "0",
            "chat_ability": chat_ability,
        },
    }


def get_cookie_http(proxy):
    """curl_cffi: GET dola.com 拿 Set-Cookie (无浏览器, Chrome TLS 指纹 + 完整伪装头)
    用 HTTP 代理 (curl_cffi 的 socks5 有兼容问题)
    """
    from fingerprint import get_random_identity, build_headers
    identity = get_random_identity()
    proxy_http = proxy.replace("socks5://", "http://") if proxy.startswith("socks5") else proxy
    proxies = {"http": proxy_http, "https": proxy_http}
    headers = build_headers(identity=identity)
    try:
        r = requests.get(DOLA_CHAT_URL, headers=headers, impersonate=identity["impersonate"],
                         proxies=proxies, timeout=20)
        if "dola" not in r.text.lower() and len(r.text) < 5000:
            return None, "BLOCKED", r.text[:100]
        cookie_str = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
        if not cookie_str:
            return None, "NO_COOKIE", "GET 成功但无 Set-Cookie"
        return cookie_str, "OK", ""
    except Exception as e:
        ename = type(e).__name__
        if "SSL" in ename or "Tls" in ename:
            return None, "SSL_ERR", str(e)[:80]
        return None, "GET_ERR", f"{ename}:{str(e)[:60]}"


def submit_t2v_http(cookie_str, proxy, full_url=None):
    """curl_cffi 提交 T2V, 返回 (conv_id, status_str)
    用 HTTP 代理 + Chrome TLS 指纹 + 完整伪装头
    """
    from fingerprint import get_random_identity, build_headers
    identity = get_random_identity()
    proxy_http = proxy.replace("socks5://", "http://") if proxy.startswith("socks5") else proxy
    proxies = {"http": proxy_http, "https": proxy_http}
    headers = build_headers(identity=identity, cookie=cookie_str, is_post=True)
    body = build_body()
    chat_url = full_url or f"https://www.dola.com{CHAT_URL_TPL.format(tab_id=str(uuid.uuid4()))}"
    try:
        r = requests.post(chat_url, json=body, headers=headers,
                          proxies=proxies, timeout=30,
                          impersonate=identity["impersonate"])
        if r.status_code != 200:
            return None, f"HTTP_{r.status_code}"
        ct = r.headers.get("content-type", "")
        if "event-stream" not in ct:
            return None, f"bad_ct:{ct[:40]}"
        # 读响应找 conv_id (curl_cffi 不支持 stream, 直接读全部)
        content = r.text
        m = re.search(r'"conversation_id"\s*:\s*"?(\d+)"?', content)
        if m:
            return m.group(1), "OK"
        return None, "no_conv_id"
    except Exception as e:
        ename = type(e).__name__
        if "SSL" in ename or "Tls" in ename:
            return None, "SSL_ERR"
        return None, f"ERR:{ename}"


def probe_node_http(node_name, proxy_url, cookie_mode="get"):
    """
    纯 HTTP 探测单个节点
    返回 {node, status, conv_id, reason, elapsed}
    """
    t0 = time.time()
    result = {"node": node_name, "status": "BLOCKED",
              "conv_id": "", "reason": "", "elapsed": 0}

    # 1. 拿 cookie
    if cookie_mode == "get":
        cookie_str, cookie_status, detail = get_cookie_http(proxy_url)
        if not cookie_str:
            result["reason"] = f"{cookie_status}:{detail[:50]}"
            result["elapsed"] = time.time() - t0
            return result
    elif cookie_mode == "browser":
        # 浏览器模式 (回退, 慢但可靠)
        from cloakbrowser import launch
        browser = None
        try:
            browser = launch(headless=True, proxy=proxy_url,
                             timezone="Asia/Singapore", locale="en-SG")
            ctx = browser.new_context()
            page = ctx.new_page()
            page.goto(DOLA_CHAT_URL, timeout=60000, wait_until="domcontentloaded")
            time.sleep(8)
            cookies = ctx.cookies()
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            if not cookie_str:
                result["reason"] = "browser_no_cookie"
                result["elapsed"] = time.time() - t0
                return result
        except Exception as e:
            result["reason"] = f"browser_err:{type(e).__name__}"
            result["elapsed"] = time.time() - t0
            return result
        finally:
            if browser:
                browser.close()

    # 2. 提交 T2V
    result["status"] = "NO_CONV"
    conv_id, submit_status = submit_t2v_http(cookie_str, proxy_url)
    if conv_id:
        result["conv_id"] = conv_id
        result["status"] = "CAPABLE"
        result["reason"] = ""
    else:
        result["reason"] = submit_status
    result["elapsed"] = time.time() - t0
    return result


def main():
    ap = argparse.ArgumentParser(description="纯 HTTP 节点探测 (去浏览器化)")
    ap.add_argument("--yaml", default=r"F:\CodexDEV\qwen2API\proxy\yaml\dola_capable.yaml",
                    help="节点 YAML")
    ap.add_argument("--nodes", default="", help="只测含关键字的节点 (逗号分隔)")
    ap.add_argument("--cookie-mode", choices=["get", "browser"], default="get",
                    help="cookie 获取方式: get=纯HTTP / browser=浏览器(慢)")
    ap.add_argument("--workers", type=int, default=8,
                    help="并发探测数 (纯HTTP模式可到20+)")
    ap.add_argument("--limit", type=int, default=0,
                    help="最多探测几个节点 (0=全部)")
    args = ap.parse_args()

    log(f"[*] 纯 HTTP 节点探测 (cookie_mode={args.cookie_mode}, workers={args.workers})")

    # 加载节点
    with open(args.yaml, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    proxies = cfg.get("proxies", []) or []
    all_names = [p.get("name", "") for p in proxies]

    # 过滤
    if args.nodes:
        keys = [k.strip().lower() for k in args.nodes.split(",") if k.strip()]
        all_names = [n for n in all_names if any(k in n.lower() for k in keys)]
    if args.limit > 0:
        all_names = all_names[:args.limit]

    total = len(all_names)
    log(f"[*] 探测 {total} 个节点\n")

    # 起 mini_clash
    mc = MiniClash(config_path=args.yaml)
    if not mc.start(timeout=30):
        return 1
    proxy_base = f"socks5://127.0.0.1:{mc.mixed_port}"

    results = []
    try:
        # 串行切换节点 + 并发探测 (因为 mini_clash 是单实例切节点)
        # 但纯 HTTP 模式下, 每个节点要独立代理 → 用多 mini_clash 实例
        # 简化: 串行切换 + 探测 (纯 HTTP 探测只 2s, 62 节点 ~2 分钟)
        t_start = time.time()
        for i, name in enumerate(all_names, 1):
            if not mc.switch_node(name):
                log(f"[{i:>3}/{total}] {name:<45} ✗ switch_fail")
                results.append({"node": name, "status": "BLOCKED", "reason": "switch_fail"})
                continue
            time.sleep(0.5)
            r = probe_node_http(name, proxy_base, cookie_mode=args.cookie_mode)
            results.append(r)
            st = r["status"]
            tag = {"CAPABLE": "✓", "BLOCKED": "✗", "NO_CONV": "?"}.get(st, "?")
            conv = f" conv={r['conv_id']}" if r["conv_id"] else ""
            log(f"[{i:>3}/{total}] {name:<45} {tag} {st:<10}{conv}  [{r['reason'][:30]}]  {r['elapsed']:.1f}s")

        elapsed = time.time() - t_start
    finally:
        mc.stop()

    # 汇总
    cap = [r for r in results if r["status"] == "CAPABLE"]
    blk = [r for r in results if r["status"] == "BLOCKED"]
    nc = [r for r in results if r["status"] == "NO_CONV"]
    avg_time = sum(r.get("elapsed", 0) for r in results) / max(1, len(results))

    log(f"\n{'='*70}")
    log(f"[*] 探测完成 ({elapsed:.0f}s, 平均 {avg_time:.1f}s/节点)")
    log(f"    ✓ CAPABLE: {len(cap)}/{total}")
    log(f"    ✗ BLOCKED: {len(blk)}/{total}")
    log(f"    ? NO_CONV: {len(nc)}/{total}")
    log(f"{'='*70}")

    if cap:
        log(f"\n[✓] CAPABLE 节点:")
        for r in cap:
            log(f"    {r['node']:<45} conv={r['conv_id']}")

    # 写 JSON
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    log(f"\n[+] 详细结果: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
