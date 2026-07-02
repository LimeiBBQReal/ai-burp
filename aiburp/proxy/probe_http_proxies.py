"""
直接探测 HTTP 代理的 DOLA 能力 (不需要 mihomo)
每个代理直接用 curl_cffi GET dola.com → 提交 T2V → 拿 conv_id

比 http_probe 快很多 (无 mihomo 启动开销)
带拟人化 (humanize)
"""
import os
import sys
import os
import time
import json
import uuid
import re

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from curl_cffi import requests
from fingerprint import get_random_identity, build_headers
from humanize import simulate_browsing
from dola_constants import (
    DOLA_CHAT_URL, CHAT_URL_TPL, BOT_ID,
    ABILITY_TYPE_VIDEO, BLOCK_TEXT, MODEL_SEEDANCE,
)
from concurrent.futures import ThreadPoolExecutor, as_completed

ALIVE_FILE = r"F:\CodexDEV\qwen2API\proxy\yaml\proxy_raw\http_alive.txt"
OUT_JSON = r"F:\CodexDEV\qwen2API\proxy_dola_capability.json"
WORKERS = 5  # DOLA 探测要提交真实请求, 并发不能太高 (防风控)


def probe_proxy(proxy_str):
    """
    探测单个 HTTP 代理的 DOLA 能力
    返回 {proxy, status, conv_id, reason, latency}
    """
    result = {"proxy": proxy_str, "status": "BLOCKED",
              "conv_id": "", "reason": "", "latency": 0}
    proxy_url = f"http://{proxy_str}"
    proxies = {"http": proxy_url, "https": proxy_url}
    idn = get_random_identity()

    t0 = time.time()
    try:
        # 1. GET cookie
        headers_get = build_headers(identity=idn)
        r = requests.get(DOLA_CHAT_URL, headers=headers_get,
                         impersonate=idn["impersonate"], proxies=proxies, timeout=12)
        if r.status_code not in (200, 301, 302):
            result["reason"] = f"GET HTTP {r.status_code}"
            result["latency"] = int((time.time() - t0) * 1000)
            return result
        # 检查页面级封禁
        if len(r.text) < 3000 and "dola" not in r.text.lower():
            result["reason"] = "page_blocked"
            result["latency"] = int((time.time() - t0) * 1000)
            return result
        cookie_str = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
        if not cookie_str:
            result["reason"] = "no_cookie"
            result["latency"] = int((time.time() - t0) * 1000)
            return result

        # 拟人化: 模拟浏览 (短等待, 探测不要太久)
        time.sleep(1.0)

        # 2. 提交 T2V
        now_ms = int(time.time() * 1000)
        ca = json.dumps({"ability_type": ABILITY_TYPE_VIDEO,
            "ability_param": {"style": "cinematic", "ratio": "16:9",
                              "model": MODEL_SEEDANCE, "duration": 5}}, ensure_ascii=False)
        body = {"client_meta": {"local_conversation_id": f"local_{now_ms}",
                                "conversation_id": "", "bot_id": BOT_ID,
                                "last_section_id": "", "last_message_index": None},
            "messages": [{"local_message_id": str(uuid.uuid4()),
                "content_block": [{"block_type": BLOCK_TEXT,
                    "content": {"text_block": {"text": "generate a 5-second video of ocean waves on a beach, cinematic",
                        "icon_url": "", "icon_url_dark": "", "summary": ""},
                        "pc_event_block": ""},
                    "block_id": str(uuid.uuid4()), "parent_id": "",
                    "meta_info": [], "append_fields": []}],
                "message_status": 0, "ext": {"chat_ability": ca}}],
            "option": {"create_time_ms": now_ms, "unique_key": str(uuid.uuid4()),
                "need_create_conversation": True, "is_audio": False,
                "need_deep_think": 0, "scene_type": 0,
                "conversation_init_option": {"need_ack_conversation": True},
                "sse_recv_event_options": {"support_chunk_delta": True},
                "recovery_option": {"is_recovery": False,
                    "req_create_time_sec": int(time.time()),
                    "append_sse_event_scene": 0}},
            "ext": {"use_deep_think": "0", "sub_conv_firstmet_type": "1",
                "collection_id": "",
                "conversation_init_option": "{\"need_ack_conversation\":true}",
                "commerce_credit_config_enable": "0", "chat_ability": ca}}
        headers_post = build_headers(identity=idn, cookie=cookie_str, is_post=True)
        chat_url = f"https://www.dola.com{CHAT_URL_TPL.format(tab_id=str(uuid.uuid4()))}"
        r2 = requests.post(chat_url, json=body, headers=headers_post,
                           impersonate=idn["impersonate"], proxies=proxies, timeout=20)
        if r2.status_code != 200:
            result["status"] = "NO_CONV"
            result["reason"] = f"POST HTTP {r2.status_code}"
            result["latency"] = int((time.time() - t0) * 1000)
            return result
        # 找 conv_id
        m = re.search(r'"conversation_id"\s*:\s*"?(\d+)"?', r2.text)
        if m:
            result["conv_id"] = m.group(1)
            result["status"] = "CAPABLE"
            result["latency"] = int((time.time() - t0) * 1000)
            return result
        result["status"] = "NO_CONV"
        ct = r2.headers.get("content-type", "")[:30]
        result["reason"] = f"no_conv_id (ct={ct})"
        result["latency"] = int((time.time() - t0) * 1000)
        return result
    except Exception as e:
        ename = type(e).__name__
        result["reason"] = f"{ename}:{str(e)[:40]}"
        result["latency"] = int((time.time() - t0) * 1000)
        return result


def main():
    # 读存活代理
    with open(ALIVE_FILE) as f:
        proxies = [l.strip() for l in f if l.strip()]
    total = len(proxies)
    print(f"[*] DOLA 探测 {total} 个 HTTP 代理 ({WORKERS} 并发)")
    print(f"[*] 每个代理: GET cookie + 拟人化等待 + 提交 T2V\n")

    results = []
    cap = 0
    blk = 0
    nc = 0
    t_start = time.time()
    tested = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(probe_proxy, p): p for p in proxies}
        for f in as_completed(futures):
            tested += 1
            r = f.result()
            results.append(r)
            if r["status"] == "CAPABLE":
                cap += 1
            elif r["status"] == "BLOCKED":
                blk += 1
            else:
                nc += 1
            tag = {"CAPABLE": "✓", "BLOCKED": "✗", "NO_CONV": "?"}.get(r["status"], "?")
            if r["status"] == "CAPABLE" or tested % 20 == 0:
                print(f"  [{tested:>3}/{total}] {tag} {r['proxy']:25} {r['status']:<10} "
                      f"conv={r['conv_id'][:15] if r['conv_id'] else '-':16} "
                      f"[{r['reason'][:25]:25}] {r['latency']}ms")

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"[*] 探测完成 ({elapsed:.0f}s)")
    print(f"    ✓ CAPABLE: {cap}/{total} ({cap*100//total}%)")
    print(f"    ✗ BLOCKED: {blk}/{total}")
    print(f"    ? NO_CONV: {nc}/{total}")

    # 写 JSON
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[+] {OUT_JSON}")

    # 生成 dola_capable_proxies.yaml
    capable = [r for r in results if r["status"] == "CAPABLE"]
    capable.sort(key=lambda x: x["latency"])
    if capable:
        import yaml
        proxies_cfg = []
        for i, r in enumerate(capable):
            ip, port = r["proxy"].split(":")
            proxies_cfg.append({
                "name": f"dola_http_{i:03d}_{r['latency']}ms",
                "type": "http", "server": ip, "port": int(port)
            })
        cfg = {
            "mixed-port": 7890, "allow-lan": False, "mode": "global",
            "log-level": "warning", "ipv6": False,
            "dns": {"enable": True, "ipv6": False, "nameserver": ["223.5.5.5", "8.8.8.8"]},
            "proxies": proxies_cfg,
            "proxy-groups": [{"name": "GLOBAL", "type": "select",
                              "proxies": [p["name"] for p in proxies_cfg] + ["DIRECT"]}],
            "rules": ["MATCH,GLOBAL"],
        }
        yaml_out = r"F:\CodexDEV\qwen2API\proxy\yaml\dola_capable_proxies.yaml"
        with open(yaml_out, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        print(f"[+] {yaml_out} ({len(proxies_cfg)} CAPABLE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
