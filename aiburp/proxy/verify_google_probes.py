"""
Phase 0: 代理测活 (Google-探针版)
- 探针: google.com/generate_204 + httpbin.org/ip + gstatic.com/generate_204
- 与业务目标完全解耦
- 输出: alive.yaml (mihomo) + proxy_pool.json + journal.pkl

监理视角: 不决策, 只收集数据; 决策权交给 ENV LLM
"""
from __future__ import annotations

import base64
import json
import pickle
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
PROXY_STATE = ROOT / ".proxy_state"
PROXY_STATE.mkdir(exist_ok=True)

PROBES = [
    {"name": "google_204", "url": "https://www.google.com/generate_204", "expect_status": 204, "timeout": 8},
    {"name": "gstatic_204", "url": "https://www.gstatic.com/generate_204", "expect_status": 204, "timeout": 8},
    {"name": "httpbin_ip", "url": "https://httpbin.org/ip", "expect_status": 200, "timeout": 8},
]

IP_PORT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})")


def _http_get(url: str, timeout: int = 15) -> str:
    import requests
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return r.text


def _parse_http_txt(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for line in text.splitlines():
        m = IP_PORT_RE.search(line.strip())
        if m:
            out.append((m.group(1), int(m.group(2))))
    return out


def _parse_geonode_json(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for item in data.get("data", []):
        ip = item.get("ip")
        port = item.get("port") or item.get("ports")
        if ip and port:
            out.append((ip, int(port)))
    return out


def _parse_clash_yaml(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        return out
    proxies = data.get("proxies", [])
    if not proxies and isinstance(data, list):
        proxies = data
    for p in proxies:
        if not isinstance(p, dict):
            continue
        server = p.get("server")
        port = p.get("port") or p.get("port-number")
        if server and port:
            out.append((str(server), int(port)))
    return out


def _parse_base64_multi(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
        except Exception:
            decoded = line
        for piece in re.split(r"[\s\r\n]+", decoded):
            m = re.search(r"@?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})", piece)
            if not m:
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})", piece)
            if m:
                out.append((m.group(1), int(m.group(2))))
    return out


def _collect_from_one(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """单条 source -> [(ip,port), ...]."""
    name = entry.get("name") or entry.get("repo") or "unknown"
    fmt = entry.get("format", "http_txt")
    urls: list[str] = []
    if "url" in entry:
        urls.append(entry["url"])
    if "urls" in entry:
        urls.extend(entry["urls"])

    collected: list[tuple[str, int]] = []
    for url in urls:
        try:
            text = _http_get(url)
        except Exception as e:
            print(f"[WARN] {name} fetch {url} fail: {e}", file=sys.stderr)
            continue
        if fmt in ("http_txt", "txt", "ip:port"):
            collected.extend(_parse_http_txt(text))
        elif fmt in ("json", "api"):
            collected.extend(_parse_geonode_json(text))
        elif fmt in ("clash_yaml", "clash_meta", "clash_yaml_dated"):
            collected.extend(_parse_clash_yaml(text))
        elif fmt in ("base64_multi", "v2ray_txt"):
            collected.extend(_parse_base64_multi(text))
        elif fmt in ("csv_http",):
            for line in text.splitlines()[1:]:
                m = IP_PORT_RE.search(line)
                if m:
                    collected.append((m.group(1), int(m.group(2))))
        else:
            collected.extend(_parse_http_txt(text))

    return [{"ip": ip, "port": port, "source": name} for ip, port in collected]


def _extract_sources() -> list[dict[str, Any]]:
    """从两个 source 文件扁平化所有 source 条目."""
    out: list[dict[str, Any]] = []

    ps = ROOT / "aiburp" / "proxy" / "proxy_sources.json"
    if ps.exists():
        try:
            data = json.loads(ps.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] proxy_sources.json parse: {e}", file=sys.stderr)
            data = {}
        for tier_key, tier in data.items():
            if not isinstance(tier, dict):
                continue
            if tier_key.startswith("_"):
                continue
            for section_key in ("sources", "projects", None):
                if section_key and section_key in tier:
                    for entry in tier[section_key] or []:
                        if isinstance(entry, dict):
                            out.append(entry)
                    break
                elif section_key is None:
                    for entry in tier.values():
                        if isinstance(entry, dict) and ("url" in entry or "urls" in entry):
                            out.append(entry)
                    break

    es = ROOT / "aiburp" / "proxy" / "extra_sources.json"
    if es.exists():
        try:
            data = json.loads(es.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] extra_sources.json parse: {e}", file=sys.stderr)
            data = {}
        for entry in data.get("extra_sources", []):
            if isinstance(entry, dict):
                out.append(entry)

    seen = set()
    uniq = []
    for e in out:
        k = e.get("name") or e.get("url") or json.dumps(e, sort_keys=True)
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    return uniq


def load_proxies() -> list[dict[str, Any]]:
    pool: list[dict[str, Any]] = []
    for entry in _extract_sources():
        try:
            pool.extend(_collect_from_one(entry))
        except Exception as e:
            print(f"[WARN] source {entry.get('name')} collect fail: {e}", file=sys.stderr)

    seen = set()
    uniq = []
    for p in pool:
        k = f"{p['ip']}:{p['port']}"
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    print(f"[INFO] 加载 {len(uniq)} 个唯一代理 (原始 {len(pool)})", file=sys.stderr)
    return uniq


def probe_one(proxy: dict[str, Any]) -> dict[str, Any]:
    import requests
    proxies = {
        "http": f"http://{proxy['ip']}:{proxy['port']}",
        "https": f"http://{proxy['ip']}:{proxy['port']}",
    }
    result = {
        "ip": proxy["ip"],
        "port": proxy["port"],
        "source": proxy["source"],
        "probes": {},
        "alive": False,
        "anonymous": None,
        "exit_ip": None,
        "latency_ms": None,
        "errors": [],
    }
    t0 = time.time()
    for probe in PROBES:
        try:
            r = requests.get(
                probe["url"],
                proxies=proxies,
                timeout=probe["timeout"],
                allow_redirects=False,
            )
            ok = r.status_code == probe["expect_status"]
            result["probes"][probe["name"]] = {
                "status": r.status_code,
                "ok": ok,
                "len": len(r.content),
            }
            if probe["name"] == "httpbin_ip" and ok:
                try:
                    body = r.json()
                    result["exit_ip"] = body.get("origin", "").split(",")[0].strip()
                except Exception:
                    pass
            if ok:
                result["alive"] = True
        except Exception as e:
            result["probes"][probe["name"]] = {"ok": False, "error": str(e)[:120]}
            result["errors"].append(f"{probe['name']}: {str(e)[:80]}")
    result["latency_ms"] = round((time.time() - t0) * 1000, 1)
    if result["exit_ip"] and result["exit_ip"] != proxy["ip"]:
        result["anonymous"] = True
    elif result["exit_ip"]:
        result["anonymous"] = False
    return result


def run(proxies: list[dict[str, Any]], workers: int = 60) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_one, p): p for p in proxies}
        done = 0
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            done += 1
            if done % 50 == 0 or done == len(proxies):
                alive_so_far = sum(1 for x in results if x["alive"])
                anon_so_far = sum(1 for x in results if x.get("anonymous"))
                print(
                    f"[PROGRESS] {done}/{len(proxies)} alive={alive_so_far} anon={anon_so_far}",
                    file=sys.stderr,
                )
    return results


def emit(results: list[dict[str, Any]]) -> None:
    alive = [r for r in results if r["alive"]]
    anon = [r for r in alive if r.get("anonymous")]
    google_ok = [r for r in alive if r["probes"].get("google_204", {}).get("ok")]
    httpbin_ok = [r for r in alive if r["probes"].get("httpbin_ip", {}).get("ok")]

    pool_path = PROXY_STATE / "cartmanager_proxy_pool.json"
    pool_path.write_text(
        json.dumps(
            {
                "target": "cartmanager.net",
                "probes": [p["name"] for p in PROBES],
                "total_tested": len(results),
                "alive_total": len(alive),
                "alive_google_204": len(google_ok),
                "alive_httpbin_ip": len(httpbin_ok),
                "anonymous": len(anon),
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        f"[INFO] pool -> {pool_path} (alive={len(alive)} google204={len(google_ok)} "
        f"httpbin={len(httpbin_ok)} anon={len(anon)})",
        file=sys.stderr,
    )

    yaml_nodes = []
    for i, r in enumerate(anon[:30], 1):
        yaml_nodes.append({"name": f"cart-anon-{i}", "type": "http", "server": r["ip"], "port": r["port"]})
    if not yaml_nodes:
        for i, r in enumerate(google_ok[:30], 1):
            yaml_nodes.append(
                {
                    "name": f"cart-google-{i}",
                    "type": "http",
                    "server": r["ip"],
                    "port": r["port"],
                }
            )

    yaml_path = PROXY_STATE / "alive.yaml"
    yaml_path.write_text(
        yaml.safe_dump({"proxies": yaml_nodes}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(f"[INFO] yaml -> {yaml_path} (nodes={len(yaml_nodes)})", file=sys.stderr)

    journal_path = PROXY_STATE / "cartmanager_journal.pkl"
    with open(journal_path, "wb") as f:
        pickle.dump({"results": results, "ts": time.time()}, f)
    print(f"[INFO] journal -> {journal_path}", file=sys.stderr)


def main() -> int:
    proxies = load_proxies()
    if not proxies:
        print("[FATAL] 没拉到任何代理", file=sys.stderr)
        return 2
    results = run(proxies)
    emit(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())