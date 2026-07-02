"""
Phase 0: 代理测活 (Google-探针版) v2 — 支持 SOCKS5 + 多协议测活

改进 vs 旧版:
1. 区分 HTTP / SOCKS5 / 未知协议, 分别用正确方式测活
2. 收集时带 `protocol` 信息, 不再全当 http 测
3. 输出含多协议分类统计
4. 保留全部向后兼容 (输出结构不变, 多加字段)
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

SOCK5_PORTS = {1080, 10808, 9050, 9150, 10808, 8080}


def _http_get(url: str, timeout: int = 15) -> str:
    import requests
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return r.text


def _parse_http_txt(text: str) -> list[tuple[str, int, str]]:
    """Return (ip, port, protocol). protocol 启发式识别."""
    out: list[tuple[str, int, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = IP_PORT_RE.search(line)
        if not m:
            continue
        ip, port_str = m.group(1), m.group(2)
        port = int(port_str)
        protocol = _guess_protocol(line, port)
        out.append((ip, port, protocol))
    return out


def _guess_protocol(line: str, port: int) -> str:
    """从 line 内容 + 端口启发式判断协议."""
    lower = line.lower()
    if "socks5" in lower or "s5" in lower:
        return "socks5"
    if "socks4" in lower or "s4" in lower:
        return "socks5"
    if "https" in lower:
        return "http"
    if "http" in lower:
        return "http"
    if port in (1080, 10808, 9050, 9150):
        return "socks5"
    return "http"


def _parse_geonode_json(text: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for item in data.get("data", []):
        ip = item.get("ip")
        port = item.get("port") or item.get("ports")
        if ip and port:
            out.append((ip, int(port), _guess_protocol("", int(port))))
    return out


def _parse_clash_yaml(text: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
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
            ptype = p.get("type", "http").lower()
            protocol = "socks5" if ptype in ("socks5", "ss", "vmess", "trojan") else "http"
            out.append((str(server), int(port), protocol))
    return out


def _parse_base64_multi(text: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
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
            lower = piece.lower()
            protocol = "http"
            if any(t in lower for t in ("ss://", "vmess://", "trojan://")):
                protocol = "socks5"
            m = re.search(r"@?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})", piece)
            if not m:
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})", piece)
            if m:
                out.append((m.group(1), int(m.group(2)), protocol))
    return out


def _collect_from_one(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """单条 source -> [{ip, port, source, protocol}, ...]."""
    name = entry.get("name") or entry.get("repo") or "unknown"
    fmt = entry.get("format", "http_txt")
    urls: list[str] = []
    if "url" in entry:
        urls.append(entry["url"])
    if "urls" in entry:
        urls.extend(entry["urls"])

    collected: list[tuple[str, int, str]] = []
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
                    port = int(m.group(2))
                    collected.append((m.group(1), port, _guess_protocol(line, port)))
        else:
            collected.extend(_parse_http_txt(text))

    return [{"ip": ip, "port": port, "source": name, "protocol": proto} for ip, port, proto in collected]


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

    proto_counts = {}
    for p in uniq:
        proto_counts[p.get("protocol", "http")] = proto_counts.get(p.get("protocol", "http"), 0) + 1
    print(
        f"[INFO] 加载 {len(uniq)} 个唯一代理 (原始 {len(pool)}), 协议分布: {proto_counts}",
        file=sys.stderr,
    )
    return uniq


def build_proxy_dict(ip: str, port: int, protocol: str) -> dict[str, str]:
    if protocol == "socks5":
        url = f"socks5://{ip}:{port}"
        return {"http": url, "https": url}
    return {
        "http": f"http://{ip}:{port}",
        "https": f"http://{ip}:{port}",
    }


def probe_one(proxy: dict[str, Any]) -> dict[str, Any]:
    import requests
    ip = proxy["ip"]
    port = proxy["port"]
    protocol = proxy.get("protocol", "http")

    proxies = build_proxy_dict(ip, port, protocol)

    result = {
        "ip": ip,
        "port": port,
        "source": proxy["source"],
        "protocol": protocol,
        "probes": {},
        "alive": False,
        "anonymous": None,
        "exit_ip": None,
        "latency_ms": None,
        "errors": [],
    }

    t0 = time.time()
    for probe_cfg in PROBES:
        try:
            r = requests.get(
                probe_cfg["url"],
                proxies=proxies,
                timeout=probe_cfg["timeout"],
                allow_redirects=False,
            )
            ok = r.status_code == probe_cfg["expect_status"]
            result["probes"][probe_cfg["name"]] = {
                "status": r.status_code,
                "ok": ok,
                "len": len(r.content),
            }
            if probe_cfg["name"] == "httpbin_ip" and ok:
                try:
                    body = r.json()
                    result["exit_ip"] = body.get("origin", "").split(",")[0].strip()
                except Exception:
                    pass
            if ok:
                result["alive"] = True
        except Exception as e:
            result["probes"][probe_cfg["name"]] = {"ok": False, "error": str(e)[:120]}
            result["errors"].append(f"{probe_cfg['name']}: {str(e)[:80]}")

    result["latency_ms"] = round((time.time() - t0) * 1000, 1)
    if result["exit_ip"] and result["exit_ip"] != ip:
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

    alive_by_protocol = {}
    for r in alive:
        proto = r.get("protocol", "http")
        alive_by_protocol.setdefault(proto, []).append(r)
    print(
        f"[INFO] alive 按协议: { {k: len(v) for k, v in alive_by_protocol.items()} }",
        file=sys.stderr,
    )

    pool_path = PROXY_STATE / "cartmanager_proxy_pool.json"
    pool_path.write_text(
        json.dumps(
            {
                "target": "cartmanager.net",
                "probes": [p["name"] for p in PROBES],
                "total_tested": len(results),
                "alive_total": len(alive),
                "alive_by_protocol": {k: len(v) for k, v in alive_by_protocol.items()},
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
        yaml_nodes.append({
            "name": f"cart-anon-{i}",
            "type": "http" if r.get("protocol") != "socks5" else "socks5",
            "server": r["ip"],
            "port": r["port"],
        })
    if not yaml_nodes:
        for i, r in enumerate(google_ok[:30], 1):
            yaml_nodes.append({
                "name": f"cart-google-{i}",
                "type": "http" if r.get("protocol") != "socks5" else "socks5",
                "server": r["ip"],
                "port": r["port"],
            })

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
