"""
批量下载 GitHub 免费节点源 → 解析合并去重 → 生成 Clash YAML

来源:
  1. mahdibland/V2RayAggregator  Eternity.yml (162 nodes, 已排序)
  2. peasoft/NoMoreWalls         list.meta.yml (Clash Meta 格式)
  3. mfuu/v2ray                  clash.yaml
  4. Leon406/SubCrawler          vless + hysteria2 (base64 URI)

输出: yaml/free_nodes_merged.yaml  (供 mini_clash 加载测活)
"""
import re
import sys
import json
import base64
import urllib.parse
import requests
import yaml
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# ============ 下载源 ============
SOURCES = {
    # 原有源
    "Eternity.yml": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml",
    "NoMoreWalls_meta": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.meta.yml",
    "mfuu_clash": "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "SubCrawler_vless": "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless",
    "SubCrawler_hy2": "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/hysteria2",
    "SubCrawler_all": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11",
    # 新增源 (2026-06-21 验证可用)
    "Ruk1ng001_clash": "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "Au1rxx_clash": "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml",
    "Au1rxx_v2ray": "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "Barabama_blues": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/blues.yaml",
    "Barabama_clashmeta": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.yaml",
    "ermaozi_v2ray": "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",
}

OUT_YAML = Path(__file__).parent / "yaml" / "free_nodes_merged.yaml"

# 小型镜像，避免 raw.githubusercontent.com 被墙
MIRRORS = [
    "https://ghfast.top/{}",
    "https://raw.gitmirror.com/{}",
    "https://fastly.jsdelivr.net/gh/{}",
]


def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """下载 URL，自动尝试镜像"""
    urls_to_try = [url]
    # 提取 owner/repo/path 用于镜像
    m = re.match(r"https://raw\.githubusercontent\.com/(.+)", url)
    if m:
        for mirror in MIRRORS:
            if "jsdelivr" in mirror:
                # jsdelivr 格式: owner/repo@branch/path
                parts = m.group(1).split("/", 3)
                if len(parts) >= 4:
                    urls_to_try.append(mirror.format(f"{parts[0]}/{parts[1]}@{parts[2]}/{parts[3]}"))
            else:
                urls_to_try.append(mirror.format(m.group(1)))

    for u in urls_to_try:
        try:
            r = requests.get(u, timeout=timeout, headers={"User-Agent": "clash-meta/1.0"})
            if r.status_code == 200 and len(r.text) > 50:
                print(f"    ✓ {u[:80]}... ({len(r.text)} bytes)")
                return r.text
        except Exception as e:
            pass
    return None


def parse_clash_yaml(text: str) -> List[Dict[str, Any]]:
    """从 Clash YAML 中提取 proxies 列表"""
    try:
        cfg = yaml.safe_load(text)
        proxies = cfg.get("proxies", []) or []
        return [p for p in proxies if isinstance(p, dict) and p.get("name") and p.get("server")]
    except Exception:
        return []


def parse_base64_sub(text: str) -> List[Dict[str, Any]]:
    """解析 base64 编码的订阅 (每行一个 URI)"""
    text = text.strip()
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        decoded = text
    nodes = []
    for line in decoded.splitlines():
        line = line.strip()
        if not line:
            continue
        node = parse_uri(line)
        if node:
            nodes.append(node)
    return nodes


def parse_uri(uri: str) -> Optional[Dict[str, Any]]:
    """解析单个代理 URI → Clash proxy dict"""
    try:
        if uri.startswith("vmess://"):
            return parse_vmess_uri(uri)
        elif uri.startswith("vless://"):
            return parse_vless_uri(uri)
        elif uri.startswith("trojan://"):
            return parse_trojan_uri(uri)
        elif uri.startswith("ss://"):
            return parse_ss_uri(uri)
        elif uri.startswith("hysteria2://") or uri.startswith("hy2://"):
            return parse_hy2_uri(uri)
    except Exception:
        pass
    return None


def parse_vmess_uri(uri: str) -> Optional[Dict[str, Any]]:
    """vmess://base64(json)"""
    raw = uri[8:]
    # 补齐 base64 padding
    padding = 4 - len(raw) % 4
    if padding < 4:
        raw += "=" * padding
    try:
        d = json.loads(base64.b64decode(raw))
    except Exception:
        return None
    name = d.get("ps", f"vmess-{d.get('add','?')}")
    p = {
        "name": name,
        "type": "vmess",
        "server": d.get("add", ""),
        "port": int(d.get("port", 443)),
        "uuid": d.get("id", ""),
        "alterId": int(d.get("aid", 0)),
        "cipher": d.get("scy", "auto"),
    }
    net = d.get("net", "")
    if net == "ws":
        p["network"] = "ws"
        ws_opts = {}
        if d.get("path"):
            ws_opts["path"] = d["path"]
        if d.get("host"):
            ws_opts["headers"] = {"Host": d["host"]}
        if ws_opts:
            p["ws-opts"] = ws_opts
    if d.get("tls") == "tls":
        p["tls"] = True
        if d.get("sni"):
            p["servername"] = d["sni"]
    return p if p["server"] else None


def parse_vless_uri(uri: str) -> Optional[Dict[str, Any]]:
    """vless://uuid@server:port?params#name"""
    m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\??(.*)", uri)
    if not m:
        return None
    uuid, server, port, query = m.groups()
    params = dict(urllib.parse.parse_qsl(query))
    name = urllib.parse.unquote(uri.split("#")[-1]) if "#" in uri else f"vless-{server}"
    p = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": int(port),
        "uuid": uuid,
        "tls": params.get("security", "") == "tls",
    }
    if params.get("sni"):
        p["servername"] = params["sni"]
    if params.get("fp"):
        p["client-fingerprint"] = params["fp"]
    net = params.get("type", "")
    if net == "ws":
        p["network"] = "ws"
        ws_opts = {}
        if params.get("path"):
            ws_opts["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            ws_opts["headers"] = {"Host": params["host"]}
        if ws_opts:
            p["ws-opts"] = ws_opts
    elif net == "grpc":
        p["network"] = "grpc"
        if params.get("serviceName"):
            p["grpc-opts"] = {"grpc-service-name": params["serviceName"]}
    return p if p["server"] else None


def parse_trojan_uri(uri: str) -> Optional[Dict[str, Any]]:
    """trojan://password@server:port?params#name"""
    m = re.match(r"trojan://([^@]+)@([^:]+):(\d+)\??(.*)", uri)
    if not m:
        return None
    password, server, port, query = m.groups()
    params = dict(urllib.parse.parse_qsl(query))
    name = urllib.parse.unquote(uri.split("#")[-1]) if "#" in uri else f"trojan-{server}"
    p = {
        "name": name,
        "type": "trojan",
        "server": server,
        "port": int(port),
        "password": urllib.parse.unquote(password),
    }
    if params.get("sni"):
        p["servername"] = params["sni"]
    if params.get("peer"):
        p["servername"] = params["peer"]
    net = params.get("type", "")
    if net == "ws":
        p["network"] = "ws"
        ws_opts = {}
        if params.get("path"):
            ws_opts["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            ws_opts["headers"] = {"Host": params["host"]}
        if ws_opts:
            p["ws-opts"] = ws_opts
    return p if p["server"] else None


def parse_ss_uri(uri: str) -> Optional[Dict[str, Any]]:
    """ss://base64(method:password)@server:port#name  或  ss://base64(method:password@server:port)#name"""
    raw = uri[5:]
    name = ""
    if "#" in raw:
        raw, name = raw.rsplit("#", 1)
        name = urllib.parse.unquote(name)

    if "@" in raw:
        # SIP002 格式
        userinfo, serverinfo = raw.rsplit("@", 1)
        # userinfo 可能是 base64
        try:
            userinfo = base64.b64decode(userinfo + "==").decode()
        except Exception:
            pass
        if ":" in serverinfo:
            server, port = serverinfo.rsplit(":", 1)
            port = int(port.rstrip("/"))
        else:
            return None
        if ":" in userinfo:
            cipher, password = userinfo.split(":", 1)
        else:
            return None
    else:
        # 旧格式: base64(cipher:password@server:port)
        try:
            decoded = base64.b64decode(raw + "==").decode()
        except Exception:
            return None
        m = re.match(r"([^:]+):([^@]+)@([^:]+):(\d+)", decoded)
        if not m:
            return None
        cipher, password, server, port = m.groups()
        port = int(port)

    if not name:
        name = f"ss-{server}"
    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": cipher,
        "password": password,
    }


def parse_hy2_uri(uri: str) -> Optional[Dict[str, Any]]:
    """hysteria2://auth@server:port?params#name"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    raw = uri[len(prefix):]
    name = ""
    if "#" in raw:
        raw, name = raw.rsplit("#", 1)
        name = urllib.parse.unquote(name)
    m = re.match(r"([^@]+)@([^:]+):(\d+)\??(.*)", raw)
    if not m:
        return None
    auth, server, port, query = m.groups()
    params = dict(urllib.parse.parse_qsl(query))
    if not name:
        name = f"hy2-{server}"
    p = {
        "name": name,
        "type": "hysteria2",
        "server": server,
        "port": int(port),
        "password": auth,
    }
    if params.get("sni"):
        p["sni"] = params["sni"]
    if params.get("insecure") == "1":
        p["skip-cert-verify"] = True
    return p


def dedup_nodes(nodes: List[Dict]) -> List[Dict]:
    """按 server:port 去重"""
    seen = set()
    result = []
    for n in nodes:
        key = f"{n.get('server','')}:{n.get('port',0)}"
        if key not in seen:
            seen.add(key)
            result.append(n)
    return result


def main():
    all_nodes: List[Dict[str, Any]] = []

    for name, url in SOURCES.items():
        print(f"\n[*] 下载 {name}: {url[:80]}...")
        text = fetch_url(url)
        if not text:
            print(f"    ✗ 下载失败")
            continue

        nodes = []
        # 根据来源类型解析
        CLASH_YAML_SOURCES = {"Eternity.yml", "NoMoreWalls_meta", "mfuu_clash",
                              "Ruk1ng001_clash", "Au1rxx_clash",
                              "Barabama_blues", "Barabama_clashmeta"}
        BASE64_SOURCES = {"SubCrawler_vless", "SubCrawler_hy2", "SubCrawler_all",
                          "Au1rxx_v2ray", "ermaozi_v2ray"}
        if name in CLASH_YAML_SOURCES:
            nodes = parse_clash_yaml(text)
            print(f"    解析为 Clash YAML → {len(nodes)} 个节点")
        elif name in BASE64_SOURCES:
            nodes = parse_base64_sub(text)
            print(f"    解析为 base64 订阅 → {len(nodes)} 个节点")

        all_nodes.extend(nodes)
        print(f"    累计: {len(all_nodes)} 个节点")

    print(f"\n[*] 去重前: {len(all_nodes)} 个节点")
    all_nodes = dedup_nodes(all_nodes)
    print(f"[*] 去重后: {len(all_nodes)} 个节点")

    if not all_nodes:
        print("[!] 没有抓到任何节点")
        return 1

    # 统计
    by_type = {}
    for n in all_nodes:
        t = n.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
    print(f"\n[*] 节点类型分布:")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")

    # 生成 Clash YAML
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "global",
        "log-level": "warning",
        "ipv6": False,
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"],
        },
        "proxies": all_nodes,
        "proxy-groups": [
            {
                "name": "GLOBAL",
                "type": "select",
                "proxies": [n["name"] for n in all_nodes] + ["DIRECT"],
            }
        ],
        "rules": ["MATCH,GLOBAL"],
    }

    import os
    os.makedirs(os.path.dirname(OUT_YAML), exist_ok=True)
    with open(OUT_YAML, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    print(f"\n[+] 已写出: {OUT_YAML}")
    print(f"    {len(all_nodes)} 个节点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
