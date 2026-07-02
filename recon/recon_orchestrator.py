"""Recon Orchestrator — 多轮采集 + 反馈循环 + 收敛检测.

解决问题:
  1. 原始管线 Phase 1→2→3 无法回传新发现的域名做二次枚举
  2. workflows/ 下 3 个独立 workflow 需手动依次触发
  3. Phase 3 url_collect/js_extract 发现的新资产被丢弃
  4. deep_subdomains IPs 未被 port_scan 覆盖

方案:
  - 单脚本编排所有 Phase 的 Python 采集器
  - 每轮结束后从 Phase 3 输出中提取新的子域名
  - 新域名回传给 Phase 1 的 passive_sources + Phase 2 的 deep_subdomain
  - 收敛条件: 连续 2 轮无新域名 或 达到 max_rounds

环境变量:
  TARGET            目标域名 (必填)
  MAX_ROUNDS        最大采集轮数 (默认 3)
  CONVERGE_ROUNDS   连续 N 轮无新域名则停止 (默认 2)
  DEEP_DEPTH        子域名递归深度 (默认 2)
  RECON_SSL_VERIFY  0/1 SSL 验证开关 (默认 0)

输出:
  out/recon_summary.data.enc + key.enc  ← 汇总报告
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from _common import (
    get_target, write_encrypted, _read_encrypted, http_get, load_wordlist,
    crt_sh_subdomains, wayback_subdomains, wayback_urls,
)
from field_journal import record_round, record_final_summary, auto_detect_patterns

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "out"

# 配置
MAX_ROUNDS = int(os.environ.get("MAX_ROUNDS", "3"))
CONVERGE_ROUNDS = int(os.environ.get("CONVERGE_ROUNDS", "2"))
DEEP_DEPTH = int(os.environ.get("DEEP_DEPTH", "2"))
RUN_PHASE1 = os.environ.get("RUN_PHASE1", "1") == "1"
RUN_PHASE2 = os.environ.get("RUN_PHASE2", "1") == "1"
RUN_PHASE3 = os.environ.get("RUN_PHASE3", "1") == "1"
RUN_PHASE4 = os.environ.get("RUN_PHASE4", "1") == "1"  # 关联资产挖掘
SCRIPTS_BASE_TIMEOUT = int(os.environ.get("SCRIPT_TIMEOUT", "600"))

# 全局状态
_all_subdomains: set[str] = set()
_all_urls: set[str] = set()
_all_ips: set[str] = set()
_all_dirs: set[str] = set()
_round_stats: list[dict[str, Any]] = []


def run_script(script_name: str, env_extra: dict | None = None, timeout: int = SCRIPTS_BASE_TIMEOUT) -> bool:
    """运行一个采集脚本，等待完成并返回是否成功."""
    script_path = ROOT / script_name
    if not script_path.exists():
        print(f"  [ORCH] 跳过: {script_name} 不存在", file=sys.stderr)
        return False
    cmd = [sys.executable, str(script_path)]
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        result = subprocess.run(cmd, cwd=str(ROOT), env=env, timeout=timeout)
        if result.returncode != 0:
            print(f"  [ORCH] {script_name} exit={result.returncode}", file=sys.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"  [ORCH] {script_name} 超时 (> {timeout}s)", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  [ORCH] {script_name} 错误: {e}", file=sys.stderr)
        return False


def extract_new_subdomains_from_urls(target: str) -> set[str]:
    """从 urls / js_urls / live_details 中以 target 结尾的子域名."""
    new_subs: set[str] = set()
    for name in ("urls", "js_urls", "live_details"):
        try:
            data = _read_encrypted(name)
        except SystemExit:
            continue
        except Exception:
            continue
        if name == "urls":
            for url in data.get("urls", []):
                try:
                    host = url.split("://")[1].split("/")[0].split(":")[0].lower()
                    if host.endswith(f".{target}") and host != target:
                        new_subs.add(host)
                except (IndexError, ValueError):
                    pass
        elif name == "js_urls":
            for u in data.get("unique_urls", []):
                try:
                    host = u.split("://")[1].split("/")[0].split(":")[0].lower()
                    if host.endswith(f".{target}") and host != target:
                        new_subs.add(host)
                except (IndexError, ValueError):
                    pass
        elif name == "live_details":
            for domain in data.get("live_details", {}):
                domain = domain.lower()
                if domain.endswith(f".{target}") and domain != target:
                    new_subs.add(domain)
    return new_subs


def extract_new_subdomains_from_passive(target: str) -> set[str]:
    """从 passive_sources 和 ptr_expanded 提取."""
    new_subs: set[str] = set()
    for name in ("passive_sources", "ptr_expanded", "deep_subdomains"):
        try:
            data = _read_encrypted(name)
        except SystemExit:
            continue
        except Exception as e:
            continue
        if name == "passive_sources":
            for sub in data.get("subdomains", []) or data.get("unique_subdomains", []):
                if isinstance(sub, str) and sub.endswith(f".{target}"):
                    new_subs.add(sub.lower())
        elif name == "ptr_expanded":
            for sub in data.get("all_subdomains", []):
                if isinstance(sub, str) and sub.endswith(f".{target}"):
                    new_subs.add(sub.lower())
        elif name == "deep_subdomains":
            for sub in data.get("subdomains", []):
                if isinstance(sub, str) and sub.endswith(f".{target}"):
                    new_subs.add(sub.lower())
    return new_subs


def supplemental_osint(target: str, new_domains: set[str], limit: int = 10) -> set[str]:
    """对新发现的域名执行快速 OSINT (crt.sh + Wayback)."""
    extra_subs: set[str] = set()
    domains_to_check = sorted(new_domains)[:limit]
    for domain in domains_to_check:
        if domain == target:
            continue
        print(f"  [ORCH] 补充 OSINT: {domain}", file=sys.stderr)
        subs = crt_sh_subdomains(domain)
        extra_subs.update(subs)
        subs = wayback_subdomains(domain, limit=2000)
        extra_subs.update(subs)
    return {s for s in extra_subs if s.endswith(f".{target}") and s != target}


def persist_new_domains(new_domains: set[str], extra_osint: set[str], round_num: int) -> None:
    """持久化新发现的域名到文件，供后续阶段读取."""
    if not new_domains and not extra_osint:
        return
    # 追加模式: 先读取已有的 passive_extra
    existing_new = []
    existing_extra = []
    try:
        old = _read_encrypted("passive_extra")
        existing_new = old.get("all_new_domains", [])
        existing_extra = old.get("all_extra_from_osint", [])
    except (SystemExit, Exception):
        pass

    write_encrypted("passive_extra", {
        "round": round_num,
        "all_new_domains": sorted(set(existing_new) | new_domains),
        "all_extra_from_osint": sorted(set(existing_extra) | extra_osint),
        "this_round_new": sorted(new_domains),
        "this_round_osint": sorted(extra_osint),
    })


def _check_ip_reality(target: str) -> tuple[int, int, bool]:
    """检查目标 IP 是否全为 CDN/TEST-NET.

    返回: (真实IP数量, 总IP数量, 是否全CDN)
    """
    total_ips = set()
    cdn_or_testnet = 0

    # 从 verify_subdomains 获取 IP
    try:
        vd = _read_encrypted("verify_subdomains")
        for sub, info in vd.get("verified_subdomains", {}).items():
            if not isinstance(info, dict):
                continue
            ip = info.get("ip", "")
            if not ip:
                continue
            total_ips.add(ip)
            # 检查是否是 CDN 或 TEST-NET
            is_cdn = info.get("is_cdn", False)
            is_testnet = (
                ip.startswith("198.18.") or  # TEST-NET-1
                ip.startswith("198.51.") or  # TEST-NET-2
                ip.startswith("203.0.") or   # TEST-NET-3
                ip.startswith("192.0.")      # IETF Reserved
            )
            if is_cdn or is_testnet:
                cdn_or_testnet += 1
    except Exception:
        pass

    # 从 ports 获取额外 IP
    try:
        pd = _read_encrypted("ports")
        for ip in pd.get("open_ports", {}):
            if ip not in total_ips:
                total_ips.add(ip)
                is_testnet = (
                    ip.startswith("198.18.") or
                    ip.startswith("198.51.") or
                    ip.startswith("203.0.") or
                    ip.startswith("192.0.")
                )
                if is_testnet:
                    cdn_or_testnet += 1
    except Exception:
        pass

    total_count = len(total_ips)
    real_count = total_count - cdn_or_testnet
    all_cdn = total_count > 0 and real_count == 0

    return real_count, total_count, all_cdn


def collect_current_assets(target: str) -> dict[str, set[str]]:
    """汇总当前轮次所有资产，返回子域名/URL/IP/目录的集合."""
    subs = set()
    urls = set()
    ips = set()
    dirs = set()

    source_map = {
        "passive_sources": ("subdomains", subs),
        "ptr_expanded": ("all_subdomains", subs),
        "verify_subdomains": ("_dict_keys", subs),
        "deep_subdomains": ("subdomains", subs),
        "live_details": ("_dict_keys", subs),
        "urls": ("urls", urls),
        "js_urls": ("unique_urls", urls),
    }

    for name, (field, target_set) in source_map.items():
        try:
            data = _read_encrypted(name)
        except (SystemExit, Exception):
            continue
        if field == "_dict_keys":
            source = data.get("live_details", {}) if name == "live_details" else data.get("verified_subdomains", {})
            for d in source:
                if isinstance(d, str):
                    target_set.add(d.lower())
        else:
            for item in data.get(field, []):
                if isinstance(item, str):
                    target_set.add(item.lower() if "sub" in field or field == "all_subdomains" else item)

    # IPs from verify + deep
    for name in ("verify_subdomains", "deep_subdomains"):
        try:
            data = _read_encrypted(name)
        except (SystemExit, Exception):
            continue
        if name == "verify_subdomains":
            for info in data.get("verified_subdomains", {}).values():
                if isinstance(info, dict) and info.get("ip"):
                    ips.add(info["ip"])
        elif name == "deep_subdomains":
            for ip in data.get("resolved", {}).values():
                if ip:
                    ips.add(ip)

    # Dirs from dirs
    try:
        dirs_data = _read_encrypted("dirs")
        for base, items in dirs_data.get("results", {}).items():
            for item in items:
                d = item.get("url", "")
                if d:
                    dirs.add(d)
    except (SystemExit, Exception):
        pass

    # Phase 4: 关联资产汇总
    # 反向 IP 发现的域名
    try:
        ri = _read_encrypted("reverse_ip")
        for ip, domains in ri.get("found_domains", {}).items():
            for d in domains:
                if isinstance(d, str):
                    subs.add(d.lower())
    except (SystemExit, Exception):
        pass

    # 证书透明度扩展
    try:
        ce = _read_encrypted("cert_ext")
        for d in ce.get("all_domains", []):
            if isinstance(d, str):
                subs.add(d.lower())
    except (SystemExit, Exception):
        pass

    # WHOIS 关联
    try:
        wc = _read_encrypted("whois_corr")
        for d in wc.get("related_domains", []):
            if isinstance(d, str):
                subs.add(d.lower())
    except (SystemExit, Exception):
        pass

    # C 段扫描发现的 IP
    try:
        cr = _read_encrypted("cidr_real")
        for host in cr.get("alive_hosts", []):
            ip = host.get("ip", "")
            if ip:
                ips.add(ip)
    except (SystemExit, Exception):
        pass

    # ASN 关联 IP 段
    try:
        al = _read_encrypted("asn_lookup")
        for r in al.get("ip_ranges", []):
            if isinstance(r, str):
                pass  # IP 段不直接加入,但可记录
    except (SystemExit, Exception):
        pass

    # 过滤子域名只保留 target 结尾的
    subs = {s for s in subs if s.endswith(f".{target}") or s == target}
    return {"subdomains": subs, "urls": urls, "ips": ips, "dirs": dirs}


def main() -> int:
    target = get_target()
    t0 = time.time()
    print(f"[ORCH] ====== Recon Orchestrator 启动 ======", file=sys.stderr)
    print(f"[ORCH] target={target} max_rounds={MAX_ROUNDS} depth={DEEP_DEPTH} "
          f"converge={CONVERGE_ROUNDS}", file=sys.stderr)

    # --- 经验引擎: 加载历史经验生成扫描建议 ---
    print(f"\n[ORCH] --- 经验引擎启动 ---", file=sys.stderr)
    run_script("experience_engine.py", timeout=60)
    # 读取经验建议
    experience_advice: dict[str, Any] = {}
    try:
        adv_data = _read_encrypted("experience_advice")
        experience_advice = adv_data.get("advice", {})
        print(f"  [ORCH] 经验引擎: 加载 {adv_data.get('journals_loaded', 0)} 条历史记录", file=sys.stderr)
        for note in experience_advice.get("notes", []):
            print(f"    • {note}", file=sys.stderr)
    except Exception as e:
        print(f"  [ORCH] 经验引擎读取失败: {e}", file=sys.stderr)

    no_new_count = 0
    total_new_in_round = 0
    all_cdn_detected = False  # Phase 4 CDN 检测标记

    # 根据经验引擎决定跳过的模块
    skip_modules: set[str] = set()
    if experience_advice.get("skip_modules"):
        skip_modules = set(experience_advice["skip_modules"])
        print(f"  [ORCH] 经验引擎建议跳过: {sorted(skip_modules)}", file=sys.stderr)

    for round_num in range(1, MAX_ROUNDS + 1):
        round_t0 = time.time()
        print(f"\n[ORCH] ===== Round {round_num}/{MAX_ROUNDS} =====", file=sys.stderr)

        new_this_round_subs: set[str] = set()

        # --- Phase 1: 被动采集 ---
        if RUN_PHASE1:
            print(f"\n[ORCH] --- Phase 1: Foundation ---", file=sys.stderr)
            if round_num == 1:
                if "dns_authoritative.py" not in skip_modules:
                    run_script("dns_authoritative.py")
                if "subdomain_enum.py" not in skip_modules:
                    run_script("subdomain_enum.py", timeout=300)
                if "passive_sources.py" not in skip_modules:
                    run_script("passive_sources.py")
                if "bypass_cdn.py" not in skip_modules:
                    run_script("bypass_cdn.py")
                # cidr_scan / ptr_expand 对 CDN 目标跳过
                if "cidr_scan.py" not in skip_modules:
                    run_script("cidr_scan.py", timeout=300)
                if "ptr_expand.py" not in skip_modules:
                    run_script("ptr_expand.py", timeout=300)
            else:
                # 后续轮: 只对新域名做被动 OSINT
                new_from_urls = extract_new_subdomains_from_urls(target)
                new_from_passive = extract_new_subdomains_from_passive(target)
                all_new = (new_from_urls | new_from_passive) - _all_subdomains
                if all_new:
                    print(f"  [ORCH] Round {round_num} 新域名 {len(all_new)} 个，执行快速 OSINT",
                          file=sys.stderr)
                    extra = supplemental_osint(target, all_new, limit=10)
                    new_this_round_subs |= all_new
                    new_this_round_subs |= extra
                    _all_subdomains.update(all_new)
                    _all_subdomains.update(extra)
                    total_new_in_round += len(all_new) + len(extra)
                    persist_new_domains(all_new, extra, round_num)
                    print(f"  [ORCH] OSINT 补充: +{len(extra)} 子域名", file=sys.stderr)
                else:
                    no_new_count += 1
                    print(f"  [ORCH] 无新域名发现 (连续 {no_new_count}/{CONVERGE_ROUNDS})",
                          file=sys.stderr)

        # --- Phase 2: 验证 + 深度爆破 ---
        if RUN_PHASE2:
            print(f"\n[ORCH] --- Phase 2: Verify + Deep ---", file=sys.stderr)
            if round_num == 1:
                run_script("verify_subdomains.py", timeout=600)
                run_script("deep_subdomain.py", {"DEEP_DEPTH": str(DEEP_DEPTH)}, timeout=600)
                run_script("http_fingerprint.py", timeout=300)
            else:
                # 后续轮: 重新验证 (新域名已在 passive_extra)
                # 如果有新域名的深度子域名, 也做爆破
                if new_this_round_subs:
                    print(f"  [ORCH] Round {round_num}: 对 {len(new_this_round_subs)} 新域名做深度爆破",
                          file=sys.stderr)
                    # 临时注入新域名到 passive_sources 供 verify_subdomains 读取
                    run_script("verify_subdomains.py", timeout=600)
                else:
                    run_script("verify_subdomains.py", timeout=300)

        # --- Phase 3: Web Scan ---
        if RUN_PHASE3:
            print(f"\n[ORCH] --- Phase 3: Web Scan ---", file=sys.stderr)
            if round_num == 1:
                if "port_scan.py" not in skip_modules:
                    run_script("port_scan.py", timeout=300)
                if "banner_grab.py" not in skip_modules:
                    run_script("banner_grab.py", timeout=300)
                if "dir_brute.py" not in skip_modules:
                    run_script("dir_brute.py", timeout=600)
                if "url_collect.py" not in skip_modules:
                    run_script("url_collect.py", timeout=600)
                if "js_extract.py" not in skip_modules:
                    run_script("js_extract.py", timeout=300)
                if "js_sign_reverse.py" not in skip_modules:
                    run_script("js_sign_reverse.py", timeout=300)
                if "js_ast_analyzer.py" not in skip_modules:
                    run_script("js_ast_analyzer.py", timeout=300)
                # param_brute 超时风险高, 通过超时保护避免无限等待
                if "param_brute.py" not in skip_modules:
                    run_script("param_brute.py", timeout=300)
                # WAF 绕过 (对 403/405 端点)
                if "waf_bypass.py" not in skip_modules:
                    run_script("waf_bypass.py", timeout=300)
            else:
                # 后续轮: 重新采集 URL + JS (新域名发现)
                # 根据经验引擎跳过模块
                if "url_collect.py" not in skip_modules:
                    run_script("url_collect.py", timeout=600)
                if "js_extract.py" not in skip_modules:
                    run_script("js_extract.py", timeout=300)
                if "js_sign_reverse.py" not in skip_modules:
                    run_script("js_sign_reverse.py", timeout=300)
                if "js_ast_analyzer.py" not in skip_modules:
                    run_script("js_ast_analyzer.py", timeout=300)
                # 后续轮跳过 param_brute (第 1 轮已做) 和 waf_bypass (无 403/405 则跳过)
                if experience_advice.get("waf_detected") and "waf_bypass.py" not in skip_modules:
                    run_script("waf_bypass.py", timeout=300)

        # --- Phase 4: 关联资产挖掘 ---
        if RUN_PHASE4 and round_num == 1:
            # 先检查是否有真实 IP(非 CDN/TEST-NET)
            real_ip_count, total_ip_count, all_cdn = _check_ip_reality(target)
            print(f"\n[ORCH] --- Phase 4: Correlation Discovery ---", file=sys.stderr)
            print(f"  [ORCH] IP 检查: {total_ip_count} 个 IP, 真实 IP: {real_ip_count}, "
                  f"全 CDN/TEST-NET: {all_cdn}", file=sys.stderr)

            if all_cdn:
                all_cdn_detected = True
                print(f"  [ORCH] ⚠️ 所有 IP 均为 CDN/TEST-NET, 跳过 Phase 4 关联挖掘", file=sys.stderr)
                print(f"  [ORCH] 原因: 无真实源站 IP,无法做反向 IP/C 段/ASN 关联", file=sys.stderr)
                # 仍然运行子域名接管检测(不需要真实 IP)
                if "subdomain_takeover.py" not in skip_modules:
                    run_script("subdomain_takeover.py", timeout=300)
            else:
                # 有真实 IP,执行全量关联挖掘
                # 反向 IP 查找 (同 IP 其他域名)
                if "reverse_ip_lookup.py" not in skip_modules:
                    run_script("reverse_ip_lookup.py", timeout=300)
                # C 段真实扫描
                if "cidr_scan_real.py" not in skip_modules:
                    run_script("cidr_scan_real.py", timeout=300)
                # 证书透明度扩展
                if "cert_transparency_ext.py" not in skip_modules:
                    run_script("cert_transparency_ext.py", timeout=300)
                # WHOIS 组织关联
                if "whois_correlate.py" not in skip_modules:
                    run_script("whois_correlate.py", timeout=300)
                # ASN/IP 段归属
                if "asn_lookup.py" not in skip_modules:
                    run_script("asn_lookup.py", timeout=300)
                # 子域名接管检测
                if "subdomain_takeover.py" not in skip_modules:
                    run_script("subdomain_takeover.py", timeout=300)

        # --- 收敛检测 ---
        current = collect_current_assets(target)
        if not new_this_round_subs:
            # 检测新轮次实际增量 explicit check
            new_this_round = current["subdomains"] - _all_subdomains
        else:
            new_this_round = new_this_round_subs - _all_subdomains

        _all_subdomains.update(current["subdomains"])
        _all_urls.update(current["urls"])
        _all_ips.update(current["ips"])
        _all_dirs.update(current["dirs"])

        round_stat = {
            "round": round_num,
            "new_subdomains": len(new_this_round),
            "total_subdomains": len(current["subdomains"]),
            "total_urls": len(current["urls"]),
            "total_ips": len(current["ips"]),
            "total_dirs": len(current["dirs"]),
            "elapsed_s": round(time.time() - round_t0, 1),
        }
        _round_stats.append(round_stat)
        print(f"\n[ORCH] Round {round_num} 统计: +{len(new_this_round)} 子域名, "
              f"累计 {len(current['subdomains'])} 子域名, "
              f"{len(current['urls'])} URLs, "
              f"{len(current['ips'])} IPs, "
              f"{len(current['dirs'])} 目录, "
              f"{round_stat['elapsed_s']}s",
              file=sys.stderr)

        if not new_this_round:
            no_new_count += 1
            if no_new_count >= CONVERGE_ROUNDS:
                print(f"\n[ORCH] 连续 {CONVERGE_ROUNDS} 轮无新域名，收敛停止", file=sys.stderr)
                break
        else:
            no_new_count = 0

        # --- 经验沉淀 (每轮结束自动记录) ---
        try:
            wildcard_detected = False
            wildcard_ips: set[str] = set()
            try:
                vd = _read_encrypted("verify_subdomains")
                wildcard_detected = vd.get("wildcard_detected", False)
                # 提取泛解析 IP (从 verified 的 CDN 标记)
                for sub, info in vd.get("verified_subdomains", {}).items():
                    if isinstance(info, dict) and info.get("is_cdn") and info.get("ip"):
                        wildcard_ips.add(info["ip"])
            except Exception:
                pass

            auto_notes = auto_detect_patterns(target)
            record_round(
                target=target,
                round_num=round_num,
                new_subdomains=len(new_this_round),
                total_subdomains=len(current["subdomains"]),
                new_urls=len(current["urls"]),
                total_urls=len(current["urls"]),
                elapsed_s=round_stat["elapsed_s"],
                wildcard_detected=wildcard_detected,
                wildcard_ips=wildcard_ips if wildcard_ips else None,
                notes=auto_notes if auto_notes else None,
            )
        except Exception as e:
            print(f"  [ORCH] 经验记录失败: {e}", file=sys.stderr)

    # --- 汇总输出 ---
    total_time = time.time() - t0

    # Phase 4 关联资产统计
    phase4_stats = {}
    try:
        ri = _read_encrypted("reverse_ip")
        phase4_stats["reverse_ip_domains"] = ri.get("total_found", 0)
    except Exception:
        phase4_stats["reverse_ip_domains"] = 0
    try:
        cr = _read_encrypted("cidr_real")
        phase4_stats["cidr_alive_hosts"] = cr.get("total_alive", 0)
    except Exception:
        phase4_stats["cidr_alive_hosts"] = 0
    try:
        ce = _read_encrypted("cert_ext")
        phase4_stats["cert_domains"] = ce.get("total_domains", 0)
    except Exception:
        phase4_stats["cert_domains"] = 0
    try:
        wc = _read_encrypted("whois_corr")
        phase4_stats["whois_related_domains"] = wc.get("total_related", 0)
    except Exception:
        phase4_stats["whois_related_domains"] = 0
    try:
        al = _read_encrypted("asn_lookup")
        phase4_stats["asn_ranges"] = al.get("total_ranges", 0)
    except Exception:
        phase4_stats["asn_ranges"] = 0
    try:
        st = _read_encrypted("takeover")
        phase4_stats["takeover_vulnerable"] = st.get("total_vulnerable", 0)
    except Exception:
        phase4_stats["takeover_vulnerable"] = 0

    summary = {
        "target": target,
        "total_rounds": len(_round_stats),
        "total_subdomains": len(_all_subdomains),
        "total_urls": len(_all_urls),
        "total_ips": len(_all_ips),
        "total_dirs": len(_all_dirs),
        "all_subdomains": sorted(_all_subdomains),
        "all_ips": sorted(_all_ips),
        "round_stats": _round_stats,
        "phase4_correlation": phase4_stats,
        "total_elapsed_s": round(total_time, 1),
        "config": {
            "max_rounds": MAX_ROUNDS,
            "converge_rounds": CONVERGE_ROUNDS,
            "deep_depth": DEEP_DEPTH,
        },
    }
    write_encrypted("recon_summary", summary)
    print(f"\n[ORCH] ====== 完成 ======", file=sys.stderr)
    print(f"[ORCH] 总轮数: {len(_round_stats)}, "
          f"总子域名: {len(_all_subdomains)}, "
          f"总 URL: {len(_all_urls)}, "
          f"总 IP: {len(_all_ips)}, "
          f"总目录: {len(_all_dirs)}, "
          f"总耗时: {total_time:.1f}s", file=sys.stderr)
    if phase4_stats:
        print(f"[ORCH] Phase 4 关联资产: {phase4_stats}", file=sys.stderr)
    if all_cdn_detected:
        print(f"[ORCH] ⚠️ 注意: 目标全在 CDN 后, Phase 4 关联挖掘已跳过", file=sys.stderr)
        print(f"[ORCH] 建议: 寻找源站真实 IP(历史 DNS/邮件头/SSL 指纹)后再做关联挖掘", file=sys.stderr)

    # --- 最终经验沉淀 ---
    try:
        record_final_summary(
            target=target,
            total_rounds=len(_round_stats),
            total_subdomains=len(_all_subdomains),
            total_urls=len(_all_urls),
            total_ips=len(_all_ips),
            total_dirs=len(_all_dirs),
            total_time=total_time,
            all_subdomains_sample=sorted(_all_subdomains),
        )
    except Exception as e:
        print(f"  [ORCH] 最终汇总记录失败: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
