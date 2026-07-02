"""经验引擎 — 跨目标经验复用与自动策略调整.

功能:
  1. 读取历史 field-journal, 提取 CDN/WAF 指纹
  2. 根据历史经验自动调整扫描参数
  3. 生成扫描建议 (跳过哪些模块、优先哪些字典)
  4. 跨目标模式识别 (同一 CDN/WAF 的通用绕过手法)

输出: out/experience_advice.data.enc + key.enc
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from _common import _read_encrypted, write_encrypted

ROOT = Path(__file__).resolve().parent
JOURNAL_DIR = ROOT / "field-journal"


def load_all_journals() -> list[dict[str, Any]]:
    """加载所有历史 journal."""
    journals: list[dict[str, Any]] = []
    if not JOURNAL_DIR.exists():
        return journals

    for f in sorted(JOURNAL_DIR.glob("*.md")):
        content = f.read_text(encoding="utf-8", errors="ignore")
        target = f.stem.split("_", 1)[1] if "_" in f.stem else "unknown"
        journals.append({
            "file": f.name,
            "target": target,
            "content": content,
            "size": len(content),
        })

    return journals


def extract_cdn_fingerprints(journals: list[dict]) -> dict[str, Any]:
    """从历史 journal 提取 CDN 指纹."""
    cdn_data: dict[str, dict[str, Any]] = {}

    for j in journals:
        content = j["content"]
        target = j["target"]

        # 提取 CDN 分布
        cdn_matches = re.findall(r'\*\*(Cloudflare|Akamai|Fastly|CloudFront|Imperva|Sucuri)\*\*.*?= (\d+)', content)
        for cdn, count in cdn_matches:
            if cdn not in cdn_data:
                cdn_data[cdn] = {"count": 0, "targets": []}
            cdn_data[cdn]["count"] += int(count)
            cdn_data[cdn]["targets"].append(target)

        # 提取泛解析信息
        wc_match = re.search(r'泛过滤了 (\d+) 个域名', content)
        if wc_match:
            if "wildcard" not in cdn_data:
                cdn_data["wildcard"] = {"total_filtered": 0, "targets": []}
            cdn_data["wildcard"]["total_filtered"] += int(wc_match.group(1))
            cdn_data["wildcard"]["targets"].append(target)

    return cdn_data


def extract_waf_patterns(journals: list[dict]) -> dict[str, Any]:
    """从历史 journal 提取 WAF 模式."""
    waf_data: dict[str, Any] = {
        "common_403_paths": [],
        "common_401_paths": [],
        "bypass_success": [],
    }

    for j in journals:
        content = j["content"]
        # 提取 403/401 路径模式
        forbidden = re.findall(r'forbidden.*?:\s*(\d+)', content, re.I)
        auth_req = re.findall(r'auth_required.*?:\s*(\d+)', content, re.I)

        if forbidden:
            waf_data["common_403_paths"].append({
                "target": j["target"],
                "count": int(forbidden[0]),
            })
        if auth_req:
            waf_data["common_401_paths"].append({
                "target": j["target"],
                "count": int(auth_req[0]),
            })

    return waf_data


def generate_scan_advice(target: str, journals: list[dict]) -> dict[str, Any]:
    """根据历史经验生成扫描建议."""
    advice = {
        "skip_modules": [],
        "priority_wordlists": [],
        "cdn_expected": None,
        "wildcard_likely": False,
        "waf_detected": False,
        "notes": [],
    }

    if not journals:
        advice["notes"].append("无历史经验, 使用默认配置")
        return advice

    # 分析历史数据
    cdn_fps = extract_cdn_fingerprints(journals)
    waf_pats = extract_waf_patterns(journals)

    # CDN 预测
    if cdn_fps:
        # 找出最常见的 CDN
        common_cdns = sorted(
            [(k, v) for k, v in cdn_fps.items() if k != "wildcard"],
            key=lambda x: x[1]["count"],
            reverse=True,
        )
        if common_cdns:
            top_cdn = common_cdns[0]
            advice["cdn_expected"] = top_cdn[0]
            advice["notes"].append(f"历史数据: 大多数目标使用 {top_cdn[0]} CDN")

    # 泛解析预测
    if "wildcard" in cdn_fps:
        wc = cdn_fps["wildcard"]
        if wc["total_filtered"] > 10:
            advice["wildcard_likely"] = True
            advice["notes"].append(f"历史泛解析过滤: {wc['total_filtered']} 个域名被过滤")

    # WAF 预测
    total_403 = sum(p["count"] for p in waf_pats["common_403_paths"])
    total_401 = sum(p["count"] for p in waf_pats["common_401_paths"])
    if total_403 > 20 or total_401 > 10:
        advice["waf_detected"] = True
        advice["notes"].append(f"历史 WAF: 403={total_403}, 401={total_401}, 建议启用 waf_bypass")

    # 模块跳过建议
    if advice["cdn_expected"] in ("Cloudflare", "Akamai", "Fastly"):
        advice["skip_modules"].extend(["cidr_scan.py", "ptr_expand.py"])
        advice["notes"].append(f"{advice['cdn_expected']} 目标: 跳过 CIDR/PTR 扫描 (TEST-NET 噪音)")

    # 字典优先级
    if advice["waf_detected"]:
        advice["priority_wordlists"].append("waf_bypass_payloads")
        advice["notes"].append("WAF 目标: 优先使用绕过字典")

    # 通用建议
    advice["notes"].append(f"基于 {len(journals)} 个历史目标的经验")

    return advice


def main() -> int:
    print("[exp-engine] 加载历史经验...", file=sys.stderr)
    journals = load_all_journals()
    print(f"[exp-engine] 历史 journal: {len(journals)} 个", file=sys.stderr)

    # 读取当前目标
    target = os.environ.get("TARGET", "unknown")

    # 生成建议
    advice = generate_scan_advice(target, journals)

    # 提取汇总数据
    cdn_fps = extract_cdn_fingerprints(journals)
    waf_pats = extract_waf_patterns(journals)

    print(f"\n[exp-engine] 扫描建议 for {target}:", file=sys.stderr)
    for note in advice["notes"]:
        print(f"  • {note}", file=sys.stderr)
    if advice["skip_modules"]:
        print(f"  跳过模块: {advice['skip_modules']}", file=sys.stderr)

    write_encrypted("experience_advice", {
        "target": target,
        "journals_loaded": len(journals),
        "advice": advice,
        "cdn_fingerprints": cdn_fps,
        "waf_patterns": waf_pats,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
