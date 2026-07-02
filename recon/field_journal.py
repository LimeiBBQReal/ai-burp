"""Field Journal — 自动经验沉淀系统.

每次采集结束后自动记录:
  - 泛解析判定结果
  - 新发现的子域名模式
  - 失败的模块与原因
  - CDN/WAF 指纹
  - 新发现的 API 端点模式

输出: field-journal/YYYY-MM-DD_<target>.md (明文, 不进 Git 的敏感信息)
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
JOURNAL_DIR = ROOT / "field-journal"
JOURNAL_DIR.mkdir(exist_ok=True)


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_read_encrypted(name: str) -> dict[str, Any]:
    """安全读取加密文件, 失败返回空 dict."""
    try:
        from _common import _read_encrypted
        return _read_encrypted(name)
    except SystemExit:
        return {}
    except Exception:
        return {}


def record_round(
    target: str,
    round_num: int,
    new_subdomains: int,
    total_subdomains: int,
    new_urls: int,
    total_urls: int,
    elapsed_s: float,
    wildcard_detected: bool = False,
    wildcard_ips: set[str] | None = None,
    failed_scripts: list[str] | None = None,
    cdn_findings: dict[str, Any] | None = None,
    notes: list[str] | None = None,
) -> Path:
    """记录一轮采集的经验."""
    date_str = _today()
    journal_file = JOURNAL_DIR / f"{date_str}_{target}.md"

    # 读取已有内容 (追加模式)
    existing = ""
    if journal_file.exists():
        existing = journal_file.read_text(encoding="utf-8")

    # 构建本轮记录
    lines = [
        f"",
        f"## Round {round_num} — {_now()}",
        f"",
        f"| 指标 | 值 |",
        f"|------|-----|",
        f"| 新增子域名 | {new_subdomains} |",
        f"| 累计子域名 | {total_subdomains} |",
        f"| 新增 URL | {new_urls} |",
        f"| 累计 URL | {total_urls} |",
        f"| 耗时 | {elapsed_s:.1f}s |",
        f"| 泛解析 | {'✅ 检测到' if wildcard_detected else '❌ 未检测'} |",
    ]

    if wildcard_ips:
        lines.append(f"| 泛解析 IP | {', '.join(sorted(wildcard_ips))} |")

    if failed_scripts:
        lines.extend([
            f"",
            f"### 失败模块",
            f"",
        ])
        for s in failed_scripts:
            lines.append(f"- ❌ {s}")

    if cdn_findings:
        lines.extend([
            f"",
            f"### CDN/WAF 发现",
            f"",
        ])
        for key, val in cdn_findings.items():
            lines.append(f"- **{key}**: {val}")

    if notes:
        lines.extend([
            f"",
            f"### 备注",
            f"",
        ])
        for note in notes:
            lines.append(f"- {note}")

    lines.append("")  # trailing newline

    new_content = "\n".join(lines)

    if existing:
        # 追加到文件末尾
        updated = existing.rstrip() + "\n" + new_content
    else:
        # 新建文件, 加标题
        updated = f"# Recon Field Journal — {target}\n\n> 创建于 {_now()}\n" + new_content

    journal_file.write_text(updated, encoding="utf-8")
    print(f"  [JOURNAL] 已记录: {journal_file.name}", file=sys.stderr)
    return journal_file


def record_final_summary(
    target: str,
    total_rounds: int,
    total_subdomains: int,
    total_urls: int,
    total_ips: int,
    total_dirs: int,
    total_time: float,
    all_subdomains_sample: list[str] | None = None,
) -> Path:
    """记录最终汇总."""
    date_str = _today()
    journal_file = JOURNAL_DIR / f"{date_str}_{target}.md"

    lines = [
        f"",
        f"---",
        f"",
        f"# 📊 Final Summary — {_now()}",
        f"",
        f"## 总览",
        f"",
        f"| 指标 | 值 |",
        f"|------|-----|",
        f"| 总轮数 | {total_rounds} |",
        f"| 总子域名 | {total_subdomains} |",
        f"| 总 URL | {total_urls} |",
        f"| 总 IP | {total_ips} |",
        f"| 总目录 | {total_dirs} |",
        f"| 总耗时 | {total_time:.1f}s ({total_time/60:.1f}min) |",
    ]

    if all_subdomains_sample:
        lines.extend([
            f"",
            f"## 子域名样本 (前 50 个)",
            f"",
        ])
        for sub in all_subdomains_sample[:50]:
            lines.append(f"- `{sub}`")

    lines.append("")

    new_content = "\n".join(lines)

    if journal_file.exists():
        updated = journal_file.read_text(encoding="utf-8").rstrip() + "\n" + new_content
    else:
        updated = f"# Recon Field Journal — {target}\n\n" + new_content

    journal_file.write_text(updated, encoding="utf-8")
    print(f"  [JOURNAL] 最终汇总已记录: {journal_file.name}", file=sys.stderr)
    return journal_file


def auto_detect_patterns(target: str) -> list[str]:
    """自动从采集结果中检测模式."""
    notes: list[str] = []

    # 读取 verify_subdomains 分析 CDN 分布
    verify_data = _safe_read_encrypted("verify_subdomains")
    vd = verify_data.get("verified_subdomains", {})

    cdn_counts: dict[str, int] = {}
    for sub, info in vd.items():
        if isinstance(info, dict) and info.get("is_cdn"):
            ip = info.get("ip", "")
            # 简单 CDN 识别
            if ip.startswith("104.") or ip.startswith("172.6"):
                cdn_counts["Cloudflare"] = cdn_counts.get("Cloudflare", 0) + 1
            elif ip.startswith("151.101.") or ip.startswith("2a04:"):
                cdn_counts["Fastly"] = cdn_counts.get("Fastly", 0) + 1
            elif ip.startswith("13.3") or ip.startswith("13.5"):
                cdn_counts["CloudFront"] = cdn_counts.get("CloudFront", 0) + 1
            elif ip.startswith("23.3") or ip.startswith("23.4"):
                cdn_counts["Akamai"] = cdn_counts.get("Akamai", 0) + 1

    if cdn_counts:
        for cdn, count in sorted(cdn_counts.items(), key=lambda x: -x[1]):
            notes.append(f"CDN 分布: {cdn} = {count} 个域名")

    # 分析子域名层级分布
    dot_counts: dict[int, int] = {}
    for sub in verify_data.get("verified_subdomains", {}):
        dots = sub.count(".") - target.count(".")
        dot_counts[dots] = dot_counts.get(dots, 0) + 1

    if dot_counts:
        level_str = ", ".join(f"L{k}: {v}" for k, v in sorted(dot_counts.items()))
        notes.append(f"子域名层级分布: {level_str}")

    # 泛解析信息
    if verify_data.get("wildcard_detected"):
        wc_count = verify_data.get("wildcard_filtered_count", 0)
        notes.append(f"泛解析过滤了 {wc_count} 个域名")

    # 读取 dirs 分析状态码分布
    dirs_data = _safe_read_encrypted("dirs")
    cat_stats = dirs_data.get("category_stats", {})
    if cat_stats:
        status_str = ", ".join(f"{k}: {v}" for k, v in sorted(cat_stats.items(), key=lambda x: -x[1]))
        notes.append(f"目录状态码分布: {status_str}")

    return notes


if __name__ == "__main__":
    # 测试入口
    print(f"[journal] 目录: {JOURNAL_DIR}", file=sys.stderr)
    print(f"[journal] 测试记录...", file=sys.stderr)

    record_round(
        target="example.com",
        round_num=1,
        new_subdomains=42,
        total_subdomains=156,
        new_urls=89,
        total_urls=340,
        elapsed_s=120.5,
        wildcard_detected=True,
        wildcard_ips={"104.16.0.1", "104.17.0.1"},
        failed_scripts=["cidr_scan.py"],
        notes=["测试记录"],
    )
    print("[journal] 测试完成", file=sys.stderr)
