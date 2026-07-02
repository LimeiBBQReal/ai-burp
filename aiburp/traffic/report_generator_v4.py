"""
V4 红队报告生成器 — 把扫描/攻击结果输出为 HTML/Markdown/JSON.

支持:
    1. ScanResult → 报告 (端口扫描)
    2. DeepCollectResult → 报告 (深度采集)
    3. AttackChainResult → 报告 (攻击链)
    4. LogicScanResult → 报告 (业务逻辑漏洞)
    5. 综合报告 (合并多种结果)

输出格式:
    - HTML (带样式, 可直接交付)
    - Markdown (可导入 GitHub/Notion)
    - JSON (程序消费)
"""

import json
import html as html_module
from datetime import datetime
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """
    红队报告生成器.

    用法:
        gen = ReportGenerator(project="redteam-2024")
        gen.add_scan_result(scan_result)
        gen.add_findings(findings)
        gen.save_html("report.html")
        gen.save_markdown("report.md")
    """

    def __init__(self, project: str = "redteam", target: str = ""):
        self.project = project
        self.target = target
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._sections: List[Dict] = []

    def add_section(self, title: str, content: Any, section_type: str = "info"):
        """添加报告章节"""
        self._sections.append({
            "title": title,
            "type": section_type,
            "content": content,
        })

    def add_scan_result(self, scan_result):
        """添加扫描结果"""
        self.add_section("资产扫描", scan_result.summary(), "scan")

    def add_findings(self, findings: List[Dict]):
        """添加漏洞发现 (自动补修复建议)"""
        from .extras import get_remediation
        enriched = []
        for f in findings:
            item = dict(f)
            vtype = f.get("type", f.get("vuln_type", f.get("cve", "")))
            remediation = get_remediation(str(vtype))
            item["remediation"] = remediation
            enriched.append(item)
        self.add_section("漏洞发现", enriched, "findings")
        # 单独加一个修复建议章节
        remediations = []
        seen = set()
        for f in findings:
            vtype = str(f.get("type", f.get("vuln_type", f.get("cve", ""))))
            if vtype not in seen:
                seen.add(vtype)
                r = get_remediation(vtype)
                remediations.append({"vuln": vtype, **r})
        if remediations:
            self.add_section("修复建议", remediations, "remediation")

    def add_attack_chain(self, chain_result):
        """添加攻击链结果"""
        self.add_section("攻击链", chain_result.to_dict(), "chain")

    def add_logic_vulns(self, logic_result):
        """添加业务逻辑漏洞"""
        self.add_section("业务逻辑漏洞", logic_result.to_dict(), "logic")

    # ============================================================
    # HTML 报告
    # ============================================================

    def generate_html(self) -> str:
        """生成完整 HTML 报告"""
        sections_html = []
        for section in self._sections:
            sections_html.append(self._section_to_html(section))

        finding_count = sum(1 for s in self._sections if s["type"] == "findings")
        vuln_count = sum(len(s["content"]) for s in self._sections
                        if s["type"] == "findings" and isinstance(s["content"], list))

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>红队评估报告 - {html_module.escape(self.project)}</title>
    <style>
        body {{ font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; margin: 40px; background: #f5f5f5; }}
        .report {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; }}
        .meta {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .meta td {{ padding: 5px 15px; }}
        .section {{ margin-bottom: 25px; padding: 15px; border-left: 4px solid #3498db; background: #fafafa; }}
        .section.findings {{ border-left-color: #e74c3c; }}
        .section.chain {{ border-left-color: #2ecc71; }}
        .section.logic {{ border-left-color: #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        tr:hover {{ background: #f0f0f0; }}
        .severity-critical {{ color: #c0392b; font-weight: bold; }}
        .severity-high {{ color: #e74c3c; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #27ae60; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; color: white; }}
        .badge-critical {{ background: #c0392b; }}
        .badge-high {{ background: #e74c3c; }}
        .badge-medium {{ background: #f39c12; }}
        .badge-low {{ background: #27ae60; }}
        .footer {{ margin-top: 40px; text-align: center; color: #95a5a6; font-size: 12px; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
<div class="report">
    <h1>🔴 红队评估报告</h1>
    <div class="meta">
        <table>
            <tr><td><strong>项目</strong></td><td>{html_module.escape(self.project)}</td>
                <td><strong>目标</strong></td><td>{html_module.escape(self.target or "(未指定)")}</td></tr>
            <tr><td><strong>日期</strong></td><td>{self.generated_at}</td>
                <td><strong>漏洞数</strong></td><td>{vuln_count}</td></tr>
        </table>
    </div>
    {''.join(sections_html)}
    <div class="footer">
        <p>AI-Burp V4 自动生成 | {self.generated_at}</p>
        <p>本报告仅供授权方使用, 未经许可不得传播</p>
    </div>
</div>
</body>
</html>"""

    def _section_to_html(self, section: Dict) -> str:
        """单个章节转 HTML"""
        title = html_module.escape(section["title"])
        stype = section["type"]
        content = section["content"]

        if stype == "findings" and isinstance(content, list):
            rows = []
            for f in content:
                if isinstance(f, str):
                    rows.append(f"<tr><td colspan='4'>{html_module.escape(f)}</td></tr>")
                elif isinstance(f, dict):
                    sev = f.get("severity", f.get("type", "info"))
                    rows.append(f"""<tr>
                        <td><span class="badge badge-{sev}">{sev.upper()}</span></td>
                        <td>{html_module.escape(str(f.get('cve', f.get('type', f.get('vuln_type', '?')))))}</td>
                        <td>{html_module.escape(str(f.get('url', f.get('target', '?'))))[:60]}</td>
                        <td>{html_module.escape(str(f.get('evidence', f.get('summary', f.get('description', ''))))[:80])}</td>
                    </tr>""")
            inner = f"""<table><thead><tr><th>严重度</th><th>类型</th><th>目标</th><th>证据</th></tr></thead>
                       <tbody>{''.join(rows)}</tbody></table>"""
        elif isinstance(content, dict):
            inner = f"<pre>{html_module.escape(json.dumps(content, indent=2, ensure_ascii=False, default=str)[:2000])}</pre>"
        elif isinstance(content, list):
            items = "".join(f"<li>{html_module.escape(str(item))}</li>" for item in content[:20])
            inner = f"<ul>{items}</ul>"
        else:
            inner = f"<p>{html_module.escape(str(content))}</p>"

        return f'<div class="section {stype}"><h2>{title}</h2>{inner}</div>'

    def save_html(self, filepath: str):
        """保存 HTML 报告"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_html())

    # ============================================================
    # Markdown 报告
    # ============================================================

    def generate_markdown(self) -> str:
        """生成 Markdown 报告"""
        lines = [
            f"# 🔴 红队评估报告 - {self.project}",
            "",
            f"| 项目 | {self.project} |",
            f"|------|-------------|",
            f"| 目标 | {self.target or '(未指定)'} |",
            f"| 日期 | {self.generated_at} |",
            "",
            "---",
            "",
        ]

        for section in self._sections:
            lines.append(f"## {section['title']}")
            lines.append("")
            content = section["content"]

            if section["type"] == "findings" and isinstance(content, list):
                lines.append("| 严重度 | 类型 | 目标 | 证据 |")
                lines.append("|--------|------|------|------|")
                for f in content:
                    if isinstance(f, str):
                        lines.append(f"| - | - | - | {f} |")
                    elif isinstance(f, dict):
                        sev = f.get("severity", f.get("type", "info"))
                        cve = f.get("cve", f.get("type", f.get("vuln_type", "?")))
                        url = str(f.get("url", f.get("target", "?")))[:50]
                        evi = str(f.get("evidence", f.get("summary", f.get("description", ""))))[:60]
                        lines.append(f"| **{sev}** | {cve} | `{url}` | {evi} |")
            elif isinstance(content, dict):
                lines.append("```json")
                lines.append(json.dumps(content, indent=2, ensure_ascii=False, default=str)[:1000])
                lines.append("```")
            elif isinstance(content, list):
                for item in content[:20]:
                    lines.append(f"- {item}")
            else:
                lines.append(str(content))
            lines.append("")

        lines.append("---")
        lines.append(f"*AI-Burp V4 自动生成 | {self.generated_at}*")
        lines.append("*本报告仅供授权方使用，未经许可不得传播*")

        return "\n".join(lines)

    def save_markdown(self, filepath: str):
        """保存 Markdown 报告"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_markdown())

    def save_json(self, filepath: str):
        """保存 JSON 报告"""
        data = {
            "project": self.project,
            "target": self.target,
            "generated_at": self.generated_at,
            "sections": self._sections,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
