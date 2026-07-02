"""
AI-Burp 报告生成器 v1.0.0

功能:
1. HTML 专业渗透测试报告
2. Markdown 报告
3. 漏洞按严重性排序
4. 请求/响应证据
5. 修复建议

用法:
    # CLI
    aiburp report generate --project heritage --format html -o report.html
    aiburp report generate --project heritage --format md -o report.md
    
    # Python API
    from aiburp.report_generator import ReportGenerator
    
    rg = ReportGenerator("heritage")
    rg.add_finding(Finding(...))
    rg.generate_html("report.html")
"""

import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH: "#fd7e14",
    Severity.MEDIUM: "#ffc107",
    Severity.LOW: "#28a745",
    Severity.INFO: "#17a2b8",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "🔵",
}


@dataclass
class Finding:
    """漏洞发现"""
    title: str
    severity: Severity
    url: str
    parameter: str = ""
    description: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Finding':
        data['severity'] = Severity(data['severity'])
        return cls(**data)


@dataclass 
class ReportMeta:
    """报告元数据"""
    title: str = "渗透测试报告"
    project: str = ""
    target: str = ""
    tester: str = "AI-Burp"
    date: str = ""
    scope: str = ""
    methodology: str = "OWASP Testing Guide v4"
    
    def __post_init__(self):
        if not self.date:
            self.date = datetime.now().strftime("%Y-%m-%d")


class ReportGenerator:
    """
    报告生成器
    
    用法:
        rg = ReportGenerator("project")
        rg.meta.title = "渗透测试报告"
        rg.meta.target = "https://target.com"
        
        rg.add_finding(Finding(
            title="SQL 注入",
            severity=Severity.CRITICAL,
            url="https://target.com/api?id=1",
            parameter="id",
            description="发现 SQL 注入漏洞...",
            evidence="响应包含数据库错误信息",
            request="GET /api?id=1' HTTP/1.1",
            response="HTTP/1.1 500...",
            remediation="使用参数化查询"
        ))
        
        rg.generate_html("report.html")
        rg.generate_md("report.md")
    """
    
    def __init__(self, project: str = "default"):
        self.project = project
        self.meta = ReportMeta(project=project)
        self.findings: List[Finding] = []
        self.data_dir = Path.home() / ".aiburp" / project
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def add_finding(self, finding: Finding):
        """添加漏洞发现"""
        self.findings.append(finding)
    
    def add_findings(self, findings: List[Finding]):
        """批量添加"""
        self.findings.extend(findings)
    
    def load_findings(self, filepath: str) -> int:
        """从 JSON 文件加载发现"""
        path = Path(filepath)
        if not path.exists():
            return 0
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            for item in data:
                self.findings.append(Finding.from_dict(item))
        
        return len(self.findings)
    
    def save_findings(self, filepath: str = None):
        """保存发现到 JSON"""
        if not filepath:
            filepath = self.data_dir / "findings.json"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump([f.to_dict() for f in self.findings], f, indent=2, ensure_ascii=False)
    
    def get_summary(self) -> Dict:
        """获取摘要统计"""
        summary = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for f in self.findings:
            summary[f.severity.value] += 1
        
        return summary
    
    def _sort_findings(self) -> List[Finding]:
        """按严重性排序"""
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    
    def generate_html(self, output_path: str) -> str:
        """生成 HTML 报告"""
        summary = self.get_summary()
        findings = self._sort_findings()
        
        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.meta.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.8; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
        .summary-card .label {{ color: #666; }}
        .critical {{ border-left: 4px solid {SEVERITY_COLORS[Severity.CRITICAL]}; }}
        .critical .count {{ color: {SEVERITY_COLORS[Severity.CRITICAL]}; }}
        .high {{ border-left: 4px solid {SEVERITY_COLORS[Severity.HIGH]}; }}
        .high .count {{ color: {SEVERITY_COLORS[Severity.HIGH]}; }}
        .medium {{ border-left: 4px solid {SEVERITY_COLORS[Severity.MEDIUM]}; }}
        .medium .count {{ color: {SEVERITY_COLORS[Severity.MEDIUM]}; }}
        .low {{ border-left: 4px solid {SEVERITY_COLORS[Severity.LOW]}; }}
        .low .count {{ color: {SEVERITY_COLORS[Severity.LOW]}; }}
        .info {{ border-left: 4px solid {SEVERITY_COLORS[Severity.INFO]}; }}
        .info .count {{ color: {SEVERITY_COLORS[Severity.INFO]}; }}
        .finding {{ background: white; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }}
        .finding-header {{ padding: 20px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }}
        .finding-header .severity-badge {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.85em; }}
        .finding-header h3 {{ flex: 1; }}
        .finding-body {{ padding: 20px; }}
        .finding-body section {{ margin-bottom: 20px; }}
        .finding-body h4 {{ color: #666; margin-bottom: 10px; font-size: 0.9em; text-transform: uppercase; }}
        .finding-body pre {{ background: #1a1a2e; color: #e0e0e0; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 0.85em; }}
        .finding-body .url {{ color: #0066cc; word-break: break-all; }}
        .finding-body .param {{ background: #fff3cd; padding: 2px 8px; border-radius: 3px; }}
        .toc {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .toc h2 {{ margin-bottom: 15px; }}
        .toc ul {{ list-style: none; }}
        .toc li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        .toc a {{ color: #333; text-decoration: none; display: flex; align-items: center; gap: 10px; }}
        .toc a:hover {{ color: #0066cc; }}
        .footer {{ text-align: center; padding: 30px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.meta.title}</h1>
            <div class="meta">
                <p>目标: {self.meta.target or '(未指定)'}</p>
                <p>测试人员: {self.meta.tester} | 日期: {self.meta.date}</p>
                <p>方法论: {self.meta.methodology}</p>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="count">{summary['total']}</div>
                <div class="label">总计</div>
            </div>
            <div class="summary-card critical">
                <div class="count">{summary['critical']}</div>
                <div class="label">严重</div>
            </div>
            <div class="summary-card high">
                <div class="count">{summary['high']}</div>
                <div class="label">高危</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{summary['medium']}</div>
                <div class="label">中危</div>
            </div>
            <div class="summary-card low">
                <div class="count">{summary['low']}</div>
                <div class="label">低危</div>
            </div>
            <div class="summary-card info">
                <div class="count">{summary['info']}</div>
                <div class="label">信息</div>
            </div>
        </div>
'''
        
        # 目录
        if findings:
            html += '''        <div class="toc">
            <h2>📋 漏洞目录</h2>
            <ul>
'''
            for i, f in enumerate(findings, 1):
                icon = SEVERITY_ICONS.get(f.severity, "⚪")
                html += f'                <li><a href="#finding-{i}">{icon} {f.title}</a></li>\n'
            
            html += '''            </ul>
        </div>
'''
        
        # 漏洞详情
        for i, f in enumerate(findings, 1):
            color = SEVERITY_COLORS.get(f.severity, "#999")
            html += f'''
        <div class="finding" id="finding-{i}">
            <div class="finding-header">
                <span class="severity-badge" style="background: {color}">{f.severity.value.upper()}</span>
                <h3>{f.title}</h3>
            </div>
            <div class="finding-body">
                <section>
                    <h4>URL</h4>
                    <p class="url">{f.url}</p>
                    {f'<p>参数: <span class="param">{f.parameter}</span></p>' if f.parameter else ''}
                </section>
'''
            if f.description:
                html += f'''                <section>
                    <h4>描述</h4>
                    <p>{f.description}</p>
                </section>
'''
            if f.evidence:
                html += f'''                <section>
                    <h4>证据</h4>
                    <p>{f.evidence}</p>
                </section>
'''
            if f.request:
                html += f'''                <section>
                    <h4>请求</h4>
                    <pre>{self._escape_html(f.request)}</pre>
                </section>
'''
            if f.response:
                resp_preview = f.response[:2000] + "..." if len(f.response) > 2000 else f.response
                html += f'''                <section>
                    <h4>响应</h4>
                    <pre>{self._escape_html(resp_preview)}</pre>
                </section>
'''
            if f.remediation:
                html += f'''                <section>
                    <h4>修复建议</h4>
                    <p>{f.remediation}</p>
                </section>
'''
            if f.references:
                html += '''                <section>
                    <h4>参考链接</h4>
                    <ul>
'''
                for ref in f.references:
                    html += f'                        <li><a href="{ref}" target="_blank">{ref}</a></li>\n'
                html += '''                    </ul>
                </section>
'''
            html += '''            </div>
        </div>
'''
        
        html += f'''
        <div class="footer">
            <p>由 AI-Burp v0.18.0 生成 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>'''
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def _escape_html(self, text: str) -> str:
        """HTML 转义"""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

    
    def generate_md(self, output_path: str) -> str:
        """生成 Markdown 报告"""
        summary = self.get_summary()
        findings = self._sort_findings()
        
        lines = [
            f"# {self.meta.title}",
            "",
            "## 报告信息",
            "",
            f"| 项目 | 值 |",
            f"|------|-----|",
            f"| 目标 | {self.meta.target or '(未指定)'} |",
            f"| 测试人员 | {self.meta.tester} |",
            f"| 日期 | {self.meta.date} |",
            f"| 方法论 | {self.meta.methodology} |",
            "",
            "## 执行摘要",
            "",
            f"本次渗透测试共发现 **{summary['total']}** 个安全问题:",
            "",
            f"| 严重性 | 数量 |",
            f"|--------|------|",
            f"| 🔴 严重 (Critical) | {summary['critical']} |",
            f"| 🟠 高危 (High) | {summary['high']} |",
            f"| 🟡 中危 (Medium) | {summary['medium']} |",
            f"| 🟢 低危 (Low) | {summary['low']} |",
            f"| 🔵 信息 (Info) | {summary['info']} |",
            "",
            "## 漏洞目录",
            "",
        ]
        
        for i, f in enumerate(findings, 1):
            icon = SEVERITY_ICONS.get(f.severity, "⚪")
            lines.append(f"{i}. {icon} [{f.title}](#{self._slugify(f.title)})")
        
        lines.extend(["", "---", "", "## 漏洞详情", ""])
        
        for i, f in enumerate(findings, 1):
            icon = SEVERITY_ICONS.get(f.severity, "⚪")
            lines.extend([
                f"### {icon} {f.title}",
                "",
                f"**严重性**: {f.severity.value.upper()}",
                "",
                f"**URL**: `{f.url}`",
                "",
            ])
            
            if f.parameter:
                lines.append(f"**参数**: `{f.parameter}`")
                lines.append("")
            
            if f.description:
                lines.extend([
                    "#### 描述",
                    "",
                    f.description,
                    "",
                ])
            
            if f.evidence:
                lines.extend([
                    "#### 证据",
                    "",
                    f.evidence,
                    "",
                ])
            
            if f.request:
                lines.extend([
                    "#### 请求",
                    "",
                    "```http",
                    f.request,
                    "```",
                    "",
                ])
            
            if f.response:
                resp_preview = f.response[:1500] + "\n... (截断)" if len(f.response) > 1500 else f.response
                lines.extend([
                    "#### 响应",
                    "",
                    "```http",
                    resp_preview,
                    "```",
                    "",
                ])
            
            if f.remediation:
                lines.extend([
                    "#### 修复建议",
                    "",
                    f.remediation,
                    "",
                ])
            
            if f.references:
                lines.extend([
                    "#### 参考链接",
                    "",
                ])
                for ref in f.references:
                    lines.append(f"- {ref}")
                lines.append("")
            
            lines.extend(["---", ""])
        
        lines.extend([
            "",
            "---",
            "",
            f"*由 AI-Burp v0.18.0 生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        ])
        
        content = "\n".join(lines)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_path
    
    def _slugify(self, text: str) -> str:
        """生成 URL 友好的 slug"""
        import re
        text = text.lower()
        text = re.sub(r'[^\w\s-]', '', text)
        text = re.sub(r'[\s_-]+', '-', text)
        return text.strip('-')
    
    def generate_json(self, output_path: str) -> str:
        """生成 JSON 报告"""
        data = {
            "meta": asdict(self.meta),
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self._sort_findings()],
            "generated_at": datetime.now().isoformat(),
            "generator": "AI-Burp v0.18.0"
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def print_summary(self):
        """打印摘要"""
        summary = self.get_summary()
        print("=" * 50)
        print(f"📊 {self.meta.title}")
        print("=" * 50)
        print(f"目标: {self.meta.target or '(未指定)'}")
        print(f"日期: {self.meta.date}")
        print()
        print(f"发现漏洞: {summary['total']} 个")
        print(f"  🔴 严重: {summary['critical']}")
        print(f"  🟠 高危: {summary['high']}")
        print(f"  🟡 中危: {summary['medium']}")
        print(f"  🟢 低危: {summary['low']}")
        print(f"  🔵 信息: {summary['info']}")
        print("=" * 50)


# 便捷函数
def create_finding(
    title: str,
    severity: str,
    url: str,
    parameter: str = "",
    description: str = "",
    evidence: str = "",
    request: str = "",
    response: str = "",
    remediation: str = ""
) -> Finding:
    """快速创建 Finding"""
    return Finding(
        title=title,
        severity=Severity(severity),
        url=url,
        parameter=parameter,
        description=description,
        evidence=evidence,
        request=request,
        response=response,
        remediation=remediation
    )
