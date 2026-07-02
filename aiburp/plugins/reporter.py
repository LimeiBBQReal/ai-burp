"""
AI-Burp 报告生成模块

支持格式:
1. JSON - 结构化数据
2. Markdown - 可读报告
3. HTML - 美观报告
"""

import json
import datetime
from pathlib import Path


class Reporter:
    """报告生成器"""
    
    def __init__(self, project="default"):
        self.project = project
        self.findings = []
        self.metadata = {
            'project': project,
            'start_time': datetime.datetime.now().isoformat(),
            'end_time': None,
            'targets': [],
        }
    
    def add_finding(self, finding):
        """添加发现"""
        finding['timestamp'] = datetime.datetime.now().isoformat()
        self.findings.append(finding)
    
    def add_target(self, target):
        """添加目标"""
        if target not in self.metadata['targets']:
            self.metadata['targets'].append(target)
    
    def finalize(self):
        """完成报告"""
        self.metadata['end_time'] = datetime.datetime.now().isoformat()
        self.metadata['total_findings'] = len(self.findings)
        
        # 统计
        self.metadata['stats'] = self._calculate_stats()
    
    def _calculate_stats(self):
        """计算统计"""
        stats = {
            'by_type': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_target': {},
        }
        
        for f in self.findings:
            # 按类型
            vuln_type = f.get('type', 'unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # 按严重程度
            severity = f.get('severity', 'medium')
            if severity in stats['by_severity']:
                stats['by_severity'][severity] += 1
            
            # 按目标
            target = f.get('target', 'unknown')
            stats['by_target'][target] = stats['by_target'].get(target, 0) + 1
        
        return stats
    
    def to_json(self, filepath=None):
        """导出 JSON"""
        self.finalize()
        
        data = {
            'metadata': self.metadata,
            'findings': self.findings,
        }
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return filepath
        
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    def to_markdown(self, filepath=None):
        """导出 Markdown"""
        self.finalize()
        
        lines = [
            f"# AI-Burp 扫描报告",
            "",
            f"**项目**: {self.metadata['project']}",
            f"**开始时间**: {self.metadata['start_time']}",
            f"**结束时间**: {self.metadata['end_time']}",
            f"**目标数量**: {len(self.metadata['targets'])}",
            f"**发现数量**: {self.metadata['total_findings']}",
            "",
            "---",
            "",
            "## 统计",
            "",
        ]
        
        # 按严重程度统计
        stats = self.metadata['stats']
        lines.append("### 按严重程度")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|---------|------|")
        for sev, count in stats['by_severity'].items():
            if count > 0:
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '⚪'}.get(sev, '⚪')
                lines.append(f"| {icon} {sev.upper()} | {count} |")
        lines.append("")
        
        # 按类型统计
        lines.append("### 按漏洞类型")
        lines.append("")
        lines.append("| 类型 | 数量 |")
        lines.append("|------|------|")
        for vuln_type, count in stats['by_type'].items():
            lines.append(f"| {vuln_type} | {count} |")
        lines.append("")
        
        # 详细发现
        lines.append("---")
        lines.append("")
        lines.append("## 详细发现")
        lines.append("")
        
        for i, f in enumerate(self.findings, 1):
            severity = f.get('severity', 'medium')
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '⚪'}.get(severity, '⚪')
            
            lines.append(f"### {icon} [{i}] {f.get('type', 'Unknown')}")
            lines.append("")
            lines.append(f"- **目标**: {f.get('target', 'N/A')}")
            lines.append(f"- **参数**: {f.get('param', 'N/A')}")
            lines.append(f"- **严重程度**: {severity.upper()}")
            
            if f.get('payload'):
                lines.append(f"- **Payload**: `{f['payload'][:100]}`")
            
            if f.get('evidence'):
                lines.append("")
                lines.append("**证据**:")
                lines.append("```")
                lines.append(f.get('evidence', '')[:500])
                lines.append("```")
            
            if f.get('description'):
                lines.append("")
                lines.append(f"**描述**: {f['description']}")
            
            lines.append("")
        
        # 目标列表
        lines.append("---")
        lines.append("")
        lines.append("## 目标列表")
        lines.append("")
        for target in self.metadata['targets']:
            lines.append(f"- {target}")
        
        content = "\n".join(lines)
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return filepath
        
        return content
    
    def to_html(self, filepath=None):
        """导出 HTML"""
        self.finalize()
        
        html_template = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI-Burp 扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .meta {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .meta p {{ margin: 5px 0; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat-card {{ background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; min-width: 150px; }}
        .stat-card h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #666; }}
        .stat-card .value {{ font-size: 24px; font-weight: bold; }}
        .finding {{ border: 1px solid #ddd; margin: 15px 0; border-radius: 5px; overflow: hidden; }}
        .finding-header {{ padding: 15px; cursor: pointer; display: flex; align-items: center; gap: 10px; }}
        .finding-header.critical {{ background: #f8d7da; }}
        .finding-header.high {{ background: #fff3cd; }}
        .finding-header.medium {{ background: #d1ecf1; }}
        .finding-header.low {{ background: #d4edda; }}
        .finding-body {{ padding: 15px; border-top: 1px solid #ddd; display: none; }}
        .finding.open .finding-body {{ display: block; }}
        .badge {{ padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge.critical {{ background: #dc3545; color: white; }}
        .badge.high {{ background: #fd7e14; color: white; }}
        .badge.medium {{ background: #17a2b8; color: white; }}
        .badge.low {{ background: #28a745; color: white; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 AI-Burp 扫描报告</h1>
        
        <div class="meta">
            <p><strong>项目:</strong> {project}</p>
            <p><strong>开始时间:</strong> {start_time}</p>
            <p><strong>结束时间:</strong> {end_time}</p>
            <p><strong>目标数量:</strong> {target_count}</p>
        </div>
        
        <h2>📊 统计</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>总发现</h3>
                <div class="value">{total_findings}</div>
            </div>
            <div class="stat-card">
                <h3>🔴 严重</h3>
                <div class="value" style="color: #dc3545;">{critical_count}</div>
            </div>
            <div class="stat-card">
                <h3>🟠 高危</h3>
                <div class="value" style="color: #fd7e14;">{high_count}</div>
            </div>
            <div class="stat-card">
                <h3>🟡 中危</h3>
                <div class="value" style="color: #17a2b8;">{medium_count}</div>
            </div>
            <div class="stat-card">
                <h3>🟢 低危</h3>
                <div class="value" style="color: #28a745;">{low_count}</div>
            </div>
        </div>
        
        <h2>🔍 详细发现</h2>
        {findings_html}
        
        <h2>🎯 目标列表</h2>
        <ul>
            {targets_html}
        </ul>
    </div>
    
    <script>
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                header.parentElement.classList.toggle('open');
            }});
        }});
    </script>
</body>
</html>'''
        
        # 生成发现 HTML
        findings_html = []
        for i, f in enumerate(self.findings, 1):
            severity = f.get('severity', 'medium')
            findings_html.append(f'''
            <div class="finding">
                <div class="finding-header {severity}">
                    <span class="badge {severity}">{severity.upper()}</span>
                    <strong>[{i}] {f.get('type', 'Unknown')}</strong>
                    <span style="margin-left: auto; color: #666;">{f.get('target', 'N/A')}</span>
                </div>
                <div class="finding-body">
                    <table>
                        <tr><th>目标</th><td>{f.get('target', 'N/A')}</td></tr>
                        <tr><th>参数</th><td>{f.get('param', 'N/A')}</td></tr>
                        <tr><th>Payload</th><td><code>{f.get('payload', 'N/A')[:100]}</code></td></tr>
                    </table>
                    {f'<h4>证据</h4><pre>{f.get("evidence", "")[:500]}</pre>' if f.get('evidence') else ''}
                    {f'<p><strong>描述:</strong> {f.get("description", "")}</p>' if f.get('description') else ''}
                </div>
            </div>
            ''')
        
        # 生成目标 HTML
        targets_html = '\n'.join(f'<li>{t}</li>' for t in self.metadata['targets'])
        
        stats = self.metadata['stats']
        
        html_content = html_template.format(
            project=self.metadata['project'],
            start_time=self.metadata['start_time'],
            end_time=self.metadata['end_time'],
            target_count=len(self.metadata['targets']),
            total_findings=self.metadata['total_findings'],
            critical_count=stats['by_severity']['critical'],
            high_count=stats['by_severity']['high'],
            medium_count=stats['by_severity']['medium'],
            low_count=stats['by_severity']['low'],
            findings_html='\n'.join(findings_html),
            targets_html=targets_html,
        )
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return filepath
        
        return html_content
    
    def save(self, filepath, format='auto'):
        """保存报告"""
        filepath = Path(filepath)
        
        if format == 'auto':
            ext = filepath.suffix.lower()
            format = {'.json': 'json', '.md': 'markdown', '.html': 'html'}.get(ext, 'json')
        
        if format == 'json':
            return self.to_json(filepath)
        elif format == 'markdown':
            return self.to_markdown(filepath)
        elif format == 'html':
            return self.to_html(filepath)
        else:
            raise ValueError(f"Unknown format: {format}")
