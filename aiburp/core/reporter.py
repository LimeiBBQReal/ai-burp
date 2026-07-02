"""
AIBURP Reporter - 报告生成模块

支持多种格式导出: MD, HTML, JSON, Nuclei
"""

import json
import html
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

from .models import Finding
from .history import History


@dataclass
class ReportConfig:
    title: str = "Security Assessment Report"
    author: str = "AIBURP"
    target: str = ""
    include_requests: bool = True
    include_responses: bool = True
    include_poc: bool = True
    min_severity: str = "info"


class Reporter:
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    
    def __init__(self, history: Optional[History] = None, config: Optional[ReportConfig] = None):
        self.history = history
        self.config = config or ReportConfig()
        self.findings: List[Finding] = []
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
    
    def add_findings(self, findings: List[Finding]):
        self.findings.extend(findings)
    
    def _filter_findings(self) -> List[Finding]:
        min_idx = self.SEVERITY_ORDER.index(self.config.min_severity)
        return [f for f in self.findings if self.SEVERITY_ORDER.index(f.severity) <= min_idx]
    
    def _sort_findings(self, findings: List[Finding]) -> List[Finding]:
        return sorted(findings, key=lambda f: self.SEVERITY_ORDER.index(f.severity))
    
    def to_markdown(self, output_path: Optional[str] = None) -> str:
        findings = self._sort_findings(self._filter_findings())
        lines = [f"# {self.config.title}", "", f"**Target:** {self.config.target}",
                 f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]
        
        lines.append("## Summary")
        lines.append(f"Total: **{len(findings)}**")
        for sev in self.SEVERITY_ORDER:
            cnt = len([f for f in findings if f.severity == sev])
            if cnt: lines.append(f"- {sev.upper()}: {cnt}")
        lines.append("")
        
        lines.append("## Findings")
        for i, f in enumerate(findings, 1):
            lines.extend([f"### {i}. [{f.severity.upper()}] {f.title}", f"**ID:** {f.id}",
                         f"**URL:** {f.url}", f"**Param:** {f.param}", ""])
            if f.payload: lines.extend(["**Payload:**", "`", f.payload, "`", ""])
            if f.evidence: lines.extend(["**Evidence:**", "`", f.evidence, "`", ""])
            lines.append("---")
        
        content = "\n".join(lines)
        if output_path: Path(output_path).write_text(content, encoding="utf-8")
        return content
    
    def to_json(self, output_path: Optional[str] = None) -> str:
        findings = self._sort_findings(self._filter_findings())
        report = {"meta": {"title": self.config.title, "target": self.config.target,
                          "date": datetime.now().isoformat()},
                  "findings": [f.to_dict() for f in findings]}
        content = json.dumps(report, indent=2, ensure_ascii=False)
        if output_path: Path(output_path).write_text(content, encoding="utf-8")
        return content
    
    def to_html(self, output_path: Optional[str] = None) -> str:
        findings = self._sort_findings(self._filter_findings())
        colors = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8"}
        
        h = f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{html.escape(self.config.title)}</title>
<style>body{{font-family:sans-serif;margin:40px;background:#f5f5f5}}.c{{max-width:1200px;margin:0 auto;background:#fff;padding:40px;border-radius:8px}}
.f{{border:1px solid #ddd;border-radius:8px;margin:20px 0;overflow:hidden}}.fh{{padding:15px;color:#fff;font-weight:bold}}
.fb{{padding:20px}}pre{{background:#f8f9fa;padding:15px;border-radius:4px}}</style></head><body><div class="c">
<h1>{html.escape(self.config.title)}</h1><p>Target: {html.escape(self.config.target)}</p><h2>Findings</h2>'''
        
        for f in findings:
            h += f'<div class="f"><div class="fh" style="background:{colors.get(f.severity,"#666")}">[{f.severity.upper()}] {html.escape(f.title)}</div>'
            h += f'<div class="fb"><p>URL: <code>{html.escape(f.url)}</code> | Param: <code>{html.escape(f.param)}</code></p>'
            if f.payload: h += f'<h4>Payload</h4><pre>{html.escape(f.payload)}</pre>'
            if f.evidence: h += f'<h4>Evidence</h4><pre>{html.escape(f.evidence)}</pre>'
            h += '</div></div>'
        
        h += '</div></body></html>'
        if output_path: Path(output_path).write_text(h, encoding="utf-8")
        return h
    
    def to_nuclei(self, output_dir: str) -> List[str]:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        generated = []
        for f in self._filter_findings():
            tpl = f'''id: {f.id.lower()}
info:
  name: {f.title}
  severity: {f.severity}
  tags: {f.type}
http:
  - method: {f.method or "GET"}
    path:
      - "{f.url}"'''
            fp = output_path / f"{f.id.lower()}.yaml"
            fp.write_text(tpl, encoding="utf-8")
            generated.append(str(fp))
        return generated
    
    def generate_poc(self, finding: Finding) -> Dict[str, str]:
        return {
            "curl": f"curl -X {finding.method or 'GET'} '{finding.url}'",
            "python": f'import requests\nresponse = requests.get("{finding.url}")\nprint(response.text)',
            "raw": finding.request or ""
        }
    
    def get_stats(self) -> Dict:
        findings = self._filter_findings()
        return {"total": len(findings), "by_severity": {s: len([f for f in findings if f.severity == s]) for s in self.SEVERITY_ORDER}}


def create_report(findings: List[Finding], title: str = "Report", target: str = "", output_format: str = "markdown", output_path: Optional[str] = None) -> str:
    r = Reporter(config=ReportConfig(title=title, target=target))
    r.add_findings(findings)
    if output_format == "html": return r.to_html(output_path)
    elif output_format == "json": return r.to_json(output_path)
    return r.to_markdown(output_path)
