"""
Recon Pipeline V2 - CatPaw 后端 (开发期间使用)

开发期间由 CatPaw AI 代替大模型，
生产环境可切换到 OpenAI/Claude 等 API。
"""
import json
import re
from typing import Optional
from .base import BaseLLM, LLMResponse


class CatPawBackend(BaseLLM):
    """
    CatPaw AI 后端 - 开发期间代替大模型

    实际生产中，此类会被 OpenAIBackend 或 ClaudeBackend 替换。
    这里提供基于规则的模拟实现，用于开发和测试。
    """

    name = "CatPaw-Dev"
    max_tokens = 4096

    def __init__(self):
        self._call_count = 0

    def call(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.3) -> LLMResponse:
        """
        调用 CatPaw AI

        开发期间使用规则引擎模拟大模型响应。
        生产环境替换为真实 API 调用。
        """
        self._call_count += 1

        # 根据提示词类型分发处理
        if "资产" in system_prompt or "相关性" in system_prompt:
            return self._analyze_assets(user_prompt)
        elif "协议" in system_prompt:
            return self._identify_protocol(user_prompt)
        elif "响应" in system_prompt or "分析" in system_prompt:
            return self._analyze_response(user_prompt)
        elif "漏洞" in system_prompt or "验证" in system_prompt:
            return self._verify_vulnerability(user_prompt)

        return LLMResponse(
            success=True,
            content="CatPaw 模拟响应",
            confidence=0.5,
        )

    def _analyze_assets(self, prompt: str) -> LLMResponse:
        """分析资产相关性"""
        # 提取目标
        target_match = re.search(r'目标:\s*(.+)', prompt)
        target = target_match.group(1).strip() if target_match else ""

        # 提取资产列表
        assets_section = prompt.split("发现的资产:")[-1] if "发现的资产:" in prompt else ""
        asset_lines = []
        for raw_line in assets_section.split("\n"):
            line = raw_line.strip()
            if not line.startswith("- "):
                continue
            asset_lines.append(line.strip("- ").strip())

        relevant = []
        irrelevant = []

        for line in asset_lines:
            if not line:
                continue

            # 提取资产值
            value = line.split(" (来源:")[0].strip() if " (来源:" in line else line

            # 简单规则判断
            if self._is_relevant(value, target):
                relevant.append({"value": value, "reason": "域名/IP 相关"})
            else:
                irrelevant.append(value)

        return LLMResponse(
            success=True,
            content=json.dumps({
                "relevant_assets": relevant,
                "irrelevant_assets": irrelevant,
                "reasoning": f"基于规则判断，目标 {target} 有 {len(relevant)} 个相关资产"
            }, ensure_ascii=False),
            structured_data={
                "relevant_assets": relevant,
                "irrelevant_assets": irrelevant,
            },
            confidence=0.8,
            reasoning="基于域名和 IP 规则的自动判断",
        )

    def _identify_protocol(self, prompt: str) -> LLMResponse:
        """识别协议"""
        port_match = re.search(r'端口:\s*(\d+)', prompt)
        port = int(port_match.group(1)) if port_match else 0

        banner_match = re.search(r'Banner:\s*(.+)', prompt, re.DOTALL)
        banner = banner_match.group(1).strip() if banner_match else ""

        # 端口-协议映射
        port_protocol = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http", 8443: "https",
            8888: "http", 9200: "elasticsearch", 11211: "memcached",
            27017: "mongodb",
        }

        protocol = port_protocol.get(port, "unknown")

        # Banner 验证
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                protocol = "ssh"
            elif "ftp" in banner_lower:
                protocol = "ftp"
            elif "http" in banner_lower:
                protocol = "http"
            elif "mysql" in banner_lower:
                protocol = "mysql"
            elif "redis" in banner_lower:
                protocol = "redis"
            elif "smtp" in banner_lower:
                protocol = "smtp"

        return LLMResponse(
            success=True,
            content=json.dumps({
                "protocol": protocol,
                "confidence": 0.9 if protocol != "unknown" else 0.3,
                "reasoning": f"基于端口 {port} 和 Banner 判断"
            }, ensure_ascii=False),
            structured_data={
                "protocol": protocol,
                "confidence": 0.9 if protocol != "unknown" else 0.3,
            },
            confidence=0.9,
        )

    def _analyze_response(self, prompt: str) -> LLMResponse:
        """分析响应"""
        findings = []

        # 检查未授权
        if "unauthenticated" in prompt.lower() or "未授权" in prompt:
            findings.append({
                "type": "unauthorized_access",
                "value": "服务允许未授权访问",
                "risk": "critical"
            })

        # 检查匿名登录
        if "anonymous" in prompt.lower() or "匿名" in prompt:
            findings.append({
                "type": "anonymous_login",
                "value": "允许匿名登录",
                "risk": "medium"
            })

        # 检查版本信息
        version_match = re.search(r'version["\s:]+(\d+\.\d+\.\d+)', prompt)
        if version_match:
            version = version_match.group(1)
            findings.append({
                "type": "version_disclosure",
                "value": f"版本: {version}",
                "risk": "low"
            })

        # 检查 HTTP 安全头
        if "http" in prompt.lower():
            missing_headers = []
            for header in ["X-Frame-Options", "X-Content-Type-Options",
                          "Content-Security-Policy", "Strict-Transport-Security"]:
                if header.lower() not in prompt.lower():
                    missing_headers.append(header)

            if missing_headers:
                findings.append({
                    "type": "missing_security_headers",
                    "value": f"缺少: {', '.join(missing_headers)}",
                    "risk": "low"
                })

        risk_level = "high" if any(f["risk"] == "critical" for f in findings) else \
                     "medium" if any(f["risk"] == "medium" for f in findings) else "low"

        return LLMResponse(
            success=True,
            content=json.dumps({
                "findings": findings,
                "risk_level": risk_level,
                "recommendations": ["建议进一步分析"]
            }, ensure_ascii=False),
            structured_data={
                "findings": findings,
                "risk_level": risk_level,
            },
            confidence=0.75,
        )

    def _verify_vulnerability(self, prompt: str) -> LLMResponse:
        """验证漏洞"""
        # 提取漏洞类型
        vuln_match = re.search(r'漏洞类型:\s*(.+)', prompt)
        vuln_type = vuln_match.group(1).strip() if vuln_match else "unknown"

        # 基于类型判断
        is_real = True
        confidence = 0.7
        severity = "medium"

        if "unauthorized" in vuln_type or "未授权" in vuln_type:
            is_real = True
            confidence = 0.9
            severity = "critical"
        elif "anonymous" in vuln_type or "匿名" in vuln_type:
            is_real = True
            confidence = 0.85
            severity = "medium"
        elif "outdated" in vuln_type or "过时" in vuln_type:
            is_real = True
            confidence = 0.6
            severity = "low"

        return LLMResponse(
            success=True,
            content=json.dumps({
                "is_real": is_real,
                "severity": severity,
                "confidence": confidence,
                "description": f"漏洞 {vuln_type} 验证结果",
                "exploitability": "easy" if severity == "critical" else "medium",
                "impact": "数据泄露" if "unauthorized" in vuln_type else "信息泄露"
            }, ensure_ascii=False),
            structured_data={
                "is_real": is_real,
                "severity": severity,
                "confidence": confidence,
            },
            confidence=confidence,
        )

    def _is_relevant(self, value: str, target: str) -> bool:
        """判断资产是否与目标相关"""
        if not value or not target:
            return False

        # 域名包含关系
        if target in value or value in target:
            return True

        # 提取根域名
        def root_domain(s):
            parts = s.split('.')
            return '.'.join(parts[-2:]) if len(parts) >= 2 else s

        if root_domain(value) == root_domain(target):
            return True

        # IP C 段匹配
        ip_match_v = re.search(r'(\d+\.\d+\.\d+)', value)
        ip_match_t = re.search(r'(\d+\.\d+\.\d+)', target)
        if ip_match_v and ip_match_t:
            if ip_match_v.group(1) == ip_match_t.group(1):
                return True

        return False

    @property
    def call_count(self) -> int:
        return self._call_count
