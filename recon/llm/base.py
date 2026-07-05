"""
Recon Pipeline V2 - 大模型基类

定义大模型接口，所有 LLM 后端必须实现此接口。
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SKIP = "skip"


@dataclass
class LLMResponse:
    """大模型响应"""
    success: bool
    content: str = ""
    structured_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    reasoning: str = ""
    error: str = ""

    @property
    def text(self) -> str:
        return self.content


class BaseLLM(ABC):
    """
    大模型基类

    子类必须实现:
    - analyze_assets() - 分析资产相关性
    - identify_protocol() - 识别协议类型
    - analyze_response() - 分析响应数据
    - verify_vulnerability() - 验证漏洞
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """LLM 名称"""
        ...

    @property
    @abstractmethod
    def max_tokens(self) -> int:
        """最大 token 数"""
        ...

    @abstractmethod
    def call(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.3) -> LLMResponse:
        """
        调用大模型

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            temperature: 温度 (0-1)

        Returns:
            LLMResponse
        """
        ...

    def analyze_assets(self, target: str, assets: List[dict]) -> LLMResponse:
        """
        分析资产与目标的相关性

        Args:
            target: 原始目标
            assets: 资产列表

        Returns:
            LLMResponse with structured_data: {
                "relevant_assets": [...],
                "irrelevant_assets": [...],
                "reasoning": "..."
            }
        """
        system_prompt = self._get_asset_analysis_system_prompt()
        user_prompt = self._format_asset_analysis_prompt(target, assets)
        return self.call(system_prompt, user_prompt, temperature=0.2)

    def identify_protocol(self, ip: str, port: int,
                          banner: str = "") -> LLMResponse:
        """
        根据 Banner 识别协议

        Args:
            ip: IP 地址
            port: 端口
            banner: Banner 信息

        Returns:
            LLMResponse with structured_data: {
                "protocol": "http",
                "confidence": 0.95,
                "reasoning": "..."
            }
        """
        system_prompt = self._get_protocol_identification_system_prompt()
        user_prompt = self._format_protocol_prompt(ip, port, banner)
        return self.call(system_prompt, user_prompt, temperature=0.1)

    def analyze_response(self, protocol: str, ip: str, port: int,
                         response: dict) -> LLMResponse:
        """
        分析协议响应数据

        Args:
            protocol: 协议类型
            ip: IP 地址
            port: 端口
            response: 响应数据

        Returns:
            LLMResponse with structured_data: {
                "findings": [...],
                "risk_level": "high",
                "recommendations": [...]
            }
        """
        system_prompt = self._get_response_analysis_system_prompt()
        user_prompt = self._format_response_prompt(protocol, ip, port, response)
        return self.call(system_prompt, user_prompt, temperature=0.3)

    def verify_vulnerability(self, vuln_type: str, asset: str,
                             evidence: dict) -> LLMResponse:
        """
        验证漏洞真实性

        Args:
            vuln_type: 漏洞类型
            asset: 资产标识
            evidence: 证据数据

        Returns:
            LLMResponse with structured_data: {
                "is_real": true,
                "severity": "critical",
                "confidence": 0.9,
                "description": "..."
            }
        """
        system_prompt = self._get_vuln_verification_system_prompt()
        user_prompt = self._format_vuln_prompt(vuln_type, asset, evidence)
        return self.call(system_prompt, user_prompt, temperature=0.2)

    # ==================== 提示词模板 ====================

    def _get_asset_analysis_system_prompt(self) -> str:
        return """你是一个网络安全侦察专家。你的任务是分析发现的资产与目标的相关性。

请根据以下维度判断:
1. 域名相关性 - 是否为目标的子域名或兄弟域名
2. IP 网络相关性 - 是否在同一 C 段或 B 段
3. 组织相关性 - 是否属于同一组织
4. 内容相关性 - 页面内容是否与目标相关

输出 JSON 格式:
{
    "relevant_assets": [{"value": "...", "reason": "..."}],
    "irrelevant_assets": ["..."],
    "reasoning": "整体分析"
}"""

    def _format_asset_analysis_prompt(self, target: str, assets: List[dict]) -> str:
        asset_list = "\n".join([
            f"- {a.get('value', '')} (来源: {a.get('source', '')})"
            for a in assets[:50]  # 限制数量避免 token 超限
        ])
        return f"""目标: {target}

发现的资产:
{asset_list}

请分析这些资产与目标的相关性。"""

    def _get_protocol_identification_system_prompt(self) -> str:
        return """你是一个协议识别专家。根据端口号和 Banner 信息识别协议类型。

常见协议特征:
- HTTP: 端口 80/8080/443, 响应以 HTTP/ 开头
- SSH: 端口 22, Banner 以 SSH- 开头
- FTP: 端口 21, 220 欢迎消息
- MySQL: 端口 3306, 握手包以 0x0a 开头
- Redis: 端口 6379, +PONG 或 NOAUTH 响应
- MongoDB: 端口 27017, OP_REPLY 消息
- PostgreSQL: 端口 5432, SSL 请求响应 S/N
- Memcached: 端口 11211, VERSION 响应
- Elasticsearch: 端口 9200, JSON 响应含 cluster_name
- SMTP: 端口 25/587, 220 欢迎消息

输出 JSON:
{
    "protocol": "http",
    "confidence": 0.95,
    "reasoning": "..."
}"""

    def _format_protocol_prompt(self, ip: str, port: int, banner: str) -> str:
        return f"""IP: {ip}
端口: {port}
Banner: {banner}

请识别此端口上运行的协议。"""

    def _get_response_analysis_system_prompt(self) -> str:
        return """你是一个安全分析师。分析协议响应数据，识别有价值的信息和安全问题。

关注点:
1. 版本信息 - 是否有已知 CVE
2. 配置问题 - 未授权访问、弱配置
3. 信息泄露 - 敏感路径、内部地址
4. 安全头 - HTTP 安全头是否缺失

输出 JSON:
{
    "findings": [
        {"type": "version", "value": "...", "risk": "info"},
        {"type": "misconfiguration", "value": "...", "risk": "high"}
    ],
    "risk_level": "high",
    "recommendations": ["..."]
}"""

    def _format_response_prompt(self, protocol: str, ip: str, port: int,
                                response: dict) -> str:
        response_str = str(response)[:2000]  # 限制长度
        return f"""协议: {protocol}
IP: {ip}
端口: {port}

响应数据:
{response_str}

请分析此响应，识别安全问题。"""

    def _get_vuln_verification_system_prompt(self) -> str:
        return """你是一个漏洞验证专家。验证潜在漏洞的真实性，减少误报。

验证标准:
1. 证据是否充分
2. 是否存在误报可能
3. 实际可利用性
4. 影响范围

输出 JSON:
{
    "is_real": true,
    "severity": "critical",
    "confidence": 0.9,
    "description": "...",
    "exploitability": "easy/medium/hard",
    "impact": "..."
}"""

    def _format_vuln_prompt(self, vuln_type: str, asset: str,
                            evidence: dict) -> str:
        evidence_str = str(evidence)[:2000]
        return f"""漏洞类型: {vuln_type}
资产: {asset}

证据:
{evidence_str}

请验证此漏洞的真实性。"""
