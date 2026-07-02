"""
triage.py — 突破点验证门控 (7-Question Gate)

从 Claude-BugHunter 知识库提取的 triage-validation 方法论核心。
当前实现 Q1 (可复现性) 和 Q3 (作用域) 两道门控。
"""
import re
from typing import Dict, List, Optional, Any


class TriageGate:
    """
    突破点验证门控。
    
    用法:
        gate = TriageGate(bt_finding)
        result = gate.run()
        if result["pass"]:
            # 通过门控, 进入验证环节
        else:
            # 被门控拦截, 跳过或降级
    """

    def __init__(self, target: str, finding: Dict[str, Any], scope_domains: List[str] = None):
        """
        Args:
            target: 目标 URL 或域名
            finding: 突破点信息
                {
                    "type": "idor|sql|xss|upload|ssrf|cmdi|auth_bypass|...",
                    "target": "完整 URL",
                    "confidence": "high|medium|low",
                    "payload_category": "...",
                    "reason": "说明"
                }
            scope_domains: 允许的域名列表, 用于 Q3 检查
        """
        self.target = target
        self.finding = finding
        self.scope_domains = scope_domains or []
        self._detail_url = finding.get("target", target)

    def run(self) -> Dict:
        """执行 Q1 + Q3 两道门控"""
        q1 = self._check_q1_reproducible()
        q3 = self._check_q3_in_scope()

        all_pass = q1["pass"] and q3["pass"]
        return {
            "pass": all_pass,
            "gates": {
                "q1_reproducible": q1,
                "q3_in_scope": q3,
            },
            "detail_url": self._detail_url,
            "finding_type": self.finding.get("type", "unknown"),
        }

    def _check_q1_reproducible(self) -> Dict:
        """
        Q1: 是否可以真实复现?
        
        检查 finding 中是否包含:
        - 完整 URL (必须有)
        - HTTP 方法 (GET/POST/PUT/DELETE 等)
        - 参数或请求体细节
        
        这个检查不依赖 LLM — 基于结构化字段判断。
        """
        reasons = []
        pass_check = True

        # 1. 必须有 target URL
        target_url = self.finding.get("target", "")
        if not target_url or target_url == self.target:
            reasons.append("缺少目标 URL 或 URL 与根域名相同")
            pass_check = False
        elif not target_url.startswith("http"):
            reasons.append("目标 URL 不是有效的 HTTP URL")
            pass_check = False
        else:
            reasons.append(f"目标 URL 有效: {target_url[:80]}")

        # 2. 必须有 reason — 说明为什么这个是一个突破口
        reason = self.finding.get("reason", "")
        if not reason or len(reason) < 10:
            reasons.append("缺少充分的突破点说明 (reason 字段)")
            pass_check = False

        # 3. 检查是否包含具体参数特征 (URL 中有 ?key=value 或 path 中有 ID)
        has_param = "?" in target_url
        has_path_id = bool(re.search(r'/\d+', target_url.split('?')[0]))
        if not has_param and not has_path_id:
            reasons.append("URL 无参数且无数字路径 ID, 可能无法通过参数变化验证漏洞")
            pass_check = False
        else:
            reasons.append(f"URL 包含参数或路径 ID")

        return {
            "pass": pass_check,
            "reasons": reasons,
        }

    def _check_q3_in_scope(self) -> Dict:
        """
        Q3: 根因在 scope 资产内吗?

        检查 finding 的 target URL 是否属于授权的目标域。
        scope_domains 为空时视为放行 (信任调用方已确认)。
        """
        if not self.scope_domains:
            return {
                "pass": True,
                "reasons": ["作用域列表为空, 信任调用方已确认"],
            }

        from urllib.parse import urlparse
        target_url = self.finding.get("target", "")
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname or ""
        except Exception:
            parsed = None
            hostname = ""

        if not hostname:
            return {
                "pass": False,
                "reasons": ["无法解析 URL 中的域名"],
            }

        # 检查域名是否在 scope 内
        in_scope = False
        for scope_domain in self.scope_domains:
            scope_clean = scope_domain.lower().strip()
            host_clean = hostname.lower()
            # 精确匹配或子域名匹配
            if host_clean == scope_clean or host_clean.endswith("." + scope_clean):
                in_scope = True
                break

        if in_scope:
            return {
                "pass": True,
                "reasons": [f"域名 {hostname} 在作用域内"],
            }
        else:
            return {
                "pass": False,
                "reasons": [f"域名 {hostname} 不在作用域 {self.scope_domains} 内"],
            }

    def summary(self, result: Dict) -> str:
        """生成人类可读的摘要"""
        if result["pass"]:
            return f"✅ [{result['finding_type']}] {result['detail_url'][:60]} — 门控通过"
        fails = []
        for gate_name, gate_result in result["gates"].items():
            if not gate_result["pass"]:
                fails.extend(gate_result["reasons"])
        fail_str = "; ".join(fails[:3])
        return f"❌ [{result['finding_type']}] {result['detail_url'][:60]} — 门控拦截: {fail_str}"
