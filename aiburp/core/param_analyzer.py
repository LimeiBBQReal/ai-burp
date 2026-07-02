"""
ParamAnalyzer - 参数深度分析器 (赏金猎人思维)

以顶级赏金猎人的视角分析每个参数，识别高价值攻击向量。

核心功能:
1. 值模式识别 (numeric_id, base64, jwt, uuid, file_path, url, json, xml, timestamp, hash)
2. 参数名敏感度分析 (debug, admin, hidden, callback, version)
3. 风险评分计算
4. 漏洞建议和攻击链生成
5. 参数关系识别
6. 隐藏参数发现
"""

import re
import json
import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from .models import Request


# ============================================================
# 数据模型
# ============================================================

@dataclass
class ParamAnalysis:
    """单个参数的分析结果"""
    name: str
    value: str
    location: str  # url, body, header, cookie
    
    # 值模式识别
    value_pattern: str = "unknown"  # numeric_id, base64, jwt, uuid, file_path, url, json, xml, timestamp, hash_md5, hash_sha1, hash_sha256, encrypted, unknown
    decoded_value: Optional[str] = None  # Base64/JWT 解码后的值
    
    # 风险评估
    risk_score: int = 0  # 0-100
    risk_factors: List[str] = field(default_factory=list)
    
    # 漏洞建议
    suggested_vulns: List[str] = field(default_factory=list)  # sqli, idor, lfi, ssrf, xss, etc.
    attack_chains: List[str] = field(default_factory=list)  # 具体攻击链建议
    
    # 赏金猎人洞察
    hunter_insight: str = ""  # 像顶级赏金猎人一样的推理
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value": self.value,
            "location": self.location,
            "value_pattern": self.value_pattern,
            "decoded_value": self.decoded_value,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "suggested_vulns": self.suggested_vulns,
            "attack_chains": self.attack_chains,
            "hunter_insight": self.hunter_insight,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class RequestAnalysis:
    """请求的完整分析结果"""
    request_id: Optional[int] = None
    url: str = ""
    method: str = ""
    
    # 参数分析
    params: List[ParamAnalysis] = field(default_factory=list)
    
    # 参数关系
    param_relationships: List[Dict] = field(default_factory=list)  # e.g., user_id + action = IDOR
    
    # 隐藏参数发现
    hidden_params_found: List[str] = field(default_factory=list)
    hidden_params_suggested: List[str] = field(default_factory=list)
    
    # 整体风险
    overall_risk: str = "low"  # critical, high, medium, low
    priority_score: int = 0
    
    # 赏金猎人总结
    hunter_summary: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "url": self.url,
            "method": self.method,
            "params": [p.to_dict() for p in self.params],
            "param_relationships": self.param_relationships,
            "hidden_params_found": self.hidden_params_found,
            "hidden_params_suggested": self.hidden_params_suggested,
            "overall_risk": self.overall_risk,
            "priority_score": self.priority_score,
            "hunter_summary": self.hunter_summary,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)



# ============================================================
# ParamAnalyzer 类
# ============================================================

class ParamAnalyzer:
    """
    参数深度分析器 - 以顶级赏金猎人思维分析每个参数
    
    核心功能:
    1. 识别值模式 (Base64? JWT? ID? 文件路径?)
    2. 识别命名模式 (debug? admin? hidden?)
    3. 计算风险评分
    4. 建议攻击链
    5. 识别参数关系
    """
    
    # 值模式正则表达式
    PATTERNS = {
        "numeric_id": r"^\d+$",
        "uuid": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        "jwt": r"^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$",
        "file_path": r"^[./\\]|\.\.\/|\.\.\\|^[a-zA-Z]:\\",
        "url": r"^https?://",
        "timestamp": r"^\d{10,13}$",
        "hash_md5": r"^[a-f0-9]{32}$",
        "hash_sha1": r"^[a-f0-9]{40}$",
        "hash_sha256": r"^[a-f0-9]{64}$",
    }
    
    # Base64 模式 (单独处理，需要更复杂的验证)
    BASE64_PATTERN = r"^[A-Za-z0-9+/]+=*$"
    
    # 敏感参数名模式
    SENSITIVE_NAMES = {
        "id_params": ["id", "uid", "user_id", "pid", "product_id", "order_id", "account_id", "userid", "accountid"],
        "file_params": ["file", "path", "filename", "filepath", "document", "attachment", "doc", "upload"],
        "url_params": ["url", "link", "redirect", "return", "next", "callback", "goto", "returnurl", "redirect_uri"],
        "auth_params": ["token", "session", "auth", "key", "api_key", "secret", "apikey", "access_token"],
        "debug_params": ["debug", "test", "dev", "verbose", "trace", "log", "mode"],
        "admin_params": ["admin", "role", "privilege", "isAdmin", "is_admin", "permission", "level", "type"],
        "hidden_params": ["_", "__", "internal", "private", "hidden"],
        "callback_params": ["callback", "jsonp", "cb", "func", "handler"],
        "version_params": ["v", "version", "api_version", "ver"],
        "search_params": ["search", "query", "q", "keyword", "term", "filter"],
    }
    
    # 漏洞映射
    VULN_MAPPING = {
        "numeric_id": ["sqli", "idor", "enumeration"],
        "base64": ["deserialization", "info_disclosure", "injection"],
        "jwt": ["jwt_none_alg", "jwt_weak_secret", "jwt_confusion"],
        "uuid": ["uuid_enumeration"],
        "file_path": ["lfi", "path_traversal", "rfi"],
        "url": ["ssrf", "open_redirect"],
        "timestamp": ["race_condition", "replay_attack"],
        "hash_md5": ["hash_length_extension", "weak_hash"],
        "hash_sha1": ["hash_length_extension", "weak_hash"],
        "hash_sha256": ["hash_length_extension"],
        "json": ["json_injection", "mass_assignment"],
        "xml": ["xxe", "xml_injection"],
    }
    
    def __init__(self, history=None):
        """
        初始化 ParamAnalyzer
        
        Args:
            history: History 实例，用于历史数据分析
        """
        self.history = history
    
    # ==================== 值模式检测 ====================
    
    def _detect_value_pattern(self, value: str) -> str:
        """
        检测值的模式
        
        Args:
            value: 参数值
            
        Returns:
            模式名称: numeric_id, base64, jwt, uuid, file_path, url, json, xml, timestamp, hash_md5, hash_sha1, hash_sha256, unknown
        """
        if not value or not isinstance(value, str):
            return "unknown"
        
        value = value.strip()
        
        if not value:
            return "unknown"
        
        # 按优先级检测模式
        
        # 1. JWT (最具体的模式，优先检测)
        if re.match(self.PATTERNS["jwt"], value):
            return "jwt"
        
        # 2. UUID
        if re.match(self.PATTERNS["uuid"], value, re.IGNORECASE):
            return "uuid"
        
        # 3. Hash 值 (按长度检测)
        if re.match(self.PATTERNS["hash_sha256"], value, re.IGNORECASE):
            return "hash_sha256"
        if re.match(self.PATTERNS["hash_sha1"], value, re.IGNORECASE):
            return "hash_sha1"
        if re.match(self.PATTERNS["hash_md5"], value, re.IGNORECASE):
            return "hash_md5"
        
        # 4. URL
        if re.match(self.PATTERNS["url"], value, re.IGNORECASE):
            return "url"
        
        # 5. 文件路径
        if re.match(self.PATTERNS["file_path"], value):
            return "file_path"
        
        # 6. 时间戳 (10-13位数字)
        if re.match(self.PATTERNS["timestamp"], value):
            return "timestamp"
        
        # 7. 纯数字 ID
        if re.match(self.PATTERNS["numeric_id"], value):
            return "numeric_id"
        
        # 8. JSON
        if self._is_json(value):
            return "json"
        
        # 9. XML
        if self._is_xml(value):
            return "xml"
        
        # 10. Base64 (最后检测，因为很多字符串都可能匹配 Base64 模式)
        if self._is_base64(value):
            return "base64"
        
        return "unknown"
    
    def _is_json(self, value: str) -> bool:
        """检测是否是 JSON"""
        value = value.strip()
        if not (value.startswith("{") or value.startswith("[")):
            return False
        try:
            json.loads(value)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def _is_xml(self, value: str) -> bool:
        """检测是否是 XML"""
        value = value.strip()
        return value.startswith("<") and value.endswith(">") and "</" in value
    
    def _is_base64(self, value: str) -> bool:
        """
        检测是否是 Base64 编码
        
        需要满足:
        1. 匹配 Base64 字符集
        2. 长度合理 (至少 4 个字符)
        3. 能成功解码
        """
        if len(value) < 4:
            return False
        
        if not re.match(self.BASE64_PATTERN, value):
            return False
        
        # 尝试解码验证
        try:
            # 补齐 padding
            padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
            decoded = base64.b64decode(padded)
            # 检查解码后是否是可打印字符 (至少 50% 可打印)
            printable_count = sum(1 for b in decoded if 32 <= b <= 126)
            return printable_count / len(decoded) > 0.5 if decoded else False
        except Exception:
            return False
    
    def _try_decode_base64(self, value: str) -> Optional[str]:
        """
        尝试 Base64 解码
        
        Args:
            value: Base64 编码的字符串
            
        Returns:
            解码后的字符串，失败返回 None
        """
        try:
            # 补齐 padding
            padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
            decoded = base64.b64decode(padded)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    def _decode_jwt(self, value: str) -> Optional[str]:
        """
        解码 JWT
        
        Args:
            value: JWT 字符串
            
        Returns:
            解码后的 Header 和 Payload，失败返回 None
        """
        try:
            parts = value.split(".")
            if len(parts) != 3:
                return None
            
            # 解码 header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = base64.urlsafe_b64decode(header_padded).decode('utf-8', errors='ignore')
            
            # 解码 payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = base64.urlsafe_b64decode(payload_padded).decode('utf-8', errors='ignore')
            
            return f"Header: {header}\nPayload: {payload}"
        except Exception:
            return None


    # ==================== 风险评分计算 ====================
    
    def _calculate_risk(self, name: str, value: str, pattern: str) -> Tuple[int, List[str]]:
        """
        计算风险评分
        
        基于:
        1. 参数名敏感度
        2. 值模式风险
        
        Args:
            name: 参数名
            value: 参数值
            pattern: 值模式
            
        Returns:
            (risk_score, risk_factors) - 风险评分 (0-100) 和风险因素列表
        """
        score = 0
        factors = []
        
        name_lower = name.lower()
        
        # ========== 参数名风险 ==========
        
        # ID 参数 - 可能存在 IDOR/SQLi
        if any(p in name_lower for p in self.SENSITIVE_NAMES["id_params"]):
            score += 30
            factors.append("ID参数 - 可能存在IDOR/SQLi")
        
        # 文件参数 - 可能存在 LFI/路径遍历
        if any(p in name_lower for p in self.SENSITIVE_NAMES["file_params"]):
            score += 40
            factors.append("文件参数 - 可能存在LFI/路径遍历")
        
        # URL 参数 - 可能存在 SSRF/开放重定向
        if any(p in name_lower for p in self.SENSITIVE_NAMES["url_params"]):
            score += 35
            factors.append("URL参数 - 可能存在SSRF/开放重定向")
        
        # 认证参数 - 敏感
        if any(p in name_lower for p in self.SENSITIVE_NAMES["auth_params"]):
            score += 30
            factors.append("认证参数 - 敏感信息")
        
        # 调试参数 - 可能泄露敏感信息
        if any(p in name_lower for p in self.SENSITIVE_NAMES["debug_params"]):
            score += 25
            factors.append("调试参数 - 可能泄露敏感信息")
        
        # 管理员参数 - 可能存在权限提升
        if any(p in name_lower for p in self.SENSITIVE_NAMES["admin_params"]):
            score += 45
            factors.append("管理员参数 - 可能存在权限提升")
        
        # 隐藏参数 - 可能存在隐藏功能
        if any(p == name_lower or name_lower.startswith(p) for p in self.SENSITIVE_NAMES["hidden_params"]):
            score += 20
            factors.append("隐藏参数 - 可能存在隐藏功能")
        
        # 回调参数 - 可能存在 XSS/SSRF
        if any(p in name_lower for p in self.SENSITIVE_NAMES["callback_params"]):
            score += 30
            factors.append("回调参数 - 可能存在XSS/SSRF")
        
        # 搜索参数 - 可能存在 SQLi/XSS
        if any(p in name_lower for p in self.SENSITIVE_NAMES["search_params"]):
            score += 25
            factors.append("搜索参数 - 可能存在SQLi/XSS")
        
        # ========== 值模式风险 ==========
        
        if pattern == "jwt":
            score += 30
            factors.append("JWT令牌 - 检查算法混淆/弱密钥")
        elif pattern == "base64":
            score += 20
            factors.append("Base64编码 - 可能隐藏敏感数据/反序列化")
        elif pattern == "numeric_id":
            score += 25
            factors.append("数字ID - 可能存在IDOR/枚举")
        elif pattern == "file_path":
            score += 35
            factors.append("文件路径 - 可能存在LFI/路径遍历")
        elif pattern == "url":
            score += 30
            factors.append("URL值 - 可能存在SSRF/开放重定向")
        elif pattern == "json":
            score += 15
            factors.append("JSON值 - 可能存在注入/Mass Assignment")
        elif pattern == "xml":
            score += 25
            factors.append("XML值 - 可能存在XXE")
        elif pattern == "timestamp":
            score += 10
            factors.append("时间戳 - 可能存在竞态条件/重放攻击")
        elif pattern in ["hash_md5", "hash_sha1"]:
            score += 15
            factors.append("弱哈希 - 可能存在哈希长度扩展攻击")
        
        # 限制最大分数为 100
        return min(score, 100), factors


    # ==================== 漏洞建议和攻击链生成 ====================
    
    def _suggest_vulns(self, name: str, pattern: str) -> List[str]:
        """
        建议可能的漏洞类型
        
        Args:
            name: 参数名
            pattern: 值模式
            
        Returns:
            可能的漏洞类型列表
        """
        vulns = set()
        name_lower = name.lower()
        
        # 基于值模式
        if pattern in self.VULN_MAPPING:
            vulns.update(self.VULN_MAPPING[pattern])
        
        # 基于参数名
        if any(p in name_lower for p in self.SENSITIVE_NAMES["id_params"]):
            vulns.update(["sqli", "idor", "enumeration"])
        
        if any(p in name_lower for p in self.SENSITIVE_NAMES["file_params"]):
            vulns.update(["lfi", "path_traversal", "rfi"])
        
        if any(p in name_lower for p in self.SENSITIVE_NAMES["url_params"]):
            vulns.update(["ssrf", "open_redirect"])
        
        if any(p in name_lower for p in self.SENSITIVE_NAMES["search_params"]):
            vulns.update(["sqli", "xss"])
        
        if any(p in name_lower for p in self.SENSITIVE_NAMES["callback_params"]):
            vulns.update(["xss", "jsonp_hijacking"])
        
        if any(p in name_lower for p in self.SENSITIVE_NAMES["admin_params"]):
            vulns.update(["privilege_escalation", "idor"])
        
        return list(vulns)
    
    def _generate_attack_chains(self, name: str, value: str, pattern: str) -> List[str]:
        """
        生成具体的攻击链建议
        
        Args:
            name: 参数名
            value: 参数值
            pattern: 值模式
            
        Returns:
            攻击链建议列表
        """
        chains = []
        
        # 基于值模式生成攻击链
        if pattern == "numeric_id":
            try:
                int_val = int(value)
                chains.append(f"IDOR: 尝试修改 {name}={int_val+1} 或 {name}={int_val-1}")
                chains.append(f"SQLi: 尝试 {name}={value}' 或 {name}={value} AND 1=1")
                chains.append(f"枚举: 尝试遍历 {name}=1 到 {name}=1000")
            except ValueError:
                pass
        
        elif pattern == "jwt":
            chains.append("JWT None算法: 修改header的alg为none，移除签名")
            chains.append("JWT弱密钥: 使用jwt_tool或hashcat爆破密钥")
            chains.append("JWT算法混淆: RS256→HS256攻击，使用公钥作为密钥")
            chains.append("JWT过期绕过: 修改exp字段延长有效期")
        
        elif pattern == "base64":
            chains.append("解码检查: 查看是否包含敏感信息")
            chains.append("反序列化: 如果是对象，尝试注入恶意payload")
            chains.append("修改重编码: 修改解码后的值，重新编码后发送")
        
        elif pattern == "file_path":
            chains.append("LFI: 尝试 ../../../etc/passwd")
            chains.append("路径遍历绕过: 尝试 ....//....//etc/passwd")
            chains.append("空字节绕过: 尝试 ../../../etc/passwd%00.jpg")
            chains.append("编码绕过: 尝试 %2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd")
        
        elif pattern == "url":
            chains.append("SSRF: 尝试 http://127.0.0.1 或 http://169.254.169.254")
            chains.append("开放重定向: 尝试 //evil.com 或 https://evil.com")
            chains.append("协议绕过: 尝试 file:///etc/passwd 或 gopher://")
            chains.append("DNS重绑定: 使用DNS重绑定绕过IP白名单")
        
        elif pattern == "json":
            chains.append("JSON注入: 尝试在JSON值中注入特殊字符")
            chains.append("Mass Assignment: 尝试添加额外字段如 isAdmin, role")
            chains.append("原型污染: 尝试 __proto__ 或 constructor.prototype")
        
        elif pattern == "xml":
            chains.append("XXE: 尝试 <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>")
            chains.append("XXE OOB: 使用外带通道提取数据")
            chains.append("XSLT注入: 如果处理XSLT，尝试代码执行")
        
        elif pattern == "timestamp":
            chains.append("竞态条件: 快速发送多个请求测试TOCTOU")
            chains.append("重放攻击: 使用旧时间戳重放请求")
        
        elif pattern in ["hash_md5", "hash_sha1"]:
            chains.append("哈希长度扩展: 如果用于签名验证，尝试长度扩展攻击")
            chains.append("彩虹表: 尝试在线彩虹表查询")
        
        # 基于参数名生成攻击链
        name_lower = name.lower()
        
        if any(p in name_lower for p in ["admin", "role", "privilege", "isadmin"]):
            chains.append(f"权限提升: 尝试 {name}=admin 或 {name}=1 或 {name}=true")
        
        if any(p in name_lower for p in ["debug", "test", "dev"]):
            chains.append(f"调试模式: 尝试 {name}=1 或 {name}=true 启用调试")
        
        if any(p in name_lower for p in ["callback", "jsonp", "cb"]):
            chains.append(f"XSS: 尝试 {name}=alert(1)// 或 {name}=<script>alert(1)</script>")
        
        return chains


    # ==================== 参数关系识别 ====================
    
    def _find_relationships(self, params: List[ParamAnalysis]) -> List[Dict]:
        """
        识别参数之间的关系
        
        识别模式:
        1. user_id + action = IDOR
        2. from + to = 转账越权
        3. source + target = 数据操作越权
        4. id + type = 类型混淆
        
        Args:
            params: 参数分析列表
            
        Returns:
            参数关系列表
        """
        relationships = []
        
        param_names = [p.name.lower() for p in params]
        param_dict = {p.name.lower(): p for p in params}
        
        # user_id + action = IDOR
        user_params = [n for n in param_names if any(kw in n for kw in ["user", "uid", "account", "member"])]
        action_params = [n for n in param_names if any(kw in n for kw in ["action", "op", "operation", "cmd", "command"])]
        
        if user_params and action_params:
            relationships.append({
                "type": "idor_candidate",
                "params": user_params + action_params,
                "insight": "用户ID + 操作 = 经典IDOR组合，尝试修改user_id执行其他用户的操作",
                "risk": "high"
            })
        
        # from + to = 转账越权
        if "from" in param_names and "to" in param_names:
            relationships.append({
                "type": "transfer_idor",
                "params": ["from", "to"],
                "insight": "转账/转移操作，尝试修改from为其他用户，或修改to为自己",
                "risk": "critical"
            })
        
        # source + target/dest = 数据操作越权
        source_params = [n for n in param_names if any(kw in n for kw in ["source", "src", "origin"])]
        target_params = [n for n in param_names if any(kw in n for kw in ["target", "dest", "destination"])]
        
        if source_params and target_params:
            relationships.append({
                "type": "data_transfer_idor",
                "params": source_params + target_params,
                "insight": "数据源+目标操作，尝试修改source或target访问其他资源",
                "risk": "high"
            })
        
        # id + type = 类型混淆
        id_params = [n for n in param_names if n.endswith("id") or n.endswith("_id")]
        type_params = [n for n in param_names if any(kw in n for kw in ["type", "kind", "category"])]
        
        if id_params and type_params:
            relationships.append({
                "type": "type_confusion",
                "params": id_params + type_params,
                "insight": "ID + 类型组合，尝试使用不同类型的ID访问资源",
                "risk": "medium"
            })
        
        # owner + resource = 所有权绕过
        owner_params = [n for n in param_names if any(kw in n for kw in ["owner", "creator", "author"])]
        resource_params = [n for n in param_names if any(kw in n for kw in ["resource", "item", "object", "file", "doc"])]
        
        if owner_params and resource_params:
            relationships.append({
                "type": "ownership_bypass",
                "params": owner_params + resource_params,
                "insight": "所有者 + 资源组合，尝试修改owner访问其他用户的资源",
                "risk": "high"
            })
        
        # role/permission + action = 权限提升
        role_params = [n for n in param_names if any(kw in n for kw in ["role", "permission", "privilege", "level"])]
        
        if role_params and action_params:
            relationships.append({
                "type": "privilege_escalation",
                "params": role_params + action_params,
                "insight": "角色 + 操作组合，尝试修改role执行高权限操作",
                "risk": "critical"
            })
        
        # 多个 ID 参数 = 批量操作越权
        multiple_ids = [n for n in param_names if "id" in n]
        if len(multiple_ids) >= 2:
            relationships.append({
                "type": "batch_idor",
                "params": multiple_ids,
                "insight": f"发现 {len(multiple_ids)} 个ID参数，可能存在批量操作越权",
                "risk": "medium"
            })
        
        return relationships


    # ==================== 赏金猎人洞察生成 ====================
    
    def _generate_hunter_insight(self, name: str, value: str, analysis: ParamAnalysis) -> str:
        """
        生成赏金猎人洞察
        
        像顶级赏金猎人一样思考，给出具体的测试建议
        
        Args:
            name: 参数名
            value: 参数值
            analysis: 参数分析结果
            
        Returns:
            赏金猎人洞察字符串
        """
        insights = []
        
        # 高风险参数
        if analysis.risk_score >= 70:
            insights.append(f"🔥 高价值目标! {name} 参数风险评分 {analysis.risk_score}/100")
        
        # JWT 发现
        if analysis.value_pattern == "jwt":
            insights.append("💡 JWT发现! 立即检查: 1)算法混淆 2)弱密钥 3)过期时间 4)敏感信息泄露")
            if analysis.decoded_value:
                if "admin" in analysis.decoded_value.lower() or "role" in analysis.decoded_value.lower():
                    insights.append("⚠️ JWT中包含角色信息，尝试修改提权!")
        
        # 数字 ID
        if analysis.value_pattern == "numeric_id":
            insights.append(f"💡 数字ID {value} - 经典IDOR目标! 尝试遍历相邻值，检查是否能访问其他用户数据")
        
        # 管理员参数
        if any(kw in name.lower() for kw in ["admin", "role", "privilege", "isadmin"]):
            insights.append("💡 权限参数! 尝试修改为 admin/root/1/true，可能直接提权")
        
        # Base64 解码后的敏感信息
        if analysis.value_pattern == "base64" and analysis.decoded_value:
            decoded_lower = analysis.decoded_value.lower()
            if any(kw in decoded_lower for kw in ["user", "id", "admin", "password", "token"]):
                insights.append("💡 Base64解码后包含敏感信息! 尝试修改后重新编码")
        
        # 文件路径
        if analysis.value_pattern == "file_path":
            insights.append("💡 文件路径参数! 立即测试LFI: ../../../etc/passwd")
        
        # URL 参数
        if analysis.value_pattern == "url":
            insights.append("💡 URL参数! 测试SSRF: http://127.0.0.1 和 http://169.254.169.254")
        
        # 调试参数
        if any(kw in name.lower() for kw in ["debug", "test", "dev", "verbose"]):
            insights.append("💡 调试参数! 尝试启用可能泄露敏感信息或绕过安全检查")
        
        # 回调参数
        if any(kw in name.lower() for kw in ["callback", "jsonp", "cb"]):
            insights.append("💡 回调参数! 测试XSS和JSONP劫持")
        
        # 搜索参数
        if any(kw in name.lower() for kw in ["search", "query", "q", "keyword"]):
            insights.append("💡 搜索参数! 测试SQLi和XSS，这是常见的注入点")
        
        return " | ".join(insights) if insights else "常规参数，优先级较低"
    
    def _generate_hunter_summary(self, analysis: RequestAnalysis) -> str:
        """
        生成赏金猎人总结
        
        Args:
            analysis: 请求分析结果
            
        Returns:
            赏金猎人总结字符串
        """
        high_risk_params = [p for p in analysis.params if p.risk_score >= 50]
        
        if not high_risk_params:
            return "低优先级目标，建议先测试其他请求"
        
        summary_parts = [f"🎯 发现 {len(high_risk_params)} 个高风险参数:"]
        
        # 按风险评分排序，显示前3个
        sorted_params = sorted(high_risk_params, key=lambda p: p.risk_score, reverse=True)
        for p in sorted_params[:3]:
            summary_parts.append(f"  - {p.name} ({p.risk_score}分): {p.value_pattern}")
            if p.suggested_vulns:
                summary_parts.append(f"    可能漏洞: {', '.join(p.suggested_vulns[:3])}")
        
        # 参数关系
        if analysis.param_relationships:
            summary_parts.append(f"⚡ 发现 {len(analysis.param_relationships)} 个参数关系，可能存在业务逻辑漏洞:")
            for rel in analysis.param_relationships[:2]:
                summary_parts.append(f"  - {rel['type']}: {rel['insight']}")
        
        # 整体建议
        if analysis.overall_risk == "critical":
            summary_parts.append("🚨 建议立即深入测试此请求!")
        elif analysis.overall_risk == "high":
            summary_parts.append("⚠️ 高优先级目标，值得投入时间测试")
        
        return "\n".join(summary_parts)


    # ==================== 主分析方法 ====================
    
    def _collect_all_params(self, request: Request) -> List[Tuple[str, str, str]]:
        """
        收集请求中的所有参数
        
        Args:
            request: Request 对象
            
        Returns:
            [(name, value, location), ...] 列表
        """
        params = []
        
        # URL 参数
        for name, value in request.params.items():
            params.append((name, str(value), "url"))
        
        # Body 参数
        for name, value in request.body_params.items():
            params.append((name, str(value), "body"))
        
        # Cookie 参数
        for name, value in request.cookies.items():
            params.append((name, str(value), "cookie"))
        
        # 特定 Header 参数 (可能包含敏感信息)
        sensitive_headers = ["Authorization", "X-Auth-Token", "X-API-Key", "X-Access-Token"]
        for header in sensitive_headers:
            if header in request.headers:
                params.append((header, request.headers[header], "header"))
        
        return params
    
    def _analyze_param(self, name: str, value: str, location: str) -> ParamAnalysis:
        """
        分析单个参数
        
        Args:
            name: 参数名
            value: 参数值
            location: 参数位置 (url, body, cookie, header)
            
        Returns:
            ParamAnalysis 对象
        """
        analysis = ParamAnalysis(name=name, value=value, location=location)
        
        # 1. 识别值模式
        analysis.value_pattern = self._detect_value_pattern(value)
        
        # 2. 尝试解码
        if analysis.value_pattern == "base64":
            analysis.decoded_value = self._try_decode_base64(value)
        elif analysis.value_pattern == "jwt":
            analysis.decoded_value = self._decode_jwt(value)
        
        # 3. 计算风险评分
        analysis.risk_score, analysis.risk_factors = self._calculate_risk(name, value, analysis.value_pattern)
        
        # 4. 建议漏洞类型
        analysis.suggested_vulns = self._suggest_vulns(name, analysis.value_pattern)
        
        # 5. 生成攻击链建议
        analysis.attack_chains = self._generate_attack_chains(name, value, analysis.value_pattern)
        
        # 6. 生成赏金猎人洞察
        analysis.hunter_insight = self._generate_hunter_insight(name, value, analysis)
        
        return analysis
    
    def _calculate_overall_risk(self, params: List[ParamAnalysis]) -> str:
        """
        计算整体风险等级
        
        Args:
            params: 参数分析列表
            
        Returns:
            风险等级: critical, high, medium, low
        """
        if not params:
            return "low"
        
        max_score = max(p.risk_score for p in params)
        
        if max_score >= 70:
            return "critical"
        elif max_score >= 50:
            return "high"
        elif max_score >= 30:
            return "medium"
        return "low"
    
    def _calculate_priority(self, analysis: RequestAnalysis) -> int:
        """
        计算测试优先级
        
        Args:
            analysis: 请求分析结果
            
        Returns:
            优先级分数 (0-100)
        """
        score = 0
        
        # 基于整体风险
        if analysis.overall_risk == "critical":
            score += 100
        elif analysis.overall_risk == "high":
            score += 70
        elif analysis.overall_risk == "medium":
            score += 40
        
        # 基于参数关系
        score += len(analysis.param_relationships) * 20
        
        # 基于高风险参数数量
        high_risk_count = len([p for p in analysis.params if p.risk_score > 50])
        score += high_risk_count * 10
        
        return min(score, 100)
    
    def deep_analyze(self, request: Request) -> RequestAnalysis:
        """
        深度分析请求的所有参数
        
        以顶级赏金猎人的思维分析每个参数:
        1. 识别值模式 (Base64? JWT? ID? 文件路径?)
        2. 识别命名模式 (debug? admin? hidden?)
        3. 计算风险评分
        4. 建议攻击链
        5. 识别参数关系
        
        Args:
            request: Request 对象
            
        Returns:
            RequestAnalysis 对象
        """
        analysis = RequestAnalysis(
            request_id=request.id,
            url=request.url,
            method=request.method,
        )
        
        # 分析所有参数
        all_params = self._collect_all_params(request)
        for name, value, location in all_params:
            param_analysis = self._analyze_param(name, value, location)
            analysis.params.append(param_analysis)
        
        # 识别参数关系
        analysis.param_relationships = self._find_relationships(analysis.params)
        
        # 计算整体风险
        analysis.overall_risk = self._calculate_overall_risk(analysis.params)
        analysis.priority_score = self._calculate_priority(analysis)
        
        # 生成赏金猎人总结
        analysis.hunter_summary = self._generate_hunter_summary(analysis)
        
        return analysis


    # ==================== 隐藏参数发现 ====================
    
    # 常见隐藏参数名列表
    COMMON_HIDDEN_PARAMS = [
        # 调试参数
        "debug", "test", "dev", "verbose", "trace", "log", "mode", "env",
        # 管理员参数
        "admin", "role", "privilege", "isAdmin", "is_admin", "permission", "level",
        "superuser", "root", "moderator", "staff",
        # 隐藏功能
        "_", "__", "internal", "private", "hidden", "secret", "beta", "alpha",
        "experimental", "feature", "flag",
        # 版本控制
        "v", "version", "api_version", "ver", "revision",
        # 格式控制
        "format", "output", "type", "encoding", "charset",
        # 分页
        "page", "limit", "offset", "size", "per_page", "count",
        # 排序
        "sort", "order", "orderby", "sortby", "direction", "asc", "desc",
        # 过滤
        "filter", "where", "query", "search", "q", "keyword",
        # 回调
        "callback", "jsonp", "cb", "func", "handler",
        # 认证
        "token", "auth", "key", "api_key", "access_token", "session",
        # 其他
        "include", "exclude", "fields", "expand", "embed", "with",
        "nocache", "cache", "refresh", "force", "override",
    ]
    
    def find_hidden_params(self, request: Request) -> Dict:
        """
        发现隐藏参数
        
        方法:
        1. Fuzz 常见隐藏参数名
        2. 分析 JavaScript 中的参数
        3. 检查 HTML 注释
        4. 测试参数污染场景
        
        Args:
            request: Request 对象
            
        Returns:
            隐藏参数发现结果
        """
        result = {
            "existing_params": list(request.all_params.keys()),
            "suggested_params": [],
            "fuzz_candidates": [],
            "js_params": [],
            "html_comment_params": [],
            "pollution_candidates": [],
            "recommendations": [],
        }
        
        existing_params = set(p.lower() for p in request.all_params.keys())
        
        # 1. 建议常见隐藏参数 (排除已存在的)
        for param in self.COMMON_HIDDEN_PARAMS:
            if param.lower() not in existing_params:
                result["suggested_params"].append(param)
        
        # 2. 生成 Fuzz 候选列表 (基于现有参数名变体)
        for existing in request.all_params.keys():
            # 添加前缀变体
            for prefix in ["_", "__", "is_", "has_", "can_", "old_", "new_"]:
                variant = f"{prefix}{existing}"
                if variant.lower() not in existing_params:
                    result["fuzz_candidates"].append(variant)
            
            # 添加后缀变体
            for suffix in ["_id", "_key", "_token", "_hash", "_old", "_new", "_backup"]:
                variant = f"{existing}{suffix}"
                if variant.lower() not in existing_params:
                    result["fuzz_candidates"].append(variant)
        
        # 3. 分析响应中的 JavaScript (如果有响应)
        if request.response and request.response.body:
            js_params = self._extract_js_params(request.response.body)
            for param in js_params:
                if param.lower() not in existing_params:
                    result["js_params"].append(param)
        
        # 4. 检查 HTML 注释中的参数
        if request.response and request.response.body:
            comment_params = self._extract_comment_params(request.response.body)
            for param in comment_params:
                if param.lower() not in existing_params:
                    result["html_comment_params"].append(param)
        
        # 5. 参数污染候选 (HPP)
        for param in request.all_params.keys():
            result["pollution_candidates"].append({
                "param": param,
                "test": f"尝试发送多个 {param} 参数，检查服务器如何处理",
                "payloads": [
                    f"{param}=value1&{param}=value2",
                    f"{param}[]=value1&{param}[]=value2",
                    f"{param}[0]=value1&{param}[1]=value2",
                ]
            })
        
        # 6. 生成建议
        result["recommendations"] = self._generate_hidden_param_recommendations(result)
        
        return result
    
    def _extract_js_params(self, body: str) -> List[str]:
        """
        从 JavaScript 代码中提取参数名
        
        Args:
            body: 响应体
            
        Returns:
            参数名列表
        """
        params = set()
        
        # 匹配常见的参数引用模式
        patterns = [
            r'["\'](\w+)["\']\s*:\s*',  # "param": value
            r'\.(\w+)\s*=',  # .param =
            r'params\[["\']([\w]+)["\']\]',  # params["param"]
            r'data\[["\']([\w]+)["\']\]',  # data["param"]
            r'request\[["\']([\w]+)["\']\]',  # request["param"]
            r'getParameter\(["\'](\w+)["\']\)',  # getParameter("param")
            r'param\s*=\s*["\'](\w+)["\']',  # param = "name"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, body)
            params.update(matches)
        
        # 过滤掉常见的非参数名
        exclude = {"function", "return", "var", "let", "const", "if", "else", "for", "while", "true", "false", "null", "undefined"}
        params = {p for p in params if p.lower() not in exclude and len(p) > 1}
        
        return list(params)
    
    def _extract_comment_params(self, body: str) -> List[str]:
        """
        从 HTML 注释中提取参数名
        
        Args:
            body: 响应体
            
        Returns:
            参数名列表
        """
        params = set()
        
        # 匹配 HTML 注释
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        
        for comment in comments:
            # 在注释中查找参数模式
            matches = re.findall(r'(\w+)\s*=', comment)
            params.update(matches)
            
            # 查找 name="param" 模式
            matches = re.findall(r'name\s*=\s*["\'](\w+)["\']', comment)
            params.update(matches)
        
        return list(params)
    
    def _generate_hidden_param_recommendations(self, result: Dict) -> List[str]:
        """
        生成隐藏参数测试建议
        
        Args:
            result: 隐藏参数发现结果
            
        Returns:
            建议列表
        """
        recommendations = []
        
        # 高优先级建议
        high_priority = ["debug", "admin", "test", "dev", "internal", "role", "privilege"]
        found_high_priority = [p for p in result["suggested_params"] if p in high_priority]
        
        if found_high_priority:
            recommendations.append(f"🔥 高优先级: 测试这些隐藏参数: {', '.join(found_high_priority)}")
        
        # JS 中发现的参数
        if result["js_params"]:
            recommendations.append(f"💡 JavaScript中发现 {len(result['js_params'])} 个未使用的参数: {', '.join(result['js_params'][:5])}")
        
        # HTML 注释中的参数
        if result["html_comment_params"]:
            recommendations.append(f"💡 HTML注释中发现 {len(result['html_comment_params'])} 个参数: {', '.join(result['html_comment_params'][:5])}")
        
        # 参数污染建议
        if result["pollution_candidates"]:
            recommendations.append(f"🔍 建议测试 {len(result['pollution_candidates'])} 个参数的HTTP参数污染")
        
        # 通用建议
        recommendations.append("📝 使用 Arjun 或 ParamMiner 进行更全面的参数发现")
        
        return recommendations
