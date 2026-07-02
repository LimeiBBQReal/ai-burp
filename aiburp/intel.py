"""
AI-Burp V3 Intelligence Layer
知识库与漏洞链引擎

核心功能:
1. KnowledgeBase: 存储全局资产信息 (凭据、IP、端点、指纹)
2. VulnerabilityChainer: 分析漏洞关联，提出复合攻击方案
3. AttackGraph: 漏洞链路径搜索
4. DependencyInjector: 跨漏洞数据注入
"""

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Asset:
    """资产项"""
    type: str          # credential, internal_ip, sub_domain, hidden_path, secret_key
    value: str
    source_url: str
    context: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict = field(default_factory=dict)

class KnowledgeBase:
    """
    全局知识库 - 跨请求的记忆中心
    """
    def __init__(self, project: str):
        self.project = project
        self.assets: List[Asset] = []
        self._seen_values: Set[str] = set()
        
        # 数据持久化目录
        self.data_dir = Path.home() / ".aiburp" / project / "intelligence"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.kb_file = self.data_dir / "knowledge_base.json"
        
        self.load()

    def add(self, asset_type: str, value: str, source_url: str, context: str = "", metadata: Dict = None):
        """添加新发现的知识"""
        if value in self._seen_values:
            return
        
        asset = Asset(asset_type, value, source_url, context, metadata=metadata or {})
        self.assets.append(asset)
        self._seen_values.add(value)
        self.save()
        print(f"🧠 [Intelligence] New Asset Found: [{asset_type}] {value[:30]}...")

    def get_by_type(self, asset_type: str) -> List[Asset]:
        """按类型获取资产"""
        return [a for a in self.assets if a.type == asset_type]

    def query(self, keyword: str) -> List[Asset]:
        """搜索知识"""
        return [a for a in self.assets if keyword.lower() in a.value.lower() or keyword.lower() in a.context.lower()]

    def save(self):
        """保存到文件"""
        data = [vars(a) for a in self.assets]
        with open(self.kb_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load(self):
        """从文件加载"""
        if self.kb_file.exists():
            try:
                with open(self.kb_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        asset = Asset(**item)
                        self.assets.append(asset)
                        self._seen_values.add(asset.value)
            except Exception as e:
                print(f"⚠️ Failed to load KnowledgeBase: {e}")


# ============================================================
#                    AttackGraph (漏洞链图)
# ============================================================

class AttackGraph:
    """
    攻击图 - 漏洞链路径搜索
    
    节点: 漏洞类型 (sqli, ssrf, lfi, rce, etc.)
    边: 可能的攻击链转换
    """
    
    # 预定义攻击链模板
    CHAIN_TEMPLATES: Dict[str, List[Tuple[str, str, str]]] = {
        # (from_vuln, to_vuln, reason)
        "ssrf_chains": [
            ("ssrf", "internal_scan", "SSRF 可探测内网服务"),
            ("ssrf", "cloud_metadata", "SSRF 可读取云元数据 (169.254.169.254)"),
            ("ssrf", "redis_rce", "SSRF + Redis 未授权 = RCE"),
            ("ssrf", "mysql_read", "SSRF + MySQL 协议 = 文件读取"),
        ],
        "sqli_chains": [
            ("sqli", "file_read", "SQLi LOAD_FILE() 读取文件"),
            ("sqli", "file_write", "SQLi INTO OUTFILE 写入 WebShell"),
            ("sqli", "credential_dump", "SQLi 提取用户凭据"),
            ("sqli", "rce", "SQLi + xp_cmdshell/UDF = RCE"),
        ],
        "lfi_chains": [
            ("lfi", "log_poison", "LFI + 日志投毒 = RCE"),
            ("lfi", "session_hijack", "LFI 读取 Session 文件"),
            ("lfi", "source_leak", "LFI 读取源码泄露敏感信息"),
            ("lfi", "rce", "LFI + PHP Wrapper = RCE"),
        ],
        "auth_chains": [
            ("credential", "privilege_escalation", "凭据 -> 提权"),
            ("credential", "lateral_movement", "凭据 -> 横向移动"),
            ("idor", "data_exfil", "IDOR -> 批量数据泄露"),
        ],
        "upload_chains": [
            ("upload", "webshell", "上传 WebShell"),
            ("upload", "xss_stored", "上传 SVG/HTML -> 存储型 XSS"),
            ("upload", "xxe", "上传 XML/DOCX -> XXE"),
        ],
    }
    
    def __init__(self):
        # 构建邻接表
        self.graph: Dict[str, List[Tuple[str, str]]] = {}
        self._build_graph()
    
    def _build_graph(self):
        """从模板构建图"""
        for chain_name, edges in self.CHAIN_TEMPLATES.items():
            for from_v, to_v, reason in edges:
                if from_v not in self.graph:
                    self.graph[from_v] = []
                self.graph[from_v].append((to_v, reason))
    
    def find_paths(self, start: str, max_depth: int = 3) -> List[List[Tuple[str, str]]]:
        """
        BFS 搜索从 start 出发的所有攻击路径
        
        Returns:
            List of paths, each path is [(node, reason), ...]
        """
        paths = []
        queue = deque([(start, [(start, "起点")])])
        
        while queue:
            current, path = queue.popleft()
            
            if len(path) > max_depth:
                continue
            
            if len(path) > 1:
                paths.append(path)
            
            if current in self.graph:
                for next_node, reason in self.graph[current]:
                    if not any(n == next_node for n, _ in path):  # 避免环
                        new_path = path + [(next_node, reason)]
                        queue.append((next_node, new_path))
        
        return paths
    
    def suggest_next(self, current_vulns: List[str]) -> List[Dict]:
        """
        根据当前发现的漏洞，建议下一步
        """
        suggestions = []
        seen = set()
        
        for vuln in current_vulns:
            if vuln in self.graph:
                for next_node, reason in self.graph[vuln]:
                    key = f"{vuln}->{next_node}"
                    if key not in seen:
                        seen.add(key)
                        suggestions.append({
                            "from": vuln,
                            "to": next_node,
                            "reason": reason,
                            "priority": self._get_priority(next_node)
                        })
        
        # 按优先级排序
        suggestions.sort(key=lambda x: x["priority"], reverse=True)
        return suggestions
    
    def _get_priority(self, vuln_type: str) -> int:
        """漏洞优先级评分"""
        priorities = {
            "rce": 100,
            "webshell": 95,
            "credential_dump": 90,
            "file_write": 85,
            "privilege_escalation": 80,
            "cloud_metadata": 75,
            "redis_rce": 75,
            "file_read": 60,
            "data_exfil": 55,
            "internal_scan": 50,
        }
        return priorities.get(vuln_type, 30)


# ============================================================
#                 DependencyInjector (数据注入)
# ============================================================

class DependencyInjector:
    """
    依赖注入器 - 将知识库中的数据注入到攻击 payload
    
    场景:
    1. SSRF 发现内网 IP -> 自动注入到后续 SSRF payload
    2. SQLi 提取凭据 -> 自动注入到认证测试
    3. LFI 发现路径 -> 自动注入到文件读取 payload
    """
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
    
    def inject_to_ssrf(self, base_payloads: List[str]) -> List[str]:
        """
        将内网 IP 注入到 SSRF payload
        
        Args:
            base_payloads: 基础 SSRF payload 模板，如 ["http://{ip}:{port}/"]
        
        Returns:
            展开后的 payload 列表
        """
        internal_ips = self.kb.get_by_type("internal_ip")
        if not internal_ips:
            # 默认内网 IP
            internal_ips = [
                Asset("internal_ip", "127.0.0.1", "default"),
                Asset("internal_ip", "192.168.1.1", "default"),
                Asset("internal_ip", "10.0.0.1", "default"),
                Asset("internal_ip", "172.16.0.1", "default"),
            ]
        
        common_ports = [80, 443, 8080, 8443, 6379, 3306, 5432, 27017, 9200]
        
        expanded = []
        for payload in base_payloads:
            for ip_asset in internal_ips[:5]:  # 限制数量
                for port in common_ports:
                    expanded.append(
                        payload.replace("{ip}", ip_asset.value).replace("{port}", str(port))
                    )
        
        return expanded
    
    def inject_credentials(self, auth_payloads: List[Dict]) -> List[Dict]:
        """
        将发现的凭据注入到认证测试 payload
        
        Args:
            auth_payloads: [{"username": "{user}", "password": "{pass}"}, ...]
        
        Returns:
            展开后的认证 payload
        """
        credentials = self.kb.get_by_type("credential")
        if not credentials:
            return auth_payloads
        
        expanded = []
        for payload in auth_payloads:
            for cred in credentials:
                # 解析凭据 (假设格式: "user:pass" 或 JSON)
                try:
                    if ":" in cred.value:
                        user, passwd = cred.value.split(":", 1)
                    else:
                        data = json.loads(cred.value)
                        user = data.get("username", data.get("user", ""))
                        passwd = data.get("password", data.get("pass", ""))
                    
                    new_payload = {}
                    for k, v in payload.items():
                        if isinstance(v, str):
                            new_payload[k] = v.replace("{user}", user).replace("{pass}", passwd)
                        else:
                            new_payload[k] = v
                    expanded.append(new_payload)
                except:
                    continue
        
        return expanded if expanded else auth_payloads
    
    def inject_paths(self, lfi_payloads: List[str]) -> List[str]:
        """
        将发现的路径注入到 LFI payload
        """
        paths = self.kb.get_by_type("hidden_path")
        if not paths:
            return lfi_payloads
        
        expanded = list(lfi_payloads)
        for path_asset in paths:
            expanded.append(path_asset.value)
            # 添加遍历变体
            expanded.append(f"../{path_asset.value}")
            expanded.append(f"../../{path_asset.value}")
        
        return expanded


# ============================================================
#                 VulnerabilityChainer (增强版)
# ============================================================

class VulnerabilityChainer:
    """
    漏洞链引擎 - 思考如何组合漏洞 (V3 增强版)
    
    集成:
    - AttackGraph: 路径搜索
    - DependencyInjector: 数据注入
    """
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self.graph = AttackGraph()
        self.injector = DependencyInjector(kb)
    
    def suggest_next_steps(self, findings: List[Any]) -> List[Dict]:
        """
        根据当前发现和知识库，建议下一步攻击
        """
        suggestions = []
        
        # 1. 提取当前漏洞类型
        current_vulns = []
        for f in findings:
            vuln_type = getattr(f, 'vuln_type', None) or str(f).lower()
            for known in ["sqli", "ssrf", "lfi", "xss", "rce", "idor", "upload", "xxe", "ssti"]:
                if known in vuln_type:
                    current_vulns.append(known)
                    break
        
        # 2. 使用 AttackGraph 建议
        if current_vulns:
            graph_suggestions = self.graph.suggest_next(current_vulns)
            for s in graph_suggestions[:5]:
                suggestions.append({
                    "action": f"chain_{s['to']}",
                    "from_vuln": s["from"],
                    "reason": s["reason"],
                    "priority": s["priority"]
                })
        
        # 3. 基于知识库的建议
        # 场景: 发现内网 IP + 可能的 SSRF
        internal_ips = self.kb.get_by_type("internal_ip")
        has_ssrf = "ssrf" in current_vulns
        
        if internal_ips and has_ssrf:
            for ip in internal_ips[:3]:
                suggestions.append({
                    "action": "ssrf_scan_internal",
                    "target": ip.value,
                    "reason": f"利用 SSRF 探测内网 {ip.value}",
                    "priority": 70
                })
        
        # 场景: 发现泄露的凭据
        credentials = self.kb.get_by_type("credential")
        if credentials:
            suggestions.append({
                "action": "auth_bypass_test",
                "credentials": [c.value for c in credentials[:5]],
                "reason": "利用泄露凭据尝试认证绕过",
                "priority": 85
            })
        
        # 4. 排序并返回
        suggestions.sort(key=lambda x: x.get("priority", 0), reverse=True)
        return suggestions
    
    def get_injection_payloads(self, vuln_type: str, base_payloads: List[str] = None) -> List[str]:
        """
        获取注入了知识库数据的 payload
        """
        if vuln_type == "ssrf":
            templates = base_payloads or ["http://{ip}:{port}/", "http://{ip}:{port}/admin"]
            return self.injector.inject_to_ssrf(templates)
        elif vuln_type == "lfi":
            templates = base_payloads or ["/etc/passwd", "/etc/shadow", "C:\\Windows\\win.ini"]
            return self.injector.inject_paths(templates)
        else:
            return base_payloads or []
    
    def analyze_chain_potential(self, findings: List[Any]) -> Dict:
        """
        分析漏洞链潜力
        """
        current_vulns = []
        for f in findings:
            vuln_type = getattr(f, 'vuln_type', None) or str(f).lower()
            for known in ["sqli", "ssrf", "lfi", "xss", "rce", "idor", "upload"]:
                if known in vuln_type:
                    current_vulns.append(known)
                    break
        
        all_paths = []
        for vuln in set(current_vulns):
            paths = self.graph.find_paths(vuln, max_depth=3)
            all_paths.extend(paths)
        
        # 找到通往 RCE 的路径
        rce_paths = [p for p in all_paths if any(n == "rce" or n == "webshell" for n, _ in p)]
        
        return {
            "current_vulns": list(set(current_vulns)),
            "total_paths": len(all_paths),
            "rce_paths": len(rce_paths),
            "highest_impact": "RCE" if rce_paths else ("Data Leak" if current_vulns else "None"),
            "paths_to_rce": rce_paths[:3]  # 前 3 条
        }
