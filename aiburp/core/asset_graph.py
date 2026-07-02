"""
资产关联图谱

功能:
- 从 History 构建资产图谱
- IP 关联 (多域名 → 同一 IP)
- 证书关联 (同一证书 → 同一应用)
- Favicon 关联 (同一 hash → 同一系统)
- 技术栈关联 (同一 CMS → 可能同一漏洞)
- 资产聚类分析
"""

import json
import hashlib
import re
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse

from .history import History
from .models import Request


@dataclass
class Asset:
    """资产节点"""
    id: str  # 唯一标识
    type: str  # domain, ip, cert, favicon, tech
    value: str  # 实际值
    properties: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "properties": self.properties,
        }


@dataclass
class Relation:
    """关联边"""
    source: str  # 源资产 ID
    target: str  # 目标资产 ID
    type: str  # resolves_to, uses_cert, has_favicon, runs_on
    properties: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "properties": self.properties,
        }


class AssetGraph:
    """
    资产关联图谱
    
    用法:
        graph = AssetGraph(history)
        graph.build()
        
        # 查找关联资产
        related = graph.find_related("example.com")
        
        # 资产聚类
        clusters = graph.clusters()
        
        # 导出
        graph.export_json("assets.json")
    """
    
    def __init__(self, history: History):
        self.history = history
        self.assets: Dict[str, Asset] = {}  # id -> Asset
        self.relations: List[Relation] = []
        
        # 索引
        self._ip_to_domains: Dict[str, Set[str]] = defaultdict(set)
        self._domain_to_ips: Dict[str, Set[str]] = defaultdict(set)
        self._cert_to_domains: Dict[str, Set[str]] = defaultdict(set)
        self._favicon_to_domains: Dict[str, Set[str]] = defaultdict(set)
        self._tech_to_domains: Dict[str, Set[str]] = defaultdict(set)
    
    def build(self, tags: List[str] = None) -> "AssetGraph":
        """
        从 History 构建图谱
        
        Args:
            tags: 筛选标签 (如 ["recon"])
        
        Returns:
            self
        """
        # 获取请求
        requests = self.history.list(tags=tags, limit=10000)
        
        for req in requests:
            self._process_request(req)
        
        # 构建关联
        self._build_relations()
        
        return self
    
    def _process_request(self, req: Request):
        """处理单个请求，提取资产信息"""
        if not req.host:
            return
        
        # 域名资产
        domain_id = f"domain:{req.host}"
        if domain_id not in self.assets:
            self.assets[domain_id] = Asset(
                id=domain_id,
                type="domain",
                value=req.host,
            )
        
        # 从响应提取信息
        if req.response:
            resp = req.response
            
            # IP (从 Host 头或其他来源)
            # 注: 实际 IP 需要 DNS 解析，这里简化处理
            
            # Server 头 (技术栈)
            server = resp.headers.get("Server", "")
            if server:
                tech_id = f"tech:{server}"
                if tech_id not in self.assets:
                    self.assets[tech_id] = Asset(
                        id=tech_id,
                        type="tech",
                        value=server,
                    )
                self._tech_to_domains[tech_id].add(domain_id)
            
            # X-Powered-By
            powered_by = resp.headers.get("X-Powered-By", "")
            if powered_by:
                tech_id = f"tech:{powered_by}"
                if tech_id not in self.assets:
                    self.assets[tech_id] = Asset(
                        id=tech_id,
                        type="tech",
                        value=powered_by,
                    )
                self._tech_to_domains[tech_id].add(domain_id)
            
            # 证书信息 (从响应头或 SSL 信息)
            # 注: 需要 SSL 握手信息，这里简化
            
            # Favicon hash (如果是 favicon 请求)
            if "/favicon" in req.path.lower() and resp.body:
                fav_hash = self._compute_favicon_hash(resp.body.encode() if isinstance(resp.body, str) else resp.body)
                fav_id = f"favicon:{fav_hash}"
                if fav_id not in self.assets:
                    self.assets[fav_id] = Asset(
                        id=fav_id,
                        type="favicon",
                        value=str(fav_hash),
                    )
                self._favicon_to_domains[fav_id].add(domain_id)
    
    def _build_relations(self):
        """构建关联关系"""
        # IP → 域名关联
        for ip_id, domains in self._ip_to_domains.items():
            if len(domains) > 1:
                # 多个域名解析到同一 IP
                for domain_id in domains:
                    self.relations.append(Relation(
                        source=domain_id,
                        target=ip_id,
                        type="resolves_to",
                    ))
        
        # 技术栈 → 域名关联
        for tech_id, domains in self._tech_to_domains.items():
            for domain_id in domains:
                self.relations.append(Relation(
                    source=domain_id,
                    target=tech_id,
                    type="runs_on",
                ))
        
        # Favicon → 域名关联
        for fav_id, domains in self._favicon_to_domains.items():
            for domain_id in domains:
                self.relations.append(Relation(
                    source=domain_id,
                    target=fav_id,
                    type="has_favicon",
                ))
        
        # 证书 → 域名关联
        for cert_id, domains in self._cert_to_domains.items():
            for domain_id in domains:
                self.relations.append(Relation(
                    source=domain_id,
                    target=cert_id,
                    type="uses_cert",
                ))
    
    def add_ip_mapping(self, domain: str, ip: str):
        """添加 IP 映射 (外部调用)"""
        domain_id = f"domain:{domain}"
        ip_id = f"ip:{ip}"
        
        if domain_id not in self.assets:
            self.assets[domain_id] = Asset(
                id=domain_id,
                type="domain",
                value=domain,
            )
        
        if ip_id not in self.assets:
            self.assets[ip_id] = Asset(
                id=ip_id,
                type="ip",
                value=ip,
            )
        
        self._ip_to_domains[ip_id].add(domain_id)
        self._domain_to_ips[domain_id].add(ip_id)
        
        self.relations.append(Relation(
            source=domain_id,
            target=ip_id,
            type="resolves_to",
        ))
    
    def add_cert_mapping(self, domain: str, cert_fingerprint: str, cert_names: List[str] = None):
        """添加证书映射"""
        domain_id = f"domain:{domain}"
        cert_id = f"cert:{cert_fingerprint[:16]}"
        
        if cert_id not in self.assets:
            self.assets[cert_id] = Asset(
                id=cert_id,
                type="cert",
                value=cert_fingerprint,
                properties={"names": cert_names or []},
            )
        
        self._cert_to_domains[cert_id].add(domain_id)
        
        self.relations.append(Relation(
            source=domain_id,
            target=cert_id,
            type="uses_cert",
        ))
    
    def find_related(self, target: str, depth: int = 2) -> Dict:
        """
        查找关联资产
        
        Args:
            target: 目标 (域名/IP)
            depth: 搜索深度
        
        Returns:
            关联资产信息
        """
        # 确定目标 ID
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            target_id = f"ip:{target}"
        else:
            target_id = f"domain:{target}"
        
        if target_id not in self.assets:
            return {"target": target, "found": False, "related": []}
        
        # BFS 搜索关联
        visited = {target_id}
        queue = [(target_id, 0)]
        related = []
        
        while queue:
            current_id, current_depth = queue.pop(0)
            
            if current_depth >= depth:
                continue
            
            # 查找关联
            for rel in self.relations:
                neighbor_id = None
                if rel.source == current_id:
                    neighbor_id = rel.target
                elif rel.target == current_id:
                    neighbor_id = rel.source
                
                if neighbor_id and neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, current_depth + 1))
                    
                    asset = self.assets.get(neighbor_id)
                    if asset:
                        related.append({
                            "asset": asset.to_dict(),
                            "relation": rel.type,
                            "depth": current_depth + 1,
                        })
        
        return {
            "target": target,
            "found": True,
            "related": related,
        }
    
    def clusters(self) -> List[Dict]:
        """
        资产聚类
        
        Returns:
            聚类列表，每个聚类包含相关资产
        """
        # 使用并查集进行聚类
        parent = {asset_id: asset_id for asset_id in self.assets}
        
        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # 根据关联合并
        for rel in self.relations:
            if rel.source in parent and rel.target in parent:
                union(rel.source, rel.target)
        
        # 分组
        groups = defaultdict(list)
        for asset_id in self.assets:
            root = find(asset_id)
            groups[root].append(asset_id)
        
        # 构建聚类结果
        clusters = []
        for root, members in groups.items():
            if len(members) > 1:  # 只返回有多个成员的聚类
                cluster = {
                    "id": root,
                    "size": len(members),
                    "assets": [self.assets[m].to_dict() for m in members],
                    "domains": [self.assets[m].value for m in members if self.assets[m].type == "domain"],
                    "ips": [self.assets[m].value for m in members if self.assets[m].type == "ip"],
                    "techs": [self.assets[m].value for m in members if self.assets[m].type == "tech"],
                }
                clusters.append(cluster)
        
        # 按大小排序
        clusters.sort(key=lambda x: x["size"], reverse=True)
        
        return clusters
    
    def same_server(self) -> List[Dict]:
        """
        找出解析到同一 IP 的域名
        
        Returns:
            同服务器域名组列表
        """
        groups = []
        for ip_id, domains in self._ip_to_domains.items():
            if len(domains) > 1:
                ip = self.assets[ip_id].value if ip_id in self.assets else ip_id.replace("ip:", "")
                groups.append({
                    "ip": ip,
                    "domains": [self.assets[d].value for d in domains if d in self.assets],
                    "count": len(domains),
                })
        
        groups.sort(key=lambda x: x["count"], reverse=True)
        return groups
    
    def same_tech(self) -> List[Dict]:
        """
        找出使用相同技术栈的域名
        
        Returns:
            同技术栈域名组列表
        """
        groups = []
        for tech_id, domains in self._tech_to_domains.items():
            if len(domains) > 1:
                tech = self.assets[tech_id].value if tech_id in self.assets else tech_id.replace("tech:", "")
                groups.append({
                    "tech": tech,
                    "domains": [self.assets[d].value for d in domains if d in self.assets],
                    "count": len(domains),
                })
        
        groups.sort(key=lambda x: x["count"], reverse=True)
        return groups
    
    def same_favicon(self) -> List[Dict]:
        """
        找出使用相同 Favicon 的域名
        
        Returns:
            同 Favicon 域名组列表
        """
        groups = []
        for fav_id, domains in self._favicon_to_domains.items():
            if len(domains) > 1:
                fav_hash = self.assets[fav_id].value if fav_id in self.assets else fav_id.replace("favicon:", "")
                groups.append({
                    "favicon_hash": fav_hash,
                    "domains": [self.assets[d].value for d in domains if d in self.assets],
                    "count": len(domains),
                })
        
        groups.sort(key=lambda x: x["count"], reverse=True)
        return groups
    
    def stats(self) -> Dict:
        """统计信息"""
        type_counts = defaultdict(int)
        for asset in self.assets.values():
            type_counts[asset.type] += 1
        
        relation_counts = defaultdict(int)
        for rel in self.relations:
            relation_counts[rel.type] += 1
        
        return {
            "total_assets": len(self.assets),
            "total_relations": len(self.relations),
            "asset_types": dict(type_counts),
            "relation_types": dict(relation_counts),
            "clusters": len(self.clusters()),
        }
    
    def export_json(self, file_path: str):
        """导出为 JSON"""
        data = {
            "assets": [a.to_dict() for a in self.assets.values()],
            "relations": [r.to_dict() for r in self.relations],
            "stats": self.stats(),
        }
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def to_json_for_ai(self) -> str:
        """返回 JSON 格式 (给 AI 看)"""
        return json.dumps({
            "stats": self.stats(),
            "same_server": self.same_server()[:10],
            "same_tech": self.same_tech()[:10],
            "same_favicon": self.same_favicon()[:10],
            "clusters": self.clusters()[:5],
        }, indent=2, ensure_ascii=False)
    
    @staticmethod
    def _compute_favicon_hash(content: bytes) -> int:
        """计算 Favicon hash"""
        import base64
        b64 = base64.b64encode(content).decode()
        b64_with_newlines = "\n".join([b64[i:i+76] for i in range(0, len(b64), 76)]) + "\n"
        
        # 简化的 MurmurHash3
        data = b64_with_newlines.encode()
        h = 0
        for i in range(0, len(data), 4):
            k = int.from_bytes(data[i:i+4].ljust(4, b'\x00'), 'little')
            k = (k * 0xcc9e2d51) & 0xffffffff
            k = ((k << 15) | (k >> 17)) & 0xffffffff
            k = (k * 0x1b873593) & 0xffffffff
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xffffffff
            h = ((h * 5) + 0xe6546b64) & 0xffffffff
        h ^= len(data)
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xffffffff
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xffffffff
        h ^= h >> 16
        if h >= 0x80000000:
            h -= 0x100000000
        return h
