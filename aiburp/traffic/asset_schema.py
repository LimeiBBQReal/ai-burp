"""
V4 三段论 — Phase ① 统一资产数据模型.

所有 Phase ① action 产出统一格式的 AssetInventory,
供 Phase ② 流量化消费.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time


@dataclass
class AssetItem:
    """单个资产项"""
    type: str          # "domain" / "ip" / "url" / "port" / "subdomain" / "credential" / "directory"
    value: str         # 资产值
    source: str        # 来源: "asset_expand" / "traffic_scan" / "dir_fuzz" / ...
    metadata: Dict = field(default_factory=dict)     # service, banner, tags, confidence, version, ...
    confidence: float = 0.8
    discovered_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)    # 语义标签: ["http", "admin", "redis", "panel:phpmyadmin", ...]


@dataclass
class AssetInventory:
    """资产清单 — Phase ① 产出物"""
    target: str        # 原始目标
    items: List[AssetItem] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def add(self, item: AssetItem):
        """添加资产项"""
        self.items.append(item)

    def by_type(self, type_str: str) -> List[AssetItem]:
        """按类型筛选"""
        return [i for i in self.items if i.type == type_str]

    def by_tag(self, tag: str) -> List[AssetItem]:
        """按标签筛选"""
        return [i for i in self.items if tag in i.tags]

    def __len__(self):
        return len(self.items)
