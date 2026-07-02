"""
资产批量扫描结果模型 (M6).

ScanResult 聚合跨协议的扫描发现, 供 AI 决策层/CLI 报告消费.

设计:
    - AssetEntry: 单个 host:port 的发现 (protocol/service/banner/tags...)
    - ScanResult: 整个扫描的聚合 (entries + 统计 + 按风险排序)
    - 协议无关: 不管用什么 adapter 扫的, 统一格式
    - AI 友好: to_dict/to_json, 高危资产排前, 含 next_steps 建议
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable

from .base import TrafficResponse


# ============================================================
#                   单个资产发现
# ============================================================

@dataclass
class AssetEntry:
    """单个 host:port 的扫描发现."""

    host: str
    port: int
    protocol: str = ""          # 探测用的协议 (http/tcp/redis/mysql...)
    service: str = ""           # 识别出的服务 (redis/mysql/ssh...)
    banner: str = ""            # 服务指纹 (redis/7.0, ssh/2.0-OpenSSH_8.9)
    ok: bool = False            # 端口是否开放/响应
    tags: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    time_ms: float = 0
    error: str = ""

    @property
    def is_high_value(self) -> bool:
        """是否高危资产 (HIGH-VALUE / UNAUTH-CONFIRMED / RCE-PATH)"""
        return any(t in self.tags for t in
                   ("HIGH-VALUE", "UNAUTH-CONFIRMED", "RCE-PATH"))

    @property
    def is_open(self) -> bool:
        """端口是否开放 (ok=True 即开放)"""
        return self.ok

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    @classmethod
    def from_response(cls, host: str, port: int, protocol: str,
                      resp: TrafficResponse) -> "AssetEntry":
        """从 TrafficResponse 构造 AssetEntry"""
        service = ""
        if protocol in ("redis", "docker", "kubelet", "mysql", "smb", "rmi",
                        "snmp", "ssh", "mongodb"):
            service = protocol
        elif resp.banner:
            service = resp.banner.split("/")[0].split("(")[0].lower()

        return cls(
            host=host, port=port,
            protocol=protocol,
            service=service,
            banner=resp.banner,
            ok=resp.ok,
            tags=list(resp.tags),
            anomalies=list(resp.anomalies),
            time_ms=resp.time_ms,
            error=resp.error,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "target": self.target,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "ok": self.ok,
            "open": self.is_open,
            "high_value": self.is_high_value,
            "tags": list(self.tags),
            "anomalies": list(self.anomalies),
            "time_ms": round(self.time_ms, 1),
            "error": self.error,
        }


# ============================================================
#                   扫描聚合结果
# ============================================================

@dataclass
class ScanResult:
    """
    批量扫描的聚合结果.

    包含所有 AssetEntry + 统计信息 + 排序/过滤工具.
    """

    entries: List[AssetEntry] = field(default_factory=list)
    scan_target: str = ""          # 扫描的 CIDR 或 host 列表描述
    start_time: float = 0
    end_time: float = 0
    total_probes: int = 0          # 总探测数 (含失败的)
    concurrency: int = 0

    def add(self, entry: AssetEntry):
        self.entries.append(entry)

    # -------- 统计 --------

    @property
    def elapsed_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0

    @property
    def open_count(self) -> int:
        """开放端口数"""
        return sum(1 for e in self.entries if e.is_open)

    @property
    def high_value_count(self) -> int:
        """高危资产数"""
        return sum(1 for e in self.entries if e.is_high_value)

    @property
    def unauth_confirmed_count(self) -> int:
        """确认未授权的资产数"""
        return sum(1 for e in self.entries
                   if "UNAUTH-CONFIRMED" in e.tags)

    @property
    def hosts_scanned(self) -> int:
        """扫描的不同 host 数"""
        return len({e.host for e in self.entries})

    @property
    def ports_scanned(self) -> int:
        """扫描的不同 port 数"""
        return len({e.port for e in self.entries})

    # -------- 过滤/排序 --------

    def open_entries(self) -> List[AssetEntry]:
        """只返回开放的"""
        return [e for e in self.entries if e.is_open]

    def high_value_entries(self) -> List[AssetEntry]:
        """只返回高危的 (按端口分组, 再按 host)"""
        hv = [e for e in self.entries if e.is_high_value]
        # 高危排前, 同优先级按 host:port
        return sorted(hv, key=lambda e: (not e.is_high_value, e.host, e.port))

    def sorted_entries(self) -> List[AssetEntry]:
        """所有 entries 排序: 开放在前, 高危在前, 再按 host:port"""
        return sorted(self.entries,
                      key=lambda e: (not e.is_open, not e.is_high_value,
                                     e.host, e.port))

    def by_host(self) -> Dict[str, List[AssetEntry]]:
        """按 host 分组"""
        result: Dict[str, List[AssetEntry]] = {}
        for e in self.entries:
            if e.is_open:
                result.setdefault(e.host, []).append(e)
        return result

    def by_service(self) -> Dict[str, List[AssetEntry]]:
        """按 service 分组 (只含开放的)"""
        result: Dict[str, List[AssetEntry]] = {}
        for e in self.entries:
            if e.is_open and e.service:
                result.setdefault(e.service, []).append(e)
        return result

    # -------- 序列化 --------

    def summary(self) -> Dict[str, Any]:
        """扫描摘要 (供报告/AI)"""
        services = self.by_service()
        return {
            "scan_target": self.scan_target,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "hosts_scanned": self.hosts_scanned,
            "ports_scanned": self.ports_scanned,
            "total_probes": self.total_probes,
            "open_count": self.open_count,
            "high_value_count": self.high_value_count,
            "unauth_confirmed_count": self.unauth_confirmed_count,
            "concurrency": self.concurrency,
            "services_found": {svc: len(items) for svc, items in services.items()},
        }

    def to_dict(self, only_open: bool = True,
                sort_by: str = "risk") -> Dict[str, Any]:
        """
        转为 dict (AI/JSON 友好).

        Args:
            only_open: 只含开放端口 (默认 True, 避免噪音)
            sort_by:   "risk" (默认, 高危在前) / "host" / "service"
        """
        entries = self.open_entries() if only_open else self.entries
        if sort_by == "risk":
            entries = sorted(entries,
                             key=lambda e: (not e.is_high_value, e.host, e.port))
        elif sort_by == "host":
            entries = sorted(entries, key=lambda e: (e.host, e.port))
        elif sort_by == "service":
            entries = sorted(entries, key=lambda e: (e.service, e.host, e.port))

        return {
            "summary": self.summary(),
            "entries": [e.to_dict() for e in entries],
        }

    def to_json(self, only_open: bool = True, sort_by: str = "risk") -> str:
        import json
        return json.dumps(self.to_dict(only_open, sort_by), ensure_ascii=False)

    # -------- 报告 --------

    def report_text(self, only_high_value: bool = False) -> str:
        """人类可读的文本报告"""
        lines = []
        s = self.summary()
        lines.append("=" * 60)
        lines.append(f"扫描报告: {s['scan_target']}")
        lines.append(f"耗时 {s['elapsed_ms']:.0f}ms | "
                     f"主机 {s['hosts_scanned']} | "
                     f"端口 {s['ports_scanned']} | "
                     f"探测 {s['total_probes']}")
        lines.append(f"开放 {s['open_count']} | "
                     f"高危 {s['high_value_count']} | "
                     f"未授权确认 {s['unauth_confirmed_count']}")
        if s["services_found"]:
            svcs = ", ".join(f"{k}({v})" for k, v in s["services_found"].items())
            lines.append(f"服务: {svcs}")
        lines.append("=" * 60)

        entries = (self.high_value_entries() if only_high_value
                   else self.sorted_entries())
        if only_high_value and not entries:
            lines.append("(无高危资产)")
            return "\n".join(lines)

        # 按 host 分组输出
        by_host: Dict[str, List[AssetEntry]] = {}
        for e in entries:
            by_host.setdefault(e.host, []).append(e)

        for host in sorted(by_host.keys()):
            host_entries = by_host[host]
            hv = any(e.is_high_value for e in host_entries)
            marker = " [HIGH-VALUE]" if hv else ""
            lines.append(f"\n{host}{marker}")
            for e in sorted(host_entries, key=lambda x: x.port):
                if not e.is_open:
                    continue
                flag = " ⚠" if e.is_high_value else " ✓"
                unauth = " UNAUTH" if "UNAUTH-CONFIRMED" in e.tags else ""
                rce = " RCE" if "RCE-PATH" in e.tags else ""
                lines.append(f"  {e.port:>5}/{e.protocol:<8} "
                             f"{e.service:<12} {e.banner:<30}"
                             f"{flag}{unauth}{rce}")

        return "\n".join(lines)
