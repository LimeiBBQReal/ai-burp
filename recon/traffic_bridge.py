"""
Bridge recon cloud phases to aiburp.traffic.

This module is intentionally thin: recon owns orchestration and evidence,
aiburp.traffic owns protocol execution.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from aiburp.traffic import TrafficEngine, TrafficRequest

from .evidence import EvidenceBundle, EvidenceRecord, EvidenceRequest


DEFAULT_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 11211, 27017,
]


@dataclass
class ReconTask:
    action: str
    target: str
    protocol: str = "auto"
    payload: Any = None
    headers: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    asset: Dict[str, Any] = field(default_factory=dict)
    timeout: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReconTask":
        return cls(
            action=data.get("action", "probe"),
            target=data.get("target", ""),
            protocol=data.get("protocol", "auto"),
            payload=data.get("payload"),
            headers=dict(data.get("headers", {}) or {}),
            meta=dict(data.get("meta", {}) or {}),
            asset=dict(data.get("asset", {}) or {}),
            timeout=data.get("timeout"),
        )

    def to_traffic_request(self) -> TrafficRequest:
        return TrafficRequest(
            protocol=self.protocol if self.protocol != "auto" else "tcp",
            target=self.target,
            payload=self.payload,
            headers=dict(self.headers),
            meta=dict(self.meta),
        )

    def to_evidence_request(self) -> EvidenceRequest:
        req = EvidenceRequest(
            protocol=self.protocol,
            target=self.target,
            headers=dict(self.headers),
            payload=self.payload,
            meta=dict(self.meta),
        )
        req.method = str(self.meta.get("method", ""))
        req.url = self.target if self.target.startswith(("http://", "https://")) else ""
        return req

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "protocol": self.protocol,
            "payload": self.payload,
            "headers": dict(self.headers),
            "meta": dict(self.meta),
            "asset": dict(self.asset),
            "timeout": self.timeout,
        }


def normalize_asset(asset: Dict[str, Any]) -> Dict[str, Any]:
    value = str(asset.get("value") or asset.get("target") or asset.get("host") or "").strip()
    out = dict(asset)
    out.setdefault("value", value)
    out.setdefault("type", infer_asset_type(value))
    return out


def infer_asset_type(value: str) -> str:
    if not value:
        return "unknown"
    if value.startswith(("http://", "https://")):
        return "url"
    host, port = split_target_host_port(value)
    if port:
        return "ip:port" if is_ip(host) else "host:port"
    if is_ip(value):
        return "ip"
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        except ValueError:
            pass
    if "." in value:
        return "domain"
    return "keyword"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def split_target_host_port(value: str) -> Tuple[str, int]:
    value = value.strip()
    if not value:
        return "", 0
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        return parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)
    if ":" in value and value.rsplit(":", 1)[-1].isdigit():
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, 0


def extract_hosts_from_assets(assets: Iterable[Dict[str, Any]]) -> List[str]:
    hosts: List[str] = []
    seen = set()
    for raw in assets:
        asset = normalize_asset(raw)
        value = asset.get("value", "")
        if not value:
            continue
        if asset.get("type") == "cidr":
            try:
                net = ipaddress.ip_network(value, strict=False)
                candidates = [str(ip) for ip in net.hosts()] if net.prefixlen < 31 else [str(net.network_address)]
            except ValueError:
                candidates = []
        else:
            host, _port = split_target_host_port(value)
            candidates = [host] if host else []
        for host in candidates:
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
    return hosts


def load_assets_from_phase_data(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    if "assets" in data:
        return [normalize_asset(a) for a in data.get("assets", [])]

    relevant = data.get("relevant_assets", [])
    asset_index: Dict[str, Dict[str, Any]] = {}
    for item in data.get("all_assets", []) or data.get("raw_assets", []):
        normalized = normalize_asset(item)
        asset_index[normalized["value"]] = normalized

    assets = []
    for item in relevant:
        if isinstance(item, str):
            value = item
            merged = dict(asset_index.get(value, {}))
            merged.setdefault("value", value)
        else:
            value = str(item.get("value", "")).strip()
            merged = dict(asset_index.get(value, {}))
            merged.update(item)
            merged.setdefault("value", value)
        assets.append(normalize_asset(merged))
    return assets


def build_port_probe_tasks(
    hosts: Iterable[str],
    ports: Iterable[int],
    max_tasks: Optional[int] = None,
) -> List[ReconTask]:
    tasks: List[ReconTask] = []
    for host in hosts:
        for port in ports:
            port_i = int(port)
            if port_i in (443, 8443):
                target = f"https://{host}:{port_i}"
            elif port_i in (80, 8080, 8000, 8888):
                target = f"http://{host}:{port_i}"
            else:
                target = f"{host}:{port_i}"
            tasks.append(ReconTask(
                action="probe",
                target=target,
                protocol="auto",
                asset={"value": target, "type": "ip:port" if is_ip(host) else "host:port", "host": host, "port": port_i},
            ))
            if max_tasks and len(tasks) >= max_tasks:
                return tasks
    return tasks


def build_tasks_from_protocol_groups(protocol_groups: Dict[str, List[Dict[str, Any]]]) -> List[ReconTask]:
    tasks: List[ReconTask] = []
    for protocol, assets in protocol_groups.items():
        for asset in assets:
            ip = asset.get("ip") or asset.get("host")
            port = asset.get("port")
            target = asset.get("target") or (f"{ip}:{port}" if ip and port else asset.get("value", ""))
            if not target:
                continue
            tasks.append(ReconTask(
                action="probe",
                target=target,
                protocol=protocol if protocol not in ("https", "http-alt", "https-alt") else "http",
                asset={
                    "value": target,
                    "type": "ip:port" if ip and is_ip(str(ip)) else "host:port",
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "banner": asset.get("banner", ""),
                },
            ))
    return tasks


async def run_tasks(
    tasks: List[ReconTask],
    target: str = "",
    phase: str = "",
    max_concurrency: int = 30,
    timeout: Optional[float] = None,
    engine: Optional[TrafficEngine] = None,
) -> EvidenceBundle:
    bundle = EvidenceBundle(target=target, phase=phase)
    sem = asyncio.Semaphore(max_concurrency)
    owned_engine = engine is None
    if engine is None:
        engine = TrafficEngine(
            http_kwargs={"delay": 0, "timeout": timeout or 10},
            tcp_kwargs={"timeout": timeout or 3, "read_window": 0.5},
            redis_kwargs={"timeout": timeout or 3, "read_window": 0.5},
            ftp_kwargs={"timeout": timeout or 5},
            ssh_kwargs={"timeout": timeout or 5},
            mysql_kwargs={"timeout": timeout or 5},
        )

    async def run_one(task: ReconTask) -> EvidenceRecord:
        async with sem:
            evidence_req = task.to_evidence_request()
            try:
                kw = {"timeout": task.timeout or timeout} if (task.timeout or timeout) else {}
                if task.action == "send":
                    req = task.to_traffic_request()
                    if task.protocol == "auto":
                        req.protocol = await engine._resolve_protocol(task.target, "auto")
                    resp = await engine.send(req, **kw)
                    evidence_req = EvidenceRequest.from_traffic_request(req)
                elif task.action == "check_unauth":
                    resp = await engine.check_unauth(task.target, protocol=task.protocol, **kw)
                else:
                    resp = await engine.probe(task.target, protocol=task.protocol, **kw)
                return EvidenceRecord.from_traffic(
                    asset=task.asset,
                    request=evidence_req,
                    response=resp,
                    stage=phase,
                    action=task.action,
                )
            except Exception as exc:
                from aiburp.traffic import TrafficResponse

                resp = TrafficResponse(
                    protocol=task.protocol or "unknown",
                    ok=False,
                    status=0,
                    target=task.target,
                    error=f"{type(exc).__name__}:{exc}",
                )
                return EvidenceRecord.from_traffic(
                    asset=task.asset,
                    request=evidence_req,
                    response=resp,
                    stage=phase,
                    action=task.action,
                )

    try:
        records = await asyncio.gather(*(run_one(task) for task in tasks))
        for record in records:
            bundle.add(record)
    finally:
        if owned_engine and engine is not None:
            await engine.close()
    return bundle


def run_tasks_sync(
    tasks: List[ReconTask],
    target: str = "",
    phase: str = "",
    max_concurrency: int = 30,
    timeout: Optional[float] = None,
) -> EvidenceBundle:
    return asyncio.run(run_tasks(
        tasks=tasks,
        target=target,
        phase=phase,
        max_concurrency=max_concurrency,
        timeout=timeout,
    ))


def records_to_protocol_groups(records: Iterable[EvidenceRecord]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for record in records:
        response = record.response
        if not response.ok:
            continue
        host, port = split_target_host_port(record.request.target or response.target)
        protocol = normalize_protocol(response.protocol, response.banner, response.tags)
        item = {
            "target": record.request.target or response.target,
            "ip": host,
            "host": host,
            "port": port,
            "protocol": protocol,
            "banner": response.banner,
            "status": response.status,
            "tags": list(response.tags),
            "anomalies": list(response.anomalies),
        }
        groups.setdefault(protocol, []).append(item)
    return groups


def normalize_protocol(protocol: str, banner: str = "", tags: Optional[List[str]] = None) -> str:
    proto = (protocol or "unknown").lower()
    tag_set = {t.upper() for t in (tags or [])}
    if proto in ("http", "https", "redis", "mysql", "ssh", "ftp", "dns", "smb", "rmi", "snmp"):
        return proto
    if "REDIS" in tag_set:
        return "redis"
    if "MYSQL" in tag_set:
        return "mysql"
    if "SSH" in tag_set:
        return "ssh"
    if banner:
        service = re.split(r"[/\s(]", banner.strip().lower(), maxsplit=1)[0]
        if service in ("redis", "mysql", "ssh", "ftp", "http", "https", "mongodb", "postgres"):
            return service
    return proto


def evidence_results_by_protocol(bundle: EvidenceBundle) -> Dict[str, List[Dict[str, Any]]]:
    results: Dict[str, List[Dict[str, Any]]] = {}
    for record in bundle.records:
        response = record.response
        protocol = normalize_protocol(response.protocol, response.banner, response.tags)
        host, port = split_target_host_port(record.request.target or response.target)
        item = response.to_dict()
        item["ip"] = host
        item["host"] = host
        item["port"] = port
        item["asset"] = f"{host}:{port}" if port else host
        item["unauthenticated"] = (
            "UNAUTH-CONFIRMED" in response.tags
            or "UNAUTH-OK" in response.tags
            or "unauth-access" in response.anomalies
        )
        results.setdefault(protocol, []).append(item)
    return results
