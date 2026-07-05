"""
Local decision layer for the recon loop.

GitHub Actions executes traffic.  This module reads Burp-style evidence and
turns it into the next strict run specification for that executor.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

from .llm import BaseLLM


HTTP_DISCOVERY_PATHS = ["/robots.txt", "/.well-known/security.txt"]
MAX_DECISION_RECORDS = 20


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class RunTask:
    action: str
    protocol: str
    target: str
    payload: Any = None
    headers: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    asset: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    timeout: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunTask":
        return cls(
            action=str(data.get("action", "probe")),
            protocol=str(data.get("protocol", "auto")),
            target=str(data.get("target", "")),
            payload=data.get("payload"),
            headers=dict(data.get("headers", {}) or {}),
            meta=dict(data.get("meta", {}) or {}),
            asset=dict(data.get("asset", {}) or {}),
            reason=str(data.get("reason", "")),
            timeout=data.get("timeout"),
        )

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "action": self.action,
            "protocol": self.protocol,
            "target": self.target,
            "payload": self.payload,
            "headers": dict(self.headers),
            "meta": dict(self.meta),
            "asset": dict(self.asset),
            "reason": self.reason,
        }
        if self.timeout is not None:
            data["timeout"] = self.timeout
        return data


@dataclass
class RunSpec:
    target: str
    phase: str
    tasks: List[RunTask] = field(default_factory=list)
    reason: str = ""
    source_phase: str = ""
    created_at: str = field(default_factory=utc_now)
    max_workers: int = 30
    stop: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunSpec":
        tasks = [RunTask.from_dict(item) for item in data.get("tasks", [])]
        return cls(
            target=str(data.get("target", "")),
            phase=str(data.get("phase", "phase3")),
            tasks=tasks,
            reason=str(data.get("reason", "")),
            source_phase=str(data.get("source_phase", "")),
            created_at=str(data.get("created_at") or utc_now()),
            max_workers=int(data.get("max_workers", 30) or 30),
            stop=bool(data.get("stop", False)),
            metadata=dict(data.get("metadata", {}) or {}),
        )

    def validate(self) -> None:
        if not self.target:
            raise ValueError("RunSpec.target is required")
        if not self.phase:
            raise ValueError("RunSpec.phase is required")
        if not self.stop and not self.tasks:
            raise ValueError("RunSpec must contain tasks unless stop=true")
        for index, task in enumerate(self.tasks):
            if not task.action:
                raise ValueError(f"Task {index}: action is required")
            if not task.protocol:
                raise ValueError(f"Task {index}: protocol is required")
            if not task.target:
                raise ValueError(f"Task {index}: target is required")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "phase": self.phase,
            "source_phase": self.source_phase,
            "created_at": self.created_at,
            "max_workers": self.max_workers,
            "stop": self.stop,
            "reason": self.reason,
            "metadata": dict(self.metadata),
            "tasks": [task.to_dict() for task in self.tasks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@dataclass
class ReconDecision:
    target: str
    source_phase: str
    run_spec: RunSpec
    summary: str
    confidence: float = 0.0
    engine: str = "rules"
    evidence_count: int = 0
    selected_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "source_phase": self.source_phase,
            "summary": self.summary,
            "confidence": self.confidence,
            "engine": self.engine,
            "evidence_count": self.evidence_count,
            "selected_count": self.selected_count,
            "run_spec": self.run_spec.to_dict(),
        }


def unwrap_evidence_bundle(data: Dict[str, Any]) -> Dict[str, Any]:
    if "evidence_bundle" in data and isinstance(data["evidence_bundle"], dict):
        return data["evidence_bundle"]
    return data


def load_evidence_bundle(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return unwrap_evidence_bundle(data)


class RuleBasedDecisionEngine:
    """Deterministic first-pass decision engine."""

    name = "rules"

    def decide(self, evidence_bundle: Dict[str, Any]) -> ReconDecision:
        bundle = unwrap_evidence_bundle(evidence_bundle)
        target = str(bundle.get("target") or "")
        source_phase = str(bundle.get("phase") or "")
        records = list(bundle.get("records", []) or [])
        selected = select_records(records)
        tasks = self._build_tasks(selected)

        if tasks:
            run_spec = RunSpec(
                target=target,
                phase=next_phase(source_phase),
                source_phase=source_phase,
                tasks=tasks,
                reason=f"Selected {len(selected)} evidence records for follow-up probes.",
                metadata={"decision_engine": self.name},
            )
            confidence = 0.75
            summary = f"Generated {len(tasks)} follow-up tasks from {len(selected)} selected records."
        else:
            run_spec = RunSpec(
                target=target or "unknown",
                phase="stop",
                source_phase=source_phase,
                stop=True,
                reason="No responsive or high-value evidence records found.",
                metadata={"decision_engine": self.name},
            )
            confidence = 0.5
            summary = "No next run is recommended by rule-based decision."

        run_spec.validate()
        return ReconDecision(
            target=run_spec.target,
            source_phase=source_phase,
            run_spec=run_spec,
            summary=summary,
            confidence=confidence,
            engine=self.name,
            evidence_count=len(records),
            selected_count=len(selected),
        )

    def _build_tasks(self, records: Iterable[Dict[str, Any]]) -> List[RunTask]:
        tasks: List[RunTask] = []
        seen = set()

        for record in records:
            request = record.get("request", {}) or {}
            response = record.get("response", {}) or {}
            asset = record.get("asset", {}) or {}
            protocol = normalize_protocol(response.get("protocol") or request.get("protocol"))
            target = response.get("target") or request.get("target") or response.get("url") or request.get("url")
            tags = {str(t).upper() for t in response.get("tags", []) or []}
            anomalies = {str(a).lower() for a in response.get("anomalies", []) or []}

            if not target:
                continue

            if protocol == "redis" or "REDIS" in tags:
                if "UNAUTH-OK" in tags or "UNAUTH-CHECK" in tags or "unauth-access" in anomalies:
                    task = RunTask(
                        action="check_unauth",
                        protocol="redis",
                        target=target,
                        asset=dict(asset),
                        reason="Redis responded without clear auth barrier; confirm unauthenticated access.",
                        timeout=5,
                    )
                    add_task(tasks, seen, task)
                continue

            if protocol in ("http", "https"):
                base_url = response.get("url") or request.get("url") or target
                for path in HTTP_DISCOVERY_PATHS:
                    follow_url = urljoin(ensure_url(base_url, protocol), path)
                    task = RunTask(
                        action="send",
                        protocol="http",
                        target=follow_url,
                        meta={"method": "GET"},
                        asset=dict(asset),
                        reason=f"Lightweight HTTP discovery path: {path}",
                        timeout=10,
                    )
                    add_task(tasks, seen, task)
                continue

            if protocol in ("mysql", "ssh", "ftp", "tcp"):
                task = RunTask(
                    action="probe",
                    protocol=protocol,
                    target=target,
                    asset=dict(asset),
                    reason=f"Keep service fingerprint evidence fresh for {protocol}.",
                    timeout=5,
                )
                add_task(tasks, seen, task)

        return tasks


class LLMDecisionEngine:
    """Optional LLM wrapper with rule fallback handled by caller."""

    name = "llm"

    def __init__(self, llm: BaseLLM):
        self.llm = llm
        self.name = f"llm:{llm.name}"

    def decide(self, evidence_bundle: Dict[str, Any]) -> ReconDecision:
        bundle = unwrap_evidence_bundle(evidence_bundle)
        target = str(bundle.get("target") or "")
        source_phase = str(bundle.get("phase") or "")
        records = select_records(list(bundle.get("records", []) or []), limit=MAX_DECISION_RECORDS)

        system_prompt = decision_system_prompt()
        user_prompt = decision_user_prompt(target, source_phase, records)
        response = self.llm.call(system_prompt, user_prompt, temperature=0.2)
        if not response.success:
            raise ValueError(f"LLM decision failed: {response.error}")

        data = response.structured_data
        if not data:
            data = json.loads(response.content)
        run_spec_data = data.get("run_spec", data)
        run_spec = RunSpec.from_dict(run_spec_data)
        if not run_spec.target:
            run_spec.target = target
        if not run_spec.source_phase:
            run_spec.source_phase = source_phase
        run_spec.metadata.setdefault("decision_engine", self.name)
        run_spec.validate()

        return ReconDecision(
            target=run_spec.target,
            source_phase=source_phase,
            run_spec=run_spec,
            summary=str(data.get("summary", run_spec.reason)),
            confidence=float(data.get("confidence", response.confidence or 0.6)),
            engine=self.name,
            evidence_count=len(bundle.get("records", []) or []),
            selected_count=len(records),
        )


def select_records(records: List[Dict[str, Any]], limit: int = MAX_DECISION_RECORDS) -> List[Dict[str, Any]]:
    candidates = [record for record in records if is_candidate(record)]
    candidates.sort(key=record_priority, reverse=True)
    return candidates[:limit]


def is_candidate(record: Dict[str, Any]) -> bool:
    response = record.get("response", {}) or {}
    if not response.get("ok"):
        return False
    if response.get("is_interesting"):
        return True
    if response.get("banner"):
        return True
    if response.get("tags") or response.get("anomalies"):
        return True
    protocol = normalize_protocol(response.get("protocol"))
    return protocol in ("http", "https")


def record_priority(record: Dict[str, Any]) -> Tuple[int, int, int]:
    response = record.get("response", {}) or {}
    tags = {str(t).upper() for t in response.get("tags", []) or []}
    anomalies = {str(a).lower() for a in response.get("anomalies", []) or []}
    protocol = normalize_protocol(response.get("protocol"))
    high_value = bool(tags & {"HIGH-VALUE", "UNAUTH-CHECK", "UNAUTH-OK", "UNAUTH-CONFIRMED"})
    rce_hint = "RCE-PATH" in tags or "rce-possible" in anomalies
    service_weight = 2 if protocol in ("redis", "mysql", "http", "https") else 1
    return (3 if rce_hint else 0, 2 if high_value else 0, service_weight)


def next_phase(source_phase: str) -> str:
    if source_phase == "phase2":
        return "phase3"
    if source_phase == "phase3":
        return "phase3_payload"
    return "phase3"


def normalize_protocol(protocol: Any) -> str:
    value = str(protocol or "auto").lower()
    if value == "https":
        return "https"
    if value in ("http", "redis", "mysql", "ssh", "ftp", "tcp"):
        return value
    return value or "auto"


def ensure_url(value: str, protocol: str = "http") -> str:
    if value.startswith(("http://", "https://")):
        return value
    scheme = "https" if protocol == "https" else "http"
    return f"{scheme}://{value}"


def add_task(tasks: List[RunTask], seen: set, task: RunTask) -> None:
    key = (task.action, task.protocol, task.target, json.dumps(task.payload, sort_keys=True, default=str))
    if key in seen:
        return
    seen.add(key)
    tasks.append(task)


def decision_system_prompt() -> str:
    return """You are the local decision layer for an authorized red-team recon loop.
Return strict JSON only. Do not include destructive payloads. Prefer low-risk
follow-up probes that preserve evidence and improve confidence.

Schema:
{
  "summary": "...",
  "confidence": 0.0,
  "run_spec": {
    "target": "...",
    "phase": "phase3",
    "source_phase": "...",
    "stop": false,
    "reason": "...",
    "tasks": [
      {
        "action": "probe|send|check_unauth",
        "protocol": "http|redis|tcp|mysql|ssh|ftp|auto",
        "target": "...",
        "payload": null,
        "headers": {},
        "meta": {},
        "asset": {},
        "reason": "..."
      }
    ]
  }
}"""


def decision_user_prompt(target: str, source_phase: str, records: List[Dict[str, Any]]) -> str:
    compact_records = []
    for record in records:
        response = record.get("response", {}) or {}
        request = record.get("request", {}) or {}
        compact_records.append({
            "request": {
                "protocol": request.get("protocol"),
                "target": request.get("target"),
                "url": request.get("url"),
            },
            "response": {
                "protocol": response.get("protocol"),
                "ok": response.get("ok"),
                "status": response.get("status"),
                "banner": response.get("banner"),
                "target": response.get("target"),
                "url": response.get("url"),
                "tags": response.get("tags", []),
                "anomalies": response.get("anomalies", []),
                "text": str(response.get("text", ""))[:500],
            },
        })
    return json.dumps({
        "target": target,
        "source_phase": source_phase,
        "records": compact_records,
        "rules": [
            "Use only low-risk follow-up probes.",
            "Do not generate exploit, credential brute force, file write, shell, or destructive tasks.",
            "Return stop=true if no evidence is worth a follow-up.",
        ],
    }, ensure_ascii=False)
