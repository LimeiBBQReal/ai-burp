"""
Burp-style evidence model for the recon cloud loop.

The recon pipeline uses GitHub Actions as an execution worker and local LLMs as
the decision layer.  This module defines the stable data contract between those
two sides: full request/response evidence, not just lossy summaries.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_RAW_MAX = 4096


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "data": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, bytearray):
        return _json_safe(bytes(value))
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


@dataclass
class EvidenceRequest:
    protocol: str
    target: str
    method: str = ""
    url: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)
    payload: Any = None
    marker: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_traffic_request(cls, req: Any) -> "EvidenceRequest":
        return cls(
            protocol=getattr(req, "protocol", "") or "",
            target=getattr(req, "target", "") or "",
            headers=dict(getattr(req, "headers", {}) or {}),
            payload=getattr(req, "payload", None),
            marker=getattr(req, "marker", "") or "",
            meta=dict(getattr(req, "meta", {}) or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "target": self.target,
            "method": self.method,
            "url": self.url,
            "headers": _json_safe(self.headers),
            "payload": _json_safe(self.payload),
            "marker": self.marker,
            "meta": _json_safe(self.meta),
        }


@dataclass
class EvidenceResponse:
    protocol: str
    ok: bool
    status: int = 0
    time_ms: float = 0.0
    headers: Dict[str, Any] = field(default_factory=dict)
    text: str = ""
    body: str = ""
    raw_b64: str = ""
    raw_truncated: bool = False
    banner: str = ""
    length: int = 0
    url: str = ""
    method: str = ""
    target: str = ""
    error: str = ""
    blocked: bool = False
    reflects: bool = False
    anomalies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    payload: str = ""
    next_steps: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_traffic_response(
        cls,
        resp: Any,
        include_raw: bool = True,
        raw_max: int = DEFAULT_RAW_MAX,
    ) -> "EvidenceResponse":
        raw = getattr(resp, "raw", b"") or b""
        raw_b64 = ""
        raw_truncated = False
        if include_raw and raw:
            raw_slice = raw[:raw_max]
            raw_b64 = base64.b64encode(raw_slice).decode("ascii")
            raw_truncated = len(raw) > raw_max

        text = getattr(resp, "text", "") or ""
        body = getattr(resp, "body", "") or text
        next_steps = getattr(resp, "next_steps", None) or []

        return cls(
            protocol=getattr(resp, "protocol", "") or "",
            ok=bool(getattr(resp, "ok", False)),
            status=int(getattr(resp, "status", 0) or 0),
            time_ms=float(getattr(resp, "time_ms", 0.0) or 0.0),
            headers=dict(getattr(resp, "headers", {}) or {}),
            text=text,
            body=body,
            raw_b64=raw_b64,
            raw_truncated=raw_truncated,
            banner=getattr(resp, "banner", "") or "",
            length=int(getattr(resp, "length", 0) or len(raw) or len(body)),
            url=getattr(resp, "url", "") or "",
            method=getattr(resp, "method", "") or "",
            target=getattr(resp, "target", "") or "",
            error=getattr(resp, "error", "") or "",
            blocked=bool(getattr(resp, "blocked", False)),
            reflects=bool(getattr(resp, "reflects", False)),
            anomalies=list(getattr(resp, "anomalies", []) or []),
            tags=list(getattr(resp, "tags", []) or []),
            payload=str(getattr(resp, "payload", "") or ""),
            next_steps=[_json_safe(s) for s in next_steps],
        )

    @property
    def is_interesting(self) -> bool:
        return (
            self.ok
            and (
                bool(self.error)
                or self.blocked
                or self.reflects
                or bool(self.anomalies)
                or bool(self.tags)
                or bool(self.banner)
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "ok": self.ok,
            "status": self.status,
            "time_ms": round(self.time_ms, 1),
            "headers": _json_safe(self.headers),
            "text": self.text,
            "body": self.body,
            "raw_b64": self.raw_b64,
            "raw_truncated": self.raw_truncated,
            "banner": self.banner,
            "length": self.length,
            "url": self.url,
            "method": self.method,
            "target": self.target,
            "error": self.error,
            "blocked": self.blocked,
            "reflects": self.reflects,
            "anomalies": list(self.anomalies),
            "tags": list(self.tags),
            "payload": self.payload,
            "next_steps": _json_safe(self.next_steps),
            "is_interesting": self.is_interesting,
        }


@dataclass
class EvidenceRecord:
    asset: Dict[str, Any]
    request: EvidenceRequest
    response: EvidenceResponse
    stage: str = ""
    action: str = "probe"
    source: str = "github-actions"
    captured_at: str = field(default_factory=utc_now)
    decision_hints: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_traffic(
        cls,
        asset: Dict[str, Any],
        request: EvidenceRequest,
        response: Any,
        stage: str,
        action: str = "probe",
        source: str = "github-actions",
    ) -> "EvidenceRecord":
        evidence_response = EvidenceResponse.from_traffic_response(response)
        hints = {
            "tags": list(evidence_response.tags),
            "anomalies": list(evidence_response.anomalies),
            "next_steps": list(evidence_response.next_steps),
            "interesting": evidence_response.is_interesting,
        }
        return cls(
            asset=dict(asset or {}),
            request=request,
            response=evidence_response,
            stage=stage,
            action=action,
            source=source,
            decision_hints=hints,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": _json_safe(self.asset),
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "stage": self.stage,
            "action": self.action,
            "source": self.source,
            "captured_at": self.captured_at,
            "decision_hints": _json_safe(self.decision_hints),
        }


@dataclass
class EvidenceBundle:
    target: str
    phase: str
    records: List[EvidenceRecord] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    run_id: str = ""
    spec_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add(self, record: EvidenceRecord) -> None:
        self.records.append(record)

    def summary(self) -> Dict[str, Any]:
        protocol_counts: Dict[str, int] = {}
        interesting = 0
        ok_count = 0
        for record in self.records:
            proto = record.response.protocol or record.request.protocol or "unknown"
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            if record.response.ok:
                ok_count += 1
            if record.response.is_interesting:
                interesting += 1

        return {
            "target": self.target,
            "phase": self.phase,
            "records": len(self.records),
            "ok_records": ok_count,
            "interesting_records": interesting,
            "protocols": protocol_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "phase": self.phase,
            "created_at": self.created_at,
            "run_id": self.run_id,
            "spec_id": self.spec_id,
            "metadata": _json_safe(self.metadata),
            "summary": self.summary(),
            "records": [r.to_dict() for r in self.records],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def save(self, path: str) -> None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.to_json(), encoding="utf-8")
