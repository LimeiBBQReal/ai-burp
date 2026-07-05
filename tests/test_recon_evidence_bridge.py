import base64

import pytest

from aiburp.traffic import TrafficResponse
from recon.evidence import EvidenceBundle, EvidenceResponse
from recon.protocols.engine import ProtocolProbeEngine
from recon.traffic_bridge import (
    ReconTask,
    build_port_probe_tasks,
    load_assets_from_phase_data,
    records_to_protocol_groups,
    run_tasks,
)


def test_evidence_response_preserves_raw_and_decision_fields():
    resp = TrafficResponse(
        protocol="tcp",
        ok=True,
        status=1,
        raw=b"hello",
        text="hello",
        banner="ssh/OpenSSH_8.9",
        target="127.0.0.1:22",
        tags=["SSH", "HIGH-VALUE"],
        anomalies=["banner-detected"],
    )

    evidence = EvidenceResponse.from_traffic_response(resp)

    assert evidence.ok is True
    assert evidence.raw_b64 == base64.b64encode(b"hello").decode("ascii")
    assert evidence.banner == "ssh/OpenSSH_8.9"
    assert evidence.is_interesting is True

    bundle = EvidenceBundle(target="127.0.0.1", phase="test", records=[])
    assert bundle.summary()["records"] == 0


def test_phase_data_loader_hydrates_relevant_assets():
    data = {
        "relevant_assets": [{"value": "api.example.com", "reason": "domain match"}],
        "all_assets": [
            {"value": "api.example.com", "type": "domain", "source": "crt.sh"},
        ],
    }

    assets = load_assets_from_phase_data(data)

    assert assets == [
        {
            "value": "api.example.com",
            "type": "domain",
            "source": "crt.sh",
            "reason": "domain match",
        }
    ]


def test_port_probe_tasks_preserve_web_schemes():
    tasks = build_port_probe_tasks(["example.com"], [80, 443])

    assert tasks[0].target == "http://example.com:80"
    assert tasks[1].target == "https://example.com:443"


@pytest.mark.asyncio
async def test_traffic_bridge_runs_burp_style_tcp_evidence(echo_server):
    task = ReconTask(
        action="send",
        protocol="tcp",
        target=f"127.0.0.1:{echo_server}",
        payload="hello",
        asset={"value": f"127.0.0.1:{echo_server}", "type": "ip:port"},
    )

    bundle = await run_tasks(
        [task],
        target="127.0.0.1",
        phase="test",
        max_concurrency=1,
        timeout=2,
    )

    assert bundle.summary()["records"] == 1
    record = bundle.records[0]
    assert record.request.protocol == "tcp"
    assert record.response.ok is True
    assert "SSH-2.0-OpenSSH_8.9" in record.response.text
    assert "ECHO:hello" in record.response.text

    groups = records_to_protocol_groups(bundle.records)
    assert groups


def test_legacy_recon_protocol_engine_still_registers_builtin_probes():
    engine = ProtocolProbeEngine(max_workers=1)
    protocols = set(engine.list_protocols())

    assert "http" in protocols
    assert "https" in protocols
