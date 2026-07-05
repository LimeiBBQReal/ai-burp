import json

from recon.decision import RuleBasedDecisionEngine, RunSpec, load_evidence_bundle
from recon.local_controller import decide_evidence_file


def make_bundle(records):
    return {
        "target": "example.com",
        "phase": "phase2",
        "records": records,
    }


def make_record(protocol, target, tags=None, anomalies=None, url=""):
    return {
        "asset": {"value": target},
        "request": {"protocol": protocol, "target": target, "url": url},
        "response": {
            "protocol": protocol,
            "ok": True,
            "status": 1 if protocol != "http" else 200,
            "target": target,
            "url": url,
            "banner": protocol,
            "tags": tags or [],
            "anomalies": anomalies or [],
            "is_interesting": True,
            "text": "",
        },
    }


def test_rule_engine_generates_redis_unauth_followup():
    bundle = make_bundle([
        make_record("redis", "127.0.0.1:6379", tags=["REDIS", "UNAUTH-OK", "HIGH-VALUE"]),
    ])

    decision = RuleBasedDecisionEngine().decide(bundle)

    assert decision.run_spec.phase == "phase3"
    assert len(decision.run_spec.tasks) == 1
    task = decision.run_spec.tasks[0]
    assert task.action == "check_unauth"
    assert task.protocol == "redis"
    assert task.target == "127.0.0.1:6379"


def test_rule_engine_generates_http_discovery_tasks():
    bundle = make_bundle([
        make_record("http", "http://example.com:80", tags=["HTTP"], url="http://example.com/"),
    ])

    decision = RuleBasedDecisionEngine().decide(bundle)

    targets = [task.target for task in decision.run_spec.tasks]
    assert "http://example.com/robots.txt" in targets
    assert "http://example.com/.well-known/security.txt" in targets
    assert all(task.action == "send" for task in decision.run_spec.tasks)


def test_rule_engine_stops_when_no_candidates():
    bundle = make_bundle([
        {
            "request": {"protocol": "tcp", "target": "127.0.0.1:1"},
            "response": {"protocol": "tcp", "ok": False, "target": "127.0.0.1:1"},
        }
    ])

    decision = RuleBasedDecisionEngine().decide(bundle)

    assert decision.run_spec.stop is True
    assert decision.run_spec.tasks == []


def test_local_controller_decide_file_writes_run_spec(tmp_path):
    evidence_path = tmp_path / "phase2.json"
    output_path = tmp_path / "run_spec.json"
    evidence_path.write_text(json.dumps({
        "evidence_bundle": make_bundle([
            make_record("redis", "127.0.0.1:6379", tags=["REDIS", "UNAUTH-OK"]),
        ])
    }), encoding="utf-8")

    run_spec = decide_evidence_file(str(evidence_path), str(output_path), backend="rules")

    assert output_path.exists()
    loaded = RunSpec.from_dict(json.loads(output_path.read_text(encoding="utf-8")))
    assert loaded.target == "example.com"
    assert loaded.tasks[0].protocol == "redis"
    assert run_spec.tasks[0].action == "check_unauth"


def test_load_evidence_bundle_unwraps_phase_output(tmp_path):
    evidence_path = tmp_path / "phase3.json"
    evidence_path.write_text(json.dumps({"evidence_bundle": make_bundle([])}), encoding="utf-8")

    bundle = load_evidence_bundle(str(evidence_path))

    assert bundle["target"] == "example.com"
