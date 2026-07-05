from recon.cloud.run_spec_executor import execute_run_spec
from recon.evidence import EvidenceBundle, EvidenceRecord, EvidenceRequest, EvidenceResponse


def make_record(target="http://example.com/robots.txt"):
    return EvidenceRecord(
        asset={"value": target},
        request=EvidenceRequest(protocol="http", target=target, method="GET", url=target),
        response=EvidenceResponse(
            protocol="http",
            ok=True,
            status=200,
            target=target,
            url=target,
            text="ok",
            tags=["HTTP"],
        ),
        stage="phase3_payload",
        action="send",
    )


def test_execute_run_spec_dispatches_tasks_through_runner():
    calls = []

    def fake_runner(tasks, target, phase, max_concurrency, timeout):
        calls.append({
            "tasks": tasks,
            "target": target,
            "phase": phase,
            "max_concurrency": max_concurrency,
            "timeout": timeout,
        })
        bundle = EvidenceBundle(target=target, phase=phase)
        bundle.add(make_record(tasks[0].target))
        return bundle

    result = execute_run_spec(
        {
            "target": "example.com",
            "phase": "phase3_payload",
            "source_phase": "phase3",
            "max_workers": 7,
            "tasks": [
                {
                    "action": "send",
                    "protocol": "http",
                    "target": "http://example.com/robots.txt",
                    "meta": {"method": "GET"},
                    "reason": "lightweight discovery",
                }
            ],
        },
        timeout=3,
        runner=fake_runner,
    )

    assert len(calls) == 1
    assert calls[0]["max_concurrency"] == 7
    assert calls[0]["timeout"] == 3
    assert calls[0]["tasks"][0].target == "http://example.com/robots.txt"
    assert result["total_tasks"] == 1
    assert result["requested_tasks"] == 1
    assert result["evidence_summary"]["records"] == 1
    assert result["evidence_bundle"]["records"][0]["response"]["status"] == 200


def test_execute_run_spec_stop_does_not_dispatch_runner():
    def fake_runner(*args, **kwargs):
        raise AssertionError("runner should not be called for stop=true")

    result = execute_run_spec(
        {
            "target": "example.com",
            "phase": "stop",
            "source_phase": "phase3",
            "stop": True,
            "reason": "No useful follow-up.",
            "tasks": [],
        },
        runner=fake_runner,
    )

    assert result["stop"] is True
    assert result["total_tasks"] == 0
    assert result["requested_tasks"] == 0
    assert result["evidence_summary"]["records"] == 0
    assert result["evidence_bundle"]["metadata"]["run_spec_stop"] is True
