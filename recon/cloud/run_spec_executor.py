"""
Execute a local decision RunSpec in GitHub Actions.

The local controller decides what should be sent next.  This cloud-side
executor only validates that contract, dispatches tasks through the Burp-style
traffic bridge, and writes an evidence bundle for the next local decision.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from recon.decision import RunSpec
from recon.evidence import EvidenceBundle
from recon.traffic_bridge import (
    ReconTask,
    evidence_results_by_protocol,
    run_tasks_sync,
)


DEFAULT_INPUT = ROOT / "recon" / "out" / "run_spec.json"
DEFAULT_OUTPUT = ROOT / "recon" / "out" / "run_spec_results.json"
ALLOWED_ACTIONS = {"probe", "send", "check_unauth"}

logger = logging.getLogger(__name__)


Runner = Callable[[List[ReconTask], str, str, int, Optional[float]], EvidenceBundle]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_run_spec(path: Path = DEFAULT_INPUT) -> RunSpec:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    run_spec = RunSpec.from_dict(data)
    run_spec.validate()
    return run_spec


def build_recon_tasks(run_spec: RunSpec) -> List[ReconTask]:
    tasks: List[ReconTask] = []
    for index, task in enumerate(run_spec.tasks):
        if task.action not in ALLOWED_ACTIONS:
            raise ValueError(f"Task {index}: unsupported action: {task.action}")
        tasks.append(ReconTask.from_dict(task.to_dict()))
    return tasks


def empty_bundle(run_spec: RunSpec) -> EvidenceBundle:
    return EvidenceBundle(
        target=run_spec.target,
        phase=run_spec.phase,
        metadata={
            "source_phase": run_spec.source_phase,
            "run_spec_stop": run_spec.stop,
            "run_spec_reason": run_spec.reason,
        },
    )


def execute_run_spec(
    run_spec_data: Dict[str, Any],
    *,
    max_workers: Optional[int] = None,
    timeout: Optional[float] = None,
    runner: Runner = run_tasks_sync,
) -> Dict[str, Any]:
    run_spec = RunSpec.from_dict(run_spec_data)
    run_spec.validate()

    requested_tasks = len(run_spec.tasks)
    if run_spec.stop:
        bundle = empty_bundle(run_spec)
        executed_tasks = 0
    else:
        tasks = build_recon_tasks(run_spec)
        workers = int(max_workers or run_spec.max_workers or 30)
        bundle = runner(tasks, run_spec.target, run_spec.phase, workers, timeout)
        bundle.metadata.setdefault("source_phase", run_spec.source_phase)
        bundle.metadata.setdefault("run_spec_reason", run_spec.reason)
        executed_tasks = len(tasks)

    return {
        "target": run_spec.target,
        "phase": run_spec.phase,
        "source_phase": run_spec.source_phase,
        "stop": run_spec.stop,
        "reason": run_spec.reason,
        "requested_tasks": requested_tasks,
        "total_tasks": executed_tasks,
        "results": evidence_results_by_protocol(bundle),
        "evidence_summary": bundle.summary(),
        "evidence_bundle": bundle.to_dict(),
        "run_spec": run_spec.to_dict(),
        "timestamp": utc_now(),
    }


def write_result(result: Dict[str, Any], output_path: Path = DEFAULT_OUTPUT) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    input_path = Path(os.environ.get("RECON_RUN_SPEC_PATH", str(DEFAULT_INPUT)))
    output_path = Path(os.environ.get("RECON_RUN_SPEC_OUTPUT", str(DEFAULT_OUTPUT)))
    timeout_env = os.environ.get("RECON_PROBE_TIMEOUT")
    timeout = float(timeout_env) if timeout_env else None
    max_workers = int(os.environ.get("RECON_MAX_WORKERS", "30"))

    logger.info("RunSpec executor starting")
    logger.info("Input: %s", input_path)

    run_spec = load_run_spec(input_path)
    result = execute_run_spec(
        run_spec.to_dict(),
        max_workers=max_workers,
        timeout=timeout,
        runner=run_tasks_sync,
    )
    write_result(result, output_path)

    logger.info(
        "RunSpec execution finished: requested=%s executed=%s stop=%s output=%s",
        result["requested_tasks"],
        result["total_tasks"],
        result["stop"],
        output_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
