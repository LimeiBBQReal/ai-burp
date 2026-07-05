"""
Local controller for the recon loop.

First pass: read a decrypted evidence JSON file and produce the next run_spec.
GitHub dispatch/download can be layered on top after this offline loop is stable.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Optional

from .decision import (
    LLMDecisionEngine,
    RuleBasedDecisionEngine,
    RunSpec,
    load_evidence_bundle,
)
from .llm import CatPawBackend, OpenAIBackend


def create_llm_backend(name: str):
    if name == "openai":
        return OpenAIBackend(
            api_key=os.environ.get("OPENAI_API_KEY") or os.environ.get("AIBURP_OPENAI_API_KEY"),
            model=os.environ.get("AIBURP_LLM_MODEL") or os.environ.get("OPENAI_MODEL", "gpt-4o"),
            base_url=(
                os.environ.get("OPENAI_API_BASE")
                or os.environ.get("OPENAI_BASE_URL")
                or os.environ.get("AIBURP_OPENAI_API_BASE")
            ),
        )
    if name == "catpaw":
        return CatPawBackend()
    raise ValueError(f"Unsupported decision backend: {name}")


def decide_evidence_file(
    evidence_path: str,
    output_path: Optional[str] = None,
    backend: str = "rules",
    fallback_to_rules: bool = True,
) -> RunSpec:
    evidence = load_evidence_bundle(evidence_path)
    rule_engine = RuleBasedDecisionEngine()

    if backend == "rules":
        decision = rule_engine.decide(evidence)
    else:
        try:
            llm = create_llm_backend(backend)
            decision = LLMDecisionEngine(llm).decide(evidence)
        except Exception:
            if not fallback_to_rules:
                raise
            decision = rule_engine.decide(evidence)
            decision.run_spec.metadata["fallback_reason"] = f"{backend} decision failed"

    if output_path:
        write_run_spec(decision.run_spec, output_path)
    return decision.run_spec


def write_run_spec(run_spec: RunSpec, output_path: str) -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(run_spec.to_json(), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m recon.local_controller",
        description="Local decision controller for decrypted recon evidence.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    decide = sub.add_parser("decide", help="Generate next run_spec from an evidence JSON file.")
    decide.add_argument("evidence", help="Path to decrypted phase JSON or direct evidence_bundle JSON.")
    decide.add_argument("--out", default="recon/out/run_spec.json", help="Output run_spec path.")
    decide.add_argument(
        "--backend",
        choices=["rules", "catpaw", "openai"],
        default="rules",
        help="Decision backend. Defaults to deterministic rules.",
    )
    decide.add_argument(
        "--no-fallback",
        action="store_true",
        help="Fail instead of falling back to rules when LLM decision fails.",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "decide":
        run_spec = decide_evidence_file(
            args.evidence,
            output_path=args.out,
            backend=args.backend,
            fallback_to_rules=not args.no_fallback,
        )
        print(json.dumps({
            "output": args.out,
            "target": run_spec.target,
            "phase": run_spec.phase,
            "tasks": len(run_spec.tasks),
            "stop": run_spec.stop,
            "reason": run_spec.reason,
        }, ensure_ascii=False, indent=2))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
