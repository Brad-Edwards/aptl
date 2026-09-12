#!/usr/bin/env python3
"""Cortex process analyzer for deterministic offline APTL QA."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


def _bounded_text(value: Any, limit: int) -> str:
    """Return an analyzer-safe string without echoing unbounded job input."""
    if isinstance(value, str):
        return value[:limit]
    return json.dumps(value, sort_keys=True, separators=(",", ":"))[:limit]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: aptl_observable.py JOB_DIRECTORY", file=sys.stderr)
        return 2

    job_dir = Path(sys.argv[1])
    input_path = job_dir / "input" / "input.json"
    output_path = job_dir / "output" / "output.json"

    try:
        job = json.loads(input_path.read_text(encoding="utf-8"))
        data_type = _bounded_text(job.get("dataType", "unknown"), 128)
        data = _bounded_text(job.get("data", ""), 4096)
        message = _bounded_text(job.get("message", ""), 1024)
        report = {
            "success": True,
            "summary": {
                "taxonomies": [
                    {
                        "level": "info",
                        "namespace": "APTL",
                        "predicate": "Observable",
                        "value": data_type,
                    }
                ]
            },
            "artifacts": [],
            "operations": [],
            "full": {"data": data, "dataType": data_type, "message": message},
        }
    except (OSError, TypeError, ValueError) as exc:
        report = {
            "success": False,
            "errorMessage": f"Invalid Cortex job input: {exc}",
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
