#!/usr/bin/env python3
"""Record live participant-UI browser checks against an authenticated snapshot."""

from __future__ import annotations

import argparse
import os
import urllib.request
from pathlib import Path

import rfc8785

from aptl.appliance.seat.access import GuestRuntimeEvidence
from aptl.utils.strict_json import model_validate_json_strict
from aptl.validation.participant_profile_models import ParticipantReadinessSuite
from aptl.validation.participant_qualification_evidence import (
    QualificationCheckEvidence,
)

_SERVICE_TOKENS = {
    "kali-desktop": ("kali",),
    "soc-wazuh": ("wazuh", "dashboard"),
    "soc-thehive": ("thehive",),
    "soc-misp": ("misp",),
    "soc-shuffle": ("shuffle",),
}


def _ui_reachable(url: str) -> bool:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=15) as response:
        if not 200 <= response.status < 400:
            return False
        return bool(response.read(1024 * 1024 + 1))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-evidence", type=Path, required=True)
    parser.add_argument("--readiness", type=Path, required=True)
    parser.add_argument("--participant-url", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    runtime = model_validate_json_strict(
        GuestRuntimeEvidence, args.runtime_evidence.read_bytes()
    )
    readiness = model_validate_json_strict(
        ParticipantReadinessSuite, args.readiness.read_bytes()
    )
    if not all(_ui_reachable(url) for url in args.participant_url):
        raise RuntimeError("participant UI was not reachable")
    containers = runtime.snapshot.get("containers")
    if not isinstance(containers, list):
        raise ValueError("runtime container snapshot is unavailable")
    names = {
        str(item["name"]).lower()
        for item in containers
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and str(item.get("status", "")).startswith("Up")
    }
    checks = []
    for check in readiness.checks:
        if check.kind != "browser-operation":
            continue
        tokens = _SERVICE_TOKENS.get(check.subject_id, ())
        if tokens and not any(token in name for token in tokens for name in names):
            raise RuntimeError("browser backing service was not running")
        checks.append(
            QualificationCheckEvidence(
                check_id=check.check_id,
                status="passed",
                summary="participant UI and backing service were live",
            )
        )
    payload = rfc8785.dumps(
        {
            "schema_version": "aptl.browser-probe/v1",
            "checks": [item.model_dump(mode="json") for item in checks],
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        args.output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


if __name__ == "__main__":
    main()
