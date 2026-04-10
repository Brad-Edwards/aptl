#!/usr/bin/env python3
"""CLI wrapper for backend conformance."""

from __future__ import annotations

import argparse
import json

from aptl.core.runtime.conformance import (
    BackendCapabilityProfile,
    run_fixture_suite,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run APTL backend conformance fixtures.")
    parser.add_argument(
        "--profile",
        choices=[profile.value for profile in BackendCapabilityProfile],
        default=BackendCapabilityProfile.ORCHESTRATION_EVALUATION.value,
        help="Backend capability profile to validate.",
    )
    args = parser.parse_args()
    report = run_fixture_suite(profile=BackendCapabilityProfile(args.profile))
    print(
        json.dumps(
            {
                "profile": report.profile.value,
                "passed": report.passed,
                "cases": [
                    {
                        "name": case.name,
                        "contract_name": case.contract_name,
                        "valid": case.valid,
                        "passed": case.passed,
                        "diagnostics": [diag.message for diag in case.diagnostics],
                    }
                    for case in report.cases
                ],
                "diagnostics": [diag.message for diag in report.diagnostics],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
