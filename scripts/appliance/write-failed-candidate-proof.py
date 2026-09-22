#!/usr/bin/env python3
"""Bind rejected candidate verification to successful post-rejection client calls."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import rfc8785

from aptl.appliance.candidate import verify_candidate_directory
from aptl.appliance.errors import ApplianceManifestError
from aptl.appliance.qualification import FailedCandidateReceipt
from aptl.utils.strict_json import loads_strict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--failed-candidate-dir", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--active-state", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest, inspection = verify_candidate_directory(
        args.candidate_dir, args.public_key
    )
    try:
        verify_candidate_directory(args.failed_candidate_dir, args.public_key)
    except ApplianceManifestError:
        pass
    else:
        raise RuntimeError("modified candidate was not rejected")
    digests = []
    for path in args.active_state:
        document = loads_strict(path.read_bytes())
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "aptl.native-client-active/v1"
        ):
            raise ValueError("active native client state is invalid")
        digests.append(document["active_response_digest"])
    receipt = FailedCandidateReceipt(
        schema_version="aptl.failed-candidate-proof/v1",
        candidate_id=manifest.candidate_id,
        candidate_manifest_digest=inspection.manifest_digest,
        rejected=True,
        active_response_digests=tuple(digests),
    )
    descriptor = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(rfc8785.dumps(receipt.model_dump(mode="json")))


if __name__ == "__main__":
    main()
