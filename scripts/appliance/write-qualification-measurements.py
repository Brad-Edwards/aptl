#!/usr/bin/env python3
"""Write a strict receipt from values measured by the KVM qualification job."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import rfc8785

from aptl.appliance.qualification import QualificationMeasurementReceipt
from aptl.validation.participant_qualification_evidence import (
    QualificationMeasurements,
)
from aptl.utils.strict_json import loads_strict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-sample", type=Path, required=True)
    parser.add_argument("--asset-sample", type=Path, required=True)
    for name in (
        "cold-start-seconds",
        "warm-start-seconds",
        "clean-reset-seconds",
    ):
        parser.add_argument("--" + name, type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    values = vars(args)
    resources = loads_strict(args.resource_sample.read_bytes())
    assets = loads_strict(args.asset_sample.read_bytes())
    if not isinstance(resources, dict) or not isinstance(assets, dict):
        raise ValueError("qualification measurement samples are invalid")
    receipt = QualificationMeasurementReceipt(
        schema_version="aptl.qualification-measurements/v1",
        measurements=QualificationMeasurements(
            peak_cpu_percent=resources["peak_cpu_percent"],
            peak_memory_bytes=resources["peak_memory_bytes"],
            staged_profile_assets_bytes=assets["staged_profile_assets_bytes"],
            unique_image_compressed_bytes=assets["unique_image_compressed_bytes"],
            unique_image_expanded_bytes=assets["unique_image_expanded_bytes"],
            peak_runtime_disk_bytes=resources["peak_runtime_disk_bytes"],
            cold_start_seconds=values["cold_start_seconds"],
            warm_start_seconds=values["warm_start_seconds"],
            clean_reset_seconds=values["clean_reset_seconds"],
        ),
    )
    descriptor = os.open(
        args.output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(rfc8785.dumps(receipt.model_dump(mode="json")))


if __name__ == "__main__":
    main()
