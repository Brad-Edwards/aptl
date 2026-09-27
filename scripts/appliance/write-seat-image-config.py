#!/usr/bin/env python3
"""Write the self-description a baked seat image carries.

`aptl seat start` reads this blob before it downloads the disk, so it states
what the host must provide and the boundary contract the guest runs under. It
is produced by the bake, from the same source that produced the disk, which is
why the two cannot describe different things.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

from aptl.appliance.policy import full_techvault_boundary_policy

# The supported participant profile. A host below this is refused before QEMU
# launches rather than failing halfway through a lab start.
RESOURCES = {
    "architecture": "x86_64",
    "vcpus": 8,
    "memory_bytes": 32 * 1024**3,
    "disk_bytes": 250 * 1024**3,
    "hardware_virtualization": True,
    "local_adapter": "qemu-kvm",
    "supported_hypervisors": ["qemu-kvm"],
}


def image_digest(reference: str) -> str:
    """Return the immutable local identity of one built image."""

    identity = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
        text=True,
    ).strip()
    if "sha256:" not in identity:
        raise SystemExit(f"no immutable identity for {reference}")
    return f"{reference.rsplit(':', 1)[0]}@{identity}"


def file_digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--disk", required=True, type=pathlib.Path)
    parser.add_argument("--description", default="APTL TechVault seat")
    arguments = parser.parse_args()

    # The configured build size may differ from the release default. The
    # launcher's capacity gate must reserve the virtual size of this disk,
    # not a constant that can understate what the guest is allowed to write.
    disk_info = json.loads(
        subprocess.check_output(
            ["qemu-img", "info", "--output=json", str(arguments.disk)], text=True
        )
    )
    virtual_size = disk_info.get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size <= 0:
        raise SystemExit("seat disk has no usable virtual size")

    config = {
        "schema_version": "aptl.seat-image/v1",
        "resources": {**RESOURCES, "disk_bytes": virtual_size},
        "boundary": full_techvault_boundary_policy().model_dump(mode="json"),
        "binding": {
            "boundary_helper_image": image_digest("aptl-network-boundary-helper:5"),
            "egress_proxy_image": image_digest("aptl-appliance-egress-proxy:1"),
            # The guest's participant routes are whatever this disk contains,
            # so the disk's own digest is what the launch is bound to.
            "raes_plan_digest": file_digest(arguments.disk),
        },
        "description": arguments.description,
    }

    # Validate before writing: an image whose declaration the launcher would
    # refuse must fail the bake, not a participant's first start.
    from aptl.appliance.seat.image_config import parse_seat_image_config

    payload = json.dumps(config, separators=(",", ":"), sort_keys=True).encode()
    parse_seat_image_config(payload)
    arguments.output.write_bytes(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
