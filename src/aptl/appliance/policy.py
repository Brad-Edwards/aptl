"""Canonical full-TechVault platform boundary policy for appliance delivery."""

from __future__ import annotations

import os
from pathlib import Path

import rfc8785

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy


def full_techvault_boundary_policy() -> ApplianceBoundaryPolicy:
    """Return the signed VM-only contract without repurposing scenario resources."""

    return ApplianceBoundaryPolicy.model_validate(
        {
            "schema_version": "aptl.appliance-boundary/v2",
            "policy_id": "techvault-full",
            "generation": 2,
            "workbench_policy_version": "participant-workbench-profile/v1",
            "default_deny": False,
            "guest_publications": [
                {
                    "audience": "participant",
                    "address": "127.0.0.1",
                    "port": 3000,
                    "protocol": "tcp",
                },
                {
                    "audience": "recovery",
                    "address": "127.0.0.1",
                    "port": 8400,
                    "protocol": "tcp",
                },
                {
                    "audience": "host-mcp",
                    "address": "127.0.0.1",
                    "port": 2222,
                    "protocol": "tcp",
                },
            ],
            "host_mcp_contract": "aptl.restricted-ssh-mcp/v1",
            "docker_authority": {
                "allowed_holder_labels": [
                    "aptl.node.address=provision.node.shuffle-orborus"
                ],
                "require_guest_daemon": True,
            },
        }
    )


def write_full_techvault_boundary_policy(output: Path) -> ApplianceBoundaryPolicy:
    """Create the canonical policy once using deterministic bytes."""

    policy = full_techvault_boundary_policy()
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o444,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(rfc8785.dumps(policy.model_dump(mode="json")))
        handle.flush()
        os.fsync(handle.fileno())
    return policy
