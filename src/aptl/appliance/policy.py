"""Canonical full-TechVault platform boundary policy for appliance delivery."""

from __future__ import annotations

import os
from pathlib import Path

import rfc8785

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy


def full_techvault_boundary_policy() -> ApplianceBoundaryPolicy:
    """Return the fixed platform boundary over observed RAES-owned resources."""

    return ApplianceBoundaryPolicy.model_validate(
        {
            "schema_version": "aptl.appliance-boundary/v1",
            "policy_id": "techvault-full",
            "generation": 1,
            "workbench_policy_version": "participant-workbench-profile/v1",
            "default_deny": True,
            "platform_networks": {
                "participant": "com.docker.compose.network=aptl-redteam",
                "management": "com.docker.compose.network=aptl-security",
                "egress": "com.docker.compose.network=aptl-dmz",
            },
            "platform_anchors": {
                "participant": "aptl.node.address=provision.node.kali",
                "management": "aptl.node.address=provision.node.soc-workstation",
                "egress": "aptl.node.address=provision.node.suricata",
            },
            "fixed_crossings": [
                {
                    "source": "management",
                    "destination": "egress",
                    "protocol": "tcp",
                    "ports": [3128],
                    "purpose": "bounded-egress-broker",
                }
            ],
            "egress_authorities": [],
            "egress_proxy_limits": {
                "max_connections": 32,
                "max_header_bytes": 4096,
                "header_timeout_seconds": 5,
                "connect_timeout_seconds": 10,
                "idle_timeout_seconds": 60,
            },
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
                    "aptl.node.address=provision.node.soc-workstation"
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
