"""Canonical full-TechVault appliance policy construction."""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.appliance.policy import (
    full_techvault_boundary_policy,
    write_full_techvault_boundary_policy,
)


def test_full_policy_uses_labels_present_on_generated_resources() -> None:
    policy = full_techvault_boundary_policy()

    assert set(policy.platform_networks.model_dump().values()) == {
        "com.docker.compose.network=aptl-redteam",
        "com.docker.compose.network=aptl-security",
        "com.docker.compose.network=aptl-dmz",
    }
    assert policy.host_mcp_contract == "aptl.restricted-ssh-mcp/v1"
    assert {item.audience for item in policy.guest_publications} == {
        "participant",
        "recovery",
        "host-mcp",
    }


def test_policy_writer_is_create_once(tmp_path: Path) -> None:
    target = tmp_path / "boundary-policy.json"
    expected = write_full_techvault_boundary_policy(target)

    assert target.stat().st_mode & 0o777 == 0o444
    assert expected == expected.model_validate_json(target.read_bytes())
    with pytest.raises(FileExistsError):
        write_full_techvault_boundary_policy(target)
