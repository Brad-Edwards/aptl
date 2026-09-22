"""Canonical full-TechVault appliance policy construction."""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.appliance.policy import (
    full_techvault_boundary_policy,
    write_full_techvault_boundary_policy,
)


def test_full_policy_keeps_vm_access_without_claiming_scenario_zones() -> None:
    policy = full_techvault_boundary_policy()

    assert policy.platform_networks is None
    assert policy.platform_anchors is None
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
