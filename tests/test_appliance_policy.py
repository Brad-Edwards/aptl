"""Canonical full-TechVault appliance policy construction."""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.appliance.policy import (
    full_techvault_boundary_policy,
    write_full_techvault_boundary_policy,
)


def test_full_policy_publishes_only_browser_desktop_without_host_bridge() -> None:
    policy = full_techvault_boundary_policy()

    assert policy.platform_networks is None
    assert policy.platform_anchors is None
    assert policy.host_mcp_contract is None
    assert [(item.audience, item.address, item.port, item.protocol)
            for item in policy.guest_publications] == [
        ("participant", "127.0.0.1", 8080, "tcp")
    ]
    assert policy.generation > 2


def test_policy_writer_is_create_once(tmp_path: Path) -> None:
    target = tmp_path / "boundary-policy.json"
    expected = write_full_techvault_boundary_policy(target)

    assert target.stat().st_mode & 0o777 == 0o444
    assert expected == expected.model_validate_json(target.read_bytes())
    with pytest.raises(FileExistsError):
        write_full_techvault_boundary_policy(target)
