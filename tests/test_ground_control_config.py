"""Repository-local Ground Control workflow and boundary contract tests."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _config() -> dict[str, object]:
    return yaml.safe_load((ROOT / ".ground-control.yaml").read_text())


def test_retired_test_quality_review_gate_is_absent() -> None:
    workflow = _config()["workflow"]

    assert "test_quality_review" not in workflow


def test_appliance_delivery_paths_have_ground_control_boundary_owners() -> None:
    boundaries = _config()["grc"]["boundaries"]
    paths_by_key = {entry["key"]: set(entry["paths"]) for entry in boundaries}

    assert "src/aptl/appliance/**" in paths_by_key["host-boundary"]
    assert "appliance/guest/**" in paths_by_key["host-boundary"]
    assert "src/aptl/workbench/**" in paths_by_key["mcp-control-plane"]
