"""Repository-local Ground Control workflow and boundary contract tests."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _config() -> dict[str, object]:
    return yaml.safe_load((ROOT / ".ground-control.yaml").read_text())


def test_retired_test_quality_review_gate_is_absent() -> None:
    workflow = _config()["workflow"]

    assert "test_quality_review" not in workflow


def test_local_workflow_uses_only_targeted_tests_and_staged_hygiene() -> None:
    workflow = _config()["workflow"]

    assert workflow["test_command"] == "bash tools/run-targeted-tests.sh"
    assert workflow["completion_command"] == "pre-commit run"
    assert workflow["lint_command"] == "pre-commit run"
    assert workflow["format_command"] == "pre-commit run"
    assert all(
        "--all-files" not in workflow[key]
        for key in (
            "test_command",
            "completion_command",
            "lint_command",
            "format_command",
        )
    )


def test_targeted_test_helper_has_no_full_suite_fallback() -> None:
    helper = (ROOT / "tools/run-targeted-tests.sh").read_text(encoding="utf-8")

    assert 'exec uv run pytest "$@"' in helper
    assert "No changed test files found." in helper
    assert 'uv run pytest "${python_tests[@]}"' in helper
    assert "uv run pytest -n" not in helper


def test_appliance_delivery_paths_have_ground_control_boundary_owners() -> None:
    boundaries = _config()["grc"]["boundaries"]
    paths_by_key = {entry["key"]: set(entry["paths"]) for entry in boundaries}

    assert "src/aptl/appliance/**" in paths_by_key["host-boundary"]
    assert "appliance/guest/**" in paths_by_key["host-boundary"]
    assert "src/aptl/workbench/**" in paths_by_key["mcp-control-plane"]
