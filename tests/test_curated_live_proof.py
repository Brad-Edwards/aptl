"""Fast tests for the generic live-surface comparison helpers."""

from pathlib import Path
import tempfile

from aptl.core.config import AptlConfig
from aptl.validation.curated_live_proof import (
    ExpectedMatrix,
    compare_to_snapshot,
    expected_reduced_matrix,
    summarize_snapshot,
)
from tests.helpers import techvault_scenario_bundle

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUNDLE = techvault_scenario_bundle(Path(tempfile.mkdtemp(prefix="aptl-matrix-")))


def _matrix() -> ExpectedMatrix:
    return ExpectedMatrix(
        scenario="example",
        selected_profiles=("otel",),
        realized_nodes=("collector",),
        expected_services=("otel-collector",),
        expected_networks=("aptl-security",),
        service_aliases={"otel-collector": frozenset({"otel-collector"})},
        network_aliases={"aptl-security": frozenset({"aptl-security"})},
    )


def _snapshot() -> dict:
    return {
        "containers": [{"name": "otel-collector", "status": "Up 1 minute"}],
        "networks": [{"name": "aptl-security"}],
    }


def test_expected_matrix_uses_acquired_bundle_root():
    matrix = expected_reduced_matrix(
        PROJECT_ROOT, AptlConfig(), BUNDLE.sdl_path, bundle=BUNDLE
    )
    assert matrix.scenario == "techvault.sdl.yaml"
    assert matrix.realized_nodes
    assert matrix.selected_profiles
    assert matrix.expected_services


def test_compare_passes_matching_snapshot():
    assert compare_to_snapshot(_matrix(), _snapshot()) == (True, [])


def test_compare_reports_missing_and_unexpected_container():
    snapshot = _snapshot()
    snapshot["containers"] = [{"name": "other", "status": "Up 1 minute"}]
    ok, diagnostics = compare_to_snapshot(_matrix(), snapshot)
    assert not ok
    assert any("has no running container" in item for item in diagnostics)
    assert any("unexpected steady-state container" in item for item in diagnostics)


def test_compare_reports_missing_and_unexpected_network():
    snapshot = _snapshot()
    snapshot["networks"] = [{"name": "other"}]
    ok, diagnostics = compare_to_snapshot(_matrix(), snapshot)
    assert not ok
    assert any("expected network" in item and "absent" in item for item in diagnostics)
    assert any("unexpected network" in item for item in diagnostics)


def test_compare_ignores_exited_one_shot_container():
    snapshot = _snapshot()
    snapshot["containers"].append({"name": "seed", "status": "Exited (0)"})
    assert compare_to_snapshot(_matrix(), snapshot) == (True, [])


def test_summarize_snapshot_trims_labels_and_keeps_surface():
    snapshot = {
        "timestamp": "2026-06-24T00:00:00+00:00",
        "containers": [
            {
                "name": "otel-collector",
                "image": "otel/collector:1",
                "status": "Up 1m",
                "health": "healthy",
                "networks": {"aptl-security": "172.20.0.53"},
                "ports": ["127.0.0.1:4317->4317/tcp"],
                "labels": {"private": "value"},
            }
        ],
        "networks": [
            {
                "name": "aptl-security",
                "subnet": "172.20.0.0/24",
                "gateway": "172.20.0.1",
                "containers": ["otel-collector"],
            }
        ],
    }
    summary = summarize_snapshot(snapshot)
    assert "labels" not in summary["containers"][0]
    assert summary["containers"][0]["health"] == "healthy"
    assert summary["networks"][0]["subnet"] == "172.20.0.0/24"
