"""Fast unit proof for the curated-variant live-proof matrix (#535).

These exercise ``aptl.validation.curated_live_proof`` without booting Docker:
each variant's model-derived ``ExpectedMatrix`` is asserted from the same ACES
realization the public start path uses, and ``compare_to_snapshot`` is checked
against synthetic snapshots for the match / missing-container / extra-container /
missing-network cases. The destructive live boot that records real evidence is
the manual, documented operator procedure in
``docs/aces/techvault-curated-live-validation-gate.md`` (not fast CI).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess

import pytest

from aptl.core.config import AptlConfig
from aptl.validation.curated_live_proof import (
    compare_to_snapshot,
    expected_reduced_matrix,
    run_participant_action_proof,
    summarize_snapshot,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"

# The always-on observability core every public start includes.
OTEL_SERVICES = frozenset({"aptl-grafana-otel", "aptl-otel-collector", "aptl-tempo"})


@dataclass(frozen=True)
class _Variant:
    catalog_id: str
    filename: str
    containers: dict[str, bool]
    expected_profiles: frozenset[str]
    # Compose services beyond the OTEL core the selected profiles must activate.
    extra_services: frozenset[str]
    expected_networks: frozenset[str]

    @property
    def config(self) -> AptlConfig:
        return AptlConfig(lab={"name": "techvault"}, containers=self.containers)

    @property
    def path(self) -> Path:
        return SCENARIOS_DIR / self.filename


VARIANTS = (
    _Variant(
        catalog_id="techvault-observability-core",
        filename="techvault-observability-core.sdl.yaml",
        containers={},
        expected_profiles=frozenset({"otel"}),
        extra_services=frozenset(),
        expected_networks=frozenset({"aptl-security"}),
    ),
    _Variant(
        catalog_id="techvault-defensive-min",
        filename="techvault-defensive-min.sdl.yaml",
        containers={"wazuh": True},
        expected_profiles=frozenset({"wazuh", "otel"}),
        extra_services=frozenset({"wazuh.manager", "wazuh.indexer", "wazuh.dashboard"}),
        expected_networks=frozenset({"aptl-security", "aptl-dmz", "aptl-internal"}),
    ),
    _Variant(
        catalog_id="techvault-enterprise-web",
        filename="techvault-enterprise-web.sdl.yaml",
        containers={"enterprise": True, "wazuh": True},
        expected_profiles=frozenset({"enterprise", "wazuh", "otel"}),
        # `--profile enterprise wazuh` activates the enterprise tier plus the
        # full wazuh profile (dashboard included, though the SDL declares only
        # manager + indexer): Compose activates services by profile, not by
        # declared ACES node.
        extra_services=frozenset(
            {
                "webapp",
                "db",
                "ad",
                "workstation",
                "wazuh.manager",
                "wazuh.indexer",
                "wazuh.dashboard",
            }
        ),
        expected_networks=frozenset({"aptl-security", "aptl-dmz", "aptl-internal"}),
    ),
    _Variant(
        catalog_id="techvault-attacker-target",
        filename="techvault-attacker-target.sdl.yaml",
        containers={"kali": True, "victim": True, "wazuh": True},
        expected_profiles=frozenset({"kali", "victim", "wazuh", "otel"}),
        extra_services=frozenset(
            {
                "kali",
                "kali-capture",
                "victim",
                "wazuh.manager",
                "wazuh.indexer",
                "wazuh.dashboard",
            }
        ),
        expected_networks=frozenset(
            {"aptl-security", "aptl-dmz", "aptl-internal", "aptl-redteam"}
        ),
    ),
)


def _good_snapshot(matrix) -> dict:
    """A snapshot whose running containers + networks match the matrix exactly."""
    return {
        "containers": [
            {"name": _container_name(service), "status": "Up 2 minutes"}
            for service in matrix.expected_services
        ],
        "networks": [
            {"name": f"aptl_{network}"} for network in matrix.expected_networks
        ],
    }


def _container_name(service: str) -> str:
    """Map a Compose service name to its running container name.

    `wazuh.manager` runs as `aptl-wazuh-manager`; the otel/enterprise services
    already carry their `aptl-`/bare container names. The normalized-alias bind
    in the comparison tolerates either, so a deterministic stand-in is enough.
    """
    if service.startswith("wazuh."):
        return "aptl-" + service.replace(".", "-")
    return service


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.catalog_id)
def test_expected_matrix_is_content_derived_and_reduced(variant: _Variant):
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)

    assert set(matrix.selected_profiles) == variant.expected_profiles
    assert matrix.realized_nodes  # realization produced ACES nodes
    services = set(matrix.expected_services)
    assert OTEL_SERVICES.issubset(services)
    assert variant.extra_services.issubset(services)
    assert set(matrix.expected_networks) == variant.expected_networks


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.catalog_id)
def test_compare_passes_on_matching_snapshot(variant: _Variant):
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)
    ok, diagnostics = compare_to_snapshot(matrix, _good_snapshot(matrix))
    assert ok, diagnostics


def test_compare_fails_on_missing_container():
    variant = VARIANTS[0]  # observability-core
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)
    snapshot = _good_snapshot(matrix)
    snapshot["containers"] = snapshot["containers"][:-1]
    ok, diagnostics = compare_to_snapshot(matrix, snapshot)
    assert not ok
    assert any("has no running container" in d for d in diagnostics)


def test_compare_fails_on_unexpected_container():
    variant = VARIANTS[0]
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)
    snapshot = _good_snapshot(matrix)
    snapshot["containers"].append({"name": "aptl-wazuh-manager", "status": "Up 1m"})
    ok, diagnostics = compare_to_snapshot(matrix, snapshot)
    assert not ok
    assert any("unexpected steady-state container" in d for d in diagnostics)


def test_compare_fails_on_unexpected_network():
    variant = VARIANTS[0]  # observability-core: only aptl-security expected
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)
    snapshot = _good_snapshot(matrix)
    snapshot["networks"].append({"name": "aptl_aptl-redteam"})
    ok, diagnostics = compare_to_snapshot(matrix, snapshot)
    assert not ok
    assert any("unexpected network" in d for d in diagnostics)


def test_compare_ignores_exited_one_shot_container():
    variant = VARIANTS[0]
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)
    snapshot = _good_snapshot(matrix)
    # An exited seed/one-shot task is not steady-state proof and must be ignored.
    snapshot["containers"].append(
        {"name": "aptl-soc-seed", "status": "Exited (0) 3s ago"}
    )
    ok, diagnostics = compare_to_snapshot(matrix, snapshot)
    assert ok, diagnostics


def test_compare_fails_on_missing_network():
    variant = VARIANTS[1]  # defensive-min (multiple networks)
    matrix = expected_reduced_matrix(PROJECT_ROOT, variant.config, variant.path)
    snapshot = _good_snapshot(matrix)
    snapshot["networks"] = snapshot["networks"][:-1]
    ok, diagnostics = compare_to_snapshot(matrix, snapshot)
    assert not ok
    assert any("expected network" in d and "absent" in d for d in diagnostics)


def test_summarize_snapshot_trims_labels_and_keeps_surface():
    snapshot = {
        "timestamp": "2026-06-24T00:00:00+00:00",
        "containers": [
            {
                "name": "aptl-otel-collector",
                "image": "otel/opentelemetry-collector-contrib:0.123.0",
                "status": "Up 1m (healthy)",
                "health": "healthy",
                "networks": {"aptl_aptl-security": "172.20.0.53"},
                "ports": ["127.0.0.1:4317->4317/tcp"],
                "labels": {"com.docker.compose.project": "aptl"},
            }
        ],
        "networks": [
            {
                "name": "aptl_aptl-security",
                "subnet": "172.20.0.0/24",
                "gateway": "172.20.0.1",
                "containers": ["aptl-otel-collector"],
            }
        ],
    }
    summary = summarize_snapshot(snapshot)
    assert summary["timestamp"] == "2026-06-24T00:00:00+00:00"
    assert "labels" not in summary["containers"][0]
    assert summary["containers"][0]["health"] == "healthy"
    assert summary["containers"][0]["ports"] == ["127.0.0.1:4317->4317/tcp"]
    assert summary["networks"][0]["subnet"] == "172.20.0.0/24"


def test_variants_yield_distinct_reduced_surfaces():
    """Anti-collapse: each variant realizes a distinct selected profile set."""
    profile_sets = {
        frozenset(
            expected_reduced_matrix(PROJECT_ROOT, v.config, v.path).selected_profiles
        )
        for v in VARIANTS
    }
    assert len(profile_sets) == len(VARIANTS)


def test_participant_action_proof_uses_control_plane_and_records_behavior(
    monkeypatch,
    tmp_path,
):
    from aptl.backends.aces_participant_runtime import PARTICIPANT_ACTION_ADDRESS
    from aptl.validation import curated_live_proof

    class FakeBackend:
        def container_exec(self, name, cmd, *, timeout=None):
            self.call = (name, cmd, timeout)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="Host: 172.20.2.20 () Ports: 22/open/tcp//ssh///",
                stderr="",
            )

    class FakeRangeSnapshot:
        def to_dict(self):
            return {
                "timestamp": "2026-06-25T00:00:00+00:00",
                "containers": [
                    {
                        "name": "aptl-kali",
                        "image": "kalilinux/kali-rolling",
                        "status": "Up 1m",
                        "health": None,
                        "networks": {"aptl_aptl-redteam": "172.20.4.10"},
                        "ports": [],
                    },
                    {
                        "name": "aptl-victim",
                        "image": "aptl/victim",
                        "status": "Up 1m",
                        "health": "healthy",
                        "networks": {"aptl_aptl-internal": "172.20.2.20"},
                        "ports": [],
                    },
                ],
                "networks": [
                    {
                        "name": "aptl_aptl-redteam",
                        "subnet": "172.20.4.0/24",
                        "gateway": "172.20.4.1",
                        "containers": ["aptl-kali"],
                    }
                ],
            }

    backend = FakeBackend()
    monkeypatch.setattr(curated_live_proof, "get_backend", lambda config, root: backend)
    monkeypatch.setattr(
        curated_live_proof,
        "capture_snapshot",
        lambda config_dir, backend: FakeRangeSnapshot(),
    )

    proof = run_participant_action_proof(
        tmp_path,
        AptlConfig(
            lab={"name": "techvault"}, containers={"kali": True, "victim": True}
        ),
    )

    assert proof["verdict"] == "PASS", proof["validation"]
    assert proof["operation_status"]["state"] == "succeeded"
    assert proof["operation_receipt_contract"] == "operation-receipt-v1"
    assert proof["runtime_snapshot_contract"] == "runtime-snapshot-v1"
    assert backend.call == (
        "aptl-kali",
        ["nmap", "-p", "22", "-Pn", "--open", "172.20.2.20", "-oG", "-"],
        120,
    )
    assert PARTICIPANT_ACTION_ADDRESS in proof["participant_episode_results"]
    behavior = proof["participant_behavior_history"][PARTICIPANT_ACTION_ADDRESS]
    assert [event["event_type"] for event in behavior] == [
        "action_attempted",
        "observation_emitted",
    ]
    assert behavior[-1]["actor_provenance"] == "codex-cli"
    assert any(
        address.startswith("participant.techvault.kali-victim-ssh-probe.")
        for address in proof["participant_snapshot_entries"]
    )
    assert proof["post_action_range_snapshot"]["containers"][0]["name"] == "aptl-kali"
