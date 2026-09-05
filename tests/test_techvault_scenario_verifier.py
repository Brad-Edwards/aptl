"""TechVault answer-key tests for the separately built verifier package."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
from types import SimpleNamespace

from aptl.backends.identity import BackendIdentity
from aptl.validation.scenario_verification import (
    ScenarioIdentity,
    VerificationContext,
    VerificationStatus,
)

PLUGIN_SRC = (
    Path(__file__).resolve().parents[1] / "plugins" / "aptl-techvault-verifier" / "src"
)
sys.path.insert(0, str(PLUGIN_SRC))
plugin = importlib.import_module("aptl_techvault_verifier")


class _Operations:
    def __init__(
        self,
        targets=(("aptl-webapp", "172.20.1.10"),),
        *,
        reached: bool = True,
        observed: bool = True,
    ) -> None:
        self.executed: list[tuple[str, tuple[str, ...], int]] = []
        self.targets = targets
        self.reached = reached
        self.observed = observed
        self.nonmatching_alert_rejected = False

    def reachability_from(self, origin: str) -> object:
        return SimpleNamespace(
            reached=self.reached,
            diagnostics=() if self.reached else ("unreachable",),
        )

    def shared_network_targets(self, origin: str) -> tuple[tuple[str, str], ...]:
        return self.targets

    def tcp_reachable_from(self, origin: str, address: str, port: int) -> bool:
        return port == 22

    def execute_in_node(
        self, origin: str, argv: tuple[str, ...], *, timeout_seconds: int
    ) -> bool:
        self.executed.append((origin, argv, timeout_seconds))
        return True

    def collect_evidence(self, **kwargs: object) -> object:
        trigger = kwargs["trigger"]
        alert_matches = kwargs["alert_matches"]
        trigger()
        assert alert_matches(
            {"rule": {"id": "5710"}, "full_log": "aptl-live-gate-invalid"}
        )
        self.nonmatching_alert_rejected = not alert_matches(
            {"rule": {"id": "1002"}, "full_log": "unrelated"}
        )
        return SimpleNamespace(
            observed=self.observed,
            diagnostics=() if self.observed else ("not observed",),
        )


def _context(operations: object | None = None) -> VerificationContext:
    return VerificationContext(
        run_id="run",
        attempt_id="attempt",
        scenario=ScenarioIdentity(
            identity="techvault",
            version="0.1.0",
            source_kind="env-pack",
            content_digest=plugin.TECHVAULT_PACK_SET_DIGEST,
        ),
        backend=BackendIdentity(
            target_name="aptl",
            target_version="0.1.0",
            profile="full-remote-control-plane",
            provider="docker-compose",
            transport="docker-compose",
        ),
        deadline_monotonic=100.0,
        poll_interval_seconds=2.0,
        operations=operations,
        observations={
            "containers": (
                "aptl-kali",
                "aptl-wazuh-manager",
                "aptl-suricata",
            )
        },
    )


def test_verifier_declares_every_exact_compatibility_dimension() -> None:
    verifier = plugin.TechVaultVerifier()

    assert verifier.scenario_source_kinds == ("env-pack",)
    assert verifier.scenario_versions == ("0.1.0",)
    assert verifier.scenario_content_digests == (plugin.TECHVAULT_PACK_SET_DIGEST,)
    assert verifier.backend_target_versions == ("0.1.0",)
    assert verifier.backend_profiles == ("full-remote-control-plane",)
    assert verifier.backend_providers == ("docker-compose", "ssh-compose")
    assert verifier.backend_transports == ("docker-compose", "ssh-compose")


def test_answer_key_drives_activity_and_correlation_from_the_plugin() -> None:
    operations = _Operations()

    report = plugin.TechVaultVerifier().run(_context(operations))

    assert report.status is VerificationStatus.PASSED
    assert {check.check_id for check in report.checks} == {
        "attacker-reachability",
        "detection-traversal",
    }
    assert any(argv[0] == "nmap" for _, argv, _ in operations.executed)
    assert any(argv[0] == "ssh" for _, argv, _ in operations.executed)
    assert operations.nonmatching_alert_rejected is True


def test_failed_attacker_reachability_produces_a_failed_verdict() -> None:
    operations = _Operations(reached=False)

    report = plugin.TechVaultVerifier().run(_context(operations))

    assert report.status is VerificationStatus.FAILED
    assert {check.check_id for check in report.failures()} == {"attacker-reachability"}


def test_missing_correlated_evidence_produces_a_failed_verdict() -> None:
    operations = _Operations(observed=False)

    report = plugin.TechVaultVerifier().run(_context(operations))

    assert operations.nonmatching_alert_rejected is True
    assert report.status is VerificationStatus.FAILED
    assert {check.check_id for check in report.failures()} == {"detection-traversal"}


def test_missing_prerequisite_blocks_before_scenario_activity() -> None:
    operations = _Operations()
    context = _context(operations)
    context = VerificationContext(
        **{
            **context.__dict__,
            "observations": {"containers": ("aptl-kali",)},
        }
    )

    report = plugin.TechVaultVerifier().run(context)

    assert report.status is VerificationStatus.BLOCKED
    assert operations.executed == []
    assert report.checks == ()


def test_missing_admitted_target_blocks_before_scenario_activity() -> None:
    operations = _Operations(targets=())

    report = plugin.TechVaultVerifier().run(_context(operations))

    assert report.status is VerificationStatus.BLOCKED
    assert any(
        item.prerequisite_id == "shared-network-target" for item in report.prerequisites
    )
    assert operations.executed == []
