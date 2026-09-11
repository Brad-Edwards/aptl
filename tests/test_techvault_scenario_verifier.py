"""TechVault answer-key tests for the scenario adapter package."""

from __future__ import annotations

from types import SimpleNamespace

from aptl.backends.identity import BackendIdentity
from aptl.validation.scenario_verification import (
    ScenarioIdentity,
    VerificationContext,
    VerificationStatus,
)
from aptl_techvault import verification as plugin


class _Operations:
    def __init__(
        self,
        targets=(("aptl-webapp", "172.20.1.10"),),
        *,
        reached: bool = True,
    ) -> None:
        self.executed: list[tuple[str, tuple[str, ...], int]] = []
        self.targets = targets
        self.reached = reached

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



def _context(operations: object | None = None) -> VerificationContext:
    return VerificationContext(
        run_id="run",
        attempt_id="attempt",
        # This file tests what `run()` does, and `run()` reads neither identity
        # -- admission is discovery's job. So the context carries a deliberately
        # synthetic identity rather than the plugin's own declaration: binding a
        # declared digest to the pack APTL admits is proved against
        # `env_pack_bundle()` in tests/test_plugin_pack_compatibility.py, never
        # by asserting a constant against itself.
        scenario=ScenarioIdentity(
            identity="techvault",
            version="0.0.0-test",
            source_kind="env-pack",
            content_digest="sha256:" + "0" * 64,
        ),
        backend=BackendIdentity(
            target_name="aptl",
            target_version="0.0.0-test",
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


def test_every_qualified_pair_is_declared_whole() -> None:
    """A release admits pairs, so no pair may be assembled from parts.

    The values themselves are not the subject here -- what they must equal is
    the admitted pack, proved in tests/test_plugin_pack_compatibility.py against
    `env_pack_bundle()`. What this asserts is the shape that makes the claim
    honest: every declared pair is complete in every dimension, and the pack
    content is identical across them, so no combination is admitted that the
    release did not qualify as a whole.
    """

    targets = plugin.TechVaultVerifier().qualified_targets

    assert targets, "an empty declaration qualifies nothing"
    assert len({target.scenario for target in targets}) == 1
    for target in targets:
        assert target.scenario.identity == "techvault"
        assert target.scenario.source_kind == "env-pack"
        assert target.scenario.version
        assert target.scenario.content_digest.startswith("sha256:")
        assert target.backend.target_name == "aptl"
        assert target.backend.target_version
        assert target.backend.profile == "full-remote-control-plane"
        # Transport is the one dimension that varies, and it varies as a whole
        # pair rather than as a second list crossed with the first.
        assert target.backend.provider == target.backend.transport
    assert {target.backend.provider for target in targets} == {
        "docker-compose",
        "ssh-compose",
    }


def test_the_answer_key_names_the_attacker_and_generates_nothing() -> None:
    """The adapter reports on the range; it does not act on it.

    The removed detection check drove nmap and failed SSH authentication, whose
    alerts and sensor records outlived the run. Asserting the empty argv list is
    the guard: reintroducing any activity in this adapter fails here.
    """

    operations = _Operations()

    report = plugin.TechVaultVerifier().run(_context(operations))

    assert report.status is VerificationStatus.PASSED
    assert {check.check_id for check in report.checks} == {"attacker-reachability"}
    assert operations.executed == []


def test_failed_attacker_reachability_produces_a_failed_verdict() -> None:
    operations = _Operations(reached=False)

    report = plugin.TechVaultVerifier().run(_context(operations))

    assert report.status is VerificationStatus.FAILED
    assert {check.check_id for check in report.failures()} == {"attacker-reachability"}


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
