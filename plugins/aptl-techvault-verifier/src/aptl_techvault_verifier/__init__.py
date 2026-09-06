"""Semantic verification for TechVault on the APTL backend.

This package holds the answer keys: which node is the attacker, what the
defensive stack is, and what counts as proof that a detection traversed it. That
knowledge is about one scenario on one backend, so it lives here rather than in
APTL core, which must serve any scenario.

What is deliberately *not* here: bounded polling windows, re-driving a trigger
while its window is open, collector credentials, and backend access. Those are
scenario-agnostic framework responsibilities. Selecting the attacker, target
priority, activity, and correlation rule is the scenario/backend answer key and
therefore stays here.

The verifier declares what it is written for and is refused when the running
range is not that — it never inspects the process to decide for itself whether it
applies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aptl.validation.scenario_verification import (
    EXTENSION_API_VERSION,
    PrerequisiteResult,
    PrerequisiteStatus,
    VerificationCheck,
    VerificationReport,
    VerificationStatus,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aptl.validation.scenario_verification import VerificationContext

__version__ = "0.1.0"

# Exact content identity of raes-env-packs 4.0.2's TechVault 0.1.0 pack.  A
# verifier update must deliberately admit a changed pack; an empty claim is not
# a wildcard for future scenario content.
TECHVAULT_PACK_SET_DIGEST = (
    "sha256:f1c807f70540ca68c640cde72e8b5606b928f4ec40cc00a44d7fd37d6bbfd55f"
)

#: The attacker node. TechVault's whole premise is that traffic originates here.
ATTACKER_NODE = "aptl-kali"

#: The SIEM every log forwarder in the scenario ships to.
SIEM_NODE = "aptl-wazuh-manager"

#: The network sensor whose EVE output feeds the SIEM.
SENSOR_NODE = "aptl-suricata"

_CORRELATION_IDENTITY = "aptl-live-gate-invalid"
_MAX_EVENT_TARGETS = 3


class TechVaultVerifier(object):
    """Verifies that TechVault's defensive stack observed the attack.

    Structural questions — is every admitted node running, does the realized
    graph match the plan — are core's and are not repeated here. This asks the
    one question core cannot: given that the range is up, did an attack from the
    attacker node produce evidence in the defensive stack.
    """

    plugin_id = "techvault"
    extension_api_version = EXTENSION_API_VERSION
    scenario_identity = "techvault"
    scenario_source_kinds = ("env-pack",)
    scenario_versions = ("0.1.0",)
    scenario_content_digests = (TECHVAULT_PACK_SET_DIGEST,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles: tuple[str, ...] = ("full-remote-control-plane",)
    backend_providers = ("docker-compose", "ssh-compose")
    backend_transports = ("docker-compose", "ssh-compose")

    def run(self, context: "VerificationContext") -> VerificationReport:
        """Evaluate TechVault's semantic expectations against the live range."""

        prerequisites = self._prerequisites(context)
        unmet = [p for p in prerequisites if not p.satisfied]
        if unmet:
            # A prerequisite that does not hold means no verdict was possible,
            # which is blocked. Reporting it as a detection failure would blame
            # the defensive stack for the harness not being ready.
            return VerificationReport(
                status=VerificationStatus.BLOCKED,
                scenario=context.scenario,
                backend=context.backend,
                run_id=context.run_id,
                attempt_id=context.attempt_id,
                plugin_id=self.plugin_id,
                prerequisites=tuple(prerequisites),
                diagnostics=tuple(
                    f"prerequisite {p.prerequisite_id} not satisfied" for p in unmet
                ),
            )

        checks = self._checks(context)
        failed = any(c.status is VerificationStatus.FAILED for c in checks)
        return VerificationReport(
            status=VerificationStatus.FAILED if failed else VerificationStatus.PASSED,
            scenario=context.scenario,
            backend=context.backend,
            run_id=context.run_id,
            attempt_id=context.attempt_id,
            plugin_id=self.plugin_id,
            prerequisites=tuple(prerequisites),
            checks=tuple(checks),
        )

    def _prerequisites(
        self, context: "VerificationContext"
    ) -> list[PrerequisiteResult]:
        """Return whether the pieces this scenario's verdict depends on are present.

        Read from the framework's observations rather than probed here: core
        already established what is running while booting, and re-deriving it
        would let the two disagree.
        """

        realized = {
            str(name) for name in (context.observations.get("containers") or ())
        }
        results = []
        for node, prerequisite_id in (
            (ATTACKER_NODE, "attacker-present"),
            (SIEM_NODE, "siem-present"),
            (SENSOR_NODE, "sensor-present"),
        ):
            present = node in realized
            results.append(
                PrerequisiteResult(
                    prerequisite_id=prerequisite_id,
                    status=(
                        PrerequisiteStatus.SATISFIED
                        if present
                        else PrerequisiteStatus.UNSATISFIED
                    ),
                    diagnostic=""
                    if present
                    else f"{node} is not in the realized range",
                )
            )
        if context.operations is None:
            results.append(
                PrerequisiteResult(
                    prerequisite_id="operations-surface",
                    status=PrerequisiteStatus.UNSATISFIED,
                    diagnostic="the core verification capability surface is unavailable",
                )
            )
        elif not context.operations.shared_network_targets(ATTACKER_NODE):
            results.append(
                PrerequisiteResult(
                    prerequisite_id="shared-network-target",
                    status=PrerequisiteStatus.UNSATISFIED,
                    diagnostic="the attacker has no admitted shared-network target",
                )
            )
        return results

    def _checks(self, context: "VerificationContext") -> list[VerificationCheck]:
        """Return the semantic verdicts for this scenario.

        Both checks name the attacker node -- the one scenario constant -- and
        ask the operations surface a scenario-neutral question. The framework
        owns how a host is reached, how the window is polled, and how evidence is
        captured; this owns which node attacks and what proves the SOC saw it.
        """

        operations = context.operations
        assert operations is not None

        checks: list[VerificationCheck] = []

        reachability = operations.reachability_from(ATTACKER_NODE)
        checks.append(
            VerificationCheck(
                check_id="attacker-reachability",
                status=(
                    VerificationStatus.PASSED
                    if reachability.reached
                    else VerificationStatus.FAILED
                ),
                diagnostic=(
                    "the attacker node reaches every host on its shared networks"
                    if reachability.reached
                    else "; ".join(reachability.diagnostics)
                ),
                category="kali_reachability",
            )
        )

        targets = operations.shared_network_targets(ATTACKER_NODE)
        detection = operations.collect_evidence(
            trigger=lambda: self._generate_event(operations, targets),
            alert_matches=self._matches_alert,
            deadline_monotonic=context.deadline_monotonic,
            poll_interval_seconds=context.poll_interval_seconds,
        )
        checks.append(
            VerificationCheck(
                check_id="detection-traversal",
                status=(
                    VerificationStatus.PASSED
                    if detection.observed
                    else VerificationStatus.FAILED
                ),
                diagnostic=(
                    "attack traffic from the attacker node produced defensive-stack "
                    "evidence within the window"
                    if detection.observed
                    else "; ".join(detection.diagnostics)
                    or "no defensive-stack evidence within the window"
                ),
                category="evidence_capture",
            )
        )
        return checks

    @staticmethod
    def _generate_event(
        operations: object, targets: tuple[tuple[str, str], ...]
    ) -> None:
        """Drive the TechVault attack trigger through core's bounded capability."""

        if not targets:
            return
        first_ip = targets[0][1]
        operations.execute_in_node(
            ATTACKER_NODE,
            ("nmap", "-Pn", "-T4", "-p", "22,80,443,445", first_ip),
            timeout_seconds=120,
        )
        listening = [
            target
            for target in targets
            if operations.tcp_reachable_from(ATTACKER_NODE, target[1], 22)
        ]
        remaining = [target for target in targets if target not in listening]
        for _name, address in (listening + remaining)[:_MAX_EVENT_TARGETS]:
            for _attempt in range(3):
                operations.execute_in_node(
                    ATTACKER_NODE,
                    (
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "ConnectTimeout=3",
                        "-p",
                        "22",
                        f"{_CORRELATION_IDENTITY}@{address}",
                        "true",
                    ),
                    timeout_seconds=15,
                )

    @staticmethod
    def _matches_alert(alert: object) -> bool:
        """Match the bounded identity emitted by the TechVault trigger."""

        return (
            isinstance(alert, dict)
            and isinstance(alert.get("rule"), dict)
            and any(
                _CORRELATION_IDENTITY in value
                for value in TechVaultVerifier._nested_strings(alert)
            )
        )

    @staticmethod
    def _nested_strings(value: object) -> list[str]:
        """Collect string leaves from one JSON-like alert."""

        strings: list[str] = []
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            for nested in value.values():
                strings.extend(TechVaultVerifier._nested_strings(nested))
        elif isinstance(value, list):
            for nested in value:
                strings.extend(TechVaultVerifier._nested_strings(nested))
        return strings


#: The entry-point target. A module-level instance keeps loading side-effect
#: free: constructing it does nothing but bind constants.
verifier = TechVaultVerifier()

__all__ = [
    "ATTACKER_NODE",
    "SENSOR_NODE",
    "SIEM_NODE",
    "TECHVAULT_PACK_SET_DIGEST",
    "TechVaultVerifier",
    "verifier",
]
