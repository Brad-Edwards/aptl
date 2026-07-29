"""Semantic verification for TechVault on the APTL backend.

This package holds the answer keys: which node is the attacker, what the
defensive stack is, and what counts as proof that a detection traversed it. That
knowledge is about one scenario on one backend, so it lives here rather than in
APTL core, which must serve any scenario.

What is deliberately *not* here: bounded polling windows, re-driving a trigger
while its window is open, and preferring probe targets that actually expose the
service being exercised. Those were fixed under #866 as scenario-agnostic
behaviour and remain framework. Copying them into this package would fork them,
and the copy would rot.

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

#: The attacker node. TechVault's whole premise is that traffic originates here.
ATTACKER_NODE = "aptl-kali"

#: The SIEM every log forwarder in the scenario ships to.
SIEM_NODE = "aptl-wazuh-manager"

#: The network sensor whose EVE output feeds the SIEM.
SENSOR_NODE = "aptl-suricata"


class TechVaultVerifier(object):
    """Verifies that TechVault's defensive stack observed the attack.

    Structural questions — is every admitted node running, does the realized
    graph match the plan — are core's and are not repeated here. This asks the
    one question core cannot: given that the range is up, did an attack from the
    attacker node produce evidence in the defensive stack.
    """

    plugin_id = "techvault-operational"
    extension_api_version = EXTENSION_API_VERSION
    scenario_identity = "techvault-operational"
    #: Empty: this verifier tracks the scenario as it evolves in-tree rather than
    #: pinning a digest that every scenario edit would invalidate. A verifier
    #: shipped independently of the scenario should pin, and the seam records
    #: which choice was made.
    scenario_content_digests: tuple[str, ...] = ()
    backend_target_name = "aptl"
    backend_profiles: tuple[str, ...] = ("full-remote-control-plane",)

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
                    diagnostic="" if present else f"{node} is not in the realized range",
                )
            )
        return results

    def _checks(self, context: "VerificationContext") -> list[VerificationCheck]:
        """Return the semantic verdicts for this scenario.

        The operations surface is scenario-neutral: this asks for detection
        evidence in a bounded window, and the framework owns how that window is
        polled and how evidence is captured.
        """

        operations = context.operations
        if operations is None:
            return [
                VerificationCheck(
                    check_id="detection-traversal",
                    status=VerificationStatus.FAILED,
                    diagnostic="no operations surface was provided to the verifier",
                )
            ]

        evidence = operations.detection_evidence(
            origin=ATTACKER_NODE, deadline_seconds=context.deadline_seconds
        )
        if evidence:
            return [
                VerificationCheck(
                    check_id="detection-traversal",
                    status=VerificationStatus.PASSED,
                    diagnostic=(
                        "attack traffic from the attacker node produced defensive-stack "
                        "evidence within the window"
                    ),
                )
            ]
        return [
            VerificationCheck(
                check_id="detection-traversal",
                status=VerificationStatus.FAILED,
                diagnostic=(
                    "no defensive-stack evidence for attack traffic from the attacker "
                    "node within the window"
                ),
            )
        ]


#: The entry-point target. A module-level instance keeps loading side-effect
#: free: constructing it does nothing but bind constants.
verifier = TechVaultVerifier()

__all__ = ["ATTACKER_NODE", "SENSOR_NODE", "SIEM_NODE", "TechVaultVerifier", "verifier"]
