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

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aptl.validation._live_gate_operations import ProductApiEndpoint
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

#: The seeded automation whose product-issued execution identity is also used
#: to correlate the worker/app runtime children admitted by APTL #974.
ALERT_TO_CASE_WORKFLOW = "APTL Alert to Case"

_AUTOMATION_API = ProductApiEndpoint(
    credential_name="SHUFFLE_API_KEY",
    port_name="APTL_HP_SHUFFLE_FRONTEND_443",
    default_port=3443,
)
_CASE_API = ProductApiEndpoint(
    credential_name="THEHIVE_API_KEY",
    port_name="APTL_HP_THEHIVE_9000",
    default_port=9000,
)


@dataclass(frozen=True)
class _WorkflowCheckpoint(object):
    """Product-observed workflow state captured before the trusted trigger."""

    workflow_id: str = ""
    existing_execution_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class _WorkflowExecutionEvidence(object):
    """Bounded post-trigger workflow and correlated-case observations."""

    execution_id: str = ""
    status: str = ""
    action_statuses: tuple[str, ...] = ()
    correlated_case_count: int = 0
    diagnostics: tuple[str, ...] = ()


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
                    diagnostic=""
                    if present
                    else f"{node} is not in the realized range",
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
        if operations is None:
            return [
                VerificationCheck(
                    check_id="detection-traversal",
                    status=VerificationStatus.FAILED,
                    diagnostic="no operations surface was provided to the verifier",
                )
            ]

        checks: list[VerificationCheck] = []

        workflow_checkpoint = self._workflow_checkpoint(operations)

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
            )
        )

        detection = operations.detection_evidence(
            ATTACKER_NODE, SENSOR_NODE, context.deadline_seconds
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
            )
        )
        workflow = self._await_workflow_case_evidence(
            operations,
            workflow_checkpoint,
            detection.correlation_marker,
            context.deadline_seconds,
        )
        terminal_success = workflow.status == "FINISHED"
        checks.append(
            VerificationCheck(
                check_id="workflow-terminal-success",
                status=(
                    VerificationStatus.PASSED
                    if terminal_success
                    else VerificationStatus.FAILED
                ),
                diagnostic=(
                    "the correlated alert-to-case workflow finished successfully"
                    if terminal_success
                    else "; ".join(workflow.diagnostics)
                    or f"workflow terminated with status {workflow.status!r}"
                ),
            )
        )
        action_results_succeeded = bool(workflow.action_statuses) and all(
            status == "SUCCESS" for status in workflow.action_statuses
        )
        checks.append(
            VerificationCheck(
                check_id="workflow-action-results",
                status=(
                    VerificationStatus.PASSED
                    if action_results_succeeded
                    else VerificationStatus.FAILED
                ),
                diagnostic=(
                    "the workflow returned non-empty successful action results"
                    if action_results_succeeded
                    else "the workflow returned no complete successful action results"
                ),
            )
        )
        one_case = workflow.correlated_case_count == 1
        checks.append(
            VerificationCheck(
                check_id="workflow-case-correlation",
                status=(
                    VerificationStatus.PASSED if one_case else VerificationStatus.FAILED
                ),
                diagnostic=(
                    "exactly one case carries the trigger correlation marker"
                    if one_case
                    else "the trigger did not produce exactly one correlated case"
                ),
            )
        )
        return checks

    def _workflow_checkpoint(self, operations: object) -> _WorkflowCheckpoint:
        """Capture the selected automation and its pre-trigger executions."""

        payload = operations.product_json(_AUTOMATION_API, "/api/v1/workflows")
        matches = [
            item
            for item in _response_items(payload)
            if str(item.get("name", "")) == ALERT_TO_CASE_WORKFLOW
            and _bounded_identity(item.get("id"))
        ]
        if len(matches) != 1:
            return _WorkflowCheckpoint(
                diagnostics=("the selected workflow is missing or ambiguous",)
            )
        workflow_id = str(matches[0]["id"])
        executions = operations.product_json(
            _AUTOMATION_API,
            f"/api/v1/workflows/{workflow_id}/executions",
        )
        if executions is None:
            return _WorkflowCheckpoint(
                diagnostics=("the workflow execution baseline is unavailable",)
            )
        return _WorkflowCheckpoint(
            workflow_id=workflow_id,
            existing_execution_ids=tuple(
                sorted(
                    identity
                    for item in _response_items(executions)
                    if (identity := _execution_id(item)) is not None
                )
            ),
        )

    def _await_workflow_case_evidence(
        self,
        operations: object,
        checkpoint: _WorkflowCheckpoint,
        correlation_marker: str,
        deadline_seconds: int,
        *,
        sleep_fn=time.sleep,
    ) -> _WorkflowExecutionEvidence:
        """Observe one new correlated automation execution and one case."""

        if checkpoint.diagnostics:
            return _WorkflowExecutionEvidence(diagnostics=checkpoint.diagnostics)
        if not _bounded_identity(checkpoint.workflow_id) or not correlation_marker:
            return _WorkflowExecutionEvidence(
                diagnostics=("workflow correlation inputs are incomplete",)
            )

        deadline = time.monotonic() + max(1, deadline_seconds)
        baseline = set(checkpoint.existing_execution_ids)
        bound_execution_id = ""
        last_status = ""
        while time.monotonic() < deadline:
            executions = operations.product_json(
                _AUTOMATION_API,
                f"/api/v1/workflows/{checkpoint.workflow_id}/executions",
            )
            candidates: list[
                tuple[str, Mapping[str, object], Mapping[str, object]]
            ] = []
            for item in _response_items(executions):
                execution_id = _execution_id(item)
                if execution_id is None or execution_id in baseline:
                    continue
                result = operations.product_json(
                    _AUTOMATION_API,
                    "/api/v1/streams/results",
                    body={"execution_id": execution_id},
                    method="POST",
                )
                if not isinstance(result, Mapping):
                    continue
                if correlation_marker not in _canonical_json((item, result)):
                    continue
                candidates.append((execution_id, item, result))

            identities = {candidate[0] for candidate in candidates}
            if len(identities) > 1:
                return _WorkflowExecutionEvidence(
                    diagnostics=("several post-trigger workflow executions matched",)
                )
            if candidates:
                execution_id, _item, result = candidates[0]
                if not bound_execution_id:
                    try:
                        operations.bind_runtime_execution(execution_id)
                    except (AttributeError, TypeError, ValueError):
                        return _WorkflowExecutionEvidence(
                            execution_id=execution_id,
                            diagnostics=(
                                "the accepted workflow execution could not be bound "
                                "to one runtime authority",
                            ),
                        )
                    bound_execution_id = execution_id
                status = str(result.get("status", ""))
                last_status = status
                if status in {"FINISHED", "ABORTED", "FAILURE"}:
                    cases = operations.product_json(
                        _CASE_API,
                        "/api/v1/query",
                        body={
                            "query": [
                                {"_name": "listCase"},
                                {
                                    "_name": "sort",
                                    "_fields": [{"_createdAt": "desc"}],
                                },
                                {"_name": "page", "from": 0, "to": 100},
                            ]
                        },
                        method="POST",
                    )
                    correlated = [
                        item
                        for item in _response_items(cases)
                        if correlation_marker in _canonical_json(item)
                    ]
                    return _WorkflowExecutionEvidence(
                        execution_id=execution_id,
                        status=status,
                        action_statuses=_action_statuses(result.get("results")),
                        correlated_case_count=len(correlated),
                    )
            sleep_fn(min(5.0, max(0.0, deadline - time.monotonic())))

        return _WorkflowExecutionEvidence(
            execution_id=bound_execution_id,
            status=last_status,
            diagnostics=("no correlated workflow reached a terminal state in time",),
        )


def _response_items(payload: object) -> list[Mapping[str, object]]:
    """Return mapping items from a list or conventional data envelope."""

    raw = payload.get("data", []) if isinstance(payload, Mapping) else payload
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _bounded_identity(value: object) -> bool:
    """Whether an opaque product identifier is safe to retain in evidence."""

    text = str(value or "")
    return bool(
        text and len(text) <= 128 and text.replace("-", "").replace("_", "").isalnum()
    )


def _execution_id(item: Mapping[str, object]) -> str | None:
    """Return the product execution identity from either supported field."""

    value = item.get("execution_id") or item.get("id")
    return str(value) if _bounded_identity(value) else None


def _canonical_json(value: object) -> str:
    """Render JSON-like evidence deterministically for a bounded marker lookup."""

    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return ""


def _action_statuses(value: object) -> tuple[str, ...]:
    """Return only bounded action status strings from a terminal response."""

    if not isinstance(value, list):
        return ()
    return tuple(
        str(item.get("status", ""))[:32] for item in value if isinstance(item, Mapping)
    )


#: The entry-point target. A module-level instance keeps loading side-effect
#: free: constructing it does nothing but bind constants.
verifier = TechVaultVerifier()

__all__ = [
    "ALERT_TO_CASE_WORKFLOW",
    "ATTACKER_NODE",
    "SENSOR_NODE",
    "SIEM_NODE",
    "TechVaultVerifier",
    "verifier",
]
