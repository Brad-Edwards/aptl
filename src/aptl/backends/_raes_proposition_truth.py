"""Project portable proposition-truth results for observed-state assertions.

ADR-069 §3 assigns the backend evaluator the job of projecting objective,
proposition, and terminal-condition facts into ACES evaluation results. APTL's
first concrete slice (issue #889) is the ADR-088 service-materialization
readback: a boolean observed-state postcondition whose evidence is the fresh
native readback the materializer already proved and disclosed into the runtime
snapshot as the ``service_materialization`` concern.

APTL projects a ``proposition-truth-result/v1`` envelope for an assertion **only
when it can genuinely corroborate it** — every subject of its proposition is an
observed content-placement carrying that realized concern. An assertion APTL
cannot observe (for example a participant/Wazuh-evidenced proposition on an
evidence channel APTL does not yet project from) gets no result: its truth is
left unresolved, never fabricated. This keeps the evaluator declaration honest —
APTL evaluates exactly the observed-state shape it actually observes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from raes_contracts.planning import EvaluationPlan
from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.backends.raes_manifest import APTL_RAES_TARGET_NAME, APTL_RAES_TARGET_VERSION
from aptl.backends.raes_service_index_schema import INTERFACE_PROFILE

_OBSERVED_STATE = "observed_state"
_CONTENT_PLACEMENT = "content-placement"
_TRUE = "true"
_FALSE = "false"
_POSITIVE = "positive"

# Provenance of the probe that decided an observed-state truth: APTL's native
# service-search-index-schema readback implementation and the capability it
# claims. Binds the decided truth to the exact backend implementation + digest.
_READBACK_IMPLEMENTATION_ID = "aptl.service-search-index-schema-readback"
_SERVICE_INDEX_SCHEMA_CAPABILITY = "service-search-index-schema-v1"
_BACKEND_MANIFEST_REF = f"{APTL_RAES_TARGET_NAME}@{APTL_RAES_TARGET_VERSION}"
# APTL's readback occurs in scenario time (matching the evaluator's declared
# supported_time_domains); the backend manifest is the clock authority.
_TIME_DOMAIN = "scenario_time"


def _invert(outcome: str) -> str:
    if outcome == _TRUE:
        return _FALSE
    if outcome == _FALSE:
        return _TRUE
    return outcome


def _service_content_subject_outcome(
    subjects: tuple[str, ...],
    snapshot: RuntimeSnapshot,
) -> tuple[str, str, str] | None:
    """Return ``(outcome, field_schema_digest, boundary_ref)`` or ``None``.

    ``None`` means APTL cannot observe this proposition (not every subject is an
    observed content-placement bearing the exact ``service_materialization``
    concern), so no truth is projected. Otherwise every subject was corroborated
    by the materializer's readback (SEM-218: the concern is present only after a
    fresh native readback proved it); the digest binds the decided truth to the
    exact observed portable field schema, and the boundary is the participant
    observation boundary the concern was projected through.
    """

    if not subjects:
        return None
    digest = ""
    boundary_ref = ""
    for subject in subjects:
        entry = snapshot.entries.get(subject)
        if entry is None or entry.resource_type != _CONTENT_PLACEMENT:
            return None
        payload = entry.payload if isinstance(entry.payload, Mapping) else {}
        binding = payload.get("service_materialization")
        if not isinstance(binding, Mapping):
            return None
        if binding.get("interface_profile") != INTERFACE_PROFILE:
            return None
        subject_digest = binding.get("canonical_field_schema_digest")
        if not isinstance(subject_digest, str) or not subject_digest:
            return None
        boundaries = _string_tuple(binding.get("observation_boundary_addresses"))
        if not boundaries:
            return None
        digest = subject_digest
        boundary_ref = boundaries[0]
    return _TRUE, digest, boundary_ref


def _string_tuple(raw: object) -> tuple[str, ...]:
    if isinstance(raw, str):
        return (raw,) if raw else ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(v) for v in raw if str(v))
    return ()


def project_proposition_truth_results(
    plan: EvaluationPlan,
    snapshot: RuntimeSnapshot,
) -> dict[str, dict[str, Any]]:
    """Project truth-result envelopes APTL can corroborate, keyed by assertion.

    Each result key equals its ``assertion_address`` (the RAES truth-result
    contract requires it).
    """

    propositions: dict[str, Mapping[str, Any]] = {}
    assertions: dict[str, Mapping[str, Any]] = {}
    for op in plan.actionable_operations:
        if op.resource_type == "proposition" and isinstance(op.payload, Mapping):
            propositions[op.address] = op.payload
        elif op.resource_type == "assertion" and isinstance(op.payload, Mapping):
            assertions[op.address] = op.payload

    results: dict[str, dict[str, Any]] = {}
    for assertion_address, apayload in assertions.items():
        proposition_address = apayload.get("proposition_address")
        ppayload = propositions.get(proposition_address) if isinstance(proposition_address, str) else None
        if ppayload is None or ppayload.get("evaluation_basis") != _OBSERVED_STATE:
            continue
        corroborated = _service_content_subject_outcome(
            _string_tuple(ppayload.get("subject_addresses")), snapshot
        )
        if corroborated is None:
            continue
        outcome, field_schema_digest, boundary_ref = corroborated
        polarity = apayload.get("polarity", _POSITIVE)
        polarity = polarity if polarity in (_POSITIVE, "negative") else _POSITIVE
        assertion_outcome = outcome if polarity == _POSITIVE else _invert(outcome)
        evidence_refs = _string_tuple(ppayload.get("evidence_requirement_refs"))
        result: dict[str, Any] = {
            "schema_version": "proposition-truth-result/v1",
            "result_id": f"aptl:{assertion_address}",
            "proposition_address": proposition_address,
            "assertion_address": assertion_address,
            "assertion_polarity": polarity,
            "proposition_outcome": outcome,
            "assertion_outcome": assertion_outcome,
            "evaluation_basis": _OBSERVED_STATE,
            "probe_binding": {
                "binding_id": f"aptl:{assertion_address}",
                "implementation_id": _READBACK_IMPLEMENTATION_ID,
                "implementation_version": APTL_RAES_TARGET_VERSION,
                "artifact_digest": field_schema_digest,
                "backend_manifest_ref": _BACKEND_MANIFEST_REF,
                "proposition_address": proposition_address,
                "capability_refs": [_SERVICE_INDEX_SCHEMA_CAPABILITY],
            },
            "temporal_context": {
                "boundary_ref": boundary_ref,
                "time_domain": _TIME_DOMAIN,
                "clock_authority": _BACKEND_MANIFEST_REF,
            },
        }
        if evidence_refs:
            result["evidence_refs"] = list(evidence_refs)
        results[assertion_address] = result
    return results
