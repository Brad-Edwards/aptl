"""Project portable proposition-truth results for observed-state assertions.

ADR-069 §3 assigns the backend evaluator the job of projecting objective,
proposition, and terminal-condition facts into ACES evaluation results. APTL's
first concrete slice (issue #889) is the ADR-088 service-materialization
readback: a boolean observed-state postcondition whose evidence is the fresh
native readback the materializer already proved and disclosed into the runtime
snapshot as the ``service_materialization`` concern.

APTL projects a ``proposition-truth-result/v1`` envelope for an assertion **only
when it can genuinely corroborate it**. That can be either the realized
``service_materialization`` concern or one of the three exact TechVault native
evidence records whose source adapter already proved the authored semantic
claim. An assertion APTL cannot observe gets no result: its truth is left
unresolved, never fabricated. This keeps the evaluator declaration honest —
APTL evaluates exactly the observed-state shapes it actually observes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from raes_contracts.contracts import ExperimentEvidenceRecordModel
from raes_contracts.planning import EvaluationPlan
from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.backends._raes_native_proposition_truth import (
    NATIVE_EVIDENCE_CAPABILITIES,
    native_evidence_result,
)
from aptl.backends.raes_manifest import APTL_RAES_TARGET_NAME, APTL_RAES_TARGET_VERSION
from aptl.backends.raes_service_index_schema import INTERFACE_PROFILE
from aptl.core.experiment.trial_plan import compute_source_set_digest

_OBSERVED_STATE = "observed_state"
_DECLARED_STATE = "declared_state"
_CONTENT_PLACEMENT = "content-placement"
_TRUE = "true"
_FALSE = "false"
_POSITIVE = "positive"
_TRUTH_RESULT_SCHEMA = "proposition-truth-result/v1"

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
    """Flip a ``true``/``false`` outcome string; any other value passes through."""

    if outcome == _TRUE:
        return _FALSE
    if outcome == _FALSE:
        return _TRUE
    return outcome


def _service_materialization_binding(
    subject: str, snapshot: RuntimeSnapshot
) -> Mapping[str, Any] | None:
    """Return ``subject``'s ``service_materialization`` binding if it is an observed
    content-placement bound to :data:`INTERFACE_PROFILE`, else ``None``.
    """

    entry = snapshot.entries.get(subject)
    if entry is None or entry.resource_type != _CONTENT_PLACEMENT:
        return None
    payload = entry.payload if isinstance(entry.payload, Mapping) else {}
    binding = payload.get("service_materialization")
    if (
        isinstance(binding, Mapping)
        and binding.get("interface_profile") == INTERFACE_PROFILE
    ):
        return binding
    return None


def _corroborated_subject(
    subject: str, snapshot: RuntimeSnapshot
) -> tuple[str, str] | None:
    """Return ``(field_schema_digest, boundary_ref)`` if ``subject`` is an observed
    content-placement corroborating the ``service_materialization`` concern, else
    ``None`` (APTL cannot observe this subject's proposition).
    """

    binding = _service_materialization_binding(subject, snapshot)
    if binding is None:
        return None
    digest = binding.get("canonical_field_schema_digest")
    boundaries = _string_tuple(binding.get("observation_boundary_addresses"))
    if not isinstance(digest, str) or not digest or not boundaries:
        return None
    return digest, boundaries[0]


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
        corroboration = _corroborated_subject(subject, snapshot)
        if corroboration is None:
            return None
        digest, boundary_ref = corroboration
    return _TRUE, digest, boundary_ref


def _string_tuple(raw: object) -> tuple[str, ...]:
    """Coerce a string or list/tuple of values into a tuple of non-empty strings."""

    if isinstance(raw, str):
        return (raw,) if raw else ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(v) for v in raw if str(v))
    return ()


def _split_plan_operations(
    plan: EvaluationPlan,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    """Split ``plan``'s actionable operations into propositions and assertions, keyed by address."""

    propositions: dict[str, Mapping[str, Any]] = {}
    assertions: dict[str, Mapping[str, Any]] = {}
    for op in plan.actionable_operations:
        if op.resource_type == "proposition" and isinstance(op.payload, Mapping):
            propositions[op.address] = op.payload
        elif op.resource_type == "assertion" and isinstance(op.payload, Mapping):
            assertions[op.address] = op.payload
    return propositions, assertions


def _declared_node_presence_result(
    assertion_address: str,
    proposition_address: str,
    polarity: str,
    ppayload: Mapping[str, Any],
    snapshot: RuntimeSnapshot,
) -> dict[str, Any] | None:
    """Decide the one declared-state predicate APTL can evaluate exactly."""

    spec = ppayload.get("spec")
    predicate = spec.get("predicate") if isinstance(spec, Mapping) else None
    subjects = _string_tuple(ppayload.get("subject_addresses"))
    if not _declared_presence_predicate(ppayload, predicate, subjects):
        return None
    outcome = (
        _TRUE
        if all(
            (entry := snapshot.entries.get(subject)) is not None
            and entry.resource_type == "node"
            for subject in subjects
        )
        else _FALSE
    )
    return {
        "schema_version": _TRUTH_RESULT_SCHEMA,
        "result_id": f"aptl:{assertion_address}",
        "proposition_address": proposition_address,
        "assertion_address": assertion_address,
        "assertion_polarity": polarity,
        "proposition_outcome": outcome,
        "assertion_outcome": outcome if polarity == _POSITIVE else _invert(outcome),
        "evaluation_basis": _DECLARED_STATE,
        "declared_artifact_digest": compute_source_set_digest(
            {
                "proposition_address": proposition_address,
                "subject_addresses": list(subjects),
                "predicate": dict(predicate),
                "quantifier": ppayload.get("quantifier"),
            }
        ),
    }


def _declared_presence_predicate(
    ppayload: Mapping[str, Any],
    predicate: object,
    subjects: tuple[str, ...],
) -> bool:
    """Validate the one declared-state predicate APTL can decide."""

    return (
        isinstance(predicate, Mapping)
        and ppayload.get("predicate_kind") == "presence"
        and ppayload.get("quantifier") == "all"
        and not _string_tuple(ppayload.get("evidence_requirement_refs"))
        and predicate.get("kind") == "presence"
        and predicate.get("property") == "node"
        and predicate.get("semantic_ref") == "urn:raes:declared-property:node"
        and predicate.get("operator") == "exists"
        and bool(subjects)
    )


def _project_assertion_result(
    assertion_address: str,
    apayload: Mapping[str, Any],
    propositions: Mapping[str, Mapping[str, Any]],
    snapshot: RuntimeSnapshot,
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
) -> dict[str, Any] | None:
    """Project one assertion's truth-result envelope, or ``None`` if APTL can't corroborate it."""

    proposition_address = apayload.get("proposition_address")
    ppayload = (
        propositions.get(proposition_address)
        if isinstance(proposition_address, str)
        else None
    )
    result = None
    if ppayload is None:
        return result
    polarity_value = apayload.get("polarity", _POSITIVE)
    polarity = (
        polarity_value if polarity_value in (_POSITIVE, "negative") else _POSITIVE
    )
    basis = ppayload.get("evaluation_basis")
    if basis == _DECLARED_STATE:
        result = _declared_node_presence_result(
            assertion_address,
            proposition_address,
            polarity,
            ppayload,
            snapshot,
        )
    elif basis == _OBSERVED_STATE:
        result = _observed_assertion_result(
            assertion_address,
            proposition_address,
            polarity,
            ppayload,
            snapshot,
            evidence_records,
        )
    return result


def _observed_assertion_result(
    assertion_address: str,
    proposition_address: str,
    polarity: str,
    ppayload: Mapping[str, Any],
    snapshot: RuntimeSnapshot,
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
) -> dict[str, Any] | None:
    """Project native evidence or corroborated service-content truth."""

    native_result = native_evidence_result(
        assertion_address,
        proposition_address,
        polarity,
        ppayload,
        evidence_records,
    )
    if native_result is not None:
        return native_result
    corroborated = _service_content_subject_outcome(
        _string_tuple(ppayload.get("subject_addresses")), snapshot
    )
    if corroborated is None:
        return None
    outcome, field_schema_digest, boundary_ref = corroborated
    assertion_outcome = outcome if polarity == _POSITIVE else _invert(outcome)
    evidence_refs = _string_tuple(ppayload.get("evidence_requirement_refs"))
    result: dict[str, Any] = {
        "schema_version": _TRUTH_RESULT_SCHEMA,
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
    return result


def project_proposition_truth_results(
    plan: EvaluationPlan,
    snapshot: RuntimeSnapshot,
    *,
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...] = (),
) -> dict[str, dict[str, Any]]:
    """Project truth-result envelopes APTL can corroborate, keyed by assertion.

    Each result key equals its ``assertion_address`` (the RAES truth-result
    contract requires it).
    """

    propositions, assertions = _split_plan_operations(plan)
    results: dict[str, dict[str, Any]] = {}
    for assertion_address, apayload in assertions.items():
        result = _project_assertion_result(
            assertion_address,
            apayload,
            propositions,
            snapshot,
            evidence_records,
        )
        if result is not None:
            results[assertion_address] = result
    return results


def native_evidence_truth_is_complete(
    plan: EvaluationPlan,
    snapshot: RuntimeSnapshot,
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
) -> bool:
    """Return whether every planned native truth demand has one bound record.

    This is the terminal fail-closed check used after control-plane
    reconciliation. A sealed capture set is insufficient if the authored
    predicate changed and therefore no longer matches APTL's exact evaluator.
    """

    propositions, _ = _split_plan_operations(plan)
    planned_requirements = tuple(
        requirement_ref
        for payload in propositions.values()
        for requirement_ref in _string_tuple(payload.get("evidence_requirement_refs"))
        if requirement_ref in NATIVE_EVIDENCE_CAPABILITIES
    )
    if not planned_requirements or len(planned_requirements) != len(
        set(planned_requirements)
    ):
        return False
    records_by_requirement: dict[str, list[ExperimentEvidenceRecordModel]] = {}
    for record in evidence_records:
        if record.capture_requirement_ref in NATIVE_EVIDENCE_CAPABILITIES:
            records_by_requirement.setdefault(
                record.capture_requirement_ref,
                [],
            ).append(record)
    if set(planned_requirements) != set(records_by_requirement) or any(
        len(records) != 1 for records in records_by_requirement.values()
    ):
        return False
    bound_record_ids = {
        str(evidence_ref)
        for result in snapshot.proposition_truth_results.values()
        if isinstance(result, Mapping)
        for evidence_ref in _string_tuple(result.get("evidence_refs"))
    }
    return all(
        records_by_requirement[requirement_ref][0].evidence_record_id
        in bound_record_ids
        for requirement_ref in planned_requirements
    )
