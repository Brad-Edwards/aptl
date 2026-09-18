"""Native-evidence proposition truth projection for the APTL evaluator."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from raes_contracts.contracts import ExperimentEvidenceRecordModel

from aptl.backends.raes_manifest import APTL_RAES_TARGET_NAME, APTL_RAES_TARGET_VERSION

_TRUE = "true"
_FALSE = "false"
_POSITIVE = "positive"
_OBSERVED_STATE = "observed_state"
_TRUTH_RESULT_SCHEMA = "proposition-truth-result/v1"
_BACKEND_MANIFEST_REF = f"{APTL_RAES_TARGET_NAME}@{APTL_RAES_TARGET_VERSION}"
_TIME_DOMAIN = "scenario_time"
_NATIVE_EVIDENCE_IMPLEMENTATION_ID = "aptl.techvault-native-evidence-readback"


@dataclass(frozen=True)
class NativeEvidenceCapability:
    """Exact authored proposition shape one trusted native record can decide."""

    predicate_property: str
    semantic_ref: str
    evidence_channel: str
    evidence_kind: str
    record_channel_ref: str


NATIVE_EVIDENCE_CAPABILITIES = {
    "cortex-enrichment-readback": NativeEvidenceCapability(
        predicate_property="cortex-enrichment-ready",
        semantic_ref="urn:raes:observable:cortex-enrichment-ready",
        evidence_channel="api_response",
        evidence_kind="observation",
        record_channel_ref="participant-observation",
    ),
    "misp-authenticated-api-readiness": NativeEvidenceCapability(
        predicate_property="misp-authenticated-api-ready",
        semantic_ref="urn:techvault:observable:misp-authenticated-api-ready",
        evidence_channel="api_response",
        evidence_kind="observation",
        record_channel_ref="participant-observation",
    ),
    "suricata-local-rule-readiness": NativeEvidenceCapability(
        predicate_property="network-detection-rule-source-ready",
        semantic_ref="urn:raes:observable:network-detection-rule-source-ready",
        evidence_channel="log",
        evidence_kind="log",
        record_channel_ref="backend-log",
    ),
    "wazuh-agent-readiness": NativeEvidenceCapability(
        predicate_property="wazuh-agent-ready",
        semantic_ref="urn:techvault:observable:wazuh-agent-ready",
        evidence_channel="file_artifact",
        evidence_kind="artifact",
        record_channel_ref="file-artifact",
    ),
    "suricata-login-sqli-alert": NativeEvidenceCapability(
        predicate_property="network-detection-alert-sid-1000010-observed",
        semantic_ref="urn:raes:observable:network-detection-alert-observed",
        evidence_channel="log",
        evidence_kind="log",
        record_channel_ref="backend-log",
    ),
}


def native_evidence_result(
    assertion_address: str,
    proposition_address: str,
    polarity: str,
    proposition: Mapping[str, Any],
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
) -> dict[str, Any] | None:
    """Project one exact TechVault evidence record into decided truth."""

    record = _native_evidence_record(proposition, evidence_records)
    if record is None:
        return None
    outcome = _TRUE
    assertion_outcome = outcome if polarity == _POSITIVE else _invert(outcome)
    digest = f"sha256:{record.raw_content.content_checksum.value}"
    requirement_ref = record.capture_requirement_ref
    return {
        "schema_version": _TRUTH_RESULT_SCHEMA,
        "result_id": f"aptl:{assertion_address}:{record.evidence_record_id}",
        "proposition_address": proposition_address,
        "assertion_address": assertion_address,
        "assertion_polarity": polarity,
        "proposition_outcome": outcome,
        "assertion_outcome": assertion_outcome,
        "evaluation_basis": _OBSERVED_STATE,
        "probe_binding": {
            "binding_id": f"aptl:{assertion_address}:{record.evidence_record_id}",
            "implementation_id": _NATIVE_EVIDENCE_IMPLEMENTATION_ID,
            "implementation_version": APTL_RAES_TARGET_VERSION,
            "artifact_digest": digest,
            "backend_manifest_ref": _BACKEND_MANIFEST_REF,
            "proposition_address": proposition_address,
            "capability_refs": [f"capture-requirement:{requirement_ref}"],
        },
        "evidence_refs": [record.evidence_record_id],
        "temporal_context": {
            "boundary_ref": record.capture_window_ref,
            "time_domain": _TIME_DOMAIN,
            "clock_authority": _BACKEND_MANIFEST_REF,
        },
    }


def _native_evidence_record(
    proposition: Mapping[str, Any],
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
) -> ExperimentEvidenceRecordModel | None:
    """Return the single native record that exactly matches the proposition."""

    context = _native_evidence_context(proposition)
    if context is None:
        return None
    requirement_ref, capability, predicate = context
    if not _native_predicate_matches(proposition, capability, predicate):
        return None
    candidates = tuple(
        record
        for record in evidence_records
        if record.capture_requirement_ref == requirement_ref
        and record.output_contract == "experiment-evidence-record-v1"
        and record.evidence_kind == capability.evidence_kind
        and record.redaction_state != "redacted"
        and _record_has_measurement_channel(record, capability.record_channel_ref)
        and record.raw_content.content_checksum.algorithm == "sha256"
    )
    return candidates[0] if len(candidates) == 1 else None


def _native_evidence_context(
    proposition: Mapping[str, Any],
) -> tuple[str, NativeEvidenceCapability, Mapping[str, object]] | None:
    """Resolve one exact evidence requirement, capability, and predicate."""

    result = None
    requirement_refs = _string_tuple(proposition.get("evidence_requirement_refs"))
    if len(requirement_refs) == 1:
        requirement_ref = requirement_refs[0]
        capability = NATIVE_EVIDENCE_CAPABILITIES.get(requirement_ref)
        spec = proposition.get("spec")
        predicate = spec.get("predicate") if isinstance(spec, Mapping) else None
        if capability is not None and isinstance(predicate, Mapping):
            result = requirement_ref, capability, predicate
    return result


def _native_predicate_matches(
    proposition: Mapping[str, Any],
    capability: NativeEvidenceCapability,
    predicate: Mapping[str, object],
) -> bool:
    """Validate every authored axis bound to one native evidence capability."""

    return not (
        proposition.get("predicate_kind") != "boolean"
        or proposition.get("quantifier") != "all"
        or _string_tuple(proposition.get("evidence_channels"))
        != (capability.evidence_channel,)
        or _string_tuple(proposition.get("unresolved_evidence_channel_refs"))
        or predicate.get("kind") != "boolean"
        or predicate.get("property") != capability.predicate_property
        or predicate.get("semantic_ref") != capability.semantic_ref
        or predicate.get("operator") != "equals"
        or predicate.get("expected") is not True
    )


def _record_has_measurement_channel(
    record: ExperimentEvidenceRecordModel,
    channel_ref: str,
) -> bool:
    """Return whether a record names the exact admitted measurement channel."""

    return any(
        source.ref_kind == "measurement-channel" and source.ref_id == channel_ref
        for source in record.source_refs
    )


def _string_tuple(raw: object) -> tuple[str, ...]:
    """Coerce a string or sequence into a tuple of non-empty strings."""

    if isinstance(raw, str):
        return (raw,) if raw else ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(value) for value in raw if str(value))
    return ()


def _invert(outcome: str) -> str:
    """Flip a true/false outcome string."""

    if outcome == _TRUE:
        return _FALSE
    if outcome == _FALSE:
        return _TRUE
    return outcome


__all__ = ("NATIVE_EVIDENCE_CAPABILITIES", "native_evidence_result")
