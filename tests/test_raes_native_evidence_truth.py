"""Truth projection from admitted, sealed TechVault native evidence."""

from __future__ import annotations

from dataclasses import replace

import pytest

from raes_contracts.contracts import (
    ExperimentCaptureSpecReferenceModel,
    ExperimentChecksumModel,
    ExperimentEvidenceRecordModel,
    ExperimentReferenceModel,
)
from raes_contracts.contracts.experiment_capture import (
    ExperimentRawEvidenceContentModel,
)
from raes_contracts.planning import (
    ChangeAction,
    EvaluationOp,
    EvaluationPlan,
    OrchestrationPlan,
    ProvisioningPlan,
    RuntimeDomain,
)
from raes_contracts.runtime_state import OperationState, RuntimeSnapshot
from raes_processor.models import ExecutionPlan, RuntimeModel
from raes_reference_backend import create_reference_backend_target

from aptl.backends._raes_proposition_truth import (
    native_evidence_truth_is_complete,
    project_proposition_truth_results,
)
from aptl.backends.raes_evaluator import AptlEvaluator, refresh_evidence_truth


def _record(
    requirement_id: str,
    *,
    evidence_kind: str = "log",
    channel_ref: str = "backend-log",
) -> ExperimentEvidenceRecordModel:
    digest = "ab" * 32
    return ExperimentEvidenceRecordModel(
        schema_version="experiment-evidence-record/v1",
        evidence_record_id=f"evidence-{requirement_id}",
        record_version="1.0.0",
        capture_spec_ref=ExperimentCaptureSpecReferenceModel(
            ref_kind="capture-spec",
            ref_id="techvault-capture",
        ),
        capture_requirement_ref=requirement_id,
        output_contract="experiment-evidence-record-v1",
        run_ref=ExperimentReferenceModel(ref_kind="run", ref_id="run-992"),
        source_refs=[
            ExperimentReferenceModel(
                ref_kind="measurement-channel",
                ref_id=channel_ref,
            )
        ],
        evidence_kind=evidence_kind,
        captured_at="2026-09-14T12:00:00Z",
        capture_window_ref="system_under_test",
        raw_content=ExperimentRawEvidenceContentModel(
            content_uri=f"evidence/blobs/{digest}",
            content_checksum=ExperimentChecksumModel(
                algorithm="sha256",
                value=digest,
            ),
            payload_summary="1 event retained",
            loss_disclosure=(
                "content withheld from participant projection; evaluator retains access"
            ),
        ),
        sensitivity="internal",
        redaction_state="withheld",
        redaction_policy="aptl.evaluator-only-withholding/v1",
    )


def _plan(
    requirement_id: str = "suricata-local-rule-readiness",
    *,
    property_name: str = "network-detection-rule-source-ready",
    semantic_ref: str = "urn:raes:observable:network-detection-rule-source-ready",
    evidence_channel: str = "log",
) -> EvaluationPlan:
    proposition_address = "evaluation.proposition.suricata-local-rules-ready"
    assertion_address = "evaluation.assertion.suricata-local-rules-ready"
    return EvaluationPlan(
        operations=[
            EvaluationOp(
                action=ChangeAction.CREATE,
                address=proposition_address,
                resource_type="proposition",
                payload={
                    "name": "suricata-local-rules-ready",
                    "spec": {
                        "predicate": {
                            "kind": "boolean",
                            "property": property_name,
                            "semantic_ref": semantic_ref,
                            "operator": "equals",
                            "expected": True,
                        }
                    },
                    "subject_addresses": (),
                    "predicate_kind": "boolean",
                    "quantifier": "all",
                    "evaluation_basis": "observed_state",
                    "evidence_requirement_refs": (requirement_id,),
                    "evidence_channels": (evidence_channel,),
                    "unresolved_evidence_channel_refs": (),
                    "required_time_domain": "scenario_time",
                },
            ),
            EvaluationOp(
                action=ChangeAction.CREATE,
                address=assertion_address,
                resource_type="assertion",
                payload={
                    "name": "suricata-local-rules-ready",
                    "proposition_address": proposition_address,
                    "role": "postcondition",
                    "polarity": "positive",
                },
            ),
        ]
    )


def test_sealed_native_record_decides_only_its_exact_techvault_proposition():
    result = project_proposition_truth_results(
        _plan(),
        RuntimeSnapshot(),
        evidence_records=(_record("suricata-local-rule-readiness"),),
    )

    truth = result["evaluation.assertion.suricata-local-rules-ready"]
    assert truth["proposition_outcome"] == "true"
    assert truth["assertion_outcome"] == "true"
    assert truth["evidence_refs"] == ["evidence-suricata-local-rule-readiness"]
    assert truth["probe_binding"]["artifact_digest"] == "sha256:" + "ab" * 32
    assert truth["temporal_context"]["boundary_ref"] == "system_under_test"


@pytest.mark.parametrize(
    (
        "requirement_id",
        "property_name",
        "semantic_ref",
        "evidence_channel",
        "evidence_kind",
        "record_channel",
    ),
    [
        (
            "cortex-enrichment-readback",
            "cortex-enrichment-ready",
            "urn:raes:observable:cortex-enrichment-ready",
            "api_response",
            "observation",
            "participant-observation",
        ),
        (
            "suricata-local-rule-readiness",
            "network-detection-rule-source-ready",
            "urn:raes:observable:network-detection-rule-source-ready",
            "log",
            "log",
            "backend-log",
        ),
        (
            "suricata-login-sqli-alert",
            "network-detection-alert-sid-1000010-observed",
            "urn:raes:observable:network-detection-alert-observed",
            "log",
            "log",
            "backend-log",
        ),
    ],
)
def test_each_exact_techvault_native_requirement_has_a_truth_binding(
    requirement_id,
    property_name,
    semantic_ref,
    evidence_channel,
    evidence_kind,
    record_channel,
):
    result = project_proposition_truth_results(
        _plan(
            requirement_id,
            property_name=property_name,
            semantic_ref=semantic_ref,
            evidence_channel=evidence_channel,
        ),
        RuntimeSnapshot(),
        evidence_records=(
            _record(
                requirement_id,
                evidence_kind=evidence_kind,
                channel_ref=record_channel,
            ),
        ),
    )

    assert len(result) == 1


def test_native_record_does_not_decide_a_mismatched_predicate():
    result = project_proposition_truth_results(
        _plan(property_name="some-other-property"),
        RuntimeSnapshot(),
        evidence_records=(_record("suricata-local-rule-readiness"),),
    )

    assert result == {}


def test_native_record_does_not_decide_a_mismatched_record_channel():
    result = project_proposition_truth_results(
        _plan(),
        RuntimeSnapshot(),
        evidence_records=(
            _record(
                "suricata-local-rule-readiness",
                evidence_kind="observation",
                channel_ref="participant-observation",
            ),
        ),
    )

    assert result == {}


def test_evaluator_projects_bound_native_evidence_into_runtime_snapshot():
    evaluator = AptlEvaluator()
    evaluator.bind_evidence_records((_record("suricata-local-rule-readiness"),))

    result = evaluator.start(_plan(), RuntimeSnapshot())

    assert result.success is True
    assert sorted(result.snapshot.proposition_truth_results) == [
        "evaluation.assertion.suricata-local-rules-ready"
    ]


def test_native_evidence_refresh_is_committed_through_the_runtime_control_plane():
    evaluator = AptlEvaluator()
    target = replace(create_reference_backend_target(), evaluator=evaluator)
    execution_plan = ExecutionPlan(
        target_name=target.name,
        manifest=target.manifest,
        base_snapshot=RuntimeSnapshot(),
        scenario_name="native-evidence-refresh",
        model=RuntimeModel(scenario_name="native-evidence-refresh"),
        provisioning=ProvisioningPlan(),
        orchestration=OrchestrationPlan(),
        evaluation=_plan(),
        observation_owner=RuntimeDomain.PROVISIONING,
    )

    refresh = refresh_evidence_truth(
        target=target,
        execution_plan=execution_plan,
        snapshot=RuntimeSnapshot(),
        evidence_records=(_record("suricata-local-rule-readiness"),),
    )

    assert refresh.status is OperationState.SUCCEEDED
    assert sorted(refresh.snapshot.proposition_truth_results) == [
        "evaluation.assertion.suricata-local-rules-ready"
    ]


def test_native_evidence_refresh_fails_when_the_authored_predicate_does_not_match():
    evaluator = AptlEvaluator()
    target = replace(create_reference_backend_target(), evaluator=evaluator)
    execution_plan = ExecutionPlan(
        target_name=target.name,
        manifest=target.manifest,
        base_snapshot=RuntimeSnapshot(),
        scenario_name="native-evidence-refresh",
        model=RuntimeModel(scenario_name="native-evidence-refresh"),
        provisioning=ProvisioningPlan(),
        orchestration=OrchestrationPlan(),
        evaluation=_plan(property_name="some-other-property"),
        observation_owner=RuntimeDomain.PROVISIONING,
    )

    refresh = refresh_evidence_truth(
        target=target,
        execution_plan=execution_plan,
        snapshot=RuntimeSnapshot(),
        evidence_records=(_record("suricata-local-rule-readiness"),),
    )

    assert refresh.status is OperationState.FAILED
    assert [diagnostic.code for diagnostic in refresh.diagnostics] == [
        "aptl.evaluator.native-evidence-truth-incomplete"
    ]


@pytest.mark.parametrize("record_count", [0, 2], ids=("missing", "duplicate"))
def test_native_evidence_truth_requires_one_bound_record_per_requirement(record_count):
    plan = _plan()
    record = _record("suricata-local-rule-readiness")
    projected = project_proposition_truth_results(
        plan,
        RuntimeSnapshot(),
        evidence_records=(record,),
    )
    snapshot = RuntimeSnapshot(proposition_truth_results=projected)

    assert not native_evidence_truth_is_complete(
        plan,
        snapshot,
        (record,) * record_count,
    )
