"""Native TechVault evidence acquisition at the lab-start boundary."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import AcquisitionDisposition, CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, RunScope
from aptl.core.experiment.capture_registry import (
    CaptureBinding,
    CaptureLimits,
    CaptureVisibility,
)
from aptl.backends.identity import BackendIdentity
from aptl.backends.scenario_capture import ScenarioCaptureContext
from aptl.backends.scenario_capture_discovery import resolve_scenario_capture
from aptl.core.scenario_bundle import PackIdentity
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST
from aptl.core.runstore import LocalRunStore
from aptl.utils.pathsafe import PathContainmentError


def _capture_selection(runtime_adapter: object | None = None):
    selection = resolve_scenario_capture(
        ScenarioCaptureContext(
            PackIdentity("techvault", "0.1.0", TECHVAULT_PACK_SET_DIGEST),
            BackendIdentity("aptl", "0.1.0", "full-remote-control-plane"),
        )
    )
    if runtime_adapter is None:
        return selection
    contribution = replace(
        selection.contribution,
        runtime_adapter=runtime_adapter,
    )
    return replace(selection, contribution=contribution)


def _binding(registration_id: str, requirement_id: str) -> CaptureBinding:
    media_type = (
        "text/plain"
        if registration_id.endswith(("rule-readiness", "session-transcript"))
        else "application/x-ndjson"
        if registration_id.endswith("wazuh-sqli")
        else "application/json"
    )
    registration = next(
        (
            item
            for item in _capture_selection().registry.registrations
            if item.registration_id == registration_id
        ),
        None,
    )
    return CaptureBinding(
        capture_spec_id="capture-plan-test",
        requirement_id=requirement_id,
        window_refs=("system_under_test",),
        registration_id=registration_id,
        implementation_version=(
            registration.implementation_version if registration else "1.0.0"
        ),
        contract_version=(
            registration.contract_version
            if registration
            else "experiment-capture-spec/v1"
        ),
        effective_config_digest=(
            registration.effective_config_digest()
            if registration
            else "sha256:" + "ab" * 32
        ),
        channel_ref_id="participant-observation",
        channel_ref_version=None,
        channel_kind="participant-observation",
        capture_kind="observation",
        capture_scope="scenario",
        expected_media_types=(media_type,),
        required_artifact_roles=("observation",),
        sensitivity="plain",
        redaction_required=False,
        integrity_requirements=("checksum",),
        retention_policy="run_lifetime",
        loss_disclosure_required=True,
        visibility_class=(
            registration.visibility_class
            if registration
            else CaptureVisibility.EVALUATOR_ONLY
        ),
        limits=(registration.limits if registration else CaptureLimits(4096, 10, 60)),
    )


class _SequenceClock:
    def __init__(self, *values: str) -> None:
        self._values = iter(values)

    def now(self) -> str:
        return next(self._values)

    def clock_context(self, **_kwargs):  # pragma: no cover - protocol-only seam
        raise NotImplementedError


@dataclass
class _Source:
    result: SourceResult
    window: tuple[str, str] | None = None

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        self.window = (start_iso, end_iso)
        return self.result


def test_on_demand_collector_bounds_query_then_records_actual_finish():
    from aptl.backends.raes_evidence_acquisition import _OnDemandNativeCollector

    source = _Source(
        SourceResult(
            status=CollectorStatus.OK,
            records=[{"ok": True}],
            source_min_time="2026-09-14T00:00:01Z",
            source_max_time="2026-09-14T00:00:04Z",
        )
    )
    clock = _SequenceClock(
        "2026-09-14T00:00:00Z",
        "2026-09-14T00:00:05Z",
    )
    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    context = CollectorContext(
        planned_trial_id="capture-plan-test",
        run_id="run-1",
        attempt_id="provisioning",
        binding=binding,
        deadline_seconds=60,
        clock=clock,
    )

    outcome = _OnDemandNativeCollector(binding.registration_id, source).stop(
        _OnDemandNativeCollector.start(context)
    )

    assert source.window == (
        "2026-09-14T00:00:00Z",
        "2026-09-14T00:01:00Z",
    )
    assert outcome.started_at == "2026-09-14T00:00:00Z"
    assert outcome.finished_at == "2026-09-14T00:00:05Z"
    assert outcome.status is CollectorStatus.OK


def test_on_demand_collector_rejects_source_time_after_actual_finish():
    from aptl.backends.raes_evidence_acquisition import _OnDemandNativeCollector

    source = _Source(
        SourceResult(
            status=CollectorStatus.OK,
            records=[{"ok": True}],
            source_max_time="2026-09-14T00:00:30Z",
        )
    )
    clock = _SequenceClock(
        "2026-09-14T00:00:00Z",
        "2026-09-14T00:00:05Z",
    )
    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    context = CollectorContext(
        planned_trial_id="capture-plan-test",
        run_id="run-1",
        attempt_id="provisioning",
        binding=binding,
        deadline_seconds=60,
        clock=clock,
    )

    outcome = _OnDemandNativeCollector(binding.registration_id, source).stop(
        _OnDemandNativeCollector.start(context)
    )

    assert outcome.status is CollectorStatus.CLOCK_SKEW


def test_acquire_native_evidence_persists_only_immediate_native_bindings(
    tmp_path, monkeypatch
):
    from aptl.backends import raes_evidence_acquisition as acquisition

    native = (
        _binding("aptl.collector.cortex-enrichment", "cortex"),
        _binding("aptl.collector.misp-authenticated-api-readiness", "misp"),
        _binding("aptl.collector.suricata-rule-readiness", "readiness"),
        _binding("aptl.collector.suricata-wazuh-sqli", "sqli"),
        _binding("aptl.collector.wazuh-agent-readiness", "wazuh"),
    )
    transcript = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(
        plan_id="capture-plan-test",
        canonical_bytes=b'{"schema_version":"aptl-capture-plan/v1"}',
        runtime_bindings=lambda: (*native, transcript),
    )
    sources = {
        item.registration_id: _Source(
            SourceResult(
                status=CollectorStatus.OK,
                chunks=(
                    b"ready\n"
                    if item.expected_media_types[0] == "text/plain"
                    else b'{"ready":true}\n',
                ),
                media_type=item.expected_media_types[0],
            )
        )
        for item in native
    }
    selection = _capture_selection(
        SimpleNamespace(native_sources=lambda _request: sources)
    )
    store = LocalRunStore(tmp_path / "runs")
    start = datetime(2026, 9, 14, tzinfo=UTC)
    times = tuple(
        (start + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
        for offset in range(10)
    )

    result = acquisition.acquire_native_evidence(
        acquisition.NativeEvidenceRequest(
            plan=plan,
            backend=object(),
            realization=object(),
            project_dir=tmp_path,
            environment={
                "INDEXER_USERNAME": "admin",
                "INDEXER_PASSWORD": "password",
                "THEHIVE_API_KEY": "operator-api-key",
            },
            run_store=store,
            run_id="run-1",
            capture_selection=selection,
            clock=_SequenceClock(*times),
        )
    )

    assert result.disposition is AcquisitionDisposition.SEALED_READY
    assert {report.registration_id for report in result.reports} == {
        item.registration_id for item in native
    }
    assert len(result.records) == 5
    assert (
        store.get_run_path("run-1") / "evidence/capture-plans/capture-plan-test.json"
    ).read_bytes() == plan.canonical_bytes


def test_acquire_native_evidence_fails_when_a_required_source_is_unavailable(
    tmp_path, monkeypatch
):
    from aptl.backends import raes_evidence_acquisition as acquisition

    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    plan = SimpleNamespace(
        plan_id="capture-plan-test",
        canonical_bytes=b"{}",
        runtime_bindings=lambda: (binding,),
    )
    selection = _capture_selection(
        SimpleNamespace(
            native_sources=lambda _request: {
                binding.registration_id: _Source(
                    SourceResult(status=CollectorStatus.SOURCE_UNAVAILABLE)
                )
            }
        )
    )

    result = acquisition.acquire_native_evidence(
        acquisition.NativeEvidenceRequest(
            plan=plan,
            backend=object(),
            realization=object(),
            project_dir=tmp_path,
            environment={
                "INDEXER_USERNAME": "admin",
                "INDEXER_PASSWORD": "password",
                "THEHIVE_API_KEY": "operator-api-key",
            },
            run_store=LocalRunStore(tmp_path / "runs"),
            run_id="run-1",
            capture_selection=selection,
            clock=_SequenceClock(
                "2026-09-14T00:00:00Z",
                "2026-09-14T00:00:01Z",
            ),
        )
    )

    assert result.disposition is AcquisitionDisposition.INCONCLUSIVE


def _lab_context(tmp_path, plan):
    from raes_contracts.runtime_state import RuntimeSnapshot

    from aptl.core.lab import _LabStartContext

    return _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        raw_env={
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": "password",
            "THEHIVE_API_KEY": "operator-api-key",
        },
        backend=object(),
        env=SimpleNamespace(indexer_username="admin", indexer_password="password"),
        admitted_start=SimpleNamespace(
            capture_plan=plan,
            capture_selection=_capture_selection(),
            realization=object(),
            target=object(),
            execution_plan=object(),
        ),
        raes_outcome=SimpleNamespace(final_snapshot=RuntimeSnapshot()),
        run_store=LocalRunStore(tmp_path / "runs"),
        run_id="run-1",
    )


def test_lab_start_native_step_is_noop_without_native_demands(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.core.lab import _step_acquire_required_native_evidence

    called = False

    def unexpected(**_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(acquisition, "acquire_native_evidence", unexpected)
    plan = SimpleNamespace(runtime_bindings=lambda: ())

    assert _step_acquire_required_native_evidence(_lab_context(tmp_path, plan)) is None
    assert called is False


def test_lab_start_native_step_retains_successful_acquisition(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.backends import raes_evaluator
    from aptl.core.lab import _step_acquire_required_native_evidence
    from raes_contracts.runtime_state import OperationState, RuntimeSnapshot

    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    capture = SimpleNamespace(
        disposition=AcquisitionDisposition.SEALED_READY,
        records=("native-record",),
    )
    monkeypatch.setattr(
        acquisition, "acquire_native_evidence", lambda *_args, **_kwargs: capture
    )
    refreshed_snapshot = RuntimeSnapshot(metadata={"native-evidence": "evaluated"})
    monkeypatch.setattr(
        raes_evaluator,
        "refresh_evidence_truth",
        lambda **_kwargs: SimpleNamespace(
            status=OperationState.SUCCEEDED,
            snapshot=refreshed_snapshot,
        ),
    )
    context = _lab_context(
        tmp_path, SimpleNamespace(runtime_bindings=lambda: (binding,))
    )

    assert _step_acquire_required_native_evidence(context) is None
    assert context.native_evidence_acquisition is capture
    assert context.raes_outcome.final_snapshot is refreshed_snapshot


def test_lab_start_native_step_supports_credential_free_adapter(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.backends import raes_evaluator
    from aptl.core.lab import _step_acquire_required_native_evidence
    from raes_contracts.runtime_state import OperationState

    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    capture = SimpleNamespace(
        disposition=AcquisitionDisposition.SEALED_READY,
        records=("native-record",),
    )
    requests = []
    monkeypatch.setattr(
        acquisition,
        "acquire_native_evidence",
        lambda request: requests.append(request) or capture,
    )
    monkeypatch.setattr(
        raes_evaluator,
        "refresh_evidence_truth",
        lambda **kwargs: SimpleNamespace(
            status=OperationState.SUCCEEDED,
            snapshot=kwargs["snapshot"],
        ),
    )
    context = _lab_context(
        tmp_path, SimpleNamespace(runtime_bindings=lambda: (binding,))
    )
    context.env = None
    context.raw_env = {"UNDECLARED_SECRET": "must-not-cross-boundary"}
    context.admitted_start.capture_selection = replace(
        context.admitted_start.capture_selection,
        contribution=replace(
            context.admitted_start.capture_selection.contribution,
            runtime_environment_keys=(),
        ),
    )

    assert _step_acquire_required_native_evidence(context) is None
    assert len(requests) == 1
    assert dict(requests[0].environment) == {}


def test_lab_start_native_step_rejects_failed_truth_refresh(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.backends import raes_evaluator
    from aptl.core.lab import _step_acquire_required_native_evidence
    from raes_contracts.runtime_state import OperationState, RuntimeSnapshot

    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    capture = SimpleNamespace(
        disposition=AcquisitionDisposition.SEALED_READY,
        records=("native-record",),
    )
    monkeypatch.setattr(
        acquisition, "acquire_native_evidence", lambda *_args, **_kwargs: capture
    )
    monkeypatch.setattr(
        raes_evaluator,
        "refresh_evidence_truth",
        lambda **_kwargs: SimpleNamespace(
            status=OperationState.FAILED,
            snapshot=RuntimeSnapshot(),
        ),
    )
    context = _lab_context(
        tmp_path, SimpleNamespace(runtime_bindings=lambda: (binding,))
    )

    result = _step_acquire_required_native_evidence(context)

    assert result is not None
    assert result.success is False
    assert result.error == "aptl.scenario-evidence.required-native-evaluation-failed"


def test_native_failure_messages_expose_codes_not_evidence_payloads():
    from aptl.core.lab import _native_capture_failure, _native_evaluation_failure

    capture = SimpleNamespace(
        reports=(
            SimpleNamespace(
                registration_id="aptl.collector.wazuh-agent-readiness",
                status=CollectorStatus.SOURCE_UNAVAILABLE,
                diagnostic_code="not-ready",
                payload="secret-body",
            ),
        )
    )
    refresh = SimpleNamespace(
        diagnostics=(
            SimpleNamespace(
                code="aptl.evaluator.native-evidence-truth-incomplete",
                message="secret-body",
            ),
        )
    )

    capture_error = _native_capture_failure(capture)
    evaluation_error = _native_evaluation_failure(refresh)

    assert "wazuh-agent-readiness=source-unavailable" in capture_error
    assert "aptl.evaluator.native-evidence-truth-incomplete" in evaluation_error
    assert "secret-body" not in capture_error + evaluation_error


def test_lab_start_native_step_rejects_failed_required_acquisition(
    tmp_path, monkeypatch
):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.core.lab import _step_acquire_required_native_evidence

    binding = _binding("aptl.collector.cortex-enrichment", "cortex")
    capture = SimpleNamespace(disposition=AcquisitionDisposition.INCONCLUSIVE)
    monkeypatch.setattr(
        acquisition, "acquire_native_evidence", lambda *_args, **_kwargs: capture
    )
    context = _lab_context(
        tmp_path, SimpleNamespace(runtime_bindings=lambda: (binding,))
    )

    result = _step_acquire_required_native_evidence(context)

    assert result is not None
    assert result.success is False
    assert result.error == "aptl.scenario-evidence.required-native-capture-failed"
    assert context.native_evidence_acquisition is capture


def test_lab_start_native_step_rejects_collector_exception(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.core.lab import _step_acquire_required_native_evidence

    binding = _binding("aptl.collector.cortex-enrichment", "cortex")

    def fail(**_kwargs):
        raise OSError("source detail must not cross the boundary")

    monkeypatch.setattr(acquisition, "acquire_native_evidence", fail)
    context = _lab_context(
        tmp_path, SimpleNamespace(runtime_bindings=lambda: (binding,))
    )

    result = _step_acquire_required_native_evidence(context)

    assert result is not None
    assert result.error == "aptl.scenario-evidence.required-native-capture-failed"


def test_lab_start_activates_admitted_transcript_before_ssh(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.core.lab import _step_activate_capture_apparatus

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(
        plan_id="capture-plan-test",
        canonical_bytes=b"{}",
        runtime_bindings=lambda: (binding,),
    )
    context = _lab_context(tmp_path, plan)
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-test",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    context.backend = SimpleNamespace(
        activate_capture_apparatus=lambda **_kwargs: authority
    )
    prepared = []
    monkeypatch.setattr(
        acquisition,
        "persist_active_transcript_authority",
        lambda **kwargs: prepared.append(kwargs),
    )

    assert _step_activate_capture_apparatus(context) is None
    assert context.transcript_capture_authority == authority
    assert prepared[0]["binding"] is binding
    assert prepared[0]["run_id"] == "run-1"


def test_lab_start_rejects_unactivatable_required_transcript(tmp_path, monkeypatch):
    from aptl.backends import raes_evidence_acquisition as acquisition
    from aptl.core.lab import _step_activate_capture_apparatus

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(
        plan_id="capture-plan-test",
        canonical_bytes=b"{}",
        runtime_bindings=lambda: (binding,),
    )
    context = _lab_context(tmp_path, plan)
    context.backend = SimpleNamespace(activate_capture_apparatus=lambda **_kwargs: None)
    monkeypatch.setattr(
        acquisition,
        "persist_active_transcript_authority",
        lambda **_kwargs: None,
    )
    failed = []
    monkeypatch.setattr(
        acquisition,
        "mark_transcript_activation_failed",
        lambda **kwargs: failed.append(kwargs),
    )

    result = _step_activate_capture_apparatus(context)

    assert result is not None
    assert result.error == "aptl.scenario-evidence.required-transcript-unavailable"
    assert failed == [
        {
            "project_dir": tmp_path,
            "plan_id": "capture-plan-test",
            "run_id": "run-1",
        }
    ]


def test_failed_transcript_activation_is_auditable_but_not_pending(tmp_path):
    from aptl.backends.raes_evidence_acquisition import (
        load_active_transcript_authorities,
        mark_transcript_activation_failed,
        persist_active_transcript_authority,
    )

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(plan_id="capture-plan-test", canonical_bytes=b"{}")
    # Matches the repository default (run_storage.local_path = "./runs").
    store = LocalRunStore(tmp_path / "runs")
    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )

    mark_transcript_activation_failed(
        project_dir=tmp_path,
        plan_id="capture-plan-test",
        run_id="run-1",
    )

    assert load_active_transcript_authorities(tmp_path) == ()
    assert (tmp_path / ".aptl/capture-authorities/run-1.json").is_file()
    assert (tmp_path / ".aptl/capture-activation-failed/run-1.json").is_file()


def test_active_transcript_authority_is_contained_create_once(tmp_path):
    from aptl.backends.raes_evidence_acquisition import (
        load_active_transcript_authorities,
        persist_active_transcript_authority,
    )

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(
        plan_id="capture-plan-test",
        canonical_bytes=b"{}",
    )
    store = LocalRunStore(tmp_path / ".aptl/runs")

    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )
    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )

    active = load_active_transcript_authorities(tmp_path)
    assert len(active) == 1
    assert active[0]["run_id"] == "run-1"
    assert active[0]["binding"]["registration_id"] == binding.registration_id
    assert Path(active[0]["run_store_base"]) == store.base_dir


def test_failed_transcript_finalization_is_terminal_and_auditable(tmp_path):
    from aptl.backends.raes_evidence_acquisition import (
        load_active_transcript_authorities,
        mark_transcript_finalization_failed,
        persist_active_transcript_authority,
    )

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(plan_id="capture-plan-test", canonical_bytes=b"{}")
    store = LocalRunStore(tmp_path / "runs")
    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )
    state = load_active_transcript_authorities(tmp_path)[0]

    mark_transcript_finalization_failed(project_dir=tmp_path, state=state)

    assert load_active_transcript_authorities(tmp_path) == ()
    assert (tmp_path / ".aptl/capture-authorities/run-1.json").is_file()
    assert (tmp_path / ".aptl/capture-finalization-failed/run-1.json").is_file()


def test_active_transcript_authority_rejects_conflicting_binding(tmp_path):
    from aptl.backends.raes_evidence_acquisition import (
        persist_active_transcript_authority,
    )

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(plan_id="capture-plan-test", canonical_bytes=b"{}")
    store = LocalRunStore(tmp_path / ".aptl/runs")
    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )

    conflicting = replace(binding, requirement_id="different-transcript")
    with pytest.raises(ValueError, match="active transcript authority conflict"):
        persist_active_transcript_authority(
            project_dir=tmp_path,
            plan=plan,
            binding=conflicting,
            run_store=store,
            run_id="run-1",
            capture_selection=_capture_selection(),
        )


def test_expected_transcript_sessions_come_from_sorted_mcp_census(tmp_path):
    from aptl.backends.raes_evidence_acquisition import (
        _expected_transcript_session_ids,
    )

    census = tmp_path / "run-1/mcp-side/sessions"
    census.mkdir(parents=True)
    (census / "session-b.jsonl").write_text("")
    (census / "session-a.jsonl").write_text("")

    assert _expected_transcript_session_ids(
        tmp_path,
        "run-1",
        max_sessions=10,
    ) == ("session-a", "session-b")


def test_expected_transcript_sessions_reject_symlinked_census_entry(tmp_path):
    from aptl.backends.raes_evidence_acquisition import (
        _expected_transcript_session_ids,
    )

    census = tmp_path / "run-1/mcp-side/sessions"
    census.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("not a census record")
    (census / "session-a.jsonl").symlink_to(outside)

    with pytest.raises(PathContainmentError):
        _expected_transcript_session_ids(
            tmp_path,
            "run-1",
            max_sessions=10,
        )


def test_finalize_transcript_quiesces_broker_persists_evidence_and_marks_complete(
    tmp_path,
):
    from aptl.backends.raes_evidence_acquisition import (
        finalize_active_transcript_authority,
        load_active_transcript_authorities,
        persist_active_transcript_authority,
    )

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(
        plan_id="capture-plan-test",
        canonical_bytes=b"{}",
    )
    # Matches the repository default (run_storage.local_path = "./runs").
    store = LocalRunStore(tmp_path / "runs")
    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )
    state = load_active_transcript_authorities(tmp_path)[0]
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-test",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    exported = {
        "authority": authority,
        "expected_session_ids": ["session-1"],
        "accepted_session_ids": ["session-1"],
        "sessions": [
            {
                "session_id": "session-1",
                "started_at": "2026-09-14T10:00:01Z",
                "finished_at": "2026-09-14T10:00:02Z",
                "close_reason": "clean-exit",
                "loss_count": 0,
                "final_chain_digest": "sha256:" + "00" * 32,
                "frames": [],
            }
        ],
    }
    census = store.get_run_path("run-1") / "mcp-side/sessions"
    census.mkdir(parents=True)
    (census / "session-1.jsonl").write_text("")
    observed_expected = None

    lifecycle = []

    def quiesce_capture_apparatus():
        lifecycle.append("quiesce")
        return True

    def export_capture_apparatus(*, expected_session_ids):
        nonlocal observed_expected
        lifecycle.append("export")
        observed_expected = expected_session_ids
        return exported

    backend = SimpleNamespace(
        quiesce_capture_apparatus=quiesce_capture_apparatus,
        export_capture_apparatus=export_capture_apparatus,
    )

    result = finalize_active_transcript_authority(
        project_dir=tmp_path,
        state=state,
        backend=backend,
        expected_run_store_base=store.base_dir,
        clock=_SequenceClock("2026-09-14T10:00:03Z"),
    )

    assert result.disposition is AcquisitionDisposition.SEALED_READY
    assert len(result.records) == 1
    assert observed_expected == ("session-1",)
    assert lifecycle == ["quiesce", "export"]
    assert load_active_transcript_authorities(tmp_path) == ()


def test_finalize_transcript_rejects_mismatched_broker_authority_and_uses_host_clock(
    tmp_path,
):
    from aptl.backends.raes_evidence_acquisition import (
        finalize_active_transcript_authority,
        load_active_transcript_authorities,
        persist_active_transcript_authority,
    )

    binding = _binding("aptl.collector.redteam-session-transcript", "transcript")
    plan = SimpleNamespace(plan_id="capture-plan-test", canonical_bytes=b"{}")
    store = LocalRunStore(tmp_path / ".aptl/runs")
    persist_active_transcript_authority(
        project_dir=tmp_path,
        plan=plan,
        binding=binding,
        run_store=store,
        run_id="run-1",
        capture_selection=_capture_selection(),
    )
    state = load_active_transcript_authorities(tmp_path)[0]
    exported = {
        "authority": {
            "run_id": "another-run",
            "plan_id": "capture-plan-test",
            "binding_id": "aptl.collector.redteam-session-transcript",
            "activated_at": "2026-09-14T10:00:00Z",
        },
        "expected_session_ids": [],
        "accepted_session_ids": [],
        "sessions": [],
    }
    clock = _SequenceClock(
        "2026-09-14T10:00:03Z",
        "2026-09-14T10:00:04Z",
    )

    result = finalize_active_transcript_authority(
        project_dir=tmp_path,
        state=state,
        backend=SimpleNamespace(
            quiesce_capture_apparatus=lambda: True,
            export_capture_apparatus=lambda **_kwargs: exported,
        ),
        expected_run_store_base=store.base_dir,
        clock=clock,
    )

    assert result.disposition is AcquisitionDisposition.INVALIDATED
    assert result.reports[0].status is CollectorStatus.FINALIZATION_FAILURE
    assert next(clock._values, None) is None


def _exported_session(*, session_id="session-1", frames=()):
    return {
        "session_id": session_id,
        "started_at": "2026-09-14T10:00:01Z",
        "finished_at": "2026-09-14T10:00:02Z",
        "close_reason": "clean-exit",
        "loss_count": 0,
        "final_chain_digest": "sha256:" + "00" * 32,
        "frames": list(frames),
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"expected_session_ids": ["session-1", "session-1"], "sessions": []},
        {
            "expected_session_ids": ["session-1"],
            "sessions": [
                _exported_session(frames=({"sequence": True, "data_b64": "eA=="},))
            ],
        },
        {
            "expected_session_ids": ["session-1"],
            "sessions": [
                _exported_session(
                    frames=(
                        {
                            "sequence": 1,
                            "timestamp": "2026-09-14T10:00:01Z",
                            "direction": "input",
                            "data_b64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==",
                        },
                    )
                )
            ],
        },
    ],
    ids=("duplicate-session-inventory", "malformed-frame", "oversized-export"),
)
def test_transcript_export_validation_maps_to_finalization_failure(payload):
    from aptl_techvault.evidence.transcript_parsing import (
        FinalizedTranscriptCollector as _FinalizedTranscriptCollector,
    )

    binding = replace(
        _binding("aptl.collector.redteam-session-transcript", "transcript"),
        limits=CaptureLimits(max_bytes=300, max_artifact_count=10, max_duration_s=60),
    )
    clock = _SequenceClock("2026-09-14T10:00:03Z")
    context = CollectorContext(
        planned_trial_id="capture-plan-test",
        run_id="run-1",
        attempt_id="teardown",
        binding=binding,
        deadline_seconds=60,
        clock=clock,
    )
    collector = _FinalizedTranscriptCollector(binding, payload, "2026-09-14T10:00:00Z")

    outcome = collector.stop(collector.start(context))

    assert outcome.status is CollectorStatus.FINALIZATION_FAILURE


def test_lab_stop_still_tears_down_when_required_transcript_finalization_fails(
    tmp_path, monkeypatch
):
    from aptl.core import lab
    from aptl.core.lab_types import LabResult

    stopped = []
    backend = SimpleNamespace(
        stop=lambda profiles, remove_volumes: (
            stopped.append((profiles, remove_volumes)) or LabResult(success=True)
        )
    )
    monkeypatch.setattr(
        lab,
        "_finalize_required_transcript_capture",
        lambda _project, _backend: LabResult(
            success=False,
            error="aptl.scenario-evidence.required-transcript-finalization-failed",
        ),
    )

    result = lab._stop_lab_owned(True, tmp_path, backend)

    assert stopped
    assert stopped[0][1] is True
    assert result.success is False
    assert (
        result.error == "aptl.scenario-evidence.required-transcript-finalization-failed"
    )
