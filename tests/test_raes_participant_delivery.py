"""SDL participant delivery planning and installed Claude transport tests."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from raes_backend_stubs.stubs import create_stub_target
from raes_contracts.runtime_state import RuntimeSnapshot
from raes_processor.models import (
    MixedControlControllerStateRuntime,
    MixedControlDispositionRulesRuntime,
    MixedControlTransitionRuntime,
    ParticipantBehaviorSpecificationRuntime,
)

from aptl.backends.raes_participant_delivery import (
    CLAUDE_CODE_REALIZATION_PROFILE,
    ClaudeCodeHostParticipantAdapter,
    ParticipantTurnResult,
    _delivery_record,
    _render_runtime_profile_config,
    bind_participant_delivery_capture,
    build_participant_delivery_plan,
    execute_participant_delivery_plan,
)
from aptl.backends.raes_manifest import create_aptl_manifest
from aptl.backends.raes_planning_compat import AptlRuntimeManager
from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence.coordinator import acquire_evidence
from aptl.core.evidence.protocol import RunScope
from aptl.core.experiment.capture_registry import (
    CaptureBinding,
    CaptureLimits,
    CaptureVisibility,
)
from aptl.core.runstore import LocalRunStore
from aptl_techvault.study import StudyCapture
from aptl.workbench.process import AgentExecutionError, ProcessResult
from aptl.workbench.profiles import ProfileId


def _compiled_delivery(role: str, phase: str, tick: int) -> SimpleNamespace:
    spec = f"{role}-study"
    address = f"participant.behavior-specification.{spec}.inject-delivery.{phase}"
    return SimpleNamespace(
        address=address,
        behavior_specification_address=(
            f"participant.behavior-specification.{spec}"
        ),
        participant_address=f"participant.behavior.{role}-operator",
        inject_address=f"orchestration.inject.{role}-{phase}",
        event_address=f"orchestration.event.{role}-{phase}",
        script_address="orchestration.script.study-sequence",
        story_address="orchestration.story.study",
        source_item_ref=f"content.{role}-{phase}-instruction",
        observation_boundary_address=f"participant.observation-boundary.{role}-view",
        policy_ref=f"projection-policy.{role}.v1",
        policy_revision="1.0.0",
        exposure_policy_ref=f"exposure-policy.{role}.v1",
        audience_scope_ref=f"audience.participant.{role}-operator",
        visibility_basis_ref=f"visibility-basis.{role}.v1",
        disclosure_basis_ref=f"disclosure.{role}.v1",
        temporal_constraint_addresses=(f"time.constraint.{role}-{phase}",),
        evidence_requirement_addresses=(f"sdl.evidence-requirements.{role}-{phase}",),
        failure_disposition="reject-no-delivery",
        control_transition_address=(
            f"participant.behavior-specification.{spec}.control-transition.direct-{phase}"
        ),
        control_effective_order=tick,
        control_valid_from_order=tick - 1,
        control_valid_until_order=tick,
        controller_address="participant.behavior.study-controller",
        control_authority_scope_addresses=(f"provision.node.{role}-workbench",),
        control_evidence_addresses=(),
        spec={
            "occurrence": {
                "event_ref": f"{role}-{phase}",
                "script_ref": "study-sequence",
                "story_ref": "study",
            }
        },
    )


def _scenario_and_model() -> tuple[object, object]:
    authored = (
        ("red", "start", 1),
        ("red", "stop", 3),
        ("blue", "start", 5),
        ("blue", "stop", 7),
    )
    deliveries = [_compiled_delivery(*item) for item in authored]
    scenario = SimpleNamespace(
        behavior_specifications={
            f"{role}-study": SimpleNamespace(
                participant_role_refs=(role,),
                realization_profile_ref=CLAUDE_CODE_REALIZATION_PROFILE,
            )
            for role in ("red", "blue")
        },
        content={
            f"{role}-{phase}-instruction": SimpleNamespace(
                text=f"authored {role} {phase} instruction"
            )
            for role, phase, _ in authored
        },
        injects={
            f"{role}-{phase}": SimpleNamespace(environment=())
            for role, phase, _ in authored
        },
        events={
            f"{role}-{phase}": SimpleNamespace(injects=(f"{role}-{phase}",))
            for role, phase, _ in authored
        },
        scripts={
            "study-sequence": SimpleNamespace(
                events={f"{role}-{phase}": tick for role, phase, tick in authored}
            )
        },
        stories={"study": SimpleNamespace(scripts=("study-sequence",))},
    )
    constraints = [
        SimpleNamespace(
            address=f"time.constraint.{role}-{phase}",
            kind="window",
            clock_address="time.clock.study",
            subject_addresses=(delivery.address,),
            start_tick=tick,
            end_tick=tick,
            start_microstep=0,
            end_microstep=0,
        )
        for (role, phase, tick), delivery in zip(authored, deliveries, strict=True)
    ]
    compiled_behaviors = {}
    for role in ("red", "blue"):
        spec_address = f"participant.behavior-specification.{role}-study"
        offset = 0 if role == "red" else 4
        state_specs = (
            ("awaiting-start", 0, offset),
            ("start-pending", offset, offset + 1),
            ("active", offset + 1, offset + 2),
            ("stop-pending", offset + 2, offset + 3),
            ("stopped", offset + 3, 8),
        )
        states = tuple(
            MixedControlControllerStateRuntime(
                address=f"{spec_address}.controller-state.{name}",
                name=name,
                spec={},
                state_id=name,
                controller_ref="study-controller",
                controller_address="participant.behavior.study-controller",
                authority_basis_refs=("entities.study-control",),
                authority_basis_addresses=("entity.study-control",),
                scope_refs=(f"nodes.{role}-workbench",),
                scope_addresses=(f"provision.node.{role}-workbench",),
                policy_revision="1.0.0",
                valid_from_order=valid_from,
                valid_until_order=valid_until,
                authority_status="active",
                evidence_refs=("entities.study-control",),
                evidence_addresses=("entity.study-control",),
            )
            for name, valid_from, valid_until in state_specs
        )
        state_addresses = {state.name: state.address for state in states}
        transitions = []
        for phase, proposal_order, direction_order, expected_revision, proposal_revision in (
            ("start", offset, offset + 1, 0, 1),
            ("stop", offset + 2, offset + 3, 2, 3),
        ):
            proposal_address = (
                f"{spec_address}.control-transition.propose-{phase}"
            )
            transitions.extend(
                (
                    MixedControlTransitionRuntime(
                        address=proposal_address,
                        name=f"propose-{phase}",
                        spec={},
                        transition_id=f"propose-{phase}",
                        transition_kind="proposal",
                        from_state_address=state_addresses[
                            "awaiting-start" if phase == "start" else "active"
                        ],
                        to_state_address=state_addresses[
                            "start-pending" if phase == "start" else "stop-pending"
                        ],
                        policy_revision="1.0.0",
                        expected_state_revision=expected_revision,
                        resulting_state_revision=expected_revision + 1,
                        effective_order=proposal_order,
                        valid_from_order=max(0, proposal_order - 1),
                        valid_until_order=proposal_order,
                    ),
                    MixedControlTransitionRuntime(
                        address=f"{spec_address}.control-transition.direct-{phase}",
                        name=f"direct-{phase}",
                        spec={},
                        transition_id=f"direct-{phase}",
                        transition_kind="external-direction",
                        from_state_address=state_addresses[
                            "start-pending" if phase == "start" else "stop-pending"
                        ],
                        to_state_address=state_addresses[
                            "active" if phase == "start" else "stopped"
                        ],
                        policy_revision="1.0.0",
                        expected_state_revision=expected_revision + 1,
                        resulting_state_revision=expected_revision + 2,
                        effective_order=direction_order,
                        valid_from_order=proposal_order,
                        valid_until_order=direction_order,
                        proposal_address=proposal_address,
                        proposal_revision=proposal_revision,
                    ),
                )
            )
        compiled_behaviors[spec_address] = ParticipantBehaviorSpecificationRuntime(
            address=spec_address,
            name=f"{role}-study",
            spec={},
            spec_name=f"{role}-study",
            semantic_version="1.0.0",
            lifecycle_state="active",
            participant_addresses=(f"participant.behavior.{role}-operator",),
            behavior_mode="mixed-control",
            mixed_control_participant_address=(
                f"participant.behavior.{role}-operator"
            ),
            mixed_control_policy_revision="1.0.0",
            mixed_control_order_strategy="total-effective-order",
            mixed_control_initial_state_address=state_addresses["awaiting-start"],
            mixed_control_dispositions=MixedControlDispositionRulesRuntime(
                duplicate="idempotent-if-equivalent",
                stale="reject-no-state-change",
                revoked="reject-no-state-change",
                late="reject-no-state-change",
                concurrent="order-then-revalidate",
                conflict="reject-no-state-change",
            ),
            controller_states=states,
            control_transitions=tuple(transitions),
        )
    model = SimpleNamespace(
        participant_inject_deliveries={item.address: item for item in deliveries},
        behavior_specifications=compiled_behaviors,
        time_model=SimpleNamespace(constraints=constraints),
    )
    return scenario, model


def test_plan_uses_four_authored_deliveries_in_declared_time_order() -> None:
    scenario, model = _scenario_and_model()

    plan = build_participant_delivery_plan(scenario, model)

    assert [(turn.profile.value, turn.tick) for turn in plan.turns] == [
        ("red", 1),
        ("red", 3),
        ("blue", 5),
        ("blue", 7),
    ]
    assert [turn.instruction for turn in plan.turns] == [
        "authored red start instruction",
        "authored red stop instruction",
        "authored blue start instruction",
        "authored blue stop instruction",
    ]
    assert all(
        turn.realization_profile_ref == CLAUDE_CODE_REALIZATION_PROFILE
        for turn in plan.turns
    )


def _binding(role: str, phase: str) -> CaptureBinding:
    return CaptureBinding(
        capture_spec_id="capture-plan-test",
        requirement_id=f"{role}-{phase}",
        window_refs=(f"{role} participant {phase} occurrence",),
        registration_id=f"aptl.collector.participant-delivery.{role}-{phase}",
        implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1",
        effective_config_digest="sha256:" + "ab" * 32,
        channel_ref_id="participant-observation",
        channel_ref_version=None,
        channel_kind="participant-observation",
        capture_kind="observation",
        capture_scope="scenario",
        expected_media_types=("application/json",),
        required_artifact_roles=("participant_instruction_delivery",),
        sensitivity="plain",
        redaction_required=True,
        redaction_policy="redact_secrets",
        integrity_requirements=("chain_of_custody",),
        retention_policy="run_lifetime",
        loss_disclosure_required=True,
        visibility_class=CaptureVisibility.APPARATUS_ONLY,
        limits=CaptureLimits(
            max_bytes=2 * 1024 * 1024,
            max_artifact_count=1,
            max_duration_s=600,
        ),
    )


def test_plan_binds_each_turn_to_its_exact_admitted_capture() -> None:
    scenario, model = _scenario_and_model()
    capture_plan = SimpleNamespace(
        runtime_bindings=lambda: tuple(
            _binding(role, phase)
            for role, phase in (
                ("red", "start"),
                ("red", "stop"),
                ("blue", "start"),
                ("blue", "stop"),
            )
        )
    )

    plan = bind_participant_delivery_capture(
        build_participant_delivery_plan(scenario, model), capture_plan
    )

    assert [turn.capture_binding.registration_id for turn in plan.turns] == [
        "aptl.collector.participant-delivery.red-start",
        "aptl.collector.participant-delivery.red-stop",
        "aptl.collector.participant-delivery.blue-start",
        "aptl.collector.participant-delivery.blue-stop",
    ]


def test_study_capture_declares_all_four_delivery_collectors() -> None:
    contribution = StudyCapture.resolve(SimpleNamespace())
    registration_ids = {
        registration.registration_id for registration in contribution.registrations
    }

    assert {
        "aptl.collector.participant-delivery.red-start",
        "aptl.collector.participant-delivery.red-stop",
        "aptl.collector.participant-delivery.blue-start",
        "aptl.collector.participant-delivery.blue-stop",
    } <= registration_ids


def test_delivery_collector_uses_public_coordinator_for_content_addressed_evidence(
    tmp_path: Path,
) -> None:
    from aptl.backends.raes_participant_delivery import _ParticipantDeliveryCollector

    scenario, model = _scenario_and_model()
    turn = build_participant_delivery_plan(scenario, model).turns[0]
    turn = replace(turn, capture_binding=_binding("red", "start"))
    store = LocalRunStore(tmp_path / "runs")

    result = ParticipantTurnResult(
        session_id="session-secret",
        response="participant response",
        provider_payload={
            "result": "participant response",
            "session_id": "session-secret",
            "usage": {"input_tokens": 3},
        },
    )
    collector = _ParticipantDeliveryCollector(
        turn.capture_binding.registration_id  # type: ignore[union-attr]
    )
    collector.bind_payload(turn, "claude-test-model")
    collector.result = result
    acquired = acquire_evidence(
        bindings=(turn.capture_binding,),  # type: ignore[arg-type]
        collectors={collector.registration_id: collector},
        run_store=store,
        scope=RunScope("run-1", "trial-1", "attempt-1"),
        clock=FixedClockProvider("2026-09-25T00:00:00Z"),
    )
    ref = acquired.refs[0]

    record = store.read_run_json(
        "run-1", f"evidence/records/{ref.evidence_record_id}.json"
    )
    assert record["raw_content"]["content_checksum"] == {
        "algorithm": "sha256",
        "value": ref.content_digest.removeprefix("sha256:"),
    }
    payload = json.loads((store.get_run_path("run-1") / ref.content_uri).read_text())
    assert payload["instruction"] == "authored red start instruction"
    assert payload["response"] == "participant response"
    assert payload["provider_metadata"]["session_id"] == "[REDACTED]"
    assert "result" not in payload["provider_metadata"]

    index_record = _delivery_record(1, turn, result, "claude-test-model", ref)
    store.append_jsonl("run-1", "participant/inject-deliveries.jsonl", [index_record])
    persisted_index = json.loads(
        (store.get_run_path("run-1") / "participant/inject-deliveries.jsonl")
        .read_text()
        .strip()
    )
    assert persisted_index["conversation_continuity_sha256"].startswith("sha256:")
    assert persisted_index["conversation_continuity_sha256"] != "[REDACTED]"
    assert "session_sha256" not in persisted_index


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []

    def run(self, argv: tuple[str, ...], **kwargs: object) -> ProcessResult:
        self.calls.append(argv)
        self.environments.append(dict(kwargs["env"]))
        return ProcessResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "type": "result",
                    "is_error": False,
                    "result": "participant response",
                }
            ).encode(),
            stderr=b"",
        )


def test_host_adapter_uses_authenticated_cli_and_strict_profile_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    config = tmp_path / "profile.json"
    config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    config.chmod(0o600)
    work = tmp_path / "work"
    work.mkdir()
    runner = _Runner()
    adapter = ClaudeCodeHostParticipantAdapter(
        Path(sys.executable),
        work,
        runner=runner,
    )

    first = adapter.deliver(
        instruction="first authored instruction",
        model="claude-test-model",
        config_path=config,
        allowed_tools=("mcp__aptl-red__kali_info",),
        session_id="00000000-0000-4000-8000-000000000001",
        resume=False,
    )
    adapter.deliver(
        instruction="second authored instruction",
        model="claude-test-model",
        config_path=config,
        allowed_tools=("mcp__aptl-red__kali_info",),
        session_id=first.session_id,
        resume=True,
    )

    initial, resumed = runner.calls
    assert "--session-id" in initial
    assert "--resume" in resumed
    assert "--strict-mcp-config" in initial
    assert "mcp__aptl-red__kali_info" in initial
    assert "--bare" in initial
    assert "--no-session-persistence" not in initial
    assert runner.environments[0]["HOME"] == str(host_home)
    assert "XDG_CONFIG_HOME" not in runner.environments[0]
    assert "CLAUDE_CONFIG_DIR" not in runner.environments[0]
    assert "PYTHONPATH" not in runner.environments[0]


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "result", "is_error": True, "result": "provider error"},
        {"type": "assistant", "is_error": False, "result": "wrong envelope"},
        {"type": "result", "is_error": False, "result": ""},
    ],
)
def test_host_adapter_rejects_non_success_result_envelopes(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    class ErrorRunner(_Runner):
        def run(self, argv: tuple[str, ...], **kwargs: object) -> ProcessResult:
            self.calls.append(argv)
            self.environments.append(dict(kwargs["env"]))
            return ProcessResult(
                returncode=0,
                stdout=json.dumps(payload).encode(),
                stderr=b"",
            )

    config = tmp_path / "profile.json"
    config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    config.chmod(0o600)
    work = tmp_path / "work"
    work.mkdir()

    with pytest.raises(AgentExecutionError, match="invalid result"):
        ClaudeCodeHostParticipantAdapter(
            Path(sys.executable), work, runner=ErrorRunner()
        ).deliver(
            instruction="authored instruction",
            model="claude-test-model",
            config_path=config,
            allowed_tools=(),
            session_id="00000000-0000-4000-8000-000000000001",
            resume=False,
        )


def test_runtime_profile_rejects_unadmitted_mcp_environment(tmp_path: Path) -> None:
    project = tmp_path / "project"
    artifact = project / "mcp/mcp-red/build/index.js"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("", encoding="utf-8")
    source = project / ".mcp.json"
    source.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl-red": {
                        "env": {
                            "APTL_STATE_DIR": "/state",
                            "NODE_OPTIONS": "--require=/tmp/untrusted.js",
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(AgentExecutionError, match="environment is not admitted"):
        _render_runtime_profile_config(
            profile=ProfileId.RED,
            project_dir=project,
            source_config=source,
            output_dir=tmp_path,
            node_executable=Path(sys.executable),
        )


class _FakeRuntimeManager(AptlRuntimeManager):
    def __init__(self) -> None:
        self._snapshot = RuntimeSnapshot()
        self.advances: list[tuple[str, int, int]] = []

    def advance_time(
        self, clock_address: str, *, ticks: int, microstep: int
    ) -> SimpleNamespace:
        self.advances.append((clock_address, ticks, microstep))
        return SimpleNamespace(success=True, snapshot=self.snapshot)


def test_execute_plan_coordinates_time_profiles_sessions_control_and_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario, model = _scenario_and_model()
    capture_plan = SimpleNamespace(
        runtime_bindings=lambda: tuple(
            _binding(role, phase)
            for role, phase in (
                ("red", "start"),
                ("red", "stop"),
                ("blue", "start"),
                ("blue", "stop"),
            )
        )
    )
    plan = bind_participant_delivery_capture(
        build_participant_delivery_plan(scenario, model), capture_plan
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text('{"mcpServers":{}}\n', encoding="utf-8")
    store = LocalRunStore(tmp_path / "runs")
    runner = _Runner()
    manager = _FakeRuntimeManager()
    selected_profiles: list[ProfileId] = []

    def render(**kwargs: object) -> tuple[Path, tuple[str, ...]]:
        profile = kwargs["profile"]
        assert isinstance(profile, ProfileId)
        selected_profiles.append(profile)
        path = tmp_path / f"{profile.value}.json"
        path.write_text('{"mcpServers":{}}\n', encoding="utf-8")
        path.chmod(0o600)
        return path, (f"mcp__aptl-{profile.value}__tool",)

    monkeypatch.setattr(
        "aptl.backends.raes_participant_delivery._render_runtime_profile_config",
        render,
    )
    monkeypatch.setattr(
        "aptl.backends.raes_participant_delivery._which_executable",
        lambda _name: Path(sys.executable),
    )

    final_snapshot = execute_participant_delivery_plan(
        plan,
        project_dir=project,
        model="claude-sonnet-5",
        run_store=store,
        run_id="run-coordinator",
        target=replace(
            create_stub_target(),
            manifest=create_aptl_manifest(participant_inject_delivery=True),
        ),
        runtime_manager=manager,
        initial_snapshot=manager.snapshot,
        runner=runner,
    )

    assert manager.advances == [
        ("time.clock.study", 1, 0),
        ("time.clock.study", 2, 0),
        ("time.clock.study", 2, 0),
        ("time.clock.study", 2, 0),
    ]
    assert selected_profiles == [ProfileId.RED, ProfileId.BLUE]
    assert len(runner.calls) == 4
    red_session = runner.calls[0][runner.calls[0].index("--session-id") + 1]
    assert UUID(red_session)
    assert runner.calls[1][runner.calls[1].index("--resume") + 1] == red_session
    blue_session = runner.calls[2][runner.calls[2].index("--session-id") + 1]
    assert UUID(blue_session)
    assert blue_session != red_session
    assert runner.calls[3][runner.calls[3].index("--resume") + 1] == blue_session
    assert sum(
        len(events) for events in final_snapshot.participant_control_history.values()
    ) == 8
    assert sum(
        len(events) for events in final_snapshot.participant_crossing_history.values()
    ) == 16
    rows = [
        json.loads(line)
        for line in (
            store.get_run_path("run-coordinator")
            / "participant/inject-deliveries.jsonl"
        )
        .read_text()
        .splitlines()
    ]
    assert [row["sequence"] for row in rows] == [1, 2, 3, 4]
    assert len(list((store.get_run_path("run-coordinator") / "evidence/records").iterdir())) == 4
