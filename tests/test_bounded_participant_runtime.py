"""End-to-end readiness tests for the bounded participant RAES v2 loop."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from itertools import combinations
from pathlib import Path

import pytest
from raes_contracts.runtime_state import OperationState

from aptl.backends.raes import _plan_scenario
from aptl.backends.raes_participant_apparatus import (
    build_participant_apparatus,
    project_participant_turn,
)
from aptl.backends.raes_participant_driver import (
    AptlParticipantControlPlane,
    MAX_ADMITTED_PARTICIPANT_ACTIONS,
    MAX_PARTICIPANT_PROPOSALS,
    run_participant_turn,
)
from aptl.backends.raes_participant_provider import (
    DeterministicSelectionProvider,
    ManagedAgentSelectionProvider,
    ParticipantDecisionSolicitation,
    candidate_payloads,
)
from aptl.backends.raes_participant_runtime import AptlParticipantRuntime
from aptl.backends import raes_participant_realizations
from aptl.backends.raes_participant_fixture import (
    VerifiedParticipantOperation,
    execute_verified_participant_operation,
)
from aptl.backends.raes_participant_realizations import BPA_ACTION_REALIZATIONS
from aptl.core.config import AptlConfig
from aptl.core.runstore import LocalRunStore
from aptl.validation import participant_agency_readiness
from aptl.validation.participant_agency_readiness import (
    ParticipantReadinessRequest,
    validate_participant_agency_readiness,
)
from aptl.validation import participant_readiness_provider
from aptl.validation.participant_agency_qualification import (
    validate_participant_agency_qualification,
)
from aptl.workbench.credentials import WorkbenchCredentialError
from aptl.workbench.participant_source_binding import (
    CredentialBindingEvidence,
    evidence_from_error,
)

PROJECT_ROOT = Path(__file__).parents[1]
SCENARIO = PROJECT_ROOT / "scenarios/bounded-participant-agency-techvault.sdl.yaml"
NODES = (
    "webapp",
    "db",
    "workstation",
    "kali",
    "defender-console",
    "event-store",
)
BEHAVIOR_ACTIONS = {
    "participant.behavior-specification.complete-normal-session": (
        "inspect-portal",
        "authenticate-synthetic-user",
        "view-permitted-account",
        "sign-out-session",
        "verify-own-state",
    ),
    "participant.behavior-specification.update-customer-profile": (
        "authenticate-synthetic-user",
        "inspect-own-profile",
        "update-own-profile",
        "verify-own-state",
        "sign-out-session",
    ),
    "participant.behavior-specification.complete-support-request": (
        "authenticate-synthetic-user",
        "browse-help",
        "create-support-request",
        "inspect-own-support-request",
        "append-support-note",
        "verify-own-state",
        "sign-out-session",
    ),
    "participant.behavior-specification.assess-public-service": (
        "inspect-public-surface",
        "probe-permitted-endpoint",
        "inspect-response-metadata",
    ),
    "participant.behavior-specification.assess-authentication-surface": (
        "inspect-public-surface",
        "probe-permitted-endpoint",
        "submit-bounded-auth-attempt",
        "inspect-auth-outcome",
    ),
    "participant.behavior-specification.reach-synthetic-objective": (
        "inspect-public-surface",
        "probe-permitted-endpoint",
        "inspect-response-metadata",
        "discover-synthetic-objective",
        "retrieve-synthetic-marker",
    ),
    "participant.behavior-specification.triage-authentication-event": (
        "list-assigned-alerts",
        "inspect-assigned-alert",
        "query-allowed-context",
        "classify-alert",
    ),
    "participant.behavior-specification.investigate-actor-activity": (
        "list-assigned-alerts",
        "inspect-assigned-alert",
        "inspect-actor-event-set",
        "query-allowed-context",
        "correlate-selected-evidence",
    ),
    "participant.behavior-specification.apply-bounded-response": (
        "list-assigned-alerts",
        "inspect-assigned-alert",
        "query-allowed-context",
        "classify-alert",
        "apply-scoped-response",
        "verify-response-effect",
    ),
}
EXPECTED_ACTION_ADDRESSES = {
    f"participant.action-contract.{name}"
    for names in BEHAVIOR_ACTIONS.values()
    for name in names
}
MULTI_VARIANT_ACTION_BEHAVIORS = {
    "inspect-own-profile": (
        "participant.behavior-specification.update-customer-profile"
    ),
    "update-own-profile": (
        "participant.behavior-specification.update-customer-profile"
    ),
    "verify-own-state": ("participant.behavior-specification.update-customer-profile"),
    "browse-help": ("participant.behavior-specification.complete-support-request"),
    "create-support-request": (
        "participant.behavior-specification.complete-support-request"
    ),
    "append-support-note": (
        "participant.behavior-specification.complete-support-request"
    ),
    "inspect-public-surface": (
        "participant.behavior-specification.assess-public-service"
    ),
    "probe-permitted-endpoint": (
        "participant.behavior-specification.assess-public-service"
    ),
    "inspect-response-metadata": (
        "participant.behavior-specification.assess-public-service"
    ),
    "submit-bounded-auth-attempt": (
        "participant.behavior-specification.assess-authentication-surface"
    ),
    "discover-synthetic-objective": (
        "participant.behavior-specification.reach-synthetic-objective"
    ),
    "list-assigned-alerts": (
        "participant.behavior-specification.triage-authentication-event"
    ),
    "inspect-assigned-alert": (
        "participant.behavior-specification.triage-authentication-event"
    ),
    "query-allowed-context": (
        "participant.behavior-specification.triage-authentication-event"
    ),
    "classify-alert": (
        "participant.behavior-specification.triage-authentication-event"
    ),
    "inspect-actor-event-set": (
        "participant.behavior-specification.investigate-actor-activity"
    ),
    "correlate-selected-evidence": (
        "participant.behavior-specification.investigate-actor-activity"
    ),
    "apply-scoped-response": (
        "participant.behavior-specification.apply-bounded-response"
    ),
}


class _StatefulBackend:
    def __init__(self) -> None:
        self.state: dict[str, str] = {}
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def container_exec(
        self,
        name: str,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        del timeout
        command = tuple(cmd)
        self.calls.append((name, command))
        if len(command) >= 5 and command[:2] == ("sh", "-c"):
            operation = command[3]
            state_path = command[4]
            key = f"{name}:{state_path}"
            if operation == "aptl-bpa-ensure":
                self.state.setdefault(key, command[5])
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if operation == "aptl-bpa-write":
                self.state[key] = command[5]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if operation == "aptl-bpa-read":
                if key not in self.state:
                    return subprocess.CompletedProcess(cmd, 1, "", "missing")
                return subprocess.CompletedProcess(cmd, 0, self.state[key], "")
        if command[:2] == ("cat", "--"):
            content = {
                "/srv/bounded-participant/index.html": (
                    "TechVault bounded participant evaluation service"
                ),
                "/srv/bounded-participant/robots.txt": "Disallow: /debug",
                "/srv/bounded-participant/debug": "BPA-SYNTHETIC-MARKER",
            }.get(command[2])
            if content is None:
                return subprocess.CompletedProcess(cmd, 1, "", "missing")
            return subprocess.CompletedProcess(cmd, 0, content, "")
        if command and command[0] == "curl":
            return subprocess.CompletedProcess(cmd, 0, "200", "")
        if command[:3] == ("test", "!", "-e"):
            prefix = f"{name}:{command[3]}"
            absent = not any(key.startswith(prefix) for key in self.state)
            return subprocess.CompletedProcess(
                cmd,
                0 if absent else 1,
                "",
                "",
            )
        return subprocess.CompletedProcess(cmd, 0, "bounded-readback-ok", "")


def _runtime(
    tmp_path: Path,
) -> tuple[
    AptlParticipantControlPlane,
    object,
    _StatefulBackend,
    LocalRunStore,
]:
    backend = _StatefulBackend()
    target, plan = _plan_scenario(
        PROJECT_ROOT,
        AptlConfig(lab={"name": "test"}),
        backend,
        SCENARIO,
        None,
    )
    store = LocalRunStore(tmp_path / "runs")
    store.create_run("readiness-run")
    target.participant_runtime.plan_authority.bind_runtime_context(
        {"nodes": [{"name": name, "container_name": f"aptl-{name}"} for name in NODES]},
        run_store=store,
        run_id="readiness-run",
    )
    control = AptlParticipantControlPlane(
        target,
        behavior_specifications=plan.model.behavior_specifications,
    )
    return control, plan.model, backend, store


def _participant_for(model: object, behavior_address: str) -> str:
    return model.behavior_specifications[behavior_address].participant_addresses[0]


def _apparatus(participant_address: str):
    return build_participant_apparatus(
        participant_address=participant_address,
        implementation_name="aptl-readiness-agent",
        implementation_version="1.0.0",
        provider_name="deterministic",
        model=None,
        run_id="readiness-run",
    )


def test_installed_model_is_bound_as_raes_implementation_configuration() -> None:
    apparatus = build_participant_apparatus(
        participant_address="participant.behavior.security-assessor-agent",
        implementation_name="aptl-installed-codex",
        implementation_version="0.145.0",
        provider_name="codex",
        model="gpt-5-nano-2025-08-07",
        run_id="explicit-model-run",
    )

    assert apparatus.provider == "codex"
    assert apparatus.model == "gpt-5-nano-2025-08-07"
    assert apparatus.selection.configuration_ref is not None
    assert apparatus.selection.configuration_digest is not None
    assert apparatus.selection.configuration_digest.startswith("sha256:")
    assert apparatus.manifest.configuration_registry is not None
    declaration = apparatus.manifest.configuration_registry.targets["model.identifier"]
    assert declaration.value_type.value == "string"
    assert declaration.allowed_value_kinds == ["literal"]
    assert declaration.default is None


def _run_selected_action(
    control: AptlParticipantControlPlane,
    model: object,
    *,
    behavior_address: str,
    participant_address: str,
    action_name: str,
):
    """Run one named delivered action through the production participant path."""

    apparatus = _apparatus(participant_address)
    turn = project_participant_turn(
        runtime_model=model,
        runtime_snapshot=control.snapshot,
        behavior_specification_address=behavior_address,
        apparatus=apparatus,
    )
    candidate_index = next(
        index
        for index, candidate in enumerate(turn.candidates)
        if candidate.action_contract_address.endswith(f".{action_name}")
    )
    return run_participant_turn(
        control,
        behavior_specification_address=behavior_address,
        apparatus=apparatus,
        provider=DeterministicSelectionProvider(candidate_index=candidate_index),
    )


def _solicitation_for_behavior(
    tmp_path: Path,
    behavior_address: str,
    *,
    satisfy_for_action: str | None = None,
) -> ParticipantDecisionSolicitation:
    control, model, _, _ = _runtime(tmp_path)
    participant = _participant_for(model, behavior_address)
    episode_id = f"managed-{behavior_address.rsplit('.', 1)[-1]}"
    control.initialize_participant_episode(participant, episode_id=episode_id)
    if satisfy_for_action is not None:
        _satisfy_candidate_prerequisites(
            control,
            model,
            behavior_address=behavior_address,
            participant_address=participant,
            action_address=f"participant.action-contract.{satisfy_for_action}",
        )
    turn = project_participant_turn(
        runtime_model=model,
        runtime_snapshot=control.snapshot,
        behavior_specification_address=behavior_address,
        apparatus=_apparatus(participant),
    )
    view = turn.surface.participant_view
    return ParticipantDecisionSolicitation(
        participant_address=participant,
        episode_id=episode_id,
        solicitation_id="participant-selection-solicitations.managed-1",
        participant_view=view.model_dump(mode="json"),
        rendered_context=turn.rendered_context,
        observation_history=turn.observation_history,
        candidate_selections=candidate_payloads(turn.candidates),
    )


class _ManagedResponseAdapter:
    def __init__(self, response: str) -> None:
        self.response = response
        self.messages: list[str] = []
        self.response_schemas: list[Mapping[str, object] | None] = []

    def respond(
        self,
        _handle: object,
        message: str,
        *,
        response_schema: Mapping[str, object] | None = None,
    ) -> str:
        self.messages.append(message)
        self.response_schemas.append(response_schema)
        return self.response

    def close(self, _handle: object) -> None:
        return None


def _managed_provider(
    response: str,
) -> tuple[ManagedAgentSelectionProvider, _ManagedResponseAdapter]:
    adapter = _ManagedResponseAdapter(response)
    provider = ManagedAgentSelectionProvider(
        adapter=adapter,
        handle=object(),
        provider_name="codex",
        model="gpt-5-nano-2025-08-07",
        implementation_name="managed-test-provider",
        implementation_version="1.0.0",
    )
    return provider, adapter


def test_managed_provider_compacts_large_surface_and_maps_exact_candidate(
    tmp_path: Path,
) -> None:
    solicitation = _solicitation_for_behavior(
        tmp_path,
        "participant.behavior-specification.triage-authentication-event",
        satisfy_for_action="classify-alert",
    )
    assert len(solicitation.candidate_selections) == 201
    provider, adapter = _managed_provider('{"candidate":200}')

    selection = json.loads(provider.select(solicitation))

    assert selection == solicitation.candidate_selections[200]
    prompt = json.loads(adapter.messages[0])
    assert len(adapter.messages[0]) <= (
        participant_readiness_provider.MAX_INSTALLED_PARTICIPANT_PROMPT_CHARS
    )
    assert "candidate_selections" not in prompt
    assert prompt["candidate_encoding"] == [
        "candidate",
        "action",
        "arguments",
    ]
    assert len(prompt["candidates"]) == len(solicitation.candidate_selections)
    assert {prompt["actions"][candidate[1]] for candidate in prompt["candidates"]} == {
        item["action_contract_address"] for item in solicitation.candidate_selections
    }
    assert {candidate[0] for candidate in prompt["candidates"]} == set(
        range(len(solicitation.candidate_selections))
    )
    assert adapter.response_schemas == [
        {
            "type": "object",
            "properties": {
                "candidate": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 200,
                }
            },
            "required": ["candidate"],
            "additionalProperties": False,
        }
    ]


@pytest.mark.parametrize(
    "response",
    [
        "",
        "not-json",
        "[]",
        "{}",
        '{"candidate":true}',
        '{"candidate":"0"}',
        '{"candidate":-1}',
        '{"candidate":201}',
        '{"candidate":0,"extra":1}',
        '{"candidate":0,"candidate":1}',
    ],
)
def test_managed_provider_rejects_invalid_compact_selections(
    tmp_path: Path,
    response: str,
) -> None:
    solicitation = _solicitation_for_behavior(
        tmp_path,
        "participant.behavior-specification.triage-authentication-event",
    )
    provider, _ = _managed_provider(response)

    with pytest.raises(ValueError, match="compact participant selection"):
        provider.select(solicitation)


def test_invalid_compact_selection_fails_before_admission_or_realization(
    tmp_path: Path,
) -> None:
    control, model, backend, store = _runtime(tmp_path)
    behavior = "participant.behavior-specification.triage-authentication-event"
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id="invalid-compact-selection",
    )
    provider, _ = _managed_provider('{"candidate":201}')
    apparatus = _apparatus(participant)

    with pytest.raises(ValueError, match="participant selection operation failed"):
        run_participant_turn(
            control,
            behavior_specification_address=behavior,
            apparatus=apparatus,
            provider=provider,
        )

    assert control.snapshot.participant_behavior_history == {}
    assert backend.calls == []
    record = json.loads(
        (
            store.get_run_path("readiness-run")
            / "evaluator/participant-control-evidence.jsonl"
        ).read_text()
    )
    assert record["solicitation_state"] == "failed"
    assert record["admission_operation_id"] is None
    assert record["selected_action_contract_address"] is None


def test_installed_provider_adapters_use_the_bounded_choice_prompt_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []

    class _Adapter:
        def __init__(self, **kwargs: object) -> None:
            captured.append(kwargs)

    monkeypatch.setattr(
        participant_readiness_provider,
        "ClaudeCodeManagedAgentAdapter",
        _Adapter,
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "CodexManagedAgentAdapter",
        _Adapter,
    )

    participant_readiness_provider._launch_adapter(
        "claude",
        tmp_path / "claude",
        tmp_path / "claude-work",
    )
    participant_readiness_provider._launch_adapter(
        "codex",
        tmp_path / "codex",
        tmp_path / "codex-work",
    )

    assert [item["max_prompt_chars"] for item in captured] == [
        participant_readiness_provider.MAX_INSTALLED_PARTICIPANT_PROMPT_CHARS,
        participant_readiness_provider.MAX_INSTALLED_PARTICIPANT_PROMPT_CHARS,
    ]


def test_all_nine_behaviors_project_the_exact_compiled_action_sets(
    tmp_path: Path,
) -> None:
    control, model, _, _ = _runtime(tmp_path)
    initialized: set[str] = set()

    for behavior_address, expected_names in BEHAVIOR_ACTIONS.items():
        participant = _participant_for(model, behavior_address)
        if participant not in initialized:
            control.initialize_participant_episode(
                participant,
                episode_id=f"projection-{participant.rsplit('.', 1)[-1]}",
            )
            initialized.add(participant)
        else:
            control.reset_participant_episode(
                participant,
                episode_id=f"projection-{behavior_address.rsplit('.', 1)[-1]}",
            )
        turn = project_participant_turn(
            runtime_model=model,
            runtime_snapshot=control.snapshot,
            behavior_specification_address=behavior_address,
            apparatus=_apparatus(participant),
        )

        assert turn.surface.surface_state == "delivered"
        assert {
            entry.action_contract_address.rsplit(".", 1)[-1]
            for entry in turn.surface.participant_view.action_entries
        } == set(expected_names)
        participant_payload = turn.surface.participant_view.model_dump_json()
        rendered_payload = json.dumps(turn.rendered_context)
        assert "study-hidden-truth" not in participant_payload
        assert "study-evaluator-evidence" not in participant_payload
        assert len(turn.rendered_context) == 1
        assert turn.rendered_context[0]["information_ref"] in (
            turn.surface.participant_view.visible_context_refs
        )
        assert "participant-visible" not in rendered_payload
        assert "BPA-HIDDEN-CANARY" not in rendered_payload


def test_projected_candidates_require_successful_prior_observations(
    tmp_path: Path,
) -> None:
    behavior = "participant.behavior-specification.triage-authentication-event"
    control, model, _, _ = _runtime(tmp_path)
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(participant, episode_id="eligible-actions")

    def available_actions() -> set[str]:
        turn = project_participant_turn(
            runtime_model=model,
            runtime_snapshot=control.snapshot,
            behavior_specification_address=behavior,
            apparatus=_apparatus(participant),
        )
        return {
            candidate.action_contract_address.rsplit(".", 1)[-1]
            for candidate in turn.candidates
        }

    assert available_actions() == {"list-assigned-alerts"}

    _run_selected_action(
        control,
        model,
        behavior_address=behavior,
        participant_address=participant,
        action_name="list-assigned-alerts",
    )
    assert available_actions() == {
        "list-assigned-alerts",
        "inspect-assigned-alert",
    }

    _run_selected_action(
        control,
        model,
        behavior_address=behavior,
        participant_address=participant,
        action_name="inspect-assigned-alert",
    )
    assert available_actions() == {
        "list-assigned-alerts",
        "inspect-assigned-alert",
        "query-allowed-context",
        "classify-alert",
    }


def test_projected_candidates_require_a_current_authenticated_session(
    tmp_path: Path,
) -> None:
    behavior = "participant.behavior-specification.complete-normal-session"
    control, model, _, _ = _runtime(tmp_path)
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(participant, episode_id="session-state")

    def available_actions() -> set[str]:
        turn = project_participant_turn(
            runtime_model=model,
            runtime_snapshot=control.snapshot,
            behavior_specification_address=behavior,
            apparatus=_apparatus(participant),
        )
        return {
            candidate.action_contract_address.rsplit(".", 1)[-1]
            for candidate in turn.candidates
        }

    assert "sign-out-session" not in available_actions()
    _run_selected_action(
        control,
        model,
        behavior_address=behavior,
        participant_address=participant,
        action_name="authenticate-synthetic-user",
    )
    assert "sign-out-session" in available_actions()
    _run_selected_action(
        control,
        model,
        behavior_address=behavior,
        participant_address=participant,
        action_name="sign-out-session",
    )
    assert "sign-out-session" not in available_actions()
    _run_selected_action(
        control,
        model,
        behavior_address=behavior,
        participant_address=participant,
        action_name="authenticate-synthetic-user",
    )
    assert "sign-out-session" in available_actions()


def _projected_candidates_for_action(
    tmp_path: Path,
    behavior_address: str,
    action_name: str,
):
    control, model, _, _ = _runtime(tmp_path)
    participant = _participant_for(model, behavior_address)
    control.initialize_participant_episode(
        participant,
        episode_id=f"variants-{action_name}",
    )
    _satisfy_candidate_prerequisites(
        control,
        model,
        behavior_address=behavior_address,
        participant_address=participant,
        action_address=f"participant.action-contract.{action_name}",
    )
    turn = project_participant_turn(
        runtime_model=model,
        runtime_snapshot=control.snapshot,
        behavior_specification_address=behavior_address,
        apparatus=_apparatus(participant),
    )
    return tuple(
        candidate
        for candidate in turn.candidates
        if candidate.action_contract_address.endswith(f".{action_name}")
    )


def _satisfy_candidate_prerequisites(
    control: AptlParticipantControlPlane,
    model: object,
    *,
    behavior_address: str,
    participant_address: str,
    action_address: str,
) -> None:
    """Create the successful episode observations required by one action."""

    for prior_address in raes_participant_realizations.REQUIRED_PRIOR_ACTIONS.get(
        action_address,
        (),
    ):
        _satisfy_candidate_prerequisites(
            control,
            model,
            behavior_address=behavior_address,
            participant_address=participant_address,
            action_address=prior_address,
        )
        completed = {
            event["action_contract_address"]
            for event in control.snapshot.participant_behavior_history.get(
                participant_address,
                [],
            )
            if event["event_type"] == "observation_emitted"
            and event["action_result"]["status"] == "succeeded"
        }
        if prior_address not in completed:
            _run_selected_action(
                control,
                model,
                behavior_address=behavior_address,
                participant_address=participant_address,
                action_name=prior_address.rsplit(".", 1)[-1],
            )


def test_decision_surface_enumerates_every_finite_governed_choice(
    tmp_path: Path,
) -> None:
    auth = _projected_candidates_for_action(
        tmp_path / "auth",
        "participant.behavior-specification.assess-authentication-surface",
        "submit-bounded-auth-attempt",
    )
    metadata = _projected_candidates_for_action(
        tmp_path / "metadata",
        "participant.behavior-specification.assess-public-service",
        "inspect-response-metadata",
    )
    alerts = _projected_candidates_for_action(
        tmp_path / "alerts",
        "participant.behavior-specification.triage-authentication-event",
        "inspect-assigned-alert",
    )
    actors = _projected_candidates_for_action(
        tmp_path / "actors",
        "participant.behavior-specification.investigate-actor-activity",
        "inspect-actor-event-set",
    )

    assert len(auth) == 12
    assert {
        (
            item.arguments["identity"],
            item.arguments["credential_candidate"],
            item.arguments["attempt_number"],
        )
        for item in auth
    } == {
        (identity, credential, attempt)
        for identity in (
            "identities.synthetic-user-a",
            "identities.synthetic-user-b",
        )
        for credential in (
            "credentials.synthetic-candidate-1",
            "credentials.synthetic-candidate-2",
        )
        for attempt in range(1, 4)
    }
    assert len(metadata) == 14
    assert {tuple(item.arguments["fields"]) for item in metadata} == {
        fields
        for size in range(1, 4)
        for fields in combinations(
            ("status", "content-type", "content-length", "location"),
            size,
        )
    }
    assert len(alerts) == 168
    assert len(actors) == 10
    for candidates in (auth, metadata, alerts, actors):
        assert len({item.proposal_ref for item in candidates}) == len(candidates)


def test_each_governed_variant_changes_the_verified_native_semantics(
    tmp_path: Path,
) -> None:
    backend = _StatefulBackend()
    containers = {name: f"aptl-{name}" for name in NODES}
    selected = {
        action_name: _projected_candidates_for_action(
            tmp_path / action_name,
            behavior_address,
            action_name,
        )
        for action_name, behavior_address in MULTI_VARIANT_ACTION_BEHAVIORS.items()
    }
    preparations = (
        (
            "authenticate-synthetic-user",
            {"identity": "identities.benign-customer"},
        ),
        (
            "create-support-request",
            {"request_template": "account-access-question"},
        ),
        (
            "append-support-note",
            {"note_template": "confirm-details"},
        ),
        (
            "probe-permitted-endpoint",
            {"endpoint": "/", "method": "GET"},
        ),
    )
    for action_name, arguments in preparations:
        address = f"participant.action-contract.{action_name}"
        operation = execute_verified_participant_operation(
            backend=backend,
            container_by_node=containers,
            action_contract_address=address,
            arguments=arguments,
            participant_address="participant.behavior.semantic-probe",
            episode_id="semantic-variants",
            target_nodes=BPA_ACTION_REALIZATIONS[address].target_nodes,
        )
        assert operation.success is True

    for action_name, candidates in selected.items():
        address = f"participant.action-contract.{action_name}"
        realization = BPA_ACTION_REALIZATIONS[address]
        digests: set[str] = set()
        for candidate in candidates:
            operation = execute_verified_participant_operation(
                backend=backend,
                container_by_node=containers,
                action_contract_address=address,
                arguments=candidate.arguments,
                participant_address="participant.behavior.semantic-probe",
                episode_id="semantic-variants",
                target_nodes=realization.target_nodes,
            )
            assert operation.success is True
            digest = (
                operation.post_state_digest
                if realization.mutates_state
                else operation.pre_state_digest
            )
            digests.add(digest)
        assert len(digests) == len(candidates)


def test_head_endpoint_probe_uses_curl_head_semantics() -> None:
    backend = _StatefulBackend()
    address = "participant.action-contract.probe-permitted-endpoint"

    operation = execute_verified_participant_operation(
        backend=backend,
        container_by_node={name: f"aptl-{name}" for name in NODES},
        action_contract_address=address,
        arguments={"endpoint": "/", "method": "HEAD"},
        participant_address="participant.behavior.semantic-probe",
        episode_id="head-semantics",
        target_nodes=BPA_ACTION_REALIZATIONS[address].target_nodes,
    )

    assert operation.success is True
    curl_calls = [command for _, command in backend.calls if command[0] == "curl"]
    assert curl_calls
    assert all("--head" in command for command in curl_calls)
    assert all("-X" not in command for command in curl_calls)


def test_participant_pipeline_accepts_only_declared_idempotent_stutters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = "participant.behavior-specification.complete-normal-session"
    action_name = "authenticate-synthetic-user"
    action_address = f"participant.action-contract.{action_name}"

    control, model, _, store = _runtime(tmp_path / "permitted")
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id="permitted-idempotent-stutter",
    )
    for _ in range(2):
        outcome = _run_selected_action(
            control,
            model,
            behavior_address=behavior,
            participant_address=participant,
            action_name=action_name,
        )
        assert (
            control.get_operation(outcome.admission_receipt.operation_id).state
            is OperationState.SUCCEEDED
        )

    evidence_path = (
        store.get_run_path("readiness-run")
        / "evaluator/participant-action-evidence.jsonl"
    )
    evidence = [json.loads(line) for line in evidence_path.read_text().splitlines()]
    assert [record["state_changed"] for record in evidence] == [True, False]
    assert evidence[-1]["allows_idempotent_stutter"] is True
    assert evidence[-1]["status"] == "succeeded"
    assert (
        control.snapshot.participant_behavior_history[participant][-1]["action_result"][
            "status"
        ]
        == "succeeded"
    )

    strict_realization = replace(
        BPA_ACTION_REALIZATIONS[action_address],
        allows_idempotent_stutter=False,
    )
    monkeypatch.setattr(
        raes_participant_realizations,
        "BPA_ACTION_REALIZATIONS",
        {
            **BPA_ACTION_REALIZATIONS,
            action_address: strict_realization,
        },
    )
    assert (
        BPA_ACTION_REALIZATIONS[
            "participant.action-contract.sign-out-session"
        ].allows_idempotent_stutter
        is False
    )

    control, model, _, store = _runtime(tmp_path / "strict")
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id="undeclared-idempotent-stutter",
    )
    for _ in range(2):
        _run_selected_action(
            control,
            model,
            behavior_address=behavior,
            participant_address=participant,
            action_name=action_name,
        )

    evidence_path = (
        store.get_run_path("readiness-run")
        / "evaluator/participant-action-evidence.jsonl"
    )
    evidence = [json.loads(line) for line in evidence_path.read_text().splitlines()]
    assert [record["state_changed"] for record in evidence] == [True, False]
    assert evidence[-1]["allows_idempotent_stutter"] is False
    assert evidence[-1]["status"] == "failed"
    assert evidence[-1]["failure_class"] == "backend_error"
    terminal = control.snapshot.participant_behavior_history[participant][-1]
    assert terminal["action_result"]["status"] == "failed"
    assert terminal["action_result"]["failure_class"] == "backend_error"


def test_provider_invocation_is_a_raes_operation_and_admission_commits_history(
    tmp_path: Path,
) -> None:
    control, model, backend, store = _runtime(tmp_path)
    behavior = "participant.behavior-specification.complete-normal-session"
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(participant, episode_id="green-1")

    outcome = run_participant_turn(
        control,
        behavior_specification_address=behavior,
        apparatus=_apparatus(participant),
        provider=DeterministicSelectionProvider(candidate_index=0),
    )

    assert (
        control.get_operation(outcome.solicitation_receipt.operation_id).state
        is OperationState.SUCCEEDED
    )
    assert (
        control.get_operation(outcome.admission_receipt.operation_id).state
        is OperationState.SUCCEEDED
    )
    assert [
        event["event_type"]
        for event in control.snapshot.participant_behavior_history[participant]
    ] == [
        "action_attempted",
        "state_transition_recorded",
        "observation_emitted",
    ]
    history = control.snapshot.participant_behavior_history[participant]
    assert participant in model.participant_behaviors
    assert all(event["participant_address"] == participant for event in history)
    assert all(
        event["action_contract_address"] in model.action_contracts for event in history
    )
    participant_records = (
        store.get_run_path("readiness-run") / "participant/observations.jsonl"
    ).read_text()
    evaluator_records = (
        store.get_run_path("readiness-run")
        / "evaluator/participant-action-evidence.jsonl"
    ).read_text()
    transaction_paths = tuple(
        (
            store.get_run_path("readiness-run")
            / "evaluator/participant-action-transactions"
        ).glob("*.json")
    )
    control_records = (
        store.get_run_path("readiness-run")
        / "evaluator/participant-control-evidence.jsonl"
    ).read_text()
    action_instance = json.loads(participant_records)["action_instance_id"]
    assert action_instance in evaluator_records
    assert len(transaction_paths) == 1
    transaction = json.loads(transaction_paths[0].read_text())
    assert transaction["action_instance_id"] == action_instance
    assert transaction["participant_projection"] == json.loads(participant_records)
    assert transaction["evaluator_projection"] == json.loads(evaluator_records)
    control_record = json.loads(control_records)
    assert control_record["solicitation_state"] == "succeeded"
    assert control_record["admission_state"] == "succeeded"
    assert (
        control_record["selected_action_contract_address"]
        == "participant.action-contract.inspect-portal"
    )
    assert outcome.selected_action_contract_address in model.action_contracts
    assert control_record["official_capture_started"] is False
    assert "BPA-HIDDEN-CANARY" not in control_records
    assert {container for container, _ in backend.calls} == {"aptl-webapp"}
    action_entries = [
        entry
        for entry in control.snapshot.entries.values()
        if entry.resource_type == "participant-action-instance"
    ]
    assert len(action_entries) == 1
    assert (
        action_entries[0].payload["action_contract_address"]
        == outcome.selected_action_contract_address
    )

    next_turn = project_participant_turn(
        runtime_model=model,
        runtime_snapshot=control.snapshot,
        behavior_specification_address=behavior,
        apparatus=_apparatus(participant),
    )
    assert next_turn.observation_history == (
        {
            "action_instance_id": action_instance,
            "action_contract_address": ("participant.action-contract.inspect-portal"),
            "status": "succeeded",
            "failure_class": None,
            "observations": ["portal HTTP status 200 with independently read content"],
        },
    )
    assert "pre_state_digest" not in json.dumps(next_turn.observation_history)
    assert "study-evaluator-evidence" not in json.dumps(next_turn.observation_history)


def test_installed_provider_control_evidence_records_model_configuration(
    tmp_path: Path,
) -> None:
    control, model, _, store = _runtime(tmp_path)
    behavior = "participant.behavior-specification.complete-normal-session"
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id="model-provenance",
    )
    provider, _ = _managed_provider('{"candidate":0}')
    apparatus = build_participant_apparatus(
        participant_address=participant,
        implementation_name=provider.implementation_name,
        implementation_version=provider.implementation_version,
        provider_name=provider.provider_name,
        model=provider.model,
        run_id="readiness-run",
    )

    run_participant_turn(
        control,
        behavior_specification_address=behavior,
        apparatus=apparatus,
        provider=provider,
    )

    record = json.loads(
        (
            store.get_run_path("readiness-run")
            / "evaluator/participant-control-evidence.jsonl"
        ).read_text()
    )
    assert record["schema"] == "aptl.participant-control-evidence/v2"
    assert record["provider"] == "codex"
    assert record["model"] == "gpt-5-nano-2025-08-07"
    assert (
        record["implementation_configuration_ref"]
        == apparatus.selection.configuration_ref
    )
    assert (
        record["implementation_configuration_digest"]
        == apparatus.selection.configuration_digest
    )
    assert record["official_capture_started"] is False


class _MalformedProvider:
    implementation_name = "malformed-provider"
    implementation_version = "1.0.0"

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        del solicitation
        return "not-json"


class _CountingProvider(DeterministicSelectionProvider):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        self.calls += 1
        return super().select(solicitation)


class _CountingMalformedProvider(_MalformedProvider):
    def __init__(self) -> None:
        self.calls = 0

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        self.calls += 1
        return super().select(solicitation)


class _OutOfSetProvider:
    implementation_name = "out-of-set-provider"
    implementation_version = "1.0.0"

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        payload = dict(solicitation.candidate_selections[0])
        payload["proposal_ref"] = "participant-proposals.outside-delivered-set"
        return json.dumps(payload)


def test_consumed_solicitation_cannot_invoke_provider_again(
    tmp_path: Path,
) -> None:
    control, model, _, _ = _runtime(tmp_path)
    behavior = "participant.behavior-specification.complete-normal-session"
    participant = _participant_for(model, behavior)
    episode_id = "replay-after-consumption"
    control.initialize_participant_episode(participant, episode_id=episode_id)
    turn = project_participant_turn(
        runtime_model=model,
        runtime_snapshot=control.snapshot,
        behavior_specification_address=behavior,
        apparatus=_apparatus(participant),
    )
    view = turn.surface.participant_view
    solicitation = ParticipantDecisionSolicitation(
        participant_address=participant,
        episode_id=episode_id,
        solicitation_id="participant-selection-solicitations.replay-1",
        participant_view=view.model_dump(mode="json"),
        rendered_context=turn.rendered_context,
        observation_history=turn.observation_history,
        candidate_selections=candidate_payloads(turn.candidates),
    )
    provider = _CountingProvider()
    runtime = control._target.participant_runtime
    assert isinstance(runtime, AptlParticipantRuntime)
    runtime.bind_selection_provider(provider)

    first = runtime.solicit_selection(solicitation, control.snapshot)
    assert first.success is True
    runtime.consume_selection(solicitation.solicitation_id)
    replay = runtime.solicit_selection(solicitation, control.snapshot)

    assert replay.success is False
    assert provider.calls == 1
    assert replay.diagnostics[0].message == (
        "participant selection solicitation was replayed"
    )

    next_episode_id = "replay-after-reset"
    control.reset_participant_episode(
        participant,
        episode_id=next_episode_id,
    )
    next_turn = project_participant_turn(
        runtime_model=model,
        runtime_snapshot=control.snapshot,
        behavior_specification_address=behavior,
        apparatus=_apparatus(participant),
    )
    next_view = next_turn.surface.participant_view
    next_episode = replace(
        solicitation,
        episode_id=next_episode_id,
        participant_view=next_view.model_dump(mode="json"),
        rendered_context=next_turn.rendered_context,
        observation_history=next_turn.observation_history,
        candidate_selections=candidate_payloads(next_turn.candidates),
    )

    accepted_after_reset = runtime.solicit_selection(
        next_episode,
        control.snapshot,
    )

    assert accepted_after_reset.success is True
    assert provider.calls == 2


def test_malformed_and_out_of_set_provider_outputs_fail_before_admission(
    tmp_path: Path,
) -> None:
    for index, provider in enumerate((_MalformedProvider(), _OutOfSetProvider())):
        control, model, backend, store = _runtime(tmp_path / str(index))
        behavior = "participant.behavior-specification.complete-normal-session"
        participant = _participant_for(model, behavior)
        control.initialize_participant_episode(
            participant, episode_id=f"rejected-{index}"
        )

        try:
            run_participant_turn(
                control,
                behavior_specification_address=behavior,
                apparatus=_apparatus(participant),
                provider=provider,
            )
        except ValueError as exc:
            assert str(exc) == "participant selection operation failed"
        else:
            raise AssertionError("invalid provider output reached admission")

        assert control.snapshot.participant_behavior_history == {}
        assert backend.calls == []
        control_evidence = (
            store.get_run_path("readiness-run")
            / "evaluator/participant-control-evidence.jsonl"
        )
        assert control_evidence.exists()
        record = json.loads(control_evidence.read_text())
        assert record["solicitation_state"] == "failed"
        assert record["admission_operation_id"] is None
        assert record["selected_action_contract_address"] is None


def test_proposal_and_admitted_action_budgets_fail_closed(
    tmp_path: Path,
) -> None:
    behavior = "participant.behavior-specification.assess-public-service"

    control, model, _, _ = _runtime(tmp_path / "admitted")
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id="admitted-budget",
    )
    apparatus = _apparatus(participant)
    for _ in range(MAX_ADMITTED_PARTICIPANT_ACTIONS):
        run_participant_turn(
            control,
            behavior_specification_address=behavior,
            apparatus=apparatus,
            provider=DeterministicSelectionProvider(),
        )
    provider = DeterministicSelectionProvider()
    with pytest.raises(
        ValueError,
        match="participant selection operation failed",
    ):
        run_participant_turn(
            control,
            behavior_specification_address=behavior,
            apparatus=apparatus,
            provider=provider,
        )
    assert len(control.snapshot.participant_behavior_history[participant]) == (
        MAX_ADMITTED_PARTICIPANT_ACTIONS * 3
    )

    control, model, backend, _ = _runtime(tmp_path / "proposals")
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id="proposal-budget",
    )
    apparatus = _apparatus(participant)
    provider = _CountingMalformedProvider()
    for _ in range(MAX_PARTICIPANT_PROPOSALS + 1):
        with pytest.raises(
            ValueError,
            match="participant selection operation failed",
        ):
            run_participant_turn(
                control,
                behavior_specification_address=behavior,
                apparatus=apparatus,
                provider=provider,
            )
    assert provider.calls == MAX_PARTICIPANT_PROPOSALS
    assert control.snapshot.participant_behavior_history == {}
    assert backend.calls == []


def test_all_26_action_realizations_execute_through_raes_v2(
    tmp_path: Path,
) -> None:
    control, model, backend, store = _runtime(tmp_path)
    initialized: set[str] = set()
    observed_actions: set[str] = set()

    for behavior_address, action_names in BEHAVIOR_ACTIONS.items():
        participant = _participant_for(model, behavior_address)
        if participant in initialized:
            control.reset_participant_episode(
                participant,
                episode_id=f"execution-{behavior_address.rsplit('.', 1)[-1]}",
            )
        else:
            control.initialize_participant_episode(
                participant,
                episode_id=f"execution-{participant.rsplit('.', 1)[-1]}",
            )
            initialized.add(participant)
        apparatus = _apparatus(participant)
        for action_name in action_names:
            turn = project_participant_turn(
                runtime_model=model,
                runtime_snapshot=control.snapshot,
                behavior_specification_address=behavior_address,
                apparatus=apparatus,
            )
            candidate_index = next(
                index
                for index, candidate in enumerate(turn.candidates)
                if candidate.action_contract_address.endswith(f".{action_name}")
            )
            outcome = run_participant_turn(
                control,
                behavior_specification_address=behavior_address,
                apparatus=apparatus,
                provider=DeterministicSelectionProvider(
                    candidate_index=candidate_index
                ),
            )
            status = control.get_operation(outcome.admission_receipt.operation_id)
            assert status.state is OperationState.SUCCEEDED
            assert outcome.selected_action_contract_address in model.action_contracts
            terminal = control.snapshot.participant_behavior_history[participant][-1]
            assert terminal["action_result"]["status"] == "succeeded"
            assert terminal["participant_address"] in model.participant_behaviors
            assert (
                terminal["action_contract_address"]
                == outcome.selected_action_contract_address
            )
            observed_actions.add(outcome.selected_action_contract_address)

    assert observed_actions == set(model.action_contracts) == EXPECTED_ACTION_ADDRESSES
    evaluator_path = (
        store.get_run_path("readiness-run")
        / "evaluator/participant-action-evidence.jsonl"
    )
    assert len(evaluator_path.read_text().splitlines()) == sum(
        len(actions) for actions in BEHAVIOR_ACTIONS.values()
    )
    evaluator_records = [
        json.loads(line) for line in evaluator_path.read_text().splitlines()
    ]
    assert all(record["status"] == "succeeded" for record in evaluator_records)
    assert all(
        record["established_precondition_ids"] and record["established_effect_ids"]
        for record in evaluator_records
    )
    assert {
        record["action_contract_address"] for record in evaluator_records
    } == EXPECTED_ACTION_ADDRESSES
    assert all(set(record["target_refs"]) <= set(NODES) for record in evaluator_records)
    assert all(
        record["allows_idempotent_stutter"]
        is BPA_ACTION_REALIZATIONS[
            record["action_contract_address"]
        ].allows_idempotent_stutter
        for record in evaluator_records
    )
    touched_containers = {name for name, _ in backend.calls}
    assert {
        "aptl-webapp",
        "aptl-db",
        "aptl-kali",
        "aptl-defender-console",
        "aptl-event-store",
    } <= touched_containers


def test_action_evidence_is_not_published_when_raes_rejects_native_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, model, _, store = _runtime(tmp_path)
    behavior = "participant.behavior-specification.complete-normal-session"
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(participant, episode_id="commit-reject")
    original = raes_participant_realizations.execute_participant_realization

    def reject_after_native_model(**kwargs):
        execution = original(**kwargs)
        assert execution.native.action_result is not None
        bad_result = execution.native.action_result.model_copy(
            update={"episode_id": "wrong-episode"}
        )
        return replace(
            execution,
            native=replace(execution.native, action_result=bad_result),
        )

    monkeypatch.setattr(
        raes_participant_realizations,
        "execute_participant_realization",
        reject_after_native_model,
    )
    outcome = run_participant_turn(
        control,
        behavior_specification_address=behavior,
        apparatus=_apparatus(participant),
        provider=DeterministicSelectionProvider(candidate_index=0),
    )

    assert (
        control.get_operation(outcome.admission_receipt.operation_id).state
        is OperationState.FAILED
    )
    run_path = store.get_run_path("readiness-run")
    assert not (run_path / "participant/observations.jsonl").exists()
    assert not (run_path / "evaluator/participant-action-evidence.jsonl").exists()
    assert not (run_path / "evaluator/participant-action-transactions").exists()


class _FaultingActionEvidenceStore:
    def __init__(self, store: LocalRunStore, phase: str) -> None:
        self._store = store
        self._phase = phase

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    def create_run_json_once(
        self,
        run_id: str,
        relative_path: str,
        payload: object,
    ) -> Path:
        if self._phase == "transaction":
            raise OSError("injected transaction failure")
        return self._store.create_run_json_once(
            run_id,
            relative_path,
            payload,
        )

    def append_jsonl(
        self,
        run_id: str,
        relative_path: str,
        records: list[dict],
    ) -> None:
        if (
            self._phase == "participant-projection"
            and relative_path == "participant/observations.jsonl"
        ) or (
            self._phase == "evaluator-projection"
            and relative_path == "evaluator/participant-action-evidence.jsonl"
        ):
            raise OSError(f"injected {self._phase} failure")
        self._store.append_jsonl(run_id, relative_path, records)


@pytest.mark.parametrize(
    "phase",
    ("transaction", "participant-projection", "evaluator-projection"),
)
def test_evidence_archival_failure_cannot_discard_an_accepted_transition(
    tmp_path: Path,
    phase: str,
) -> None:
    control, model, _, store = _runtime(tmp_path)
    runtime = control._target.participant_runtime
    assert isinstance(runtime, AptlParticipantRuntime)
    assert runtime.plan_authority is not None
    runtime.plan_authority.run_store = _FaultingActionEvidenceStore(
        store,
        phase,
    )
    behavior = "participant.behavior-specification.complete-normal-session"
    participant = _participant_for(model, behavior)
    control.initialize_participant_episode(
        participant,
        episode_id=f"evidence-failure-{phase}",
    )

    outcome = run_participant_turn(
        control,
        behavior_specification_address=behavior,
        apparatus=_apparatus(participant),
        provider=DeterministicSelectionProvider(candidate_index=0),
    )

    status = control.get_operation(outcome.admission_receipt.operation_id)
    assert status is not None
    assert status.state is OperationState.SUCCEEDED
    assert any(
        diagnostic.code == "aptl.participant-runtime.evidence-publication-failed"
        for diagnostic in status.diagnostics
    )
    assert len(control.snapshot.participant_behavior_history[participant]) == 3
    assert len(runtime.behavior_history()[participant]) == 3
    assert any(
        entry.resource_type == "participant-action-instance"
        for entry in control.snapshot.entries.values()
    )
    transaction_dir = (
        store.get_run_path("readiness-run")
        / "evaluator/participant-action-transactions"
    )
    assert transaction_dir.exists() is (phase != "transaction")


def test_provider_executable_is_admitted_before_version_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "claude"
    subprocess_called = False

    monkeypatch.setattr(
        participant_readiness_provider.shutil,
        "which",
        lambda _name: str(candidate),
    )

    def reject_executable(_path: Path) -> Path:
        raise ValueError("untrusted provider executable")

    def unexpected_run(*_args: object, **_kwargs: object) -> object:
        nonlocal subprocess_called
        subprocess_called = True
        raise AssertionError("version probe crossed executable admission")

    monkeypatch.setattr(
        participant_readiness_provider,
        "_admitted_executable",
        reject_executable,
    )
    monkeypatch.setattr(
        participant_readiness_provider.subprocess,
        "run",
        unexpected_run,
    )
    monkeypatch.setenv("APTL_SELECTED_CLAUDE", "model-secret")

    config = AptlConfig(
        experiment={
            "participant_models": {"claude": "claude-sonnet-4-5-20250929"},
            "participant_credential_sources": {
                "claude": {
                    "kind": "process-environment",
                    "variable": "APTL_SELECTED_CLAUDE",
                }
            },
        }
    )
    with pytest.raises(ValueError, match="untrusted provider executable"):
        participant_agency_readiness._selection_provider(
            "claude",
            config=config,
            project_dir=tmp_path,
            run_id="rejected-provider",
        )

    assert subprocess_called is False


def test_provider_version_probe_uses_only_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def version_run(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="provider 1.2.3\n",
            stderr="",
        )

    monkeypatch.setattr(
        participant_readiness_provider.subprocess,
        "run",
        version_run,
    )

    version = participant_agency_readiness._installed_version(Path("/trusted/provider"))

    assert version == "1.2.3"
    assert captured["env"] == {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "NO_COLOR": "1",
    }
    assert captured["stdin"] is subprocess.DEVNULL


def test_installed_provider_uses_only_the_configured_credential_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_secret = "configured-claude-secret"
    ambient_secret = "unselected-native-secret"
    captured: dict[str, object] = {}

    class _Adapter:
        def launch(self, launch: object, credentials: object) -> object:
            captured["launch"] = launch
            captured["credentials"] = dict(credentials)  # type: ignore[arg-type]
            return object()

        def list_tools(self, _handle: object) -> dict[str, object]:
            return {}

        def credential_isolation_controls(self, _handle: object) -> tuple[str, ...]:
            return (
                "minimal-child-environment",
                "private-home",
                "private-claude-config",
                "claude-bare-api-key-mode",
            )

        def close(self, _handle: object) -> None:
            captured["closed"] = True

    monkeypatch.setenv("APTL_SELECTED_CLAUDE", configured_secret)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ambient_secret)
    monkeypatch.setattr(
        participant_readiness_provider.shutil,
        "which",
        lambda _name: str(tmp_path / "claude"),
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "_admitted_executable",
        lambda path: path,
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "installed_version",
        lambda _path: "1.2.3",
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "_launch_adapter",
        lambda *_args: _Adapter(),
    )
    config = AptlConfig(
        experiment={
            "participant_models": {"claude": "claude-sonnet-4-5-20250929"},
            "participant_credential_sources": {
                "claude": {
                    "kind": "process-environment",
                    "variable": "APTL_SELECTED_CLAUDE",
                }
            },
        }
    )

    provider, cleanup, evidence = (
        participant_readiness_provider.build_selection_provider(
            "claude",
            config=config,
            project_dir=tmp_path,
            run_id="configured-provider",
        )
    )

    assert provider.provider_name == "claude"
    assert captured["credentials"] == {"ANTHROPIC_API_KEY": configured_secret}
    assert ambient_secret not in repr(captured["credentials"])
    assert evidence is not None
    assert evidence.to_payload()["acquisition"] == "succeeded"
    assert evidence.to_payload()["isolation"] == "controls-enforced"
    cleanup()
    assert captured["closed"] is True
    assert evidence.to_payload()["local_cleanup"] == "succeeded"


def test_installed_provider_fails_closed_when_isolation_controls_are_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _Adapter:
        def launch(self, _launch: object, _credentials: object) -> object:
            return object()

        def credential_isolation_controls(self, _handle: object) -> tuple[str, ...]:
            return ("minimal-child-environment",)

        def list_tools(self, _handle: object) -> dict[str, object]:
            captured["inventory_attempted"] = True
            return {}

        def close(self, _handle: object) -> None:
            captured["closed"] = True

    monkeypatch.setenv("APTL_SELECTED_CLAUDE", "configured-claude-secret")
    monkeypatch.setattr(
        participant_readiness_provider.shutil,
        "which",
        lambda _name: str(tmp_path / "claude"),
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "_admitted_executable",
        lambda path: path,
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "installed_version",
        lambda _path: "1.2.3",
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "_launch_adapter",
        lambda *_args: _Adapter(),
    )
    config = AptlConfig(
        experiment={
            "participant_models": {"claude": "claude-sonnet-4-5-20250929"},
            "participant_credential_sources": {
                "claude": {
                    "kind": "process-environment",
                    "variable": "APTL_SELECTED_CLAUDE",
                }
            },
        }
    )

    with pytest.raises(
        WorkbenchCredentialError,
        match="installed participant provider launch failed",
    ) as raised:
        participant_readiness_provider.build_selection_provider(
            "claude",
            config=config,
            project_dir=tmp_path,
            run_id="incomplete-isolation",
        )

    evidence = evidence_from_error(raised.value)
    assert evidence is not None
    assert evidence.to_payload()["isolation"] == "failed"
    assert evidence.to_payload()["isolation_controls_applied"] == []
    assert evidence.to_payload()["local_cleanup"] == "succeeded"
    assert captured["closed"] is True
    assert "inventory_attempted" not in captured


def test_tool_inventory_rejection_preserves_cleanup_failure_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Adapter:
        def launch(self, _launch: object, _credentials: object) -> object:
            return object()

        def credential_isolation_controls(self, _handle: object) -> tuple[str, ...]:
            return (
                "minimal-child-environment",
                "private-home",
                "private-claude-config",
                "claude-bare-api-key-mode",
            )

        def list_tools(self, _handle: object) -> dict[str, tuple[str, ...]]:
            return {"unexpected": ("action_tool",)}

        def close(self, _handle: object) -> None:
            raise OSError("provider-secret cleanup detail")

    monkeypatch.setenv("APTL_SELECTED_CLAUDE", "configured-claude-secret")
    monkeypatch.setattr(
        participant_readiness_provider.shutil,
        "which",
        lambda _name: str(tmp_path / "claude"),
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "_admitted_executable",
        lambda path: path,
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "installed_version",
        lambda _path: "1.2.3",
    )
    monkeypatch.setattr(
        participant_readiness_provider,
        "_launch_adapter",
        lambda *_args: _Adapter(),
    )
    config = AptlConfig(
        experiment={
            "participant_models": {"claude": "claude-sonnet-4-5-20250929"},
            "participant_credential_sources": {
                "claude": {
                    "kind": "process-environment",
                    "variable": "APTL_SELECTED_CLAUDE",
                }
            },
        }
    )

    with pytest.raises(
        WorkbenchCredentialError,
        match="decision-only provider exposed action tools",
    ) as raised:
        participant_readiness_provider.build_selection_provider(
            "claude",
            config=config,
            project_dir=tmp_path,
            run_id="tool-inventory-cleanup-failure",
        )

    evidence = evidence_from_error(raised.value)
    assert evidence is not None
    assert evidence.to_payload()["acquisition"] == "succeeded"
    assert evidence.to_payload()["isolation"] == "failed"
    assert evidence.to_payload()["local_cleanup"] == "failed"
    assert "provider-secret cleanup detail" not in repr(evidence.to_payload())
    assert "configured-claude-secret" not in repr(evidence.to_payload())


def test_missing_configured_source_fails_before_executable_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery_attempted = False

    def unexpected_discovery(_name: str) -> str | None:
        nonlocal discovery_attempted
        discovery_attempted = True
        return None

    monkeypatch.setenv("ANTHROPIC_API_KEY", "unselected-native-secret")
    monkeypatch.setattr(
        participant_readiness_provider.shutil,
        "which",
        unexpected_discovery,
    )
    config = AptlConfig(
        experiment={"participant_models": {"claude": "claude-sonnet-4-5-20250929"}}
    )

    with pytest.raises(ValueError) as raised:
        participant_readiness_provider.build_selection_provider(
            "claude",
            config=config,
            project_dir=tmp_path,
            run_id="missing-source",
        )

    assert (
        str(raised.value) == "installed participant credential source is not configured"
    )
    evidence = evidence_from_error(raised.value)
    assert evidence is not None
    assert evidence.to_payload()["acquisition"] == "source-not-configured"
    assert discovery_attempted is False


def test_readiness_runner_is_explicitly_pre_capture(
    tmp_path: Path,
) -> None:
    store = LocalRunStore(tmp_path / "runs")

    report = validate_participant_agency_readiness(
        ParticipantReadinessRequest(
            project_dir=PROJECT_ROOT,
            config=AptlConfig(lab={"name": "test"}),
            run_store=store,
            provider_name="deterministic",
            behavior_name="red-public-service",
            turns=2,
            run_id="pre-capture-readiness",
            backend=_StatefulBackend(),
        )
    )

    assert report.passed is True
    assert report.completed_turns == 2
    assert set(report.selected_actions) <= EXPECTED_ACTION_ADDRESSES
    assert len(report.terminal_outcomes) == report.completed_turns
    assert all(
        outcome["action_contract_address"] in EXPECTED_ACTION_ADDRESSES
        and outcome["status"]
        in {"succeeded", "failed", "partial_success", "rejected", "withheld"}
        for outcome in report.terminal_outcomes
    )
    assert report.participant_address.startswith("participant.behavior.")
    assert report.episode_terminal_reason
    assert report.official_capture_started is False
    assert report.model is None
    assert (
        store.get_run_path("pre-capture-readiness")
        / "participant/readiness-report.json"
    ).exists()
    payload = json.loads(
        (
            store.get_run_path("pre-capture-readiness")
            / "participant/readiness-report.json"
        ).read_text()
    )
    assert payload["schema"] == "aptl.participant-agency-readiness/v3"
    assert payload["model"] is None


def test_missing_installed_model_fails_before_provider_launch_with_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_discovery_attempted = False

    def unexpected_discovery(_name: str) -> str | None:
        nonlocal executable_discovery_attempted
        executable_discovery_attempted = True
        return None

    monkeypatch.setattr(
        participant_readiness_provider.shutil,
        "which",
        unexpected_discovery,
    )
    store = LocalRunStore(tmp_path / "runs")

    report = validate_participant_agency_readiness(
        ParticipantReadinessRequest(
            project_dir=PROJECT_ROOT,
            config=AptlConfig(lab={"name": "test"}),
            run_store=store,
            provider_name="codex",
            behavior_name="green-normal-session",
            turns=1,
            run_id="missing-installed-model",
            backend=_StatefulBackend(),
        )
    )

    assert report.passed is False
    assert report.provider == "codex"
    assert report.model is None
    assert report.completed_turns == 0
    assert report.diagnostics == (
        "participant decision provider is unavailable: "
        "installed participant model is not configured",
    )
    assert executable_discovery_attempted is False
    payload = json.loads(
        (
            store.get_run_path("missing-installed-model")
            / "participant/readiness-report.json"
        ).read_text()
    )
    assert payload["schema"] == "aptl.participant-agency-readiness/v3"
    assert payload["provider"] == "codex"
    assert payload["model"] is None


def test_cleanup_failure_is_secret_free_evidence_and_fails_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = CredentialBindingEvidence(
        provider="claude",
        run_id="cleanup-failure",
        source_kind="process-environment",
        descriptor_sha256="sha256:" + "a" * 64,
        config_ref="experiment.participant_credential_sources.claude",
        delivery_contract="aptl.claude-credential-environment/v1",
        acquisition="succeeded",
        isolation="controls-enforced",
        isolation_controls_applied=(
            "minimal-child-environment",
            "private-home",
            "private-claude-config",
            "claude-bare-api-key-mode",
        ),
        local_cleanup="pending",
    )

    def failing_cleanup() -> None:
        raise OSError("synthetic secret-like cleanup detail")

    monkeypatch.setattr(
        participant_agency_readiness,
        "_resolve_selection_provider",
        lambda *_args: (
            DeterministicSelectionProvider(),
            failing_cleanup,
            evidence,
        ),
    )
    store = LocalRunStore(tmp_path / "runs")

    report = validate_participant_agency_readiness(
        ParticipantReadinessRequest(
            project_dir=PROJECT_ROOT,
            config=AptlConfig(lab={"name": "test"}),
            run_store=store,
            provider_name="claude",
            behavior_name="green-normal-session",
            turns=1,
            run_id="cleanup-failure",
            backend=_StatefulBackend(),
        )
    )

    assert report.passed is False
    assert report.credential_binding is not None
    assert report.credential_binding["local_cleanup"] == "failed"
    assert report.diagnostics[-1] == "participant provider cleanup failed"
    payload = json.loads(
        (
            store.get_run_path("cleanup-failure") / "participant/readiness-report.json"
        ).read_text()
    )
    assert payload["schema"] == "aptl.participant-agency-readiness/v3"
    assert payload["participant_source_binding"]["local_cleanup"] == "failed"
    assert "synthetic secret-like cleanup detail" not in repr(payload)


def test_successful_readiness_persists_secret_free_source_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = CredentialBindingEvidence(
        provider="claude",
        run_id="source-lifecycle-success",
        source_kind="process-environment",
        descriptor_sha256="sha256:" + "b" * 64,
        config_ref="experiment.participant_credential_sources.claude",
        delivery_contract="aptl.claude-credential-environment/v1",
        acquisition="succeeded",
        isolation="controls-enforced",
        isolation_controls_applied=(
            "minimal-child-environment",
            "private-home",
            "private-claude-config",
            "claude-bare-api-key-mode",
        ),
        local_cleanup="pending",
    )

    def successful_cleanup() -> None:
        evidence.local_cleanup = "succeeded"

    monkeypatch.setattr(
        participant_agency_readiness,
        "_resolve_selection_provider",
        lambda *_args: (
            DeterministicSelectionProvider(),
            successful_cleanup,
            evidence,
        ),
    )
    store = LocalRunStore(tmp_path / "runs")

    report = validate_participant_agency_readiness(
        ParticipantReadinessRequest(
            project_dir=PROJECT_ROOT,
            config=AptlConfig(lab={"name": "test"}),
            run_store=store,
            provider_name="claude",
            behavior_name="green-normal-session",
            turns=1,
            run_id="source-lifecycle-success",
            backend=_StatefulBackend(),
        )
    )

    assert report.passed is True
    payload = json.loads(
        (
            store.get_run_path("source-lifecycle-success")
            / "participant/readiness-report.json"
        ).read_text()
    )
    binding = payload["participant_source_binding"]
    assert binding == evidence.to_payload()
    assert binding["acquisition"] == "succeeded"
    assert binding["local_cleanup"] == "succeeded"
    assert binding["expiry"] == "unknown"
    assert binding["renewal"] == "unsupported"
    assert binding["upstream_revocation"] == "unsupported-by-aptl"
    assert "APTL_PARTICIPANT_CLAUDE_CREDENTIAL" not in repr(payload)
    assert "model-secret" not in repr(payload)


@pytest.mark.parametrize(
    ("isolation", "local_cleanup", "expected_diagnostic"),
    [
        (
            "not-verified",
            "succeeded",
            "participant credential isolation was not verified",
        ),
        (
            "controls-enforced",
            "pending",
            "participant credential cleanup was not verified",
        ),
    ],
)
def test_readiness_fails_closed_when_credential_evidence_is_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolation: str,
    local_cleanup: str,
    expected_diagnostic: str,
) -> None:
    evidence = CredentialBindingEvidence(
        provider="claude",
        run_id="unverified-credential-evidence",
        source_kind="process-environment",
        descriptor_sha256="sha256:" + "c" * 64,
        config_ref="experiment.participant_credential_sources.claude",
        delivery_contract="aptl.claude-credential-environment/v1",
        acquisition="succeeded",
        isolation=isolation,
        local_cleanup=local_cleanup,
    )
    monkeypatch.setattr(
        participant_agency_readiness,
        "_resolve_selection_provider",
        lambda *_args: (
            DeterministicSelectionProvider(),
            lambda: None,
            evidence,
        ),
    )

    report = validate_participant_agency_readiness(
        ParticipantReadinessRequest(
            project_dir=PROJECT_ROOT,
            config=AptlConfig(lab={"name": "test"}),
            run_store=LocalRunStore(tmp_path / "runs"),
            provider_name="claude",
            behavior_name="green-normal-session",
            turns=1,
            run_id="unverified-credential-evidence",
            backend=_StatefulBackend(),
        )
    )

    assert report.passed is False
    assert expected_diagnostic in report.diagnostics


def test_positive_readiness_rejects_a_failed_native_terminal_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_native_operation(**_kwargs: object) -> VerifiedParticipantOperation:
        return VerifiedParticipantOperation(
            success=False,
            summary="injected native failure",
            pre_state={},
            post_state={},
            diagnostic="injected native failure",
            failure_class="backend_error",
        )

    monkeypatch.setattr(
        raes_participant_realizations,
        "execute_verified_participant_operation",
        fail_native_operation,
    )
    store = LocalRunStore(tmp_path / "runs")

    report = validate_participant_agency_readiness(
        ParticipantReadinessRequest(
            project_dir=PROJECT_ROOT,
            config=AptlConfig(lab={"name": "test"}),
            run_store=store,
            provider_name="deterministic",
            behavior_name="red-public-service",
            turns=1,
            run_id="failed-positive-readiness",
            backend=_StatefulBackend(),
        )
    )

    assert report.passed is False
    assert report.completed_turns == 1
    assert report.terminal_outcomes[0]["status"] == "failed"
    assert any(
        "requires a succeeded terminal outcome" in diagnostic
        for diagnostic in report.diagnostics
    )


def test_full_qualification_covers_all_actions_and_boundary_challenges(
    tmp_path: Path,
) -> None:
    store = LocalRunStore(tmp_path / "runs")

    report = validate_participant_agency_qualification(
        project_dir=PROJECT_ROOT,
        config=AptlConfig(lab={"name": "test"}),
        run_store=store,
        run_id="full-pre-capture-qualification",
        backend=_StatefulBackend(),
    )

    assert report.passed is True
    assert set(report.covered_action_contracts) == EXPECTED_ACTION_ADDRESSES
    assert all(check.passed for check in report.checks)
    assert {
        check.check_id for check in report.checks if check.check_id.startswith("BC-")
    } == {f"BC-{index:02d}" for index in range(1, 11)}
    assert report.official_capture_started is False
    assert report.installed_model is None
    assert (
        store.get_run_path("full-pre-capture-qualification")
        / "participant/readiness-suite-report.json"
    ).exists()
    payload = json.loads(
        (
            store.get_run_path("full-pre-capture-qualification")
            / "participant/readiness-suite-report.json"
        ).read_text()
    )
    assert payload["schema"] == "aptl.participant-agency-qualification/v3"
    assert payload["installed_model"] is None
