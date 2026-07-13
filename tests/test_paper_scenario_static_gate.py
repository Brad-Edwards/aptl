"""Static gate for the ACES paper scenario realization (#573, #691).

Issue #691 remodels the paper scenario's evidence surfaces off content
placement (ADR-046 Paper Scenario Evidence Modeling Addendum):

- participant output is owned by the observation boundary and carried by the
  runtime participant-observation envelope — it is neither `content` nor an
  evidence requirement;
- Wazuh corroboration and negative boundary checks are authored ACES
  `evidence_requirements` (capture intent, not proof of capture);
- the participant runtime binding rides the compiled behavior specification's
  `x-aptl:participant-runtime-binding` governed extension, not planted content;
- the only remaining `content:` entry is the participant-visible task brief,
  which lowers to a typed `DeploymentContentRealization` on the existing
  `kali_operations` volume.

So the gate proves the whole content surface realizes (zero
`content-placement-rejected` diagnostics AND a typed realization for the task
brief) rather than enshrining the prior six fail-closed rejections.
"""

from pathlib import Path
from unittest.mock import MagicMock

from aces_processor.compiler import compile_runtime_model
from aces_runtime.manager import RuntimeManager
from aces_sdl import parse_sdl_file

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_participant_actions import (
    participant_action_specs_from_runtime_model,
    _action_snapshot_entries,
)
from aptl.backends.aces_participant_bindings import (
    _BINDING_EXTENSION_KEY,
    _BINDING_SCHEMA,
)
from aptl.backends.aces_profiles import select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import DeploymentContentRealization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAPER_SCENARIO = PROJECT_ROOT / "scenarios" / "paper-agent-loop.sdl.yaml"


def _paper_plan():
    scenario = parse_sdl_file(PAPER_SCENARIO)
    model = compile_runtime_model(scenario)
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "kali": True, "wazuh": True},
    )
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=config,
        backend=MagicMock(),
    )
    return scenario, model, RuntimeManager(target).plan(scenario), config


def _assert_paper_scoring_chain_is_not_supported(plan) -> None:
    diagnostics = {(d.code, d.address) for d in plan.diagnostics}
    assert diagnostics == {
        ("evaluator.unsupported-section", "evaluation.metrics"),
        ("evaluator.unsupported-section", "evaluation.evaluations"),
        ("evaluator.unsupported-section", "evaluation.tlos"),
        ("evaluator.unsupported-section", "evaluation.goals"),
        ("evaluator.scoring-unsupported", "evaluation.scoring"),
    }


def test_paper_scenario_compiles_with_participant_runtime_artifacts():
    scenario, model, plan, _config = _paper_plan()

    assert model.diagnostics == []

    # The runtime binding is backend-private and rides the behavior-spec
    # governed extension, NOT a planted content placement (#691).
    assert "provision.content.aptl-participant-runtime-binding" not in (
        model.content_placements
    )
    spec_artifact = model.behavior_specifications[
        "participant.behavior-specification.paper-agent-behavior"
    ]
    binding = spec_artifact.spec["extensions"][_BINDING_EXTENSION_KEY]
    assert binding["schema_version"] == _BINDING_SCHEMA
    assert binding["command"]["argv"][:2] == ["bash", "-lc"]

    # Evidence surfaces are authored ACES evidence requirements, not content.
    assert set(scenario.evidence_requirements) == {
        "wazuh-evidence",
        "boundary-check-evidence",
    }
    assert set(scenario.content) == {"task-brief"}
    assert "participant-observation" not in scenario.evidence_requirements

    assert "participant.behavior.paper-agent" in model.participant_behaviors
    assert (
        "participant.action-contract.probe-customer-portal-login"
        in model.action_contracts
    )
    assert (
        "participant.observation-boundary.paper-agent-view"
        in model.observation_boundaries
    )
    _assert_paper_scoring_chain_is_not_supported(plan)
    assert not (
        PROJECT_ROOT / "src/aptl/backends/aces_paper_participant_actions.py"
    ).exists()


def test_paper_scenario_content_surface_realizes_with_no_rejection():
    _scenario, _model, plan, config = _paper_plan()
    _assert_paper_scoring_chain_is_not_supported(plan)

    realization = interpret_provisioning_plan(
        plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )

    # #691: every remaining content placement must lower to a typed
    # realization. The ADR is explicit that the absence of a diagnostic is not
    # proof of realization — assert the typed `DeploymentContentRealization`,
    # not just an empty rejection set.
    assert [
        d
        for d in realization.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    ] == []
    assert realization.diagnostics == ()

    content_placements = [
        placement
        for placement in realization.placements
        if placement.resource_type == "content-placement"
    ]
    assert [p.address for p in content_placements] == ["provision.content.task-brief"]
    task_brief = content_placements[0].content
    assert isinstance(task_brief, DeploymentContentRealization)
    assert task_brief.content_name == "task-brief"
    assert task_brief.volume_suffix == "kali_operations"
    assert task_brief.dest_relpath == "scenario/task.md"
    assert task_brief.source_kind == "inline-text"

    assert select_backend_profiles(config, realization.profiles) == [
        "wazuh",
        "kali",
        "enterprise",
        "otel",
    ]
    nodes = {node.name: node for node in realization.nodes}
    assert {
        name: (node.container_name, node.networks)
        for name, node in nodes.items()
    } == {
        "customer-db": ("aptl-db", ("internal-net",)),
        "customer-portal": ("aptl-webapp", ("dmz-net", "internal-net")),
        "red-workbench": ("aptl-kali", ("dmz-net", "redteam-net")),
        "wazuh-indexer": ("aptl-wazuh-indexer", ("security-net",)),
        "wazuh-manager": (
            "aptl-wazuh-manager",
            ("internal-net", "security-net"),
        ),
    }
    assert set(plan.evaluation.resources) >= {
        "evaluation.condition.red-workbench.participant-observation-recorded",
        "evaluation.condition.red-workbench.boundary-checks-recorded",
        "evaluation.condition.wazuh-manager.wazuh-evidence-recorded",
        "evaluation.objective.demonstrate-handoff",
    }


def test_paper_evidence_requirements_declare_authored_capture_intent():
    scenario, _model, _plan, _config = _paper_plan()

    wazuh = scenario.evidence_requirements["wazuh-evidence"]
    assert wazuh.source_class.value == "scenario_native_observability"
    assert wazuh.scope_refs == ["nodes.wazuh-manager"]
    assert wazuh.trigger_ref == "action_contracts.probe-customer-portal-login"

    boundary = scenario.evidence_requirements["boundary-check-evidence"]
    assert boundary.source_class.value == "participant_action"
    assert boundary.scope_refs == ["nodes.red-workbench"]
    assert boundary.boundary_ref == "observation_boundaries.paper-agent-view"


def test_paper_observation_boundary_hides_evaluator_and_negative_surfaces():
    _scenario, model, plan, config = _paper_plan()

    specs = participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )
    spec = specs["participant.behavior.paper-agent"]
    entries = _action_snapshot_entries(
        "participant.behavior.paper-agent", spec, "probe-0001", success=True
    )
    boundary = entries[spec.observation_boundary_address].payload

    # ADR-046: internal DB / Wazuh endpoint identities (the negative-boundary
    # refs) must never project into the participant view.
    projected = set(boundary["observable_refs"]) | set(boundary["disclosed_refs"])
    assert not any(ref.startswith("boundary-negative:") for ref in projected)
    assert boundary["observable_refs"] == [
        "container:aptl-kali",
        "container:aptl-webapp",
        "http://172.20.1.20:8080/login",
    ]
    # They remain as evaluator-only evidence alongside the action instance.
    assert boundary["evidence_refs"] == [
        "probe-0001",
        "boundary-negative:tcp:172.20.2.11:5432",
        "boundary-negative:tcp:172.20.2.30:55000",
    ]
