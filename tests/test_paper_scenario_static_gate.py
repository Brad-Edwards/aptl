"""Static gate for the ACES paper scenario realization (#573)."""

from pathlib import Path
from unittest.mock import MagicMock

from aces_processor.compiler import compile_runtime_model
from aces_runtime.manager import RuntimeManager
from aces_sdl import parse_sdl_file

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_profiles import select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig

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
    return model, RuntimeManager(target).plan(scenario), config


def test_paper_scenario_compiles_with_participant_runtime_artifacts():
    model, plan, _config = _paper_plan()

    assert model.diagnostics == []
    binding = model.content_placements["provision.content.aptl-participant-runtime-binding"]
    assert "aptl-participant-runtime-binding" in binding.spec["tags"]
    assert "schema_version: aptl-participant-runtime-binding/v1" in binding.spec["text"]
    assert "participant.behavior.paper-agent" in model.participant_behaviors
    assert (
        "participant.action-contract.probe-customer-portal-login"
        in model.action_contracts
    )
    assert (
        "participant.observation-boundary.paper-agent-view"
        in model.observation_boundaries
    )
    assert plan.diagnostics == []
    assert not (
        PROJECT_ROOT / "src/aptl/backends/aces_paper_participant_actions.py"
    ).exists()


def test_paper_scenario_realizes_declared_topology_and_evaluator_surfaces():
    _model, plan, config = _paper_plan()

    realization = interpret_provisioning_plan(
        plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )

    # #689 makes content-placement realization real (fail closed) instead of
    # the prior count-only behavior. The paper scenario's `content:` entries
    # are either evaluator-evidence contracts (`dataset` type: consumed by
    # the evaluator through `plan.evaluation`, never planted as file/dir
    # content) or a Kali-targeted task brief/runtime binding with no
    # registered APTL content mount — none of them are project-contained
    # file/directory content backed by a typed backend volume, so every one
    # now correctly fails closed with a diagnostic rather than being
    # silently counted as realized (the exact anti-pattern ADR-046 removes).
    # Non-content diagnostics still must be empty.
    content_diagnostics = {
        d.address: d
        for d in realization.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    }
    assert set(content_diagnostics) == {
        "provision.content.task-brief",
        "provision.content.participant-observation",
        "provision.content.aptl-participant-runtime-binding",
        "provision.content.wazuh-evidence",
        "provision.content.boundary-check-evidence",
        "provision.content.evaluator-notes",
    }
    assert all(d.is_error for d in content_diagnostics.values())
    assert [d for d in realization.diagnostics if d.address not in content_diagnostics] == []
    assert (
        "dataset-not-realizable"
        in content_diagnostics["provision.content.participant-observation"].message
    )
    assert (
        "dataset-not-realizable"
        in content_diagnostics["provision.content.wazuh-evidence"].message
    )
    assert (
        "dataset-not-realizable"
        in content_diagnostics["provision.content.boundary-check-evidence"].message
    )
    assert (
        "destination-without-backing-mount"
        in content_diagnostics["provision.content.task-brief"].message
    )
    assert (
        "destination-without-backing-mount"
        in content_diagnostics[
            "provision.content.aptl-participant-runtime-binding"
        ].message
    )
    assert (
        "destination-without-backing-mount"
        in content_diagnostics["provision.content.evaluator-notes"].message
    )
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
        "evaluation.metric.participant-evidence-complete",
        "evaluation.metric.wazuh-evidence-complete",
        "evaluation.metric.boundary-evidence-complete",
        "evaluation.tlo.authored-runtime-handoff",
    }
