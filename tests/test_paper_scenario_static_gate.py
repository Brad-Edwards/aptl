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

    assert realization.diagnostics == ()
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
    content = {
        placement.address: (placement.container_name, placement.target_path)
        for placement in realization.content_placements
    }
    assert content == {
        "provision.content.aptl-participant-runtime-binding": (
            "aptl-kali",
            "/scenario/aptl-participant-runtime-binding.yaml",
        ),
        "provision.content.evaluator-notes": (
            "aptl-wazuh-manager",
            "/scenario/evaluator-notes.md",
        ),
        "provision.content.task-brief": ("aptl-kali", "/scenario/task.md"),
    }
    assert all(
        placement.content_type == "file"
        for placement in realization.content_placements
    )
