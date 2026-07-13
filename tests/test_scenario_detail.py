"""Tests for the ACES scenario-detail workbench projection (UI-008d).

The projection turns a curated catalog entry plus its parsed ACES SDL
``Scenario`` into a backend-owned ``ScenarioDetailResponse``: header facts
plus an ordered ``WorkbenchBlock`` discriminated union. The block families
are projected from whatever ACES actually owns and are omitted when the
source section is empty — no fabricated steps/objectives for infra-only SDLs.
"""

from pathlib import Path

import pytest

pytest.importorskip("aces_sdl", reason="ACES SDL not installed")

from aces_sdl import parse_sdl, parse_sdl_file  # noqa: E402

from aptl.api.scenario_projection import (  # noqa: E402
    build_scenario_detail,
    scenario_required_containers,
)
from aptl.core.scenario_catalog import (  # noqa: E402
    ScenarioCatalogEntry,
    ScenarioCatalogMetadata,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

EDGE_SDL = """
name: edge-scenario
description: A small edge scenario.
nodes:
  the-net:
    type: switch
    description: network switch, never a container
  ssh-target:
    type: vm
    os: linux
    services:
      - {name: ssh, port: 22, protocol: tcp}
  quiet-host:
    type: vm
    os: linux
    services: []
"""


def _entry(scenario_id="edge", *, metadata=None):
    return ScenarioCatalogEntry(
        id=scenario_id,
        name="Edge Scenario",
        path="scenarios/secret-internal-path.sdl.yaml",
        description="A catalog description.",
        metadata=metadata,
    )


def _block_types(detail):
    return [b.type for b in detail.blocks]


class TestHeaderFacts:
    def test_required_containers_are_vm_nodes_only(self):
        scenario = parse_sdl(EDGE_SDL)
        assert scenario_required_containers(scenario) == ["ssh-target", "quiet-host"]

    def test_detail_carries_catalog_header_facts(self):
        scenario = parse_sdl(EDGE_SDL)
        detail = build_scenario_detail(_entry(), scenario)
        assert detail.id == "edge"
        assert detail.name == "Edge Scenario"
        assert detail.required_containers == ["ssh-target", "quiet-host"]
        assert detail.validation.valid is True

    def test_catalog_metadata_extension_flows_to_header(self):
        meta = ScenarioCatalogMetadata(
            mode="purple",
            difficulty="intermediate",
            estimated_minutes=45,
            tags=["web", "detection"],
        )
        detail = build_scenario_detail(_entry(metadata=meta), parse_sdl(EDGE_SDL))
        assert detail.mode == "purple"
        assert detail.difficulty == "intermediate"
        assert detail.estimated_minutes == 45
        assert detail.tags == ["web", "detection"]

    def test_absent_metadata_leaves_header_facts_none(self):
        detail = build_scenario_detail(_entry(metadata=None), parse_sdl(EDGE_SDL))
        assert detail.mode is None
        assert detail.difficulty is None
        assert detail.estimated_minutes is None
        assert detail.tags == []


class TestBlockProjection:
    def test_first_block_is_title_narrative(self):
        detail = build_scenario_detail(_entry(), parse_sdl(EDGE_SDL))
        first = detail.blocks[0]
        assert first.type == "narrative"
        assert "Edge Scenario" in first.content
        assert "A catalog description." in first.content

    def test_container_status_block_lists_vm_nodes(self):
        detail = build_scenario_detail(_entry(), parse_sdl(EDGE_SDL))
        status = [b for b in detail.blocks if b.type == "container-status"]
        assert len(status) == 1
        assert status[0].containers == ["ssh-target", "quiet-host"]

    def test_terminal_blocks_only_for_ssh_exposing_nodes(self):
        detail = build_scenario_detail(_entry(), parse_sdl(EDGE_SDL))
        terminals = [b for b in detail.blocks if b.type == "terminal"]
        assert [t.container for t in terminals] == ["ssh-target"]

    def test_infra_only_scenario_emits_no_objective_step_or_siem_blocks(self):
        scenario = parse_sdl_file(
            PROJECT_ROOT / "scenarios" / "techvault-operational.sdl.yaml"
        )
        detail = build_scenario_detail(
            _entry("techvault-operational"), scenario
        )
        types = set(_block_types(detail))
        assert "objective" not in types
        assert "step" not in types
        assert "siem-query" not in types
        # ...but the honest infra families are present.
        assert "narrative" in types
        assert "container-status" in types

    def test_keys_are_unique(self):
        detail = build_scenario_detail(_entry(), parse_sdl(EDGE_SDL))
        keys = [b.key for b in detail.blocks]
        assert len(keys) == len(set(keys))


class TestRichScenarioProjection:
    """A scenario carrying objectives + workflows + vm nodes projects blocks.

    Driven by the test-owned engine fixture (test data, not a catalog
    scenario), which is the only in-repo SDL that declares objectives and
    workflows.
    """

    @pytest.fixture
    def rich_detail(self):
        scenario = parse_sdl_file(
            PROJECT_ROOT / "tests" / "fixtures" / "aces" / "participant-evidence.sdl.yaml"
        )
        return build_scenario_detail(_entry("participant-evidence"), scenario)

    def test_objective_blocks_projected_from_aces_objectives(self, rich_detail):
        objectives = [b for b in rich_detail.blocks if b.type == "objective"]
        assert objectives, "the fixture declares objectives"
        assert any("handoff" in o.name for o in objectives)
        # Every objective carries a human success summary derived from ACES.
        assert all(o.success for o in objectives)

    def test_step_blocks_projected_from_aces_workflows(self, rich_detail):
        steps = [b for b in rich_detail.blocks if b.type == "step"]
        assert steps, "the fixture declares a workflow with steps"
        assert [s.index for s in steps] == sorted(s.index for s in steps)


class TestProjectionBoundary:
    def test_internal_catalog_path_never_leaks(self):
        detail = build_scenario_detail(_entry(), parse_sdl(EDGE_SDL))
        serialized = detail.model_dump_json()
        assert "secret-internal-path" not in serialized
        assert ".sdl.yaml" not in serialized
