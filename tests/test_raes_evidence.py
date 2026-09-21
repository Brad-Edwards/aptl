"""TechVault SDL evidence admission and acquisition contracts for issue #992."""

from __future__ import annotations

import importlib.resources as ir
from pathlib import Path

import pytest
from raes import parse_sdl_file
from raes.evidence_requirements import EvidenceRequirement
from raes.realization_designation import RealizationDesignation
from raes_processor.capture_admission import (
    capture_admission_diagnostics,
    compile_scenario_capture_demands,
)

from aptl.core.experiment.errors import AdmissionRejection

_DEMAND_IDS = {
    "cortex-enrichment-readback",
    "misp-authenticated-api-readiness",
    "redteam-session-transcript",
    "suricata-local-rule-readiness",
    "suricata-login-sqli-alert",
    "wazuh-agent-readiness",
}


def _registry():
    from aptl.core.experiment.capture_registry import CollectorRegistry
    from aptl_techvault.capture_registrations import BUILTIN_REGISTRATIONS

    return CollectorRegistry(BUILTIN_REGISTRATIONS)


@pytest.fixture
def scenario():
    return parse_sdl_file(
        Path(
            str(
                ir.files("raes_env_packs")
                / "resources/packs/techvault/sdl/techvault.sdl.yaml"
            )
        )
    )


def test_manifest_exactly_admits_every_released_techvault_demand(scenario):
    from aptl.backends.raes_manifest import create_aptl_manifest

    demands = compile_scenario_capture_demands(scenario)
    observation = create_aptl_manifest(_registry()).observation

    assert {demand.demand_id for demand in demands} == _DEMAND_IDS
    assert capture_admission_diagnostics(demands, observation) == []
    assert observation is not None
    assert {offer.offer_id for offer in observation.capture_offers} == {
        "aptl.collector.cortex-enrichment",
        "aptl.collector.misp-authenticated-api-readiness",
        "aptl.collector.redteam-session-transcript",
        "aptl.collector.suricata-rule-readiness",
        "aptl.collector.suricata-wazuh-sqli",
        "aptl.collector.wazuh-agent-readiness",
    }


def test_sdl_capture_plan_uses_public_demands_without_synthesizing_capture_spec(
    scenario,
):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    before = scenario.model_dump(mode="json")
    plan = admit_sdl_evidence(scenario, registry=_registry())

    assert scenario.model_dump(mode="json") == before
    assert {binding.demand.demand_id for binding in plan.bindings} == _DEMAND_IDS
    assert plan.plan_id.startswith("capture-plan-")
    assert plan.plan_digest.startswith("sha256:")
    assert b"ExperimentCaptureSpecModel" not in plan.canonical_bytes
    assert {binding.selected_output_contract for binding in plan.bindings} == {
        "experiment-evidence-record-v1"
    }
    assert {binding.output_contract for binding in plan.runtime_bindings()} == {
        "experiment-evidence-record-v1"
    }
    assert b'"selected_output_contract":"experiment-evidence-record-v1"' in (
        plan.canonical_bytes
    )


def test_demands_admit_only_the_two_required_minimum_apparatus(scenario):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    plan = admit_sdl_evidence(scenario, registry=_registry())

    assert [item.apparatus_id for item in plan.apparatus] == [
        "aptl.apparatus.kali-session-capture",
        "aptl.apparatus.suricata-traffic-mirror",
    ]
    assert plan.apparatus[0].governing_scopes == ("#/",)
    assert plan.apparatus[0].service_name == "kali-capture"
    assert plan.apparatus[0].environment_visible is True
    assert plan.apparatus[1].governing_scopes == ("#/",)
    assert plan.apparatus[1].service_name == "backend-traffic-mirror"
    assert plan.apparatus[1].container_name == ""
    assert plan.apparatus[1].target_refs == (
        "nodes.kali",
        "nodes.suricata",
        "nodes.webapp",
    )
    assert b"aptl.apparatus.kali-session-capture" in plan.canonical_bytes
    assert b"aptl.apparatus.suricata-traffic-mirror" in plan.canonical_bytes


def test_closed_scope_rejects_required_kali_capture_addition(scenario):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    del scenario.evidence_requirements["suricata-login-sqli-alert"]
    scenario.realization = RealizationDesignation(default="closed")

    with pytest.raises(AdmissionRejection) as excinfo:
        admit_sdl_evidence(scenario, registry=_registry())

    assert {diagnostic.code for diagnostic in excinfo.value.diagnostics} == {
        "aptl.capture-apparatus.closed-realization-scope"
    }


def test_closed_scope_rejects_required_traffic_mirror_addition(scenario):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    del scenario.evidence_requirements["redteam-session-transcript"]
    scenario.realization = RealizationDesignation(default="closed")

    with pytest.raises(AdmissionRejection) as excinfo:
        admit_sdl_evidence(scenario, registry=_registry())

    assert {diagnostic.code for diagnostic in excinfo.value.diagnostics} == {
        "aptl.capture-apparatus.closed-realization-scope"
    }


def test_demands_with_native_visibility_add_no_observability_apparatus(scenario):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    del scenario.evidence_requirements["redteam-session-transcript"]
    del scenario.evidence_requirements["suricata-login-sqli-alert"]
    plan = admit_sdl_evidence(scenario, registry=_registry())

    assert plan.apparatus == ()


def test_open_scope_without_an_otel_dependent_demand_omits_optional_stack():
    from raes import parse_sdl

    from aptl.backends.raes_observability_scope import observability_scope_decision

    scenario = parse_sdl("name: native-only\nrealization: {default: open}\n")
    decision = observability_scope_decision(scenario)

    assert decision.enabled is False
    assert decision.reason == "minimum-intrusion"
    assert decision.select_profiles(["wazuh"]) == ["wazuh"]


@pytest.mark.parametrize(
    ("requirement_id", "changed"),
    [
        ("cortex-enrichment-readback", {"retention": "archival"}),
        ("suricata-local-rule-readiness", {"media_types": ["application/json"]}),
        ("suricata-login-sqli-alert", {"integrity": "signature"}),
        ("redteam-session-transcript", {"redaction": "aggregate_only"}),
    ],
)
def test_any_unoffered_required_axis_rejects_the_entire_sdl_capture_plan(
    scenario, requirement_id, changed
):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    original = scenario.evidence_requirements[requirement_id].model_dump(mode="json")
    scenario.evidence_requirements[requirement_id] = EvidenceRequirement.model_validate(
        original | changed
    )

    with pytest.raises(AdmissionRejection):
        admit_sdl_evidence(scenario, registry=_registry())


def test_capture_rejection_precedes_artifact_probe(scenario, tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    from aptl.backends import raes
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import project_tree_bundle

    requirement_id = "redteam-session-transcript"
    original = scenario.evidence_requirements[requirement_id].model_dump(mode="json")
    scenario.evidence_requirements[requirement_id] = EvidenceRequirement.model_validate(
        original | {"retention": "archival"}
    )
    bundle = project_tree_bundle(tmp_path, tmp_path / "scenario.sdl.yaml")
    monkeypatch.setattr(raes, "resolve_scenario_bundle", lambda *args: bundle)
    monkeypatch.setattr(raes, "parse_sdl_file", lambda path: scenario)
    monkeypatch.setattr(
        raes,
        "artifact_availability_for_scenario",
        lambda *args, **kwargs: pytest.fail("artifact probe before capture admission"),
    )

    config = AptlConfig()
    backend = MagicMock()
    parameters = {
        f"flag_{host}_{level}": f"{host}-{level}"
        for host in ("victim", "workstation", "webapp", "fileshare", "ad")
        for level in ("user", "root")
    }
    with pytest.raises(AdmissionRejection):
        raes.admit_raes_scenario(tmp_path, config, backend, parameters=parameters)


def test_no_evidence_intent_needs_no_capture_plan(scenario):
    from aptl.backends.raes_evidence import admit_sdl_evidence

    scenario.evidence_requirements.clear()
    assert admit_sdl_evidence(scenario, registry=_registry()).bindings == ()
