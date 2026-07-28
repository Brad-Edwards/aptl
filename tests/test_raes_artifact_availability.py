"""Trusted artifact availability facts fed to RAES planning (ADR-050).

Availability is an *input* to planning, not something the planner derives from
the local image cache. These tests pin the two properties that matter:

* HONEST FACTS — an obtainable artifact appears in the address-scoped facts and
  RAES admits it; an unobtainable one does not appear, and RAES rejects the
  requirement with ``artifact.unavailable-exact-artifact`` instead of APTL
  quietly substituting something else.
* ADDRESS SCOPING — facts are partitioned per compiled address, so an artifact
  available for one node cannot satisfy a different node's requirement.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from raes.parser import parse_sdl_file
from raes_processor.semantics.artifact_realization import artifact_requirement_diagnostics
from raes_processor.semantics.realization import CompiledRealizationRequirement
from raes_processor.compiler import compile_runtime_model

from aptl.backends.raes_artifact_availability import artifact_availability_for_scenario
from aptl.backends.raes_artifact_mechanisms import exact_artifact_profile
from aptl.backends.raes_manifest import create_aptl_manifest

_DIGEST = "sha256:" + "1" * 64
_OTHER_DIGEST = "sha256:" + "2" * 64


class _Probe:
    """Backend stub recording which references were checked."""

    def __init__(self, available: set[str]) -> None:
        self.available = available
        self.calls: list[tuple[str, bool]] = []

    def artifact_available(self, image_ref: str, *, allow_remote: bool = True) -> bool:
        self.calls.append((image_ref, allow_remote))
        if allow_remote is False and image_ref not in self.available:
            return False
        return image_ref in self.available


def _scenario(tmp_path: Path, digest: str = _DIGEST):
    """Return a parsed one-node scenario authoring an exact artifact pin."""

    profile = exact_artifact_profile()
    body = textwrap.dedent(
        f"""
        name: availability-fixture
        description: One node with an exact artifact requirement.
        nodes:
          probe-net:
            type: switch
            description: Fixture network.
          target:
            type: vm
            os: linux
            source:
              name: example/app
              version: "1.0"
              artifact_requirement:
                requirement_id: target-image
                explicitness: exact
                exact_artifact:
                  artifact_id: example/app
                  version: "1.0"
                  digest: "{digest}"
                  media_type: application/vnd.oci.image.manifest.v1+json
                permitted_routes:
                  - mechanism:
                      mechanism: "{profile.mechanism}"
                      profile: "{profile.profile}"
                      version: "{profile.version}"
                      digest: "{profile.digest}"
                    acquisition: pull
                    timing: backend-preparation
        infrastructure:
          probe-net:
            properties: {{cidr: 10.99.0.0/24, gateway: 10.99.0.1, internal: true}}
          target:
            links: [probe-net]
        """
    ).strip()
    path = tmp_path / "availability.sdl.yaml"
    path.write_text(body + "\n", encoding="utf-8")
    return parse_sdl_file(path)


def _requirements(scenario) -> tuple[CompiledRealizationRequirement, ...]:
    """Return the compiled artifact requirements for ``scenario``."""

    return tuple(
        requirement
        for requirement in compile_runtime_model(scenario).realization_requirements
        if requirement.artifact_requirement is not None
    )


def _codes(scenario, availability) -> list[str]:
    """Return RAES admission diagnostic codes for ``scenario``."""

    return [
        d.code
        for d in artifact_requirement_diagnostics(
            _requirements(scenario), create_aptl_manifest(), availability=availability
        )
    ]


def test_scenario_authoring_an_artifact_requirement_produces_facts(tmp_path):
    """The provider discovers artifact demand and probes its exact reference."""

    scenario = _scenario(tmp_path)
    probe = _Probe({f"example/app@{_DIGEST}"})

    context = artifact_availability_for_scenario(scenario, probe)

    assert [entry.address for entry in context.requirements] == ["provision.node.target"]
    assert context.requirements[0].available_artifact_digests == [_DIGEST]
    assert probe.calls == [(f"example/app@{_DIGEST}", None)]


def test_available_artifact_is_admitted_by_raes(tmp_path):
    """Honest facts let RAES admit the authored pin."""

    scenario = _scenario(tmp_path)
    probe = _Probe({f"example/app@{_DIGEST}"})

    availability = artifact_availability_for_scenario(scenario, probe)

    assert _codes(scenario, availability) == []


def test_unobtainable_artifact_is_rejected_not_substituted(tmp_path):
    """An artifact the backend cannot obtain fails admission (ADR-098 §2.1)."""

    scenario = _scenario(tmp_path)
    probe = _Probe(set())

    availability = artifact_availability_for_scenario(scenario, probe)

    assert availability.requirements[0].available_artifact_digests == []
    assert "artifact.unavailable-exact-artifact" in _codes(scenario, availability)


def test_offline_staging_refuses_a_merely_resolvable_artifact(tmp_path):
    """With allow_remote False only locally present artifacts count."""

    scenario = _scenario(tmp_path)
    probe = _Probe(set())

    availability = artifact_availability_for_scenario(
        scenario, probe, allow_remote=False
    )

    assert probe.calls == [(f"example/app@{_DIGEST}", False)]
    assert "artifact.unavailable-exact-artifact" in _codes(scenario, availability)


def test_facts_are_scoped_to_the_declaring_address(tmp_path):
    """A digest available elsewhere cannot satisfy this node's requirement."""

    scenario = _scenario(tmp_path)
    # The probe has a different artifact entirely.
    probe = _Probe({f"example/app@{_OTHER_DIGEST}"})

    availability = artifact_availability_for_scenario(scenario, probe)

    assert availability.requirements[0].address == "provision.node.target"
    assert availability.requirements[0].available_artifact_digests == []
    assert "artifact.unavailable-exact-artifact" in _codes(scenario, availability)


def test_shipped_scenario_declares_artifact_demand_for_every_imaged_node():
    """The shipped scenario now pins each image-backed node to an exact artifact."""

    scenario = parse_sdl_file(
        Path(__file__).resolve().parents[1]
        / "scenarios"
        / "techvault-operational.sdl.yaml"
    )
    probe = _Probe(set())

    context = artifact_availability_for_scenario(scenario, probe)

    # One address per image-backed node, each probed by digest-pinned reference.
    assert len(context.requirements) == 18
    assert all(ref.count("@sha256:") == 1 for ref, _ in probe.calls)
    # Nothing was obtainable for this probe, so nothing is claimed available.
    assert all(not e.available_artifact_digests for e in context.requirements)
