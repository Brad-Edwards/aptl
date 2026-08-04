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

import pytest
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


def test_shipped_scenario_declares_artifact_demand_for_every_imaged_node(tmp_path):
    """The shipped scenario pins each artifact-bearing address to an exact artifact."""

    from tests.helpers import techvault_scenario_path

    scenario = parse_sdl_file(techvault_scenario_path(tmp_path))
    probe = _Probe(set())

    context = artifact_availability_for_scenario(scenario, probe)

    # One address per artifact-bearing address — every image-backed node and
    # every digest-pinned content placement in the full TechVault env-pack.
    assert len(context.requirements) == 44
    # Exact pins are probed by digest-pinned reference; materialized components
    # probe their locked base input the same way.
    assert all(ref.count("@sha256:") == 1 for ref, _ in probe.calls)
    # Nothing was obtainable for this probe, so nothing is claimed available.
    assert all(not e.available_artifact_digests for e in context.requirements)


# -- env-pack content availability (ADR-051 content boundary, issue #875) -----
#
# Content declared by an exact env-pack artifact is not an OCI image, so the
# Docker probe can never confirm it. Its availability is a fact about the pack:
# the opaque id must resolve to bytes the pack's manifest binds to the authored
# digest. These tests replace the resolver so each outcome -- match, drift,
# unresolvable -- is driven directly.


class _StubIdentity:
    def __init__(self, digest):
        self.digest = digest


class _StubResolved:
    def __init__(self, digest):
        self.identity = _StubIdentity(digest)


@pytest.fixture
def stub_pack(monkeypatch):
    """Replace the pack resolver with an in-memory ``artifact_id -> digest`` map."""

    from raes_env_packs import PackDigestError

    resolved: dict[str, str] = {}

    def _resolve(pack_root, artifact, **kwargs):
        if artifact not in resolved:
            raise PackDigestError("no such artifact in this pack")
        return _StubResolved(resolved[artifact])

    monkeypatch.setattr("raes_env_packs.resolve_pack_artifact", _resolve)
    return resolved


def _pack_requirement(digest: str = _DIGEST, *, route=None):
    """An EXACT content requirement routed through APTL's env-pack copy route."""

    from raes.artifact_requirements import (
        ArtifactIdentity,
        ArtifactRequirement,
        ArtifactSatisfactionRoute,
    )
    from raes.explicitness import ExplicitnessClass

    from aptl.backends.raes_artifact_mechanisms import env_pack_copy_profile

    return ArtifactRequirement(
        requirement_id="pack-content",
        explicitness=ExplicitnessClass.EXACT,
        exact_artifact=ArtifactIdentity(
            artifact_id="techvault-readme",
            version="0.1.0",
            digest=digest,
            media_type="text/markdown",
        ),
        permitted_routes=[
            route
            or ArtifactSatisfactionRoute(
                mechanism=env_pack_copy_profile(),
                acquisition="copy",
                timing="pack-ingestion",
            )
        ],
    )


def test_pack_content_whose_bytes_match_the_pin_is_available(tmp_path, stub_pack):
    """The pack, not the Docker backend, is what confirms content availability."""

    from aptl.backends.raes_artifact_availability import _env_pack_digest_and_provenance
    from aptl.backends.raes_artifact_mechanisms import env_pack_copy_provenance_ref

    stub_pack["techvault-readme"] = _DIGEST

    assert _env_pack_digest_and_provenance(_pack_requirement(), tmp_path) == (
        _DIGEST,
        env_pack_copy_provenance_ref(),
    )


def test_pack_content_whose_bytes_drifted_from_the_pin_is_not_available(
    tmp_path, stub_pack
):
    """RAES must reject the requirement rather than let APTL substitute bytes."""

    from aptl.backends.raes_artifact_availability import _env_pack_digest_and_provenance

    stub_pack["techvault-readme"] = _OTHER_DIGEST

    assert _env_pack_digest_and_provenance(_pack_requirement(), tmp_path) is None


def test_pack_content_the_pack_cannot_resolve_is_not_available(tmp_path, stub_pack):
    """Fail closed on a resolver error instead of assuming the artifact is there."""

    from aptl.backends.raes_artifact_availability import _env_pack_digest_and_provenance

    assert _env_pack_digest_and_provenance(_pack_requirement(), tmp_path) is None


def test_content_availability_needs_a_scenario_root_to_resolve_against(stub_pack):
    """Without a staged pack there is no pack to establish the fact from."""

    from aptl.backends.raes_artifact_availability import _env_pack_digest_and_provenance

    stub_pack["techvault-readme"] = _DIGEST

    assert _env_pack_digest_and_provenance(_pack_requirement(), None) is None


def test_a_requirement_routed_to_a_registry_pull_is_not_pack_content(
    tmp_path, stub_pack
):
    """Only the advertised copy route resolves its bytes from the pack.

    An exact requirement APTL would satisfy by pulling an OCI artifact stays the
    Docker probe's business; confirming it from the pack would establish the
    fact in the wrong domain.
    """

    from raes.artifact_requirements import ArtifactSatisfactionRoute

    from aptl.backends.raes_artifact_availability import _env_pack_digest_and_provenance

    stub_pack["techvault-readme"] = _DIGEST
    pull = ArtifactSatisfactionRoute(
        mechanism=exact_artifact_profile(),
        acquisition="pull",
        timing="backend-preparation",
    )

    assert _env_pack_digest_and_provenance(_pack_requirement(route=pull), tmp_path) is None
