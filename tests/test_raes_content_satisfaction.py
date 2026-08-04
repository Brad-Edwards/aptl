"""Satisfaction disclosure for env-pack-resolved content (issue #875).

The 19 TechVault content placements that author an EXACT ``source.artifact_requirement``
were rejected by RAES's SEM-218 runtime gate with ``runtime.backend-contract-invalid``
because APTL disclosed nothing for them: the disclosure path only covered nodes.
These tests run that same real gate (``evaluate_artifact_realization``) against a
real staged TechVault pack, so a pass proves the disclosed digest is the digest
of the pack bytes the placement actually resolved — not a payload that merely
looks well-shaped.

The decisive cases are the negatives: a placement the backend did not realize,
and a pin the pack's bytes do not match, must both produce *no* disclosure and
leave the gate rejecting.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from raes.artifact_requirements import (
    ArtifactIdentity,
    ArtifactRequirement,
    ArtifactSatisfactionRoute,
)
from raes.explicitness import ExplicitnessClass, ExplicitnessProvenance
from raes_contracts.contracts import (
    ArtifactAvailabilityContext,
    ArtifactRequirementAvailability,
)
from raes_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeDomain,
)
from raes_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry
from raes_processor.semantics.artifact_realization import evaluate_artifact_realization
from raes_processor.semantics.realization import CompiledRealizationRequirement

from aptl.backends.raes_artifact_mechanisms import (
    SOURCE_ARTIFACT_REQUIREMENT_KIND,
    env_pack_copy_profile,
    env_pack_copy_provenance_ref,
    exact_artifact_profile,
)
from aptl.backends.raes_content_satisfaction import content_satisfactions_for_plan
from aptl.backends.raes_manifest import create_aptl_manifest
from aptl.core.deployment.realization import DeploymentContentRealization
from aptl.core.scenario_bundle import env_pack_bundle

_ADDRESS = "provision.content.misp-suricata-sync-readme"
_FIELD_PATH = "content.misp-suricata-sync-readme.source.artifact_requirement"
# The readme artifact the bundled TechVault pack really carries, and the digest
# its manifest really binds those bytes to.
_ARTIFACT_ID = "techvault-misp-sync-readme"
_DIGEST = "sha256:07c3dee4987c47e57bc8f0333073abdc07b832a7e82136c3123577531978231b"
_OTHER_DIGEST = "sha256:" + "4" * 64


def _identity(digest: str = _DIGEST) -> ArtifactIdentity:
    return ArtifactIdentity(
        artifact_id=_ARTIFACT_ID,
        version="0.1.0",
        digest=digest,
        media_type="text/markdown",
    )


def _contract(digest: str = _DIGEST) -> ArtifactRequirement:
    return ArtifactRequirement(
        requirement_id="techvault-misp-sync-readme-requirement",
        explicitness=ExplicitnessClass.EXACT,
        exact_artifact=_identity(digest),
        permitted_routes=[
            ArtifactSatisfactionRoute(
                mechanism=env_pack_copy_profile(),
                acquisition="copy",
                timing="pack-ingestion",
            )
        ],
    )


def _plan(contract: ArtifactRequirement) -> ProvisioningPlan:
    return ProvisioningPlan(
        resources={
            _ADDRESS: PlannedResource(
                address=_ADDRESS,
                domain=RuntimeDomain.PROVISIONING,
                resource_type="content-placement",
                payload={
                    "content_name": "misp-suricata-sync-readme",
                    "spec": {
                        "type": "file",
                        "path": "/app/README.md",
                        "source": {
                            "name": _ARTIFACT_ID,
                            "artifact_requirement": contract.model_dump(mode="json"),
                        },
                    },
                },
            )
        }
    )


def _content(artifact_id: str = _ARTIFACT_ID) -> DeploymentContentRealization:
    """The typed placement the realization lowered for this content."""

    return DeploymentContentRealization(
        address=_ADDRESS,
        target_address="provision.node.misp-suricata-sync",
        content_name="misp-suricata-sync-readme",
        volume_suffix="",
        dest_relpath="app/README.md",
        source_kind="pack-file",
        artifact_id=artifact_id,
        artifact_digest=_DIGEST,
        media_type="text/markdown",
    )


def _compiled(contract: ArtifactRequirement) -> CompiledRealizationRequirement:
    return CompiledRealizationRequirement(
        field_path=_FIELD_PATH,
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        explicitness=ExplicitnessClass.EXACT,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="#/content/misp-suricata-sync-readme",
        artifact_requirement=contract,
    )


def _availability() -> ArtifactAvailabilityContext:
    """The facts APTL's availability pass verifies for pack-copied content."""

    return ArtifactAvailabilityContext(
        requirements=[
            ArtifactRequirementAvailability(
                address=_ADDRESS,
                available_artifact_digests=[_DIGEST],
                verified_integrity_refs=[_DIGEST],
                verified_provenance_refs=[env_pack_copy_provenance_ref()],
            )
        ]
    )


def _disclosures(bundle_root, content, contract: ArtifactRequirement | None = None):
    contract = contract if contract is not None else _contract()
    return content_satisfactions_for_plan(
        _plan(contract),
        {} if content is None else {_ADDRESS: content},
        bundle_root,
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )


def _evaluate(payload: dict[str, object] | None, contract: ArtifactRequirement):
    """Run RAES's runtime gate over a disclosure attached to the snapshot."""

    snapshot = RuntimeSnapshot(
        entries={
            _ADDRESS: SnapshotEntry(
                address=_ADDRESS,
                domain="runtime-realization",
                resource_type="content-placement",
                payload={} if payload is None else {"artifact_satisfaction": payload},
            )
        }
    )
    return evaluate_artifact_realization(
        _compiled(contract),
        {
            _ADDRESS: ProvisionOp(
                address=_ADDRESS,
                action=ChangeAction.CREATE,
                resource_type="content-placement",
                payload={},
            )
        },
        snapshot,
        manifest=create_aptl_manifest(),
        availability=_availability(),
    )


@pytest.fixture(scope="module")
def bundle_root(tmp_path_factory):
    """A real staged, validated TechVault pack — the bytes under test."""

    return env_pack_bundle(tmp_path_factory.mktemp("staged"), "techvault").root


@pytest.mark.integration
def test_realized_pack_content_satisfies_the_runtime_gate(bundle_root):
    """The disclosed digest is the pack's own bytes, and the gate accepts it."""

    disclosures = _disclosures(bundle_root, _content())

    assert set(disclosures) == {_ADDRESS}
    payload = disclosures[_ADDRESS]
    # Derived from the resolved bytes, not echoed from the declaration.
    assert payload["integrity_refs"] == [_DIGEST]
    assert payload["provenance_refs"] == [env_pack_copy_provenance_ref()]
    assert (payload["acquisition"], payload["timing"]) == ("copy", "pack-ingestion")

    diagnostic, provenance = _evaluate(payload, _contract())

    assert diagnostic is None
    assert provenance is not None
    assert provenance.provenance is ExplicitnessProvenance.AUTHOR_DECLARED


def test_absent_disclosure_is_rejected_by_the_runtime_gate():
    """The gate this suite runs really does reject an undisclosed placement."""

    diagnostic, provenance = _evaluate(None, _contract())

    assert diagnostic is not None
    assert diagnostic.code == "runtime.backend-contract-invalid"
    assert provenance is None


@pytest.mark.integration
def test_content_the_backend_did_not_realize_gets_no_disclosure(bundle_root):
    """A placement the realization never lowered discloses nothing."""

    assert _disclosures(bundle_root, None) == {}


@pytest.mark.integration
def test_content_whose_pack_bytes_differ_from_the_pin_gets_no_disclosure(bundle_root):
    """A pin the pack's actual bytes do not match is a refusal, not an echo."""

    contract = _contract(_OTHER_DIGEST)

    assert _disclosures(bundle_root, _content(), contract) == {}


@pytest.mark.integration
def test_unresolvable_artifact_id_gets_no_disclosure(bundle_root):
    """Content whose bytes the pack cannot resolve fails closed."""

    assert _disclosures(bundle_root, _content("techvault-not-in-this-pack")) == {}


@pytest.mark.integration
def test_non_pack_content_discloses_nothing(bundle_root):
    """Inline text carries no pack-resolved bytes, so there is nothing to claim."""

    inline = DeploymentContentRealization(
        address=_ADDRESS,
        target_address="provision.node.misp-suricata-sync",
        content_name="misp-suricata-sync-readme",
        volume_suffix="",
        dest_relpath="app/README.md",
        source_kind="inline-text",
        inline_text="not the pack's bytes",
    )

    assert _disclosures(bundle_root, inline) == {}


# -- unit coverage of the disclosure logic, independent of a staged pack ------
#
# The tests above run the real gate against the real pack. These drive the same
# module with the pack resolver replaced by an in-memory one, so the branches
# that decide *whether* to disclose -- resolution failures, non-pack content,
# an unadvertised route, several placements sharing one artifact -- are each
# exercised against bytes the test controls, and the disclosed digest can be
# checked against a hash the test computes itself.


class _StubResolved(object):
    """The shape ``resolve_pack_artifact`` returns: verified bytes + identity."""

    def __init__(self, data: object) -> None:
        self.data = data


@pytest.fixture
def stub_pack(monkeypatch):
    """Replace the pack resolver with an in-memory artifact-id -> bytes store."""

    from raes_env_packs import PackDigestError

    store: dict[str, object] = {}
    calls: list[str] = []

    def _resolve(pack_root, artifact, **kwargs):
        calls.append(str(artifact))
        if artifact not in store:
            raise PackDigestError("no such artifact in this pack")
        return _StubResolved(store[artifact])

    monkeypatch.setattr("raes_env_packs.resolve_pack_artifact", _resolve)
    return store, calls


def _digest_of(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


def _pack_contract(digest: str, routes: list | None = None) -> ArtifactRequirement:
    contract = _contract(digest)
    if routes is not None:
        contract = ArtifactRequirement(
            requirement_id=contract.requirement_id,
            explicitness=contract.explicitness,
            exact_artifact=contract.exact_artifact,
            permitted_routes=routes,
        )
    return contract


def test_the_disclosed_digest_is_the_hash_of_the_bytes_the_pack_resolved(stub_pack):
    """The disclosure is an independent observation, not the author's own claim.

    Hashing the resolved bytes here is what stops the gate comparing a
    declaration against itself (issue #578): the digest is only disclosable
    because the bytes really hash to it.
    """

    store, _calls = stub_pack
    payload_bytes = b"# TechVault MISP sync\n"
    store[_ARTIFACT_ID] = payload_bytes
    digest = _digest_of(payload_bytes)

    disclosures = _disclosures(Path("unused"), _content(), _pack_contract(digest))

    assert disclosures[_ADDRESS]["integrity_refs"] == [digest]
    assert disclosures[_ADDRESS]["provenance_refs"] == [env_pack_copy_provenance_ref()]


def test_bytes_that_do_not_hash_to_the_pin_produce_no_disclosure(stub_pack):
    """A pack whose bytes drifted from the pin is a refusal, not a disclosure."""

    store, _calls = stub_pack
    store[_ARTIFACT_ID] = b"these are not the authored bytes"

    disclosures = _disclosures(
        Path("unused"), _content(), _pack_contract(_digest_of(b"the authored bytes"))
    )

    assert disclosures == {}


def test_one_artifact_shared_by_several_placements_is_resolved_once(stub_pack):
    """Re-validating the pack per placement would buy nothing but wall time.

    Several TechVault placements plant the same artifact, so the resolver is
    keyed by artifact id; every sharing address must still get its own
    disclosure.
    """

    store, calls = stub_pack
    payload_bytes = b"shared artifact bytes"
    store[_ARTIFACT_ID] = payload_bytes
    contract = _pack_contract(_digest_of(payload_bytes))
    second = "provision.content.misp-suricata-sync-readme-copy"
    plan = _plan(contract)
    plan.resources[second] = PlannedResource(
        address=second,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload=plan.resources[_ADDRESS].payload,
    )
    content = _content()

    disclosures = content_satisfactions_for_plan(
        plan,
        {_ADDRESS: content, second: content},
        Path("unused"),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )

    assert set(disclosures) == {_ADDRESS, second}
    assert calls == [_ARTIFACT_ID]  # opened once, not once per placement


def test_a_plan_resource_that_is_not_a_content_placement_is_skipped(stub_pack):
    """Node artifact demand is disclosed by the node path, not this one."""

    store, calls = stub_pack
    store[_ARTIFACT_ID] = b"bytes"
    plan = _plan(_pack_contract(_digest_of(b"bytes")))
    plan.resources[_ADDRESS] = PlannedResource(
        address=_ADDRESS,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload=plan.resources[_ADDRESS].payload,
    )

    disclosures = content_satisfactions_for_plan(
        plan,
        {_ADDRESS: _content()},
        Path("unused"),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )

    assert disclosures == {}
    assert calls == []  # the pack was never opened for a non-content resource


def test_content_authoring_no_artifact_requirement_discloses_nothing(stub_pack):
    """Only an authored EXACT requirement has anything to disclose against."""

    store, _calls = stub_pack
    store[_ARTIFACT_ID] = b"bytes"
    plan = _plan(_pack_contract(_digest_of(b"bytes")))
    plan.resources[_ADDRESS].payload["spec"].pop("source")

    disclosures = content_satisfactions_for_plan(
        plan,
        {_ADDRESS: _content()},
        Path("unused"),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )

    assert disclosures == {}


def test_a_requirement_routed_somewhere_other_than_the_pack_discloses_nothing(
    stub_pack,
):
    """A digest established in the wrong domain is worse than no disclosure.

    Only the env-pack copy route resolves its bytes from the pack. A requirement
    APTL would satisfy by pulling an OCI artifact has no pack digest to derive,
    so this module discloses nothing and leaves it to the node path.
    """

    store, calls = stub_pack
    store[_ARTIFACT_ID] = b"bytes"
    pull_route = ArtifactSatisfactionRoute(
        mechanism=exact_artifact_profile(),
        acquisition="pull",
        timing="backend-preparation",
    )

    disclosures = _disclosures(
        Path("unused"),
        _content(),
        _pack_contract(_digest_of(b"bytes"), routes=[pull_route]),
    )

    assert disclosures == {}
    assert calls == []  # refused before the bytes were ever opened


def test_an_unresolvable_artifact_id_discloses_nothing(stub_pack):
    """Fail closed: the gate then reports an unrealized requirement."""

    # Nothing is registered in the stub pack, so resolution raises.
    disclosures = _disclosures(
        Path("unused"), _content(), _pack_contract(_digest_of(b"bytes"))
    )

    assert disclosures == {}


def test_a_resolution_that_yields_no_bytes_discloses_nothing(stub_pack):
    """A resolver result carrying no ``bytes`` is not something to hash."""

    store, _calls = stub_pack
    store[_ARTIFACT_ID] = None

    disclosures = _disclosures(
        Path("unused"), _content(), _pack_contract(_digest_of(b"bytes"))
    )

    assert disclosures == {}


def test_inline_text_content_discloses_nothing_without_touching_the_pack(stub_pack):
    """Inline text is not pack-resolved, so there is no artifact to claim."""

    _store, calls = stub_pack
    inline = DeploymentContentRealization(
        address=_ADDRESS,
        target_address="provision.node.misp-suricata-sync",
        content_name="misp-suricata-sync-readme",
        volume_suffix="",
        dest_relpath="app/README.md",
        source_kind="inline-text",
        inline_text="not the pack's bytes",
    )

    assert _disclosures(Path("unused"), inline) == {}
    assert calls == []
