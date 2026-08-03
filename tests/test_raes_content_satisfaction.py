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
)
from aptl.backends.raes_content_satisfaction import content_satisfactions_for_plan
from aptl.backends.raes_manifest import create_aptl_manifest
from aptl.core.deployment.realization import DeploymentContentRealization
from aptl.core.scenario_bundle import env_pack_bundle

pytestmark = pytest.mark.integration

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


def test_content_the_backend_did_not_realize_gets_no_disclosure(bundle_root):
    """A placement the realization never lowered discloses nothing."""

    assert _disclosures(bundle_root, None) == {}


def test_content_whose_pack_bytes_differ_from_the_pin_gets_no_disclosure(bundle_root):
    """A pin the pack's actual bytes do not match is a refusal, not an echo."""

    contract = _contract(_OTHER_DIGEST)

    assert _disclosures(bundle_root, _content(), contract) == {}


def test_unresolvable_artifact_id_gets_no_disclosure(bundle_root):
    """Content whose bytes the pack cannot resolve fails closed."""

    assert _disclosures(bundle_root, _content("techvault-not-in-this-pack")) == {}


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
