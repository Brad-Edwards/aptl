"""Authored artifact demand is the sole authority for a node's image (ADR-050).

The local product allowlist in ``raes_image_realization`` predates RAES artifact
requirements. Once a node authors an artifact identity, that identity decides
what APTL pulls, and the allowlist must not be able to rescue, override, or
silently substitute for it — that substitution is what SEM-218 I1/I2 forbid and
what ADR-098 replaces.

These tests pin the *negative* space, which is where the risk lives: a node whose
authored demand cannot be resolved must produce no image and a loud diagnostic,
even when the allowlist would happily have answered.
"""

from __future__ import annotations

from raes_contracts.planning import PlannedResource

from aptl.backends.raes_image_realization import resolve_node_image

_ALLOWLISTED_NAME = "wazuh-manager"
_ALLOWLISTED_VERSION = "4.x"
_DIGEST = "sha256:" + "5" * 64


def _resource(source: dict[str, object]) -> PlannedResource:
    return PlannedResource(
        address="provision.node.target",
        domain="provisioning",
        resource_type="node",
        payload={"spec": {"node": {"source": source}}},
    )


def _resolve(source: dict[str, object], tmp_path):
    diagnostics: list = []
    image = resolve_node_image(
        resource=_resource(source),
        payload={"spec": {"node": {"source": source}}},
        project_dir=tmp_path,
        service_name="target",
        diagnostics=diagnostics,
    )
    return image, [d.message for d in diagnostics]


def test_allowlist_still_answers_a_node_with_no_authored_demand(tmp_path):
    """Legacy path intact: an unmigrated scenario keeps resolving."""

    image, diagnostics = _resolve(
        {"name": _ALLOWLISTED_NAME, "version": _ALLOWLISTED_VERSION}, tmp_path
    )

    assert image is not None
    assert image.policy_rule == "allowed-source"
    assert diagnostics == []


def test_authored_demand_wins_over_the_allowlist(tmp_path):
    """The authored digest is pulled, not the allowlist's tag."""

    image, diagnostics = _resolve(
        {
            "name": _ALLOWLISTED_NAME,
            "version": _ALLOWLISTED_VERSION,
            "artifact_requirement": {
                "requirement_id": "target-image",
                "explicitness": "exact",
                "exact_artifact": {
                    "artifact_id": "wazuh/wazuh-manager",
                    "version": "4.12.0",
                    "digest": _DIGEST,
                    "media_type": "application/vnd.oci.image.manifest.v1+json",
                },
            },
        },
        tmp_path,
    )

    assert image is not None
    assert image.policy_rule == "authored-exact-artifact"
    assert image.image_ref == f"wazuh/wazuh-manager@{_DIGEST}"
    assert diagnostics == []


def test_unresolvable_authored_demand_is_not_rescued_by_the_allowlist(tmp_path):
    """A non-exact posture APTL does not advertise must fail, not fall back.

    The source name and version here are allowlisted, so the pre-ADR-050 code
    path would have produced an image. Authored demand must suppress that.
    """

    image, diagnostics = _resolve(
        {
            "name": _ALLOWLISTED_NAME,
            "version": _ALLOWLISTED_VERSION,
            "artifact_requirement": {
                "requirement_id": "target-image",
                "explicitness": "open",
            },
        },
        tmp_path,
    )

    assert image is None
    assert any("untrusted-image" in message for message in diagnostics)


def test_malformed_authored_identity_is_refused_not_downgraded(tmp_path):
    """A bad digest fails closed rather than reverting to the allowlist."""

    image, diagnostics = _resolve(
        {
            "name": _ALLOWLISTED_NAME,
            "version": _ALLOWLISTED_VERSION,
            "artifact_requirement": {
                "requirement_id": "target-image",
                "explicitness": "exact",
                "exact_artifact": {
                    "artifact_id": "wazuh/wazuh-manager",
                    "version": "4.12.0",
                    "digest": "not-a-digest",
                    "media_type": "application/vnd.oci.image.manifest.v1+json",
                },
            },
        },
        tmp_path,
    )

    assert image is None
    assert any("untrusted-image" in message for message in diagnostics)


def test_authored_demand_suppresses_build_provenance(tmp_path):
    """``Source.build`` is observed provenance and cannot satisfy demand.

    ADR-098: reinterpreting build provenance as executable authority would turn
    evidence into a substitute for the authored artifact.
    """

    image, diagnostics = _resolve(
        {
            "name": _ALLOWLISTED_NAME,
            "version": _ALLOWLISTED_VERSION,
            "build": {
                "dockerfile_path": "containers/ad/Dockerfile",
                "instructions": ["FROM scratch"],
            },
            "artifact_requirement": {
                "requirement_id": "target-image",
                "explicitness": "open",
            },
        },
        tmp_path,
    )

    assert image is None
    assert any("untrusted-image" in message for message in diagnostics)
