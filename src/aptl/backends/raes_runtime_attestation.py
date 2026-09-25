"""Content-addressed attestations for TechVault configuration concerns.

The released TechVault pack describes configuration that is distributed across
immutable images and exact pack-content placements.  Rediscovering those
declarations by installing an in-world inventory agent would be more intrusive
and, for this open scope, unnecessary.  APTL instead keeps a narrow backend
compatibility attestation: it binds the released pack semantic digest to the
canonical projection of each supported concern, then corroborates the running
node through its settled-container observation, exact image digest, and exact
content-placement observations before this module is called.

This is deliberately not a general "echo the plan" path.  An unknown pack,
changed concern value, missing content observation, mutable image reference, or
different realized image yields no disclosure, so RAES rejects realization.
APTL #1017 tracks deleting this release-specific compatibility surface once the
upstream evidence-source contract tracked by OpenRAE/rae#1285 is available.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from raes_contracts.canonical import canonical_json_digest
from raes_processor.semantics.realization import (
    CONCERN_PAYLOAD_PATH,
    project_realization_concern,
)

from aptl.backends._runtime_concern_disclosure import _disclose
from aptl.core.deployment._wazuh_attestation import (
    declared_wazuh_facts_match,
)
from aptl.core.scenario_bundle import PackIdentity

if TYPE_CHECKING:
    from aptl.backends.raes_realization_model import NodeRealization
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext


TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST = (
    "sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b"
)
TECHVAULT_STUDY_RUNTIME_ATTESTATION_SET_DIGEST = (
    "sha256:65040b16d53a525861116a779c14cc8b58c1bfc6c30257e4d8940d552a755934"
)

# These are configuration descriptions whose realized implementation is bound
# to a released immutable image and/or exact pack content.  Dynamic state fields
# are excluded by RAES's concern projectors; local identity, dependency
# installation, and the Docker socket use direct observers instead.
ARTIFACT_ATTESTED_RUNTIME_CONCERNS = frozenset(
    {
        "runtime-app-authorizations",
        "runtime-applications",
        "runtime-database-services",
        "runtime-datastore-services",
        "runtime-dns-services",
        "runtime-file-services",
        "runtime-identity-authorities",
        "runtime-network-detection-engines",
        "runtime-network-sensors",
        "runtime-orchestration-authorities",
        "runtime-platform-applications",
        "runtime-security-monitoring-managers",
        "runtime-software-components",
    }
)

_RUNTIME_FIELD_BY_KIND = {
    "runtime-app-authorizations": "app_authorizations",
    "runtime-applications": "applications",
    "runtime-database-services": "database_services",
    "runtime-datastore-services": "datastore_services",
    "runtime-dns-services": "dns_services",
    "runtime-file-services": "file_services",
    "runtime-identity-authorities": "identity_authorities",
    "runtime-network-detection-engines": "network_detection_engines",
    "runtime-network-sensors": "network_sensors",
    "runtime-orchestration-authorities": "orchestration_authorities",
    "runtime-platform-applications": "platform_applications",
    "runtime-security-monitoring-managers": "security_monitoring_managers",
    "runtime-software-components": "software_components",
}

# Canonical projections from raes-env-packs 6.1.0's content-identified
# TechVault semantic parent.  Each key is independently pinned so changing one
# SDL claim cannot borrow the pack-level identity and pass as the old contract.
_TECHVAULT_PROJECTION_DIGESTS: Mapping[tuple[str, str], str] = {
    (
        "wazuh-manager",
        "runtime-security-monitoring-managers",
    ): "sha256:72687494a6fb4ada178d1827425b9321b3d9697ece1204c12081ed4f5a5f8272",
    (
        "wazuh-indexer",
        "runtime-datastore-services",
    ): "sha256:f5765db8f0ba02df04ef4d6b373ef528e5e9bac46e82b76d38efb855332083dd",
    (
        "wazuh-dashboard",
        "runtime-applications",
    ): "sha256:563eec6239d88d3765d0ccd8f51194df897faf127524f86aa5b3cffc2d03ecda",
    (
        "wazuh-dashboard",
        "runtime-platform-applications",
    ): "sha256:610e9f3f21f2260c8839a4a4a6f57d7a02d4734596cf38a52e72222431d164ea",
    (
        "suricata",
        "runtime-network-sensors",
    ): "sha256:6db48f0b36ebaf391850e28030901b8c819576bbdc2cf706af353a17bbcd05c6",
    (
        "suricata",
        "runtime-network-detection-engines",
    ): "sha256:1565f219d7ba3f41bf2a62d7e9461c52ba7282ab6877668f5c09e232ab5bf9c2",
    (
        "misp",
        "runtime-applications",
    ): "sha256:695a466be1a4fd1d028dca59e7882cb1920989807e90b8fafdca243dc6b88d59",
    (
        "misp",
        "runtime-platform-applications",
    ): "sha256:8f624772231c88df702acaa80459c03c42c8262239b100a1e2efa881a77a0258",
    (
        "misp",
        "runtime-app-authorizations",
    ): "sha256:8ac233f5a5fa7d0db293530e3e358a2087c86b56249e8bb52cb4ac5c4bf1b373",
    (
        "misp-db",
        "runtime-database-services",
    ): "sha256:2709e6a3c901c70357ca10c2ecd3a050d64a0cc2904ca43ae2504232996924ca",
    (
        "misp-redis",
        "runtime-datastore-services",
    ): "sha256:d61c29f46d1fe792418f5ebb6dc523af9742646c9bffc76244b33709986bda28",
    (
        "thehive",
        "runtime-applications",
    ): "sha256:25d79a15dd2ff14252df9865a15815b9de75f163d27490dc77eb68921867dfdb",
    (
        "thehive",
        "runtime-platform-applications",
    ): "sha256:3bde1d181f247b5e4ba276cea79e03e0a45637bc1726a4e47a78f77da23a64ab",
    (
        "thehive-cassandra",
        "runtime-datastore-services",
    ): "sha256:326196501a77fab81362db069cf443d657b2ae01f4bb4e4ea9cb9cdd3e97db3b",
    (
        "thehive-es",
        "runtime-datastore-services",
    ): "sha256:80f071daa8b1525d255bb004cefc651b948fb0b9ac420d0fc44d01123fb82ae3",
    (
        "cortex",
        "runtime-applications",
    ): "sha256:0a9e923b5b72896dd1597addbde277cadaa54ef7157f08695c8e9473fc357488",
    (
        "cortex",
        "runtime-platform-applications",
    ): "sha256:86ffcb02a02f981b318a6fceba6e28ae8479d5dfadba898f5652cc88e0979879",
    (
        "cortex",
        "runtime-app-authorizations",
    ): "sha256:3aa823bef478c17bff706dd7c4634777a33439341ef86d391e5752c8193b059e",
    (
        "shuffle-backend",
        "runtime-applications",
    ): "sha256:821ef558662cee89cfa372b7d2ef46ef60acdb57be9e230fc2daf15d5e61168e",
    (
        "shuffle-backend",
        "runtime-platform-applications",
    ): "sha256:a6d2948051f9478d4a86172a28dc86be39075e516565f2120b5193a03942b6db",
    (
        "shuffle-frontend",
        "runtime-applications",
    ): "sha256:20af8f50579a8093236f7e4658c656d912d62a2887945ca7846eae32bff5e992",
    (
        "shuffle-frontend",
        "runtime-software-components",
    ): "sha256:cf75dd9ed99885b9eca91d735936bf0179ec76674b128368b0f6680afe3f91d1",
    (
        "shuffle-orborus",
        "runtime-software-components",
    ): "sha256:185a161019fbb37f346035b269776c0264a15df83eaeca4a3fe8d743e714688b",
    (
        "shuffle-orborus",
        "runtime-orchestration-authorities",
    ): "sha256:e1c3a94200650b644c26ee8c99538be39c88349da45d23aecd465b35d9184e20",
    (
        "shuffle-opensearch",
        "runtime-datastore-services",
    ): "sha256:1cc53bd45b8d502a8530a91040119aeda334f95b3f0a57bf3d87d254a6f735d6",
    (
        "webapp",
        "runtime-applications",
    ): "sha256:5c93ae8784004257f49defe999fd51f6636bf869f5c119839e6c467730ad8a14",
    (
        "ad",
        "runtime-identity-authorities",
    ): "sha256:4eac474d038b87493e76130f1546d5279a61dcc32957b50024056087522873b4",
    (
        "db",
        "runtime-database-services",
    ): "sha256:61b3795fd7e204c536d4ffe0a9e85d22330208e9afed5620142b0d7ebcc654aa",
    (
        "fileshare",
        "runtime-file-services",
    ): "sha256:2174880b6fa567241fc5833ff45b6402d4a0b38c20204b85bf060cad7a20fbd3",
    (
        "dns",
        "runtime-dns-services",
    ): "sha256:94f5fbaed6fb987cacb4ff1f3624bc56480097d86ccca5b94f31ac88b430e1cb",
    (
        "kali",
        "runtime-software-components",
    ): "sha256:e83b38223edc02f4efe69e75fe93d5d1c4754a2609da58a6d7827e50a233643c",
    (
        "soc-workstation",
        "runtime-software-components",
    ): "sha256:e45538e8e267f242ca508397cdb200219da2d4b20fa846f3d72f594c14826db6",
}


def _identified_release(identity: PackIdentity | None) -> bool:
    """Return whether the bundle is the one attested TechVault release."""

    return bool(
        identity is not None
        and (
            identity.pack_id,
            identity.pack_version,
            identity.set_digest,
        )
        in {
            ("techvault", "0.1.0", TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST),
            (
                "techvault-participant-study",
                "0.1.0",
                TECHVAULT_STUDY_RUNTIME_ATTESTATION_SET_DIGEST,
            ),
        }
    )


def _expected_image_digest(node: NodeRealization) -> str | None:
    """Read an exact immutable digest from the node's admitted image reference."""

    image = getattr(node, "image", None)
    image_ref = getattr(image, "image_ref", None)
    if not isinstance(image_ref, str) or "@" not in image_ref:
        return None
    digest = image_ref.rsplit("@", 1)[1]
    return digest if digest.startswith("sha256:") and len(digest) == 71 else None


def _implementation_observed(
    backend: DeploymentBackend,
    node: NodeRealization,
    *,
    content_verified: bool,
    observation_context: DeploymentObservationContext | None,
) -> bool:
    """Bind the attestation to this settled node's immutable implementation."""

    expected = _expected_image_digest(node)
    if expected is not None:
        return _container_digest_observed(backend, node, expected, observation_context)
    image = getattr(node, "image", None)
    backend_build = bool(
        getattr(image, "mode", None) == "build"
        and getattr(image, "policy_rule", None) == "backend-open-profile"
    )
    if backend_build:
        selected = backend.substrate_image_identity(image.image_ref)
        actual = backend.container_image_config_id(node.container_name or "")
        return bool(selected is not None and actual == selected[0])
    # Dynamic-composition nodes have no authored OCI source.  Their exact pack
    # content is the implementation authority, so at least one targeted content
    # placement must have passed its own native type/digest observation.
    return bool(node.image is None and content_verified)


def _container_digest_observed(
    backend: DeploymentBackend,
    node: NodeRealization,
    expected: str,
    observation_context: DeploymentObservationContext | None,
) -> bool:
    """Verify a running or completed container against its admitted digest."""

    container_name = node.container_name or ""
    actual = backend.container_image_digest(container_name)
    if actual is None and observation_context is not None:
        actual = observation_context.completed_image_digest(container_name)
    return actual == expected


def observe_techvault_attested_concerns(
    backend: DeploymentBackend,
    node: NodeRealization,
    pack_identity: PackIdentity | None,
    *,
    content_verified: bool,
    observation_context: DeploymentObservationContext | None = None,
) -> dict[tuple[str, ...], object]:
    """Return only released, implementation-bound TechVault configuration."""

    if not _node_is_attestable(
        backend,
        node,
        pack_identity,
        content_verified=content_verified,
        observation_context=observation_context,
    ):
        return {}

    concerns: dict[tuple[str, ...], object] = {}
    for kind, field in _RUNTIME_FIELD_BY_KIND.items():
        disclosed = _attested_concern(backend, node, kind, field)
        if disclosed is not None:
            concerns[CONCERN_PAYLOAD_PATH[kind]] = disclosed
    return concerns


def _node_is_attestable(
    backend: DeploymentBackend,
    node: NodeRealization,
    pack_identity: PackIdentity | None,
    *,
    content_verified: bool,
    observation_context: DeploymentObservationContext | None,
) -> bool:
    """Return whether one node is bound to an admitted released implementation."""

    return bool(
        node.runtime is not None
        and node.container_name
        and _identified_release(pack_identity)
        and _implementation_observed(
            backend,
            node,
            content_verified=content_verified,
            observation_context=observation_context,
        )
    )


def _attested_concern(
    backend: DeploymentBackend,
    node: NodeRealization,
    kind: str,
    field: str,
) -> object | None:
    """Return one digest-bound concern after its required native observation."""

    value = getattr(node.runtime, field, None)
    expected = _TECHVAULT_PROJECTION_DIGESTS.get((node.name, kind))
    result: object | None = None
    observation_ok = not _requires_declared_wazuh_attestation(
        node, kind
    ) or _declared_wazuh_facts_observed(backend, node)
    if value not in (None, [], {}) and expected is not None and observation_ok:
        projected = project_realization_concern(kind, value, observed=False)
        if canonical_json_digest(projected) == expected:
            result = _disclose(kind, value)
    return result


def _declared_wazuh_facts_observed(
    backend: DeploymentBackend, node: NodeRealization
) -> bool:
    """Require native API evidence before disclosing Wazuh runtime facts."""

    readiness = getattr(backend, "declared_wazuh_attestation", {})
    services = tuple(getattr(node, "backend_services", ()))
    service = services[0] if len(services) == 1 else None
    return declared_wazuh_facts_match(readiness, service, node)


def _requires_declared_wazuh_attestation(node: NodeRealization, kind: str) -> bool:
    """Identify the two Wazuh declarations backed by native API observations."""

    return (node.name, kind) in {
        ("wazuh-indexer", "runtime-datastore-services"),
        ("wazuh-manager", "runtime-security-monitoring-managers"),
    }


__all__ = [
    "ARTIFACT_ATTESTED_RUNTIME_CONCERNS",
    "TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST",
    "observe_techvault_attested_concerns",
]
