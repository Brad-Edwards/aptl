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
from aptl.core.scenario_bundle import PackIdentity

if TYPE_CHECKING:
    from aptl.backends.raes_realization_model import NodeRealization
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext


TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST = (
    "sha256:6300b3d539ab9c1e2287b9852e5408e1811516b818a7acf015f045cb3c9c5b89"
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
}

# Canonical projections from raes-env-packs 6.0.0's content-identified
# TechVault semantic parent.  Each key is independently pinned so changing one
# SDL claim cannot borrow the pack-level identity and pass as the old contract.
_TECHVAULT_PROJECTION_DIGESTS: Mapping[tuple[str, str], str] = {
    (
        "wazuh-manager",
        "runtime-security-monitoring-managers",
    ): "sha256:673273444cb0113758a647456b9991ffe4fe14664c5e1c5c53b914ccda913588",
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
    ): "sha256:dd387e507e924d39c31590a1d6d1b2fdf52f7b0d0fa054270efeb4319b9b9486",
    (
        "suricata",
        "runtime-network-sensors",
    ): "sha256:572fa6498ba4a8638834ba09e88d21d1e00d8e04cee9ffca6b917026119e4274",
    (
        "suricata",
        "runtime-network-detection-engines",
    ): "sha256:4029678c47ecbecc41fc687137a2e060280fe8592a509c733b7cdeb8a9fd12d0",
    (
        "misp",
        "runtime-applications",
    ): "sha256:695a466be1a4fd1d028dca59e7882cb1920989807e90b8fafdca243dc6b88d59",
    (
        "misp",
        "runtime-platform-applications",
    ): "sha256:d35d442e8487794e4406c397e4847ee4508ab8ff2b77711baca8244a36816b19",
    (
        "misp-db",
        "runtime-database-services",
    ): "sha256:58585580257e0c58d9ff05a6bded97731d2ca29595cae0b49af43f20bd8a7f85",
    (
        "misp-redis",
        "runtime-datastore-services",
    ): "sha256:532908f8723fec8b61323bb244e2e7347d10067d8970a36fc9620f7b56973ff5",
    (
        "thehive",
        "runtime-applications",
    ): "sha256:25d79a15dd2ff14252df9865a15815b9de75f163d27490dc77eb68921867dfdb",
    (
        "thehive",
        "runtime-platform-applications",
    ): "sha256:54e3f6ae2ba346a02ded3198ab549c11d2341c00f847322a2cfee31bf4a2a2a3",
    (
        "thehive-cassandra",
        "runtime-datastore-services",
    ): "sha256:326196501a77fab81362db069cf443d657b2ae01f4bb4e4ea9cb9cdd3e97db3b",
    (
        "cortex",
        "runtime-applications",
    ): "sha256:0a9e923b5b72896dd1597addbde277cadaa54ef7157f08695c8e9473fc357488",
    (
        "cortex",
        "runtime-platform-applications",
    ): "sha256:f3b91902229e65b5d2897c0ab6200a664966becf143943230fde61e1298c0674",
    (
        "cortex",
        "runtime-app-authorizations",
    ): "sha256:a1b19c12c39187d499d0c2efe442c04007b53900ecf30774c042e1a6c680b9ed",
    (
        "shuffle-backend",
        "runtime-applications",
    ): "sha256:821ef558662cee89cfa372b7d2ef46ef60acdb57be9e230fc2daf15d5e61168e",
    (
        "shuffle-backend",
        "runtime-platform-applications",
    ): "sha256:132c0dbd2c236fef56b3a8c338777cdfd58b0ab9eda9525824460e84036f8c5a",
    (
        "shuffle-frontend",
        "runtime-applications",
    ): "sha256:20af8f50579a8093236f7e4658c656d912d62a2887945ca7846eae32bff5e992",
    (
        "shuffle-orborus",
        "runtime-orchestration-authorities",
    ): "sha256:9e55aa19ef3e27f14f76810e8b30c1b4cc50f242506ecb4aa132d1f51ce2ce5e",
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
}


def _identified_release(identity: PackIdentity | None) -> bool:
    return bool(
        identity is not None
        and identity.pack_id == "techvault"
        and identity.pack_version == "0.1.0"
        and identity.set_digest == TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST
    )


def _expected_image_digest(node: NodeRealization) -> str | None:
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
        actual = backend.container_image_digest(node.container_name or "")
        if actual is None and observation_context is not None:
            actual = observation_context.completed_image_digest(
                node.container_name or ""
            )
        return actual == expected
    # Dynamic-composition nodes have no authored OCI source.  Their exact pack
    # content is the implementation authority, so at least one targeted content
    # placement must have passed its own native type/digest observation.
    return bool(node.image is None and content_verified)


def observe_techvault_attested_concerns(
    backend: DeploymentBackend,
    node: NodeRealization,
    pack_identity: PackIdentity | None,
    *,
    content_verified: bool,
    observation_context: DeploymentObservationContext | None = None,
) -> dict[tuple[str, ...], object]:
    """Return only released, implementation-bound TechVault configuration."""

    runtime = node.runtime
    if (
        runtime is None
        or not node.container_name
        or not _identified_release(pack_identity)
        or not _implementation_observed(
            backend,
            node,
            content_verified=content_verified,
            observation_context=observation_context,
        )
    ):
        return {}

    concerns: dict[tuple[str, ...], object] = {}
    for kind, field in _RUNTIME_FIELD_BY_KIND.items():
        value = getattr(runtime, field, None)
        expected = _TECHVAULT_PROJECTION_DIGESTS.get((node.name, kind))
        if value in (None, [], {}) or expected is None:
            continue
        projected = project_realization_concern(kind, value, observed=False)
        if canonical_json_digest(projected) != expected:
            continue
        disclosed = _disclose(kind, value)
        if disclosed is not None:
            concerns[CONCERN_PAYLOAD_PATH[kind]] = disclosed
    return concerns


__all__ = [
    "ARTIFACT_ATTESTED_RUNTIME_CONCERNS",
    "TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST",
    "observe_techvault_attested_concerns",
]
