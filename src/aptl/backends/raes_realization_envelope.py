"""APTL's ``realization-envelope-v1`` disclosure (RAES ADR-088 / issue #889).

A backend that admits a service-materialization profile must publish a complete,
digest-valid realization envelope whose ``content-placement`` concern is
``realized`` with at least ``daemon-observed`` strength — the independent-readback
evidence the RAES planner requires before a profile claim is admissible
(``service_materialization_plan_diagnostics``). APTL never advertised a profile
before, so this is its first envelope; it is intentionally honest about what APTL
realizes and observes through the Docker daemon and does not overclaim shapes
APTL only sees from planned or logical state.

The two digests (the configuration digest and the envelope digest) are computed
from the canonical payload rather than hand-authored, so the disclosure cannot
silently drift from its content.
"""

from __future__ import annotations

from raes_backend_protocols.provisioner_capabilities import ProvisionerCapabilities
from raes_contracts.realization_envelope import (
    BackendRealizationEnvelopeModel,
    realization_envelope_digest,
    realizer_configuration_digest,
)

APTL_ENVELOPE_MODE = "aptl-docker-compose"
_ENVELOPE_ID = "aptl-docker-compose.v1"
_PLACEHOLDER_DIGEST = "sha256:" + "0" * 64

# Every governed concern must be disclosed. APTL realizes and observes these
# through the Docker daemon. content-placement is realized at daemon-observed
# strength: content and service materialization are proven by read-after-write /
# fresh native readback against the running daemon, not merely driver-reported.
# feature-binding is unsupported: APTL resolves a feature to its target node but
# performs no separate operational realization op with independent observation
# (the capability ships in the node image), matching the libvirt backend's own
# feature-binding disclosure. An unsupported concern is the only disposition that
# carries no observation/mechanism.
_CONCERNS = (
    ("topology", "realized", "daemon-observed", "docker-compose-networking"),
    ("architecture", "realized", "daemon-observed", "container-architecture-readback"),
    ("image", "realized", "daemon-observed", "oci-image-inspect-readback"),
    ("resource-allocation", "realized", "daemon-observed", "compose-resource-limits-readback"),
    ("network", "realized", "daemon-observed", "docker-network-readback"),
    ("content-placement", "realized", "daemon-observed", "compose-and-service-materialization-readback"),
    ("account-placement", "realized", "daemon-observed", "container-exec-account-readback"),
    ("feature-binding", "unsupported", "none", None),
    ("service", "realized", "daemon-observed", "compose-service-readback"),
    ("acl", "realized", "daemon-observed", "nftables-owner-scoped-readback"),
)


def _configuration_payload(provisioner: ProvisionerCapabilities) -> dict[str, object]:
    """Build the realizer configuration payload, digested in place below."""

    configuration: dict[str, object] = {
        "mode": APTL_ENVELOPE_MODE,
        "configuration_digest": _PLACEHOLDER_DIGEST,
        "architecture": "x86_64",
        "image_policy": "oci-exact-pull-or-per-component-build",
        "network_policy": "docker-compose-managed",
        "supported_node_types": sorted(provisioner.supported_node_types),
        "supported_os_families": sorted(provisioner.supported_os_families),
        "supported_content_types": sorted(provisioner.supported_content_types),
        "supported_account_features": sorted(provisioner.supported_account_features),
        "supported_domain_profiles": sorted(provisioner.supported_domain_profiles),
        "supports_acls": provisioner.supports_acls,
        "memory_mib": {"minimum": 128, "maximum": None},
        "vcpus": {"minimum": 1, "maximum": None},
    }
    # ``realizer_configuration_digest`` canonicalizes over the configuration
    # ignoring the self-referential digest field, so a placeholder is safe here.
    configuration["configuration_digest"] = realizer_configuration_digest(configuration)
    return configuration


def build_aptl_realization_envelope(
    provisioner: ProvisionerCapabilities,
) -> BackendRealizationEnvelopeModel:
    """Return APTL's digest-valid realization-envelope-v1 disclosure."""

    payload: dict[str, object] = {
        "schema_version": "realization-envelope/v1",
        "contract_id": "realization-envelope-v1",
        "id": _ENVELOPE_ID,
        "expression": {
            "schema_version": "realization-envelope/v1",
            "id": "aptl-docker-compose.expression.v1",
            "scope": "scenario",
            "domains": {},
            "bindings": [],
            "closure": [],
        },
        "configuration": _configuration_payload(provisioner),
        "concerns": [
            {
                "concern": concern,
                "disposition": disposition,
                "observation_strength": strength,
                "mechanism": mechanism,
                "transformations": [],
            }
            for concern, disposition, strength, mechanism in _CONCERNS
        ],
        "digest": _PLACEHOLDER_DIGEST,
    }
    payload["digest"] = realization_envelope_digest(payload)
    return BackendRealizationEnvelopeModel.model_validate(payload)
