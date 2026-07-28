"""RAES apparatus-manifest provenance (REP-003 / issue #452).

Records WHICH processor and backend the run was realized against, using the
owner-native serializers — :func:`create_aptl_manifest` plus
``raes_backend_protocols.manifest.backend_manifest_payload`` for the backend,
and ``raes_processor.manifest.reference_processor_manifest_payload`` for the
processor.

The payloads are hashed as opaque owner-native documents. APTL does not
restate, subclass, or locally validate a RAES DTO here; the manifests'
declared capabilities already come from the same code-owned registries that
implement them (for example, ``create_aptl_manifest()``'s observation
capability is projected from the collector registry, not a hand-maintained
matrix).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

import rfc8785
from raes_backend_protocols.manifest import backend_manifest_payload
from raes_processor.manifest import reference_processor_manifest_payload

from aptl.backends.raes_manifest import create_aptl_manifest
from aptl.core.provenance.identity import ProvenanceLeaf, digest_bytes
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult

log = logging.getLogger(__name__)

#: The code-owned provider id for apparatus manifests.
APPARATUS_PROVIDER_ID = "apparatus"


def _default_backend_payload() -> Mapping[str, object]:
    """Return the canonical APTL backend manifest payload."""
    return backend_manifest_payload(create_aptl_manifest())


def _identity_projection(payload: Mapping[str, object]) -> dict[str, object]:
    """Return the small, safe identity summary for a manifest payload.

    The full payload is hashed into the leaf; only stable identity and the
    declared contract versions are surfaced as readable fields, so the record
    stays bounded while remaining answerable.
    """
    identity = payload.get("identity")
    identity = identity if isinstance(identity, Mapping) else {}
    contracts = payload.get("supported_contract_versions")
    return {
        "name": identity.get("name"),
        "version": identity.get("version"),
        "schema_version": payload.get("schema_version"),
        "supported_contract_versions": sorted(contracts)
        if isinstance(contracts, (list, tuple, set, frozenset))
        else [],
    }


class ApparatusManifestProvider:
    """Collects processor and backend manifest identity from their owners."""

    provider_id = APPARATUS_PROVIDER_ID

    def __init__(
        self,
        backend_manifest_factory: Callable[[], Mapping[str, object]] = _default_backend_payload,
        processor_manifest_factory: Callable[
            [], Mapping[str, object]
        ] = reference_processor_manifest_payload,
    ) -> None:
        self._backend_factory = backend_manifest_factory
        self._processor_factory = processor_manifest_factory

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Serialize both manifests and bind each to its logical role."""
        try:
            backend = dict(self._backend_factory())
            processor = dict(self._processor_factory())
            leaves = (
                ProvenanceLeaf("backend-manifest", digest_bytes(rfc8785.dumps(backend))),
                ProvenanceLeaf("processor-manifest", digest_bytes(rfc8785.dumps(processor))),
            )
        except Exception:
            # A manifest serializer failing is an owner fault. Its exception
            # text can name host paths and is never carried into the record.
            log.warning("run-provenance: apparatus manifest serialization failed")
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.FAILED,
                detail="owner reported failure",
            )

        if context.expired():
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.TIMED_OUT,
                detail="deadline exceeded",
            )

        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=tuple(sorted(leaves)),
            payload={
                "backend": _identity_projection(backend),
                "processor": _identity_projection(processor),
            },
        )
