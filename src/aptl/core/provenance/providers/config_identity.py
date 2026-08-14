"""Safe effective-configuration identity (REP-003 / issue #452).

Records WHICH configuration the apparatus was realized under, as a versioned
projection built beside the strict :class:`~aptl.core.config.AptlConfig`
owner — never ``model_dump()`` of the whole config, and never a digest of the
config FILE.

Both rejected alternatives are unsafe for the same reason: they are
open-by-default. A whole-model dump silently absorbs every field a future
schema adds, including the next credential locator, and
``snapshot._hash_config_files()`` hashes ``.env`` itself. ADR-029 and the
preflight both require the opposite posture — an explicit allowlist of
apparatus-relevant fields, with secret values, private-key material,
credential locators, and privacy-sensitive host/path details excluded by
construction.

Deployment MODE is apparatus-relevant and kept; the deployment HOST, user, key
path, and remote directory are not, and are dropped. That distinction is what
lets a reader assess comparability ("this ran over ssh-compose") without the
record disclosing where or as whom.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from aptl.core.provenance.identity import ProvenanceLeaf, derive_identity
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult
from aptl.core.provenance.providers import _degraded
from aptl.core.provenance.providers._degraded import ProviderDegraded

log = logging.getLogger(__name__)

#: The code-owned provider id for effective-configuration identity.
CONFIG_PROVIDER_ID = "config-identity"

#: Versioned identity of the safe projection shape. Adding or removing an
#: allowlisted field bumps this so an archived identity is never reinterpreted.
SAFE_CONFIG_SCHEMA_VERSION = "aptl-safe-config-identity/v2"

#: Identity domain for the configuration projection.
_DOMAIN = "config"


def _containers_projection(config: object) -> dict[str, object]:
    """Return the enabled-container flags, which shape the realized range."""
    containers = getattr(config, "containers", None)
    if containers is None:
        return {}
    dumped = containers.model_dump()
    # Every field of ContainerSettings is a first-party boolean toggle
    # (ADR-025 strict schema), so this stays a closed, non-secret surface.
    return {
        key: value for key, value in sorted(dumped.items()) if isinstance(value, bool)
    }


def _participant_models_projection(config: object) -> dict[str, object]:
    """Return the frozen installed-participant model identities."""
    experiment = getattr(config, "experiment", None)
    models = getattr(experiment, "participant_models", None) if experiment else None
    if models is None:
        return {}
    return {
        "claude": getattr(models, "claude", None),
        "codex": getattr(models, "codex", None),
    }


def _participant_credential_sources_projection(
    config: object,
) -> dict[str, object]:
    """Return locator-free identities for configured participant sources."""

    experiment = getattr(config, "experiment", None)
    sources = (
        getattr(experiment, "participant_credential_sources", None)
        if experiment
        else None
    )
    if sources is None:
        return {}
    projection: dict[str, object] = {}
    for provider in ("claude", "codex"):
        source = getattr(sources, provider, None)
        projection[provider] = (
            None
            if source is None
            else {
                "kind": source.kind,
                "descriptor_sha256": source.descriptor_digest(),
            }
        )
    return projection


def safe_config_projection(config: object) -> dict[str, object]:
    """Return the versioned, allowlisted apparatus-relevant configuration.

    Only the fields named here are ever recorded. Anything not listed —
    including every field a future schema revision introduces — is excluded by
    default rather than by a later filter.
    """
    lab = getattr(config, "lab", None)
    deployment = getattr(config, "deployment", None)
    run_storage = getattr(config, "run_storage", None)
    experiment = getattr(config, "experiment", None)
    lifecycle = getattr(config, "lifecycle_policy", None)

    return {
        "schema_version": SAFE_CONFIG_SCHEMA_VERSION,
        "lab_name": getattr(lab, "name", None),
        "lab_network_subnet": getattr(lab, "network_subnet", None),
        # Mode only. ssh_host / ssh_user / ssh_key / remote_dir / ssh_port are
        # host details and a credential locator, and are deliberately absent.
        "deployment_provider": getattr(deployment, "provider", None),
        "deployment_project_name": getattr(deployment, "project_name", None),
        # Backend kind only; local_path and the s3 bucket/prefix are locators.
        "run_storage_backend": getattr(run_storage, "backend", None),
        "containers": _containers_projection(config),
        "participant_action_timeout_seconds": getattr(
            experiment, "participant_action_timeout_seconds", None
        ),
        "participant_models": _participant_models_projection(config),
        "participant_source_descriptors": (
            _participant_credential_sources_projection(config)
        ),
        "lifecycle_policy_declared": lifecycle is not None,
    }


class ConfigIdentityProvider:
    """Collects the effective configuration's identity as one leaf."""

    provider_id = CONFIG_PROVIDER_ID

    def __init__(self, config: object | None) -> None:
        self._config = config

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Derive one identity from the safe configuration projection."""
        try:
            projection, leaf = self._gather(context)
        except ProviderDegraded as signal:
            return signal.as_result(self.provider_id)
        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=(leaf,),
            payload=dict(projection),
        )

    def _gather(
        self, context: ProvenanceContext
    ) -> tuple[Mapping[str, object], ProvenanceLeaf]:
        """Build the safe projection and its leaf, or declare a degradation."""
        if self._config is None:
            raise _degraded.absent()
        try:
            projection: Mapping[str, object] = safe_config_projection(self._config)
            leaf = ProvenanceLeaf(
                "effective-config", derive_identity(_DOMAIN, projection)
            )
        except (TypeError, ValueError, AttributeError) as exc:
            log.warning(
                "run-provenance: safe config projection could not be identified"
            )
            raise _degraded.owner_failure() from exc
        if context.expired():
            raise _degraded.deadline()
        return projection, leaf
