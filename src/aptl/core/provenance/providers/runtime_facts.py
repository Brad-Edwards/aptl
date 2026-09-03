"""Realized image, tool, and range-inventory provenance (REP-003 / issue #452).

Reads the APTL :class:`~aptl.core.snapshot.RangeSnapshot` the deployment owner
already captured — this provider never calls Docker, Compose, SSH, or a shell,
and never re-inspects the range.

Two distinctions from the preflight are enforced here:

* **Identity versus observation.** An image's immutable digest is identity; its
  tag, container id, status, and health are observations that must not perturb
  a stable identity. A container whose immutable digest is missing is declared
  in ``images_without_digest`` rather than having a tag substituted for it —
  ``ContainerSnapshot.image_digest`` is not currently proven to be populated
  everywhere, and a guessed identity is worse than a disclosed gap.
* **Bounded projection.** Container labels and arbitrary metadata are NOT
  embedded. A hostile or oversized label set would otherwise become record
  keys and unbounded content; only the range snapshot's own redacted
  projection is folded into a single identity.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

import rfc8785

from aptl.core.provenance.identity import (
    ProvenanceLeaf,
    derive_identity,
    digest_bytes,
    normalize_digest,
    validate_logical_id,
)
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult
from aptl.core.provenance.providers import _degraded
from aptl.core.provenance.providers._degraded import ProviderDegraded

log = logging.getLogger(__name__)

#: The code-owned provider id for realized runtime facts.
RUNTIME_PROVIDER_ID = "runtime-facts"

#: Identity domain for runtime facts.
_DOMAIN = "runtime"

#: The tool versions the snapshot owner exposes, as (record key, attribute).
_TOOL_FIELDS = (
    ("python", "python_version"),
    ("docker", "docker_version"),
    ("compose", "compose_version"),
    ("wazuh_manager", "wazuh_manager_version"),
    ("wazuh_indexer", "wazuh_indexer_version"),
    ("aptl", "aptl_version"),
    ("raes", "raes_version"),
)


#: The CLOSED allowlist of host/runtime facts that are relevant to validity.
#: This is not an inventory dump: hostname, user, network addresses, hardware,
#: process lists, and environment are all deliberately outside it.
_HOST_FACT_KEYS = frozenset({"os", "arch", "kernel", "python", "docker_mode"})

#: Bound on any single host-fact value, so a probe cannot inject unbounded
#: content into the record.
_MAX_HOST_FACT_LEN = 128


def default_host_facts() -> dict[str, str]:
    """Return the bounded, validity-relevant host facts.

    Reuses the existing host-environment owner rather than probing directly:
    :func:`aptl.core.hostenv.host_os` and
    :func:`aptl.core.hostenv.docker_mode` already own those determinations.

    ``docker_mode()`` spawns a real ``docker info`` subprocess, so this is the
    only I/O this provider performs. It is therefore NOT the constructor
    default — see :func:`no_host_facts`.
    """
    import platform

    from aptl.core.hostenv import docker_mode, host_os

    return {
        "os": host_os(),
        "arch": platform.machine(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "docker_mode": docker_mode(),
    }


def no_host_facts() -> dict[str, str]:
    """Return no host facts. The constructor default.

    Host inventory is the one source in this provider that costs a subprocess
    probe, so *composing* it is an explicit decision made once in
    :func:`aptl.core.provenance.registrations.build_default_providers`, not a
    hidden default that every construction silently inherits.

    Making the live probe the default meant any caller — including every test
    that only cared about image digests — transparently spawned
    ``docker info``, making behavior depend on whether a Docker daemon was
    installed, running, and responsive, and paying up to a 15-second stall
    against a hung daemon. That contradicted this module's own rule that a
    provider receives narrow owner inputs rather than reaching for the
    environment.
    """
    return {}


def _safe_host_facts(probe: Callable[[], Mapping[str, object]]) -> dict[str, str]:
    """Return the allowlisted, bounded facts from ``probe``, or ``{}``.

    Filtering to :data:`_HOST_FACT_KEYS` here — rather than trusting whatever
    the probe returns — is what keeps the record from widening into a host
    inventory if a future owner starts reporting more. A failing probe yields
    no facts rather than failing the whole provider: host detail is context,
    not the apparatus identity itself.
    """
    try:
        raw = probe()
    except Exception:
        log.warning("run-provenance: host fact probe failed")
        return {}
    facts: dict[str, str] = {}
    for key, value in dict(raw).items():
        if key not in _HOST_FACT_KEYS:
            continue
        if not isinstance(value, str) or len(value) > _MAX_HOST_FACT_LEN:
            return {}
        facts[key] = value
    return facts


def _stable_range_projection(snapshot: object) -> dict[str, object]:
    """Return the range's STABLE apparatus facts, excluding observation state.

    ``RangeSnapshot.to_dict()`` is the owner's redacted projection, but it is
    an observation: it carries the capture timestamp and each container's
    status, health, and runtime id. Hashing it wholesale made two runs of an
    identical apparatus produce different identities — the exact drift the
    identity/observation boundary exists to prevent.

    What remains here is what actually identifies the realized range: the
    container set and each container's immutable image digest. The volatile
    projection is still recorded, as a non-identity observation.
    """
    containers = tuple(getattr(snapshot, "containers", ()) or ())
    return {
        "containers": sorted(
            (
                {
                    "name": str(getattr(container, "name", "")),
                    "image_digest": str(getattr(container, "image_digest", "") or ""),
                }
                for container in containers
            ),
            # Dicts are not orderable, so a keyless sort raises TypeError once the
            # range has two containers and silently degrades the whole run's
            # reproducibility record. Order by the stable identity fields.
            key=lambda entry: (entry["name"], entry["image_digest"]),
        )
    }


def _tool_versions(snapshot: object) -> dict[str, str]:
    """Return the recorded tool/collector versions from the snapshot owner."""
    software = getattr(snapshot, "software", None)
    if software is None:
        return {}
    return {
        key: value
        for key, attribute in _TOOL_FIELDS
        if isinstance(value := getattr(software, attribute, ""), str) and value
    }


class RuntimeFactsProvider:
    """Collects immutable image identities, tool versions, and range identity."""

    provider_id = RUNTIME_PROVIDER_ID

    def __init__(
        self,
        snapshot: object | None,
        host_facts: Callable[[], Mapping[str, object]] = no_host_facts,
    ) -> None:
        self._snapshot = snapshot
        self._host_facts = host_facts

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Project the captured range snapshot into leaves and observations."""
        try:
            leaves, payload = self._gather(context)
        except ProviderDegraded as signal:
            return signal.as_result(self.provider_id)
        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=leaves,
            payload=payload,
        )

    def _gather(
        self, context: ProvenanceContext
    ) -> tuple[tuple[ProvenanceLeaf, ...], dict[str, object]]:
        """Build the image, tool, range, and host leaves, or declare a degradation."""
        snapshot = self._snapshot
        if snapshot is None:
            raise _degraded.absent()

        containers = tuple(getattr(snapshot, "containers", ()) or ())
        # +3 for the tool-versions, range-snapshot, and host-facts leaves.
        if len(containers) + 3 > context.max_entries:
            raise _degraded.entry_limit()

        try:
            leaves, without_digest = self._image_leaves(containers)
            versions = _tool_versions(snapshot)
            leaves.append(
                ProvenanceLeaf("tool-versions", derive_identity(_DOMAIN, versions))
            )
            leaves.append(
                ProvenanceLeaf(
                    "range-snapshot",
                    derive_identity(_DOMAIN, _stable_range_projection(snapshot)),
                )
            )
            host_facts = _safe_host_facts(self._host_facts)
            leaves.append(
                ProvenanceLeaf("host-facts", derive_identity(_DOMAIN, host_facts))
            )
            observation = digest_bytes(rfc8785.dumps(snapshot.to_dict()))
        except (TypeError, ValueError, AttributeError) as exc:
            log.warning("run-provenance: range snapshot projection was rejected")
            raise _degraded.owner_failure() from exc
        if context.expired():
            raise _degraded.deadline()

        payload: dict[str, object] = {
            "tool_versions": versions,
            "range_snapshot_identity": next(
                leaf.digest for leaf in leaves if leaf.logical_id == "range-snapshot"
            ),
            # The owner's full redacted projection, kept as an OBSERVATION
            # only: it is deliberately outside every identity above.
            "range_snapshot_observation": observation,
            "container_count": len(containers),
            "images_without_digest": sorted(without_digest),
            "host_facts": host_facts,
        }
        return tuple(sorted(leaves)), payload

    @staticmethod
    def _image_leaves(containers: tuple[object, ...]) -> tuple[list[ProvenanceLeaf], list[str]]:
        """Return the image-digest leaves and the containers that had none."""
        leaves: list[ProvenanceLeaf] = []
        without_digest: list[str] = []
        for container in containers:
            name = validate_logical_id(str(getattr(container, "name", "")))
            digest = str(getattr(container, "image_digest", "") or "")
            if digest:
                leaves.append(ProvenanceLeaf(f"image/{name}", normalize_digest(digest)))
            else:
                # Disclosed gap, not a tag substituted for an identity.
                without_digest.append(name)
        return leaves, without_digest
