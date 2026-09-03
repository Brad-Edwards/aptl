"""Dependency and asset lock provenance (REP-003 / issue #452).

Records the dependency and asset locks the run was actually realized from —
``uv.lock`` and each participant profile's ``asset-lock.json``.

The lock that is PRESENT is what gets recorded. The preflight is explicit that
an ambient ``pip freeze``/``npm list`` or an unrelated release SBOM must not be
substituted: those describe the environment answering the question, not the
environment that ran the experiment.

Locks are read through the same contained no-follow path as detection content,
so a symlinked lock is refused rather than silently resolving outside the
project.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from aptl.core.provenance.identity import ProvenanceLeaf, digest_bytes, validate_logical_id
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult
from aptl.core.provenance.providers import _degraded
from aptl.core.provenance.providers._degraded import ProviderDegraded
from aptl.utils.pathsafe import PathContainmentError, open_contained_nofollow

log = logging.getLogger(__name__)

#: The code-owned provider id for dependency and asset artifacts.
ARTIFACTS_PROVIDER_ID = "dependency-artifacts"

#: Maximum participant profiles scanned for an asset lock.
_MAX_PROFILES = 64


@dataclass(frozen=True)
class DependencyArtifact:
    """One code-owned lock artifact and the logical role it fills."""

    logical_id: str
    relative_path: str


#: Fixed single-file lock artifacts.
DEPENDENCY_ARTIFACTS: tuple[DependencyArtifact, ...] = (
    DependencyArtifact(logical_id="uv.lock", relative_path="uv.lock"),
)

#: Directory holding participant profiles, each of which may carry an asset lock.
_PARTICIPANT_PROFILE_ROOT = "participant-profiles"
_ASSET_LOCK_NAME = "asset-lock.json"


def _participant_asset_locks(project_dir: Path) -> list[DependencyArtifact]:
    """Return the asset-lock artifacts present under the participant profiles.

    Enumeration is discovery only; each candidate is still opened no-follow and
    contained, so a swapped component cannot cause an out-of-tree read.
    """
    root = project_dir / _PARTICIPANT_PROFILE_ROOT
    if root.is_symlink() or not root.is_dir():
        return []

    artifacts: list[DependencyArtifact] = []
    try:
        with os.scandir(root) as entries:
            profiles = sorted(
                entry.name
                for entry in entries
                if entry.is_dir(follow_symlinks=False) and not entry.is_symlink()
            )
    except OSError:
        return []

    for profile in profiles[:_MAX_PROFILES]:
        candidate = root / profile / _ASSET_LOCK_NAME
        if candidate.is_file() and not candidate.is_symlink():
            artifacts.append(
                DependencyArtifact(
                    logical_id=f"asset-lock/{profile}",
                    relative_path=f"{_PARTICIPANT_PROFILE_ROOT}/{profile}/{_ASSET_LOCK_NAME}",
                )
            )
    return artifacts


class DependencyArtifactProvider:
    """Collects dependency and asset lock identities from the project tree."""

    provider_id = ARTIFACTS_PROVIDER_ID

    def __init__(self, project_dir: Path) -> None:
        self._project_dir = Path(project_dir)

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Read every present lock artifact under the declared limits."""
        try:
            leaves = self._gather(context)
        except ProviderDegraded as signal:
            return signal.as_result(self.provider_id)
        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=leaves,
            payload={"artifact_count": len(leaves)},
        )

    def _gather(self, context: ProvenanceContext) -> tuple[ProvenanceLeaf, ...]:
        """Build a leaf per present lock, or declare a degradation."""
        artifacts = list(DEPENDENCY_ARTIFACTS) + _participant_asset_locks(self._project_dir)
        leaves: list[ProvenanceLeaf] = []
        consumed = 0
        for artifact in artifacts:
            if context.expired():
                raise _degraded.deadline()
            if len(leaves) >= context.max_entries:
                raise _degraded.entry_limit()
            data = self._read(artifact.relative_path, context.max_bytes - consumed)
            if data is None:
                continue
            consumed += len(data)
            leaves.append(
                ProvenanceLeaf(
                    logical_id=validate_logical_id(artifact.logical_id),
                    digest=digest_bytes(data),
                )
            )
        if not leaves:
            raise _degraded.absent({"artifact_count": 0})
        return tuple(sorted(leaves))

    def _read(self, relative: str, remaining: int) -> bytes | None:
        """Read one lock no-follow; ``None`` when it is simply not an artifact here.

        A :class:`PathContainmentError` means the lock is absent, symlinked, or
        not a regular file. None of those is an admitted artifact, so the entry
        contributes nothing rather than degrading the whole provider.
        """
        if remaining <= 0:
            raise _degraded.byte_limit()
        try:
            with open_contained_nofollow(self._project_dir, relative) as handle:
                data = handle.read(remaining + 1)
        except PermissionError as exc:
            raise _degraded.denied() from exc
        except PathContainmentError:
            return None
        except OSError as exc:
            log.warning("run-provenance: a dependency artifact could not be read")
            raise _degraded.owner_failure() from exc
        if len(data) > remaining:
            raise _degraded.byte_limit()
        return data
