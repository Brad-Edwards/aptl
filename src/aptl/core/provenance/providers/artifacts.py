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


class _ByteBudgetExceeded(Exception):
    """Internal signal that the declared byte budget would be exceeded."""


class DependencyArtifactProvider:
    """Collects dependency and asset lock identities from the project tree."""

    provider_id = ARTIFACTS_PROVIDER_ID

    def __init__(self, project_dir: Path):
        self._project_dir = Path(project_dir)

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Read every present lock artifact under the declared limits."""
        artifacts = list(DEPENDENCY_ARTIFACTS) + _participant_asset_locks(self._project_dir)

        leaves: list[ProvenanceLeaf] = []
        consumed = 0
        for artifact in artifacts:
            if context.expired():
                return ProvenanceResult(
                    provider_id=self.provider_id,
                    status=ProvenanceStatus.TIMED_OUT,
                    detail="deadline exceeded",
                )
            if len(leaves) >= context.max_entries:
                return ProvenanceResult(
                    provider_id=self.provider_id,
                    status=ProvenanceStatus.TRUNCATED,
                    detail="entry limit reached",
                )
            try:
                data = self._read(artifact.relative_path, context.max_bytes - consumed)
            except _ByteBudgetExceeded:
                return ProvenanceResult(
                    provider_id=self.provider_id,
                    status=ProvenanceStatus.TRUNCATED,
                    detail="byte limit reached",
                )
            except PermissionError:
                return ProvenanceResult(
                    provider_id=self.provider_id,
                    status=ProvenanceStatus.DENIED,
                    detail="source not readable",
                )
            except PathContainmentError:
                # Absent, symlinked, or not a regular file: never an admitted
                # artifact, so it contributes nothing rather than failing the
                # whole provider.
                continue
            except OSError:
                log.warning("run-provenance: dependency artifact could not be read")
                return ProvenanceResult(
                    provider_id=self.provider_id,
                    status=ProvenanceStatus.FAILED,
                    detail="owner reported failure",
                )
            consumed += len(data)
            leaves.append(
                ProvenanceLeaf(
                    logical_id=validate_logical_id(artifact.logical_id),
                    digest=digest_bytes(data),
                )
            )

        if not leaves:
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.UNAVAILABLE,
                detail="source not present",
                payload={"artifact_count": 0},
            )
        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=tuple(sorted(leaves)),
            payload={"artifact_count": len(leaves)},
        )

    def _read(self, relative: str, remaining: int) -> bytes:
        """Read one lock no-follow, refusing to exceed the byte budget."""
        if remaining <= 0:
            raise _ByteBudgetExceeded
        with open_contained_nofollow(self._project_dir, relative) as handle:
            data = handle.read(remaining + 1)
        if len(data) > remaining:
            raise _ByteBudgetExceeded
        return data
