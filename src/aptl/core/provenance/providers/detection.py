"""Detector rule, policy, and allowlist provenance (REP-003 / issue #452).

This provider supersedes :func:`aptl.core.snapshot.detection_content_digest`
for provenance purposes. That helper had four defects the preflight named, all
of which this module fixes:

1. **Unframed aggregate.** It concatenated file bytes into one digest, so
   ``"ab" + "c"`` and ``"a" + "bc"`` were indistinguishable and no targeted
   difference could be explained. Here every artifact is a leaf bound to its
   logical role, and the family identity folds the sorted
   ``{logical_id, digest}`` sequence.
2. **Stale, non-recursive roots.** Its globs read
   ``config/wazuh/etc/rules`` and ``config/wazuh/etc/decoders`` — directories
   that do not exist in this repository — while the real Wazuh rule/decoder/
   allowlist surface lives under ``config/wazuh_cluster``, and Suricata's MISP
   content is nested under ``config/suricata/rules/misp``. In practice it
   covered a single top-level Suricata file.
3. **Unsafe reads.** ``glob()`` + ``read_bytes()`` follows symlinks and will
   happily open a special file. Every read here goes through
   :func:`aptl.utils.pathsafe.open_contained_nofollow`, which walks each
   component with ``O_NOFOLLOW`` and reads from the one handle it opened.
4. **Empty success.** No files produced ``""``, which reads downstream as
   "collected, nothing to report". Absence is now an explicit
   :attr:`~aptl.core.provenance.outcomes.ProvenanceStatus.UNAVAILABLE`.

Sources are allowlisted, not filtered: a root declares exactly which suffixes
and filenames are detection content, so a secret-shaped or executable file
sitting in a rules directory is never opened at all.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from aptl.core.provenance.identity import ProvenanceLeaf, digest_bytes
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult
from aptl.core.provenance.providers import _degraded
from aptl.core.provenance.providers._degraded import ProviderDegraded
from aptl.utils.pathsafe import PathContainmentError, open_contained_nofollow

log = logging.getLogger(__name__)

#: The code-owned provider id for detection content.
DETECTION_PROVIDER_ID = "detection-content"

#: Directory nesting depth a recursive root may descend. Bounds a hostile or
#: accidental deep tree before it becomes traversal work.
_MAX_DEPTH = 8


@dataclass(frozen=True)
class DetectionRoot:
    """One code-owned detection-content location and what it admits.

    A root admits a file only by declared ``suffixes`` or by exact declared
    ``filenames``. There is deliberately no wildcard: admitting "every file
    that is not a dotfile" is directory DISCOVERY, not a non-secret source
    allowlist. An extensionless credential, token, or default password
    dropped into a rules tree would then be read and its digest folded into
    the section identity — and because only the derived digest reaches the
    payload redactor and the run-store secret invariant, neither could detect
    it. Against a small tree with known logical names, that digest is an
    offline confirmation oracle for candidate values. Unknown files therefore
    stay unread.
    """

    root_id: str
    relative_root: str
    recursive: bool
    suffixes: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()


#: The declared detection surface. Every entry is under ``config/`` and names
#: its own admitted artifacts; nothing here is discovered from configuration,
#: an experiment document, or the environment.
DETECTION_ROOTS: tuple[DetectionRoot, ...] = (
    DetectionRoot(
        root_id="suricata-rules",
        relative_root="config/suricata/rules",
        recursive=True,
        suffixes=(".rules", ".conf"),
    ),
    DetectionRoot(
        root_id="suricata-policy",
        relative_root="config/suricata",
        recursive=False,
        suffixes=(".yaml",),
    ),
    DetectionRoot(
        root_id="wazuh-rules-decoders",
        relative_root="config/wazuh_cluster",
        recursive=False,
        suffixes=(".xml",),
    ),
    DetectionRoot(
        root_id="wazuh-allowlists",
        relative_root="config/wazuh_cluster/etc/lists",
        recursive=True,
        # Named explicitly: the Wazuh CDB list this lab ships is
        # extensionless, so there is no suffix to key on. Adding a new
        # allowlist means adding its name here, which is the intended cost of
        # an explicit source allowlist.
        filenames=("active-response-whitelist",),
    ),
)


def _admits(root: DetectionRoot, name: str) -> bool:
    """Return whether ``name`` is an admitted artifact for ``root``.

    Admission is positive-only: a file must match a declared suffix or a
    declared exact filename. Anything else — including a file that merely
    fails to be a dotfile — is not read at all.
    """
    if name.startswith("."):
        return False
    if name in root.filenames:
        return True
    return any(name.endswith(suffix) for suffix in root.suffixes)


def _is_candidate(entry: os.DirEntry[str], root: DetectionRoot) -> bool:
    """Return whether a directory entry is an admitted regular file."""
    return (
        not entry.is_symlink()
        and entry.is_file(follow_symlinks=False)
        and _admits(root, entry.name)
    )


def _scan_directory(
    current: Path, root: DetectionRoot, depth: int
) -> tuple[list[Path], list[str]]:
    """Return one directory's (subdirectories to descend, admitted file paths)."""
    subdirectories: list[Path] = []
    files: list[str] = []
    with os.scandir(current) as entries:
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if root.recursive and depth < _MAX_DEPTH:
                    subdirectories.append(Path(entry.path))
            elif _is_candidate(entry, root):
                files.append(entry.path)
    return subdirectories, files


def _relative_files(project_dir: Path, root: DetectionRoot) -> list[str]:
    """Return the project-relative POSIX paths of ``root``'s admitted artifacts.

    Enumeration is discovery only — every candidate is still opened no-follow
    and contained, so a directory swapped underneath this walk cannot cause an
    out-of-tree read. A symlinked directory is skipped here as well, so its
    entry names never even reach a log line.
    """
    base = project_dir / root.relative_root
    if base.is_symlink() or not base.is_dir():
        return []

    found: list[str] = []
    stack: list[tuple[Path, int]] = [(base, 0)]
    while stack:
        current, depth = stack.pop()
        subdirectories, files = _scan_directory(current, root, depth)
        stack.extend((subdirectory, depth + 1) for subdirectory in subdirectories)
        found.extend(
            Path(path).relative_to(project_dir).as_posix() for path in files
        )
    return sorted(found)


def _leaf_name(root: DetectionRoot, relative: str) -> str:
    """Return the artifact's path relative to its own root.

    Keeping the leaf name root-relative (rather than project-relative) means a
    root's location can move without every leaf identity changing, while the
    ``root_id`` prefix preserves the role boundary.
    """
    root_prefix = f"{root.relative_root}/"
    return relative[len(root_prefix) :] if relative.startswith(root_prefix) else relative


class DetectionContentProvider:
    """Collects per-artifact identities for detector rules, policies, and allowlists."""

    provider_id = DETECTION_PROVIDER_ID

    def __init__(
        self, project_dir: Path, roots: tuple[DetectionRoot, ...] = DETECTION_ROOTS
    ) -> None:
        self._project_dir = Path(project_dir)
        self._roots = roots
        self._counts: dict[str, int] = {}

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Read every admitted detection artifact under the declared roots."""
        self._counts = {root.root_id: 0 for root in self._roots}
        try:
            leaves = self._gather(context)
        except ProviderDegraded as signal:
            signal.payload.update(self._payload(0))
            return signal.as_result(self.provider_id)
        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=leaves,
            payload=self._payload(len(leaves)),
        )

    def _payload(self, artifact_count: int) -> dict[str, object]:
        """Return the bounded payload: per-root counts and a total."""
        return {
            "roots": dict(sorted(self._counts.items())),
            "artifact_count": artifact_count,
        }

    def _gather(self, context: ProvenanceContext) -> tuple[ProvenanceLeaf, ...]:
        """Accumulate leaves under the context's entry, byte, and time limits."""
        leaves: list[ProvenanceLeaf] = []
        consumed = 0
        for root in self._roots:
            for relative in self._list_root(root):
                self._check_budget(context, len(leaves))
                data = self._read_artifact(relative, context.max_bytes - consumed)
                consumed += len(data)
                leaves.append(
                    ProvenanceLeaf(
                        logical_id=f"{root.root_id}/{_leaf_name(root, relative)}",
                        digest=digest_bytes(data),
                    )
                )
                self._counts[root.root_id] += 1
        if not leaves:
            raise _degraded.absent()
        return tuple(sorted(leaves))

    def _list_root(self, root: DetectionRoot) -> list[str]:
        """Enumerate one root's admitted artifacts, or declare a degradation."""
        try:
            return _relative_files(self._project_dir, root)
        except PermissionError as exc:
            raise _degraded.denied() from exc
        except OSError as exc:
            log.warning("run-provenance: detection root %s could not be listed", root.root_id)
            raise _degraded.owner_failure() from exc

    @staticmethod
    def _check_budget(context: ProvenanceContext, collected: int) -> None:
        """Raise when the declared deadline or entry budget is exhausted."""
        if context.expired():
            raise _degraded.deadline()
        if collected >= context.max_entries:
            raise _degraded.entry_limit()

    def _read_artifact(self, relative: str, remaining: int) -> bytes:
        """Read one artifact no-follow, declaring a degradation on any refusal.

        A :class:`PathContainmentError` means a component became a symlink
        between enumeration and open, or the leaf is not a regular file. That
        is treated as an owner failure rather than skipped: enumeration already
        admitted it, so a disagreement between the two is a fact worth
        disclosing rather than quietly dropping an artifact from the identity.
        """
        if remaining <= 0:
            raise _degraded.byte_limit()
        try:
            with open_contained_nofollow(self._project_dir, relative) as handle:
                data = handle.read(remaining + 1)
        except PermissionError as exc:
            raise _degraded.denied() from exc
        except PathContainmentError as exc:
            raise _degraded.owner_failure() from exc
        except OSError as exc:
            log.warning("run-provenance: a detection artifact could not be read")
            raise _degraded.owner_failure() from exc
        if len(data) > remaining:
            raise _degraded.byte_limit()
        return data
