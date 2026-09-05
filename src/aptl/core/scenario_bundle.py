"""The scenario bundle APTL realizes, and where its content is anchored.

A bundle names the thing being realized and, crucially, the root its content is
anchored to. Acquired packs are staged and identity-validated before callers
receive the bundle. Explicit project-tree scenarios remain a development path,
but ordinary startup never assumes that scenario content lives in APTL.

This is deliberately not a pack reader. RAES owns portable scenario semantics
and env-packs owns the pack format and its content-identity model; APTL owns
admitted-plan realization and trusted source acquisition. The bundle is APTL's
side of that seam and defines no scenario semantics of its own.

The resolver returns either the validated staged pack root or the explicit
project root, and every content consumer asks the bundle which one applies.
"""

from __future__ import annotations

import importlib.resources as _resources
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow

_ENV_PACK_PACKAGE = "raes_env_packs"


class EnvPackError(Exception):
    """An env-pack could not be acquired, staged, or validated.

    Raised — never swallowed — so acquisition fails closed: APTL refuses to
    realize a scenario from a pack that is missing, malformed, or rejected by
    env-packs' own gates, rather than silently falling back to its own tree.
    """


class ScenarioSourceKind(str, Enum):
    """Where a bundle's bytes came from.

    Recorded so a run's evidence can distinguish a scenario realized from the
    engine's own tree — reproducible only for someone with this checkout — from
    one realized from an acquired, content-identified bundle.
    """

    PROJECT_TREE = "project-tree"
    ENV_PACK = "env-pack"


@dataclass(frozen=True)
class PackIdentity:
    """Content-bound identity returned by env-packs' public validation gate."""

    pack_id: str
    pack_version: str
    set_digest: str


@dataclass(frozen=True)
class ScenarioBundle:
    """One scenario APTL has been handed, and the root its content resolves against.

    ``root`` is the containment base for every asset the scenario declares. It is
    not necessarily the project directory: that equality holds only for the
    in-tree resolver and callers must not assume it.
    """

    identity: str
    root: Path
    sdl_path: Path
    source_kind: ScenarioSourceKind = ScenarioSourceKind.PROJECT_TREE
    pack_identity: PackIdentity | None = None

    def read_asset(self, relative_path: str | Path) -> bytes:
        """Read one bundle-relative asset, refusing anything outside the bundle.

        Containment is checked against this bundle's root rather than the
        project directory, which is the whole point of the type: an acquired
        bundle must not reach into the engine's checkout, and the engine must
        not silently satisfy a scenario asset from its own tree.

        Reuses the existing symlink-refusing contained reader rather than
        resolving a path and trusting the caller, so a bundle cannot smuggle a
        link out of its root.
        """

        return read_contained_nofollow(self.root, relative_path)

    def details(self) -> dict[str, str]:
        """Return non-secret bundle identity for run evidence."""

        return {
            "identity": self.identity,
            "source_kind": self.source_kind.value,
            # The root is an operational location, not scenario identity, so it
            # is deliberately absent: two runs of the same bundle staged at
            # different paths are the same scenario.
            "sdl_name": self.sdl_path.name,
        }


def project_tree_bundle(
    project_dir: Path, sdl_path: Path, *, identity: str | None = None
) -> ScenarioBundle:
    """Return a bundle for a scenario that lives inside the APTL checkout.

    The transitional resolver. Content is anchored to the project directory,
    matching today's behaviour exactly, so routing callers through the bundle
    changes nothing until a different resolver supplies a different root.
    """

    resolved_root = project_dir.resolve()
    resolved_sdl = sdl_path if sdl_path.is_absolute() else project_dir / sdl_path
    # Start-state documents are named ``<identity>.sdl.yaml``, so one stem still
    # carries the ``.sdl`` marker.
    derived = resolved_sdl.name.removesuffix(".yaml").removesuffix(".sdl")
    return ScenarioBundle(
        identity=identity or derived,
        root=resolved_root,
        sdl_path=resolved_sdl.resolve(),
        source_kind=ScenarioSourceKind.PROJECT_TREE,
    )


def env_pack_bundle(
    staging_root: Path,
    identity: str = "techvault",
    *,
    source_pack: Path | None = None,
    package: str = _ENV_PACK_PACKAGE,
) -> ScenarioBundle:
    """Stage and validate a bundled RAES env-pack, returning its scenario bundle.

    The pack-backed resolver. Content is anchored to the *staged* pack root, so
    every realization consumer resolves the scenario's bytes from the pack's
    content-identity model (env-packs) rather than from APTL's checkout.

    Acquisition is APTL's side of the seam and is deliberately explicit:

    1. Locate the pack. By default the one bundled inside the installed
       ``raes_env_packs`` package at ``resources/packs/<identity>``; a
       ``source_pack`` override lets a caller (or a test) point at another
       already-present pack directory. No network, URL, or ambient-path lookup.
    2. Stage an immutable owned copy under ``staging_root/<identity>``. This is
       not incidental: package installers hardlink data files, and env-packs
       refuses any pack member that is not a *singly-linked* regular file, so the
       installed location cannot be validated in place. A fresh copy yields
       singly-linked, owned, containment-checked files.
    3. Gate it through env-packs' own ``validate_pack`` and
       ``validate_pack_content_manifest``. Anything they reject raises
       :class:`EnvPackError`; APTL never realizes an unvalidated pack.

    Raises:
        EnvPackError: if the pack is missing, has no ``sdl/<identity>.sdl.yaml``,
            or fails either env-packs validation gate.
    """

    staging_root = Path(staging_root)
    if source_pack is not None:
        return _stage_and_validate(Path(source_pack), staging_root, identity)
    resource = _resources.files(package) / "resources" / "packs" / identity
    with _resources.as_file(resource) as located:
        return _stage_and_validate(Path(located), staging_root, identity)


_STAGING_SWEEP_AGE_SECONDS = 3600


def _sweep_stale_stagings(staging_root: Path, identity: str) -> None:
    """Best-effort removal of this identity's stale per-invocation staged trees.

    Per-invocation staging (below) never reuses or deletes a tree another caller
    might be reading, but that means finished invocations leave their tree
    behind. Sweep siblings older than an hour -- long past any realization that
    still needs its staged content -- so the staging root does not grow without
    bound. A tree a live peer is still writing or reading is younger than the
    threshold and is left alone; a concurrent sweeper losing the race to remove
    one is expected and ignored.
    """

    prefix = f"{identity}."
    try:
        entries = list(staging_root.iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.name.startswith(prefix) or not entry.is_dir():
            continue
        try:
            age = time.time() - entry.stat().st_mtime
        except OSError:
            continue
        if age < _STAGING_SWEEP_AGE_SECONDS:
            continue
        shutil.rmtree(entry, ignore_errors=True)


def _stage_and_validate(
    source_pack: Path, staging_root: Path, identity: str
) -> ScenarioBundle:
    """Stage an installed env-pack into an isolated tree and validate it.

    Returns the bundle rooted at the staged copy. Raises ``EnvPackError`` when the
    source is absent, the pack fails env-packs' own gates, or the staged pack
    declares no SDL document.
    """

    if not source_pack.is_dir():
        raise EnvPackError(f"env-pack source not found for {identity!r}: {source_pack}")

    staging_root.mkdir(parents=True, exist_ok=True)
    _sweep_stale_stagings(staging_root, identity)
    # Each invocation stages into its own fresh directory. Two concurrent
    # invocations (pytest-xdist workers exercising the gate, or two aptl runs on
    # one project) therefore never share a tree, so none rmtrees or reads a tree
    # a peer is copying, and no tree is ever reused after another test polluted
    # it (e.g. __pycache__ written when a pack .py file is imported), which the
    # env-packs exact-inventory gate would reject. A stable shared path with a
    # lock cannot give both properties at once; isolation gives both (issue #875).
    #
    # The per-invocation token lands on the PARENT directory; the staged pack
    # itself keeps the identity as its directory name, because env-packs'
    # validate_pack checks the pack directory name against the pack's declared
    # identity.
    token = f"{identity}.{os.getpid()}-{uuid.uuid4().hex[:12]}"
    staged = staging_root / token / identity
    # copytree copies file *contents* (not hardlinks), so every staged member is
    # a singly-linked regular file, and the tree is fresh, so its inventory is
    # exactly the pack's -- except that a pip install (unlike uv) byte-compiles
    # the pack's shipped .py files in place, so the installed source carries
    # __pycache__/*.pyc the manifest never lists. Those are installer artifacts,
    # not pack content; excluding them keeps the staged inventory exactly the
    # manifest's, so the env-packs exact-inventory gate passes (issue #875).
    shutil.copytree(
        source_pack,
        staged,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    pack_identity = _validate_staged_pack(staged, identity)

    sdl_path = staged / "sdl" / f"{identity}.sdl.yaml"
    if not sdl_path.is_file():
        raise EnvPackError(
            f"env-pack {identity!r} declares no sdl/{identity}.sdl.yaml"
        )
    return ScenarioBundle(
        identity=identity,
        root=staged.resolve(),
        sdl_path=sdl_path.resolve(),
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=pack_identity,
    )


def _validate_staged_pack(staged: Path, identity: str) -> PackIdentity:
    """Run env-packs' own gates on the staged pack, failing closed on rejection.

    env-packs owns the pack format and its content-identity model; APTL must not
    reimplement or second-guess it. It validates the layout and the
    associated-artifact manifest (exact inventory, per-member digests, no
    symlinks/hardlinks/special files) — the guarantees a later
    ``resolve_pack_artifact`` byte-open relies on.
    """

    # Imported lazily to keep the seam import-light.
    from raes_env_packs import (
        PackDigestError,
        validate_pack,
        validate_pack_content_manifest,
    )

    result = validate_pack(str(staged))
    if not getattr(result, "ok", False):
        count = len(getattr(result, "diagnostics", []) or [])
        raise EnvPackError(
            f"env-pack {identity!r} failed validate_pack "
            f"({count} diagnostic(s)); refusing to realize"
        )
    try:
        manifest = validate_pack_content_manifest(str(staged))
    except PackDigestError as exc:
        raise EnvPackError(
            f"env-pack {identity!r} content manifest is invalid: {exc}"
        ) from exc
    try:
        return PackIdentity(
            pack_id=str(manifest.parent_ref.ref_id),
            pack_version=str(manifest.manifest_version),
            set_digest=str(manifest.set_digest),
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnvPackError(
            f"env-pack {identity!r} returned no validated content identity"
        ) from exc


__all__ = [
    "EnvPackError",
    "PackIdentity",
    "PathContainmentError",
    "ScenarioBundle",
    "ScenarioSourceKind",
    "env_pack_bundle",
    "project_tree_bundle",
]
