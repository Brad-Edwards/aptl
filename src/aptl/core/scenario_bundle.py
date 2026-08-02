"""The scenario bundle APTL realizes, and where its content is anchored.

APTL currently resolves every scenario asset relative to its own checkout: the
SDL lives under ``scenarios/``, planted content under ``scenarios/fixtures/``,
component build contexts under ``containers/``, and containment is checked
against the project directory. That single assumption is what makes a scenario
inseparable from the engine — every content path, build context, and profile is
anchored to APTL's working tree.

A bundle names the thing being realized and, crucially, the root its content is
anchored to. Once callers ask the bundle where content lives instead of assuming
the project directory, the scenario can move without touching realization: only
the resolver that produces the bundle changes.

This is deliberately not a pack reader. RAES owns portable scenario semantics
and env-packs owns the pack format and its content-identity model; APTL owns
admitted-plan realization and trusted source acquisition. The bundle is APTL's
side of that seam and defines no scenario semantics of its own.

Today one resolver exists and it returns the project directory as the root, so
behaviour is unchanged. A pack-backed resolver returns a staged pack root
instead, and every consumer already asks the right question.
"""

from __future__ import annotations

import importlib.resources as _resources
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow

_ENV_PACK_PACKAGE = "raes_env_packs"


class EnvPackError(Exception):
    """A bundled env-pack could not be acquired, staged, or validated.

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


def _stage_and_validate(
    source_pack: Path, staging_root: Path, identity: str
) -> ScenarioBundle:
    if not source_pack.is_dir():
        raise EnvPackError(f"env-pack source not found for {identity!r}: {source_pack}")

    staged = staging_root / identity
    if staged.exists():
        # Immutable staging: every run starts from a fresh copy, never a tree a
        # previous run (or anything else) may have mutated.
        shutil.rmtree(staged)
    staging_root.mkdir(parents=True, exist_ok=True)
    # copytree copies file *contents* (not hardlinks), so every staged member is
    # a singly-linked regular file.
    shutil.copytree(source_pack, staged)

    _validate_staged_pack(staged, identity)

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
    )


def _validate_staged_pack(staged: Path, identity: str) -> None:
    """Run env-packs' own gates on the staged pack, failing closed on rejection.

    env-packs owns the pack format and its content-identity model; APTL must not
    reimplement or second-guess it. It validates the layout and the
    associated-artifact manifest (exact inventory, per-member digests, no
    symlinks/hardlinks/special files) — the guarantees a later
    ``resolve_pack_artifact`` byte-open relies on.
    """

    from raes_env_packs import (  # imported lazily to keep the seam import-light
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
        validate_pack_content_manifest(str(staged))
    except PackDigestError as exc:
        raise EnvPackError(
            f"env-pack {identity!r} content manifest is invalid: {exc}"
        ) from exc


__all__ = [
    "EnvPackError",
    "PathContainmentError",
    "ScenarioBundle",
    "ScenarioSourceKind",
    "env_pack_bundle",
    "project_tree_bundle",
]
