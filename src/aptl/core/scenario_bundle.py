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

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow


class ScenarioSourceKind(str, Enum):
    """Where a bundle's bytes came from.

    Recorded so a run's evidence can distinguish a scenario realized from the
    engine's own tree — reproducible only for someone with this checkout — from
    one realized from an acquired, content-identified bundle.
    """

    PROJECT_TREE = "project-tree"


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


__all__ = [
    "PathContainmentError",
    "ScenarioBundle",
    "ScenarioSourceKind",
    "project_tree_bundle",
]
