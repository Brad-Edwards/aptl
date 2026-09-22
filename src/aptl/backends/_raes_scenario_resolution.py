"""Resolve which scenario a RAES run realizes, and where its bytes come from.

Split out of :mod:`aptl.backends.raes` so that module keeps the runtime-target
composition and start/apply flow while this one carries the selection seam:
explicit development path or configured acquired pack, and the staged-env-pack
vs project-tree bundle choice. Both names are re-exported from
``aptl.backends.raes`` unchanged.
"""

from __future__ import annotations

from pathlib import Path

from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import (
    ScenarioBundle,
    env_pack_bundle,
    project_tree_bundle,
)

_PACK_STAGING_RELPATH = Path(".aptl/staged-packs")


def _resolve_scenario_path(
    project_dir: Path,
    scenario_path: Path | None,
    config: AptlConfig | None = None,
) -> Path:
    """Resolve which scenario to realize, and where its bytes come from.

    An explicit project-contained path is a development override. Otherwise a
    project-tree source must be configured explicitly; there is no implicit
    in-tree scenario fallback. A backend is handed a scenario rather than
    owning one, so the operator chooses it before ``aptl lab start``.
    """

    if scenario_path is not None:
        return (
            scenario_path
            if scenario_path.is_absolute()
            else project_dir / scenario_path
        )
    if config is not None:
        selection = config.scenario
        relative = Path(f"{selection.identity}.sdl.yaml")
        base = Path(selection.root) if selection.root else Path("scenarios")
        return project_dir / base / relative
    raise ValueError(
        "scenario selection requires an explicit scenario path or configuration"
    )


def resolve_scenario_bundle(
    project_dir: Path,
    scenario_path: Path | None,
    config: AptlConfig | None = None,
) -> ScenarioBundle:
    """Resolve the scenario bundle: a staged env-pack when selected, else in-tree.

    An explicit ``scenario_path`` always wins (an operator overriding with a
    local file), so the pack is used only for the default/configured selection
    when ``config.scenario.source`` is ``env-pack``. Staging + validation happen
    inside :func:`env_pack_bundle`; the pack is never read in place.
    """

    if (
        scenario_path is None
        and config is not None
        and config.scenario.source == "env-pack"
    ):
        return env_pack_bundle(
            project_dir / _PACK_STAGING_RELPATH, config.scenario.identity
        )
    return project_tree_bundle(
        project_dir, _resolve_scenario_path(project_dir, scenario_path, config)
    )
