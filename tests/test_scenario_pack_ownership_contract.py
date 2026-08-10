"""Structural contract for the scenario-pack ownership decision."""

from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_OWNERSHIP_NOTE = (
    _REPO_ROOT / "docs/architecture/issue-589-scenario-pack-capture-ownership-preflight.md"
)
_README = _REPO_ROOT / "README.md"
_SDL_BOUNDARY = _REPO_ROOT / "docs/sdl/index.md"

_ENV_PACKS_REPO = "https://github.com/OpenRAE/env-packs"


def _decision_rows(note: str) -> dict[str, str]:
    decision = note.split("## Decision\n", maxsplit=1)[1].split("## ", maxsplit=1)[0]
    table = next(
        block.splitlines()
        for block in decision.split("\n\n")
        if block.startswith("| Concern | Owner | APTL boundary |")
    )
    rows = [line for line in table if line.startswith("|")][2:]
    return {
        cells[2].strip(" `"): f"{cells[1]} {cells[3]}"
        for line in rows
        if len(cells := line.split("|")) >= 4
    }


def test_scenario_pack_ownership_remains_four_way_and_current() -> None:
    note = _OWNERSHIP_NOTE.read_text(encoding="utf-8")
    owners = _decision_rows(note)

    assert set(owners) == {
        "RAES",
        "OpenRAE/env-packs",
        "Downstream scenario or experiment owner",
        "APTL",
    }
    assert "semantic" in owners["RAES"].lower()
    assert "format" in owners["OpenRAE/env-packs"].lower()
    assert "scenario" in owners["Downstream scenario or experiment owner"].lower()
    assert "realization" in owners["APTL"].lower()
    assert "https://github.com/OpenRAE/rae/issues/629" in note
    assert "https://github.com/OpenRAE/env-packs/issues/138" in note
    assert "Brad-Edwards/aces" not in note
    # The RAESystem org was renamed to OpenRAE; the stale name must not return.
    assert "RAESystem" not in note


def test_user_docs_cross_reference_env_pack_companion_repo() -> None:
    """Issue #590: README and the authoring boundary link the pack-definition repo.

    The companion repo is described as pack-definition and authoring support
    (AC2), and the authoring boundary keeps APTL runtime guidance APTL-owned
    (AC3).
    """
    readme = _README.read_text(encoding="utf-8")
    boundary = _SDL_BOUNDARY.read_text(encoding="utf-8")

    # AC2: both user-facing surfaces cross-reference the companion repo.
    assert _ENV_PACKS_REPO in readme
    assert _ENV_PACKS_REPO in boundary

    # AC2: the boundary page frames it as pack-definition / authoring support.
    lowered = boundary.lower()
    assert "environment-pack" in lowered
    assert "authoring" in lowered

    # AC3: APTL runtime realization stays explicitly APTL-owned.
    assert "APTL-owned" in boundary

    # The stale org name must not appear in either user-facing surface.
    assert "RAESystem" not in readme
    assert "RAESystem" not in boundary
