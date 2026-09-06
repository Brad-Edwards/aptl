"""Structural contracts for scenario-pack ownership and terminology."""

import re
from collections import Counter
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_OWNERSHIP_NOTE = (
    _REPO_ROOT / "docs/architecture/issue-589-scenario-pack-capture-ownership-preflight.md"
)
_README = _REPO_ROOT / "README.md"
_SDL_BOUNDARY = _REPO_ROOT / "docs/sdl/index.md"
_TERMINOLOGY_NOTE = (
    _REPO_ROOT / "docs/architecture/issue-592-scenario-pack-terminology-preflight.md"
)
_IDENTITY_ADR = _REPO_ROOT / "docs/adrs/adr-054-lilrae-core-and-experience-ownership.md"

_ENV_PACKS_REPO = "https://github.com/OpenRAE/env-packs"
_PACK_TERM = re.compile(r"\b(?:scenario|environment|env)[ -]packs?\b", re.IGNORECASE)


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


def _terminology_rows(note: str) -> dict[str, str]:
    decision = (
        note.split("## Terminology decision\n", maxsplit=1)[1]
        .split("## ", maxsplit=1)[0]
        .strip()
    )
    table = next(
        block.splitlines()
        for block in decision.split("\n\n")
        if block.startswith("| Meaning | Canonical wording | Boundary |")
    )
    rows = [line for line in table if line.startswith("|")][2:]
    return {
        cells[1].strip(): f"{cells[2]} {cells[3]}"
        for line in rows
        if len(cells := line.split("|")) >= 4
    }


def _current_pack_docs() -> set[str]:
    candidates = [_README, *_REPO_ROOT.joinpath("docs").rglob("*.md")]
    candidates.extend(_REPO_ROOT.joinpath("plugins").rglob("README.md"))
    discovered: set[str] = set()
    for path in candidates:
        relative = path.relative_to(_REPO_ROOT).as_posix()
        if relative.startswith(("docs/requirements/", "docs/reviews/")):
            continue
        if _PACK_TERM.search(path.read_text(encoding="utf-8")):
            discovered.add(relative)
    return discovered


def _uninventoried_paths(paths: set[str], inventory: str) -> list[str]:
    basename_counts = Counter(Path(path).name for path in paths)
    return sorted(
        path
        for path in paths
        if f"`{path}`" not in inventory
        and not (
            basename_counts[Path(path).name] == 1
            and f"`{Path(path).name}`" in inventory
        )
    )


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


def test_scenario_pack_terminology_inventory_covers_current_docs() -> None:
    note = _TERMINOLOGY_NOTE.read_text(encoding="utf-8")
    inventory = note.split("## Repository documentation inventory\n", maxsplit=1)[
        1
    ].split("## ", maxsplit=1)[0]

    missing = _uninventoried_paths(_current_pack_docs(), inventory)

    assert not missing, f"scenario-pack documentation is not inventoried: {missing}"


def test_inventory_matching_does_not_alias_duplicate_readmes() -> None:
    paths = {
        "README.md",
        "plugins/example-a/README.md",
        "plugins/example-b/README.md",
    }

    assert _uninventoried_paths(paths, "`README.md`") == [
        "plugins/example-a/README.md",
        "plugins/example-b/README.md",
    ]


def test_current_scenario_pack_owners_use_raes_native_terms() -> None:
    terminology = _TERMINOLOGY_NOTE.read_text(encoding="utf-8")
    ownership = _OWNERSHIP_NOTE.read_text(encoding="utf-8")
    identity_adr = _IDENTITY_ADR.read_text(encoding="utf-8")
    rows = _terminology_rows(terminology)

    assert "RAES scenario" in rows["Portable authored meaning"]
    assert "OpenRAE/env-packs" in rows["Reusable packaged scenario material"]
    assert "APTL startup catalog" in rows["APTL operator selection index"]
    assert not re.search(
        r"\b(?P<name>RAES)\s+is\s+the\s+renamed\s+(?P=name)\s+project\b",
        ownership,
    )

    proposed_decision = identity_adr.split("## Proposed decision\n", maxsplit=1)[
        1
    ].split("## ", maxsplit=1)[0]
    assert re.search(
        r"OpenRAE/env-packs.*owns the environment-pack format",
        proposed_decision,
        flags=re.DOTALL,
    )
    assert re.search(
        r"scenario authors own authored scenario content", proposed_decision
    )
    assert re.search(
        r"LilRAE owns.*startup catalog", proposed_decision, flags=re.DOTALL
    )


def test_aptl_catalog_language_stays_product_owned() -> None:
    readme = _README.read_text(encoding="utf-8")
    boundary = _SDL_BOUNDARY.read_text(encoding="utf-8")
    scenario_section = readme.split("## Scenarios\n", maxsplit=1)[1].split(
        "## ", maxsplit=1
    )[0]
    unqualified_catalog_sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", scenario_section)
        if re.search(r"\bcatalog\b", sentence, re.IGNORECASE)
        and "aptl" not in sentence.lower()
    ]

    assert not unqualified_catalog_sentences
    assert "APTL-owned" in boundary
    assert "Compose topology" in boundary
