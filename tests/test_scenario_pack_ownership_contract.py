"""Structural contract for the scenario-pack ownership decision."""

from pathlib import Path


_OWNERSHIP_NOTE = (
    Path(__file__).resolve().parents[1]
    / "docs/architecture/issue-589-scenario-pack-capture-ownership-preflight.md"
)


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


def test_scenario_pack_ownership_remains_three_way_and_current() -> None:
    note = _OWNERSHIP_NOTE.read_text(encoding="utf-8")
    owners = _decision_rows(note)

    assert set(owners) == {"RAES", "RAESystem/env-packs", "APTL"}
    assert "semantic" in owners["RAES"].lower()
    assert "pack" in owners["RAESystem/env-packs"].lower()
    assert "realization" in owners["APTL"].lower()
    assert "https://github.com/RAESystem/rae/issues/629" in note
    assert "https://github.com/RAESystem/env-packs/issues/138" in note
    assert "Brad-Edwards/aces" not in note
