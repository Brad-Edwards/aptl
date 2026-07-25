"""Structural acceptance gate for ADR-049 and GitHub issue #819."""

from pathlib import Path
import re


ADR_PATH = (
    Path(__file__).parents[1]
    / "docs"
    / "adrs"
    / "adr-049-sealed-disposable-lab-appliance.md"
)


def _adr() -> str:
    return ADR_PATH.read_text(encoding="utf-8")


def _section(document: str, heading: str) -> str:
    match = re.search(
        rf"(?ms)^##+ {re.escape(heading)}\s*$\n(.*?)(?=^##+ |\Z)",
        document,
    )
    assert match is not None, f"ADR-049 must contain a {heading!r} section"
    return match.group(1)


def _first_column(table_section: str) -> set[str]:
    rows: set[str] = set()
    for line in table_section.splitlines():
        if not line.startswith("|"):
            continue
        first_cell = line.split("|")[1].strip()
        if first_cell and not re.fullmatch(r"[-: ]+", first_cell):
            rows.add(first_cell)
    return rows


def test_adr_is_accepted_and_published() -> None:
    document = _adr()

    assert _section(document, "Status").strip() == "accepted"
    assert "[049](adr-049-sealed-disposable-lab-appliance.md)" in (
        ADR_PATH.parent / "README.md"
    ).read_text(encoding="utf-8")
    assert "adrs/adr-049-sealed-disposable-lab-appliance.md" in (
        ADR_PATH.parents[2] / "mkdocs.yml"
    ).read_text(encoding="utf-8")


def test_adr_contains_topology_and_data_flow_diagrams() -> None:
    document = _adr()
    topology = _section(document, "Topology")
    data_flow = _section(document, "Data flow")

    assert re.search(r"```mermaid\s+flowchart\b", topology)
    assert re.search(r"```mermaid\s+sequenceDiagram\b", data_flow)


def test_threat_model_covers_the_required_attackers_and_boundaries() -> None:
    threats = _first_column(_section(_adr(), "Threat model"))

    assert {
        "Participant compromise",
        "Kali root",
        "Docker socket holders",
        "Model credentials",
        "Venue LAN access",
        "Guest escape",
        "Operator recovery",
    } <= threats


def test_host_and_guest_contracts_are_explicit_testable_tables() -> None:
    document = _adr()

    for heading in ("Physical-host contract", "Appliance-guest contract"):
        contract = _section(document, heading)
        assert "| Testable invariant | Required result |" in contract
        assert len(_first_column(contract) - {"Testable invariant"}) >= 6


def test_supported_forms_share_one_payload_and_participant_experience() -> None:
    forms = _section(_adr(), "Same payload, two supported forms")
    normalized_forms = " ".join(forms.split())

    assert "| Property | Supported local appliance |" in forms
    assert "Supported hosted per-seat appliance |" in forms
    assert "same signed appliance payload" in normalized_forms
    assert "same participant web UX" in normalized_forms


def test_follow_on_work_is_reconciled_and_acceptance_evidence_is_mapped() -> None:
    reconciliation = _section(_adr(), "Follow-on issue reconciliation")
    assert "Issue #557" in reconciliation
    assert "Issue #541" in reconciliation
    assert "before implementation proceeds" in reconciliation

    evidence_rows = _first_column(_section(_adr(), "Acceptance evidence"))
    assert {
        "Accepted ADR with topology and data flow",
        "Complete threat model",
        "Explicit host and guest contracts",
        "Local and hosted payload parity",
        "Follow-on reconciliation",
    } <= evidence_rows
