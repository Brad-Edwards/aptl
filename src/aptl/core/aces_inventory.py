"""ACES inventory mapping ledger validation.

The ledger is a methodology handoff artifact: capture issues record facts and
the later encoding issues can see which current ACES surface, caveat, or gap
issue owns each fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
import yaml

LEDGER_FILENAME = "mapping-ledger.yaml"


class StrictModel(BaseModel):
    """Base class for ledger schema models."""

    model_config = ConfigDict(extra="forbid")


class MappingDisposition(str, Enum):
    """Disposition for a captured fact's ACES/APTL mapping attempt."""

    ENCODED = "encoded"
    ENCODED_WITH_CAVEAT = "encoded_with_caveat"
    BLOCKED_BY_ACES_GAP = "blocked_by_aces_gap"
    BLOCKED_BY_APTL_GAP = "blocked_by_aptl_gap"
    NEEDS_GAP_TRIAGE = "needs_gap_triage"


class AcesSurface(str, Enum):
    """Known current ACES surfaces the ledger can reference."""

    NODES = "nodes"
    INFRASTRUCTURE = "infrastructure"
    NODE_SERVICES = "nodes.services"
    FEATURES = "features"
    CONTENT = "content"
    ACCOUNTS = "accounts"
    RELATIONSHIPS = "relationships"
    AGENTS = "agents"
    OBJECTIVES = "objectives"
    WORKFLOWS = "workflows"
    VARIABLES = "variables"
    CONDITIONS = "conditions"
    VULNERABILITIES = "vulnerabilities"
    RUNTIME_CONTRACT = "runtime_contract"


class AttestationStatus(str, Enum):
    """Whether stronger supply-chain provenance was found for the asset."""

    CAPTURED = "captured"
    NOT_AVAILABLE = "not_available"
    NOT_CHECKED = "not_checked"
    NOT_APPLICABLE = "not_applicable"


class AttestationVerificationStatus(str, Enum):
    """Whether captured attestations were cryptographically verified."""

    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    NOT_APPLICABLE = "not_applicable"


class EvidenceRef(StrictModel):
    """Evidence file reference relative to the inventory bundle."""

    path: str
    note: str = ""


class GapIssue(StrictModel):
    """Tracker issue that owns an expressivity or implementation gap."""

    tracker: str
    number: int | str
    url: str


class AcesMapping(StrictModel):
    """Mapping attempt from a captured fact to current ACES/APTL surfaces."""

    disposition: MappingDisposition
    surface: AcesSurface | None = None
    fields: list[str] = Field(default_factory=list)
    caveat: str = ""
    rationale: str = ""
    checked_surfaces: list[AcesSurface] = Field(default_factory=list)
    why_not_current_surfaces: str = ""
    gap_issue: GapIssue | None = None

    @model_validator(mode="after")
    def validate_disposition_requirements(self) -> "AcesMapping":
        if self.disposition in {
            MappingDisposition.ENCODED,
            MappingDisposition.ENCODED_WITH_CAVEAT,
        }:
            if self.surface is None:
                raise ValueError("encoded mappings require surface")
            if not self.fields:
                raise ValueError("encoded mappings require fields")
            if (
                self.disposition == MappingDisposition.ENCODED_WITH_CAVEAT
                and not self.caveat
            ):
                raise ValueError("encoded_with_caveat requires caveat")
        if self.disposition in {
            MappingDisposition.BLOCKED_BY_ACES_GAP,
            MappingDisposition.BLOCKED_BY_APTL_GAP,
        }:
            if not self.checked_surfaces:
                raise ValueError("blocked mappings require checked_surfaces")
            if not self.why_not_current_surfaces:
                raise ValueError("blocked mappings require why_not_current_surfaces")
            if self.gap_issue is None:
                raise ValueError("blocked mappings require gap_issue")
        return self


class CapturedFact(StrictModel):
    """One captured configuration fact and its mapping attempt."""

    id: str
    category: str
    summary: str
    evidence: list[EvidenceRef] = Field(min_length=1)
    aces: AcesMapping


class AssetInfo(StrictModel):
    """Asset identity for the mapping ledger."""

    id: str
    scenario: str
    aptl_issue: int | str
    aces_methodology_issue: int | str
    source_class: str
    proof_scope: str


class AttestationInfo(StrictModel):
    """Supply-chain attestation capture status for the asset."""

    status: AttestationStatus
    verification_status: AttestationVerificationStatus
    standards: list[str] = Field(default_factory=list)
    predicate_types: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_attestation_requirements(self) -> "AttestationInfo":
        if self.status == AttestationStatus.CAPTURED and not self.evidence:
            raise ValueError("captured attestations require evidence")
        if (
            self.status != AttestationStatus.CAPTURED
            and self.verification_status != AttestationVerificationStatus.NOT_APPLICABLE
        ):
            raise ValueError(
                "non-captured attestations require verification_status=not_applicable"
            )
        if (
            self.status == AttestationStatus.CAPTURED
            and self.verification_status == AttestationVerificationStatus.NOT_VERIFIED
            and not self.limits
        ):
            raise ValueError("unverified captured attestations require limits")
        return self


class ProvenanceInfo(StrictModel):
    """Provenance data that applies to the inventory bundle as a whole."""

    image_digest: str
    attestation: AttestationInfo


class CorrespondenceCheck(StrictModel):
    """Planned or implemented spec-to-reality correspondence check."""

    id: str
    status: Literal["implemented", "planned", "blocked"]
    source: str
    realized_evidence: list[EvidenceRef] = Field(default_factory=list)
    ledger_fact_ids: list[str] = Field(default_factory=list)
    method: str
    limit: str = ""

    @model_validator(mode="after")
    def validate_correspondence_check(self) -> "CorrespondenceCheck":
        if self.status in {"implemented", "planned"} and not self.ledger_fact_ids:
            raise ValueError("correspondence checks require ledger_fact_ids")
        if self.status == "implemented" and not self.realized_evidence:
            raise ValueError("implemented correspondence checks require evidence")
        if self.status == "blocked" and not self.limit:
            raise ValueError("blocked correspondence checks require limit")
        return self


class MappingLedger(StrictModel):
    """Versioned mapping ledger schema."""

    schema_version: Literal[1]
    asset: AssetInfo
    provenance: ProvenanceInfo
    correspondence_checks: list[CorrespondenceCheck] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    facts: list[CapturedFact] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_fact_ids(self) -> "MappingLedger":
        ids = [fact.id for fact in self.facts]
        duplicates = sorted({fact_id for fact_id in ids if ids.count(fact_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate fact ids: {', '.join(duplicates)}")
        known_ids = set(ids)
        unknown_refs = sorted(
            {
                fact_id
                for check in self.correspondence_checks
                for fact_id in check.ledger_fact_ids
                if fact_id not in known_ids
            }
        )
        if unknown_refs:
            raise ValueError(
                "correspondence checks reference unknown fact ids: "
                + ", ".join(unknown_refs)
            )
        return self


@dataclass(frozen=True)
class InventoryValidationResult:
    """Validation result for one mapping ledger."""

    ledger_path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fact_count: int = 0
    encoded_count: int = 0
    blocked_count: int = 0
    triage_count: int = 0
    gap_issues: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def mapping_ledger_schema() -> dict[str, Any]:
    """Return the versioned JSON Schema for mapping ledgers."""
    return MappingLedger.model_json_schema()


def resolve_ledger_path(path: Path) -> Path:
    """Return the ledger path for either a bundle directory or YAML path."""
    if path.is_dir():
        return path / LEDGER_FILENAME
    return path


def load_mapping_ledger(path: Path) -> dict[str, Any]:
    """Load a mapping ledger from a bundle directory or explicit YAML path."""
    ledger_path = resolve_ledger_path(path)
    with ledger_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{ledger_path} must contain a YAML mapping")
    return data


def parse_mapping_ledger(path: Path) -> MappingLedger:
    """Load and parse a mapping ledger through the Pydantic schema."""
    return MappingLedger.model_validate(load_mapping_ledger(path))


def validate_mapping_ledger(path: Path) -> InventoryValidationResult:
    """Validate ledger schema, evidence references, and gap accountability."""
    ledger_path = resolve_ledger_path(path)
    if not ledger_path.exists():
        return InventoryValidationResult(
            ledger_path=ledger_path,
            errors=[f"missing ledger: {ledger_path}"],
        )

    try:
        ledger = parse_mapping_ledger(ledger_path)
    except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
        return InventoryValidationResult(
            ledger_path=ledger_path,
            errors=[f"cannot read ledger: {exc}"],
        )

    errors: list[str] = []
    warnings = _ledger_warnings(ledger)
    _validate_evidence_paths(ledger, ledger_path.parent, errors)

    encoded_count = sum(
        1
        for fact in ledger.facts
        if fact.aces.disposition
        in {
            MappingDisposition.ENCODED,
            MappingDisposition.ENCODED_WITH_CAVEAT,
        }
    )
    blocked_count = sum(
        1
        for fact in ledger.facts
        if fact.aces.disposition
        in {
            MappingDisposition.BLOCKED_BY_ACES_GAP,
            MappingDisposition.BLOCKED_BY_APTL_GAP,
        }
    )
    triage_count = sum(
        1
        for fact in ledger.facts
        if fact.aces.disposition == MappingDisposition.NEEDS_GAP_TRIAGE
    )
    return InventoryValidationResult(
        ledger_path=ledger_path,
        errors=errors,
        warnings=warnings,
        fact_count=len(ledger.facts),
        encoded_count=encoded_count,
        blocked_count=blocked_count,
        triage_count=triage_count,
        gap_issues=sorted(_gap_issue_labels(ledger)),
    )


def gap_report(path: Path) -> dict[str, Any]:
    """Return structured gap and triage data from a mapping ledger."""
    ledger_path = resolve_ledger_path(path)
    ledger = parse_mapping_ledger(ledger_path)
    gaps = [
        _gap_row(fact)
        for fact in ledger.facts
        if fact.aces.disposition
        in {
            MappingDisposition.BLOCKED_BY_ACES_GAP,
            MappingDisposition.BLOCKED_BY_APTL_GAP,
        }
    ]
    triage = [
        _gap_row(fact)
        for fact in ledger.facts
        if fact.aces.disposition == MappingDisposition.NEEDS_GAP_TRIAGE
    ]
    return {
        "asset": ledger.asset.model_dump(mode="json"),
        "ledger": str(ledger_path),
        "gaps": gaps,
        "triage_needed": triage,
    }


def format_validation_result(result: InventoryValidationResult) -> str:
    """Render a compact validation summary for CLI use."""
    status = "OK" if result.ok else "FAILED"
    lines = [
        f"Inventory ledger {status}: {result.ledger_path}",
        (
            f"facts={result.fact_count} encoded={result.encoded_count} "
            f"blocked={result.blocked_count} triage={result.triage_count}"
        ),
    ]
    if result.gap_issues:
        lines.append("gap_issues=" + ", ".join(result.gap_issues))
    lines.extend(f"warning: {warning}" for warning in result.warnings)
    lines.extend(f"error: {error}" for error in result.errors)
    return "\n".join(lines)


def format_gap_report(report: dict[str, Any]) -> str:
    """Render blocked and triage facts for humans."""
    asset = report.get("asset", {})
    asset_id = (
        asset.get("id", "unknown-asset") if isinstance(asset, dict) else "unknown-asset"
    )
    lines = [f"Inventory gaps for {asset_id}"]
    gaps = report.get("gaps", [])
    triage = report.get("triage_needed", [])
    lines.append(f"blocked={len(gaps)} triage={len(triage)}")
    lines.extend(_format_gap_rows("blocked", gaps))
    lines.extend(_format_gap_rows("triage", triage))
    return "\n".join(lines)


def _ledger_warnings(ledger: MappingLedger) -> list[str]:
    warnings: list[str] = []
    attestation = ledger.provenance.attestation
    if attestation.status == AttestationStatus.NOT_CHECKED:
        warnings.append("supply-chain attestations were not checked")
    if (
        attestation.status == AttestationStatus.CAPTURED
        and attestation.verification_status
        == AttestationVerificationStatus.NOT_VERIFIED
    ):
        warnings.append("supply-chain attestations captured but not verified")
    warnings.extend(
        f"{fact.id}: needs gap triage"
        for fact in ledger.facts
        if fact.aces.disposition == MappingDisposition.NEEDS_GAP_TRIAGE
    )
    return warnings


def _validate_evidence_paths(
    ledger: MappingLedger,
    ledger_dir: Path,
    errors: list[str],
) -> None:
    refs: list[tuple[str, EvidenceRef]] = [
        ("provenance.attestation", ref)
        for ref in ledger.provenance.attestation.evidence
    ]
    refs.extend(
        (f"correspondence_checks.{check.id}", ref)
        for check in ledger.correspondence_checks
        for ref in check.realized_evidence
    )
    refs.extend((fact.id, ref) for fact in ledger.facts for ref in fact.evidence)
    for owner, ref in refs:
        if not (ledger_dir / ref.path).exists():
            errors.append(f"{owner}: evidence path does not exist: {ref.path}")


def _gap_issue_labels(ledger: MappingLedger) -> set[str]:
    labels: set[str] = set()
    for fact in ledger.facts:
        issue = fact.aces.gap_issue
        if issue:
            labels.add(_issue_label(issue))
    return labels


def _issue_label(issue: GapIssue | dict[str, Any]) -> str:
    if isinstance(issue, GapIssue):
        return f"{issue.tracker} #{issue.number}"
    tracker = issue.get("tracker")
    number = issue.get("number")
    if not tracker or not number:
        return ""
    return f"{tracker} #{number}"


def _gap_row(fact: CapturedFact) -> dict[str, Any]:
    issue = fact.aces.gap_issue
    return {
        "fact_id": fact.id,
        "summary": fact.summary,
        "evidence": [ref.model_dump(mode="json") for ref in fact.evidence],
        "checked_surfaces": [surface.value for surface in fact.aces.checked_surfaces],
        "why_not_current_surfaces": fact.aces.why_not_current_surfaces,
        "gap_issue": issue.model_dump(mode="json") if issue else None,
    }


def _format_gap_rows(label: str, rows: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for row in rows:
        issue = row.get("gap_issue", {})
        issue_label = _issue_label(issue) if isinstance(issue, dict) else ""
        suffix = f" ({issue_label})" if issue_label else ""
        lines.append(f"- {label}: {row.get('fact_id', '')}{suffix}")
        lines.append(f"  {row.get('summary', '')}")
    return lines
