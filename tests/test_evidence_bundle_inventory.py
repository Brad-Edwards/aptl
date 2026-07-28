"""Tests for schema resolution, inventory rows, and the packaging envelope."""

from __future__ import annotations

from aptl.core.evidence_bundle.closure import (
    ClosureEntry,
    ClosureLimitation,
    Disclosures,
    SealBinding,
    SealScope,
)
from aptl.core.evidence_bundle.envelope import SCHEMA_VERSION
from aptl.core.evidence_bundle.inventory import (
    build_envelope,
    envelope_member,
    row_from_closure_entry,
    row_from_schema,
)
from aptl.core.evidence_bundle.schemas import collect_schemas, resolve_schema


def _entry(bundle_path: str = "evidence/records/evidence-x.json") -> ClosureEntry:
    return ClosureEntry(
        bundle_path=bundle_path,
        logical_role="evidence-record",
        classification="canonical",
        contract_id="experiment-evidence-record/v1",
        source_ref="evidence-x",
        digest="sha256:" + "a" * 64,
        size=42,
        media_type="application/json",
        source_run_relpath="evidence/records/evidence-x.json",
        disclosures=Disclosures(
            sensitivity="restricted",
            redaction_state="redacted",
            loss_disclosure="1 field",
        ),
    )


def _unsealed() -> SealBinding:
    return SealBinding(scope=SealScope.UNSEALED, root_identity=None, verifier_id=None)


class TestSchemaResolution:
    def test_resolves_published_evidence_record_schema(self) -> None:
        schema = resolve_schema("experiment-evidence-record/v1")
        assert schema is not None
        assert schema.corpus_relpath.endswith("experiment-evidence-record-v1.json")
        assert schema.digest.startswith("sha256:")
        assert schema.schema_id.startswith("https://")
        assert schema.raes_version

    def test_unknown_contract_is_unresolved_not_fabricated(self) -> None:
        schemas, unresolved = collect_schemas({"totally-made-up/v9"})
        assert schemas == []
        assert unresolved == ["totally-made-up/v9"]

    def test_collect_is_deterministically_ordered(self) -> None:
        schemas, _ = collect_schemas(
            {
                "experiment-run/v1",
                "experiment-evidence-record/v1",
                "experiment-capture-spec/v1",
            }
        )
        paths = [s.corpus_relpath for s in schemas]
        assert paths == sorted(paths)


class TestInventoryRows:
    def test_row_carries_disclosures_from_entry(self) -> None:
        row = row_from_closure_entry(_entry())
        assert row.sensitivity == "restricted"
        assert row.redaction_state == "redacted"
        assert row.loss_disclosure == "1 field"
        assert row.classification == "canonical"

    def test_schema_row_is_reference_classified(self) -> None:
        schema = resolve_schema("experiment-evidence-record/v1")
        assert schema is not None
        row = row_from_schema(schema)
        assert row.classification == "reference"
        assert row.logical_role == "raes-schema"


class TestEnvelope:
    def test_envelope_has_versioned_schema_and_sorted_inventory(self) -> None:
        rows = [
            row_from_closure_entry(_entry("z.json")),
            row_from_closure_entry(_entry("a.json")),
        ]
        envelope = build_envelope(
            run_id="run-1",
            bundle_profile="aptl-evidence-bundle-profile/v1",
            limits_profile="aptl-evidence-bundle-limits/v1",
            seal=_unsealed(),
            rows=rows,
            schemas=[],
            projections=[],
            limitations=[
                ClosureLimitation(
                    "aptl.evidence-bundle.seal-absent", "unsealed", "run-1"
                )
            ],
            validation_disclosures=["json-schema structural validation performed"],
        )
        assert envelope.schema_version == SCHEMA_VERSION
        assert [row.bundle_path for row in envelope.inventory] == ["a.json", "z.json"]
        assert envelope.seal.scope == "unsealed"
        assert envelope.limitations[0].code == "aptl.evidence-bundle.seal-absent"

    def test_created_at_is_excluded_from_reproducible_identity(self) -> None:
        rows = [row_from_closure_entry(_entry())]
        kwargs = dict(
            run_id="run-1",
            bundle_profile="p",
            limits_profile="l",
            seal=_unsealed(),
            rows=rows,
            schemas=[],
            projections=[],
            limitations=[],
            validation_disclosures=[],
        )
        without = build_envelope(**kwargs)
        stamped = build_envelope(**kwargs, created_at="2026-07-28T00:00:00Z")

        assert without.root_identity() == stamped.root_identity()
        assert without.to_canonical_bytes() != stamped.to_canonical_bytes()

    def test_root_identity_excludes_the_detached_seal(self) -> None:
        rows = [row_from_closure_entry(_entry())]
        common = dict(
            run_id="run-1",
            bundle_profile="p",
            limits_profile="l",
            rows=rows,
            schemas=[],
            projections=[],
            limitations=[],
            validation_disclosures=[],
        )
        unsealed = build_envelope(
            seal=SealBinding(SealScope.UNSEALED, None, None), **common
        )
        verified = build_envelope(
            seal=SealBinding(SealScope.VERIFIED, "sha256:" + "b" * 64, "verifier-x"),
            **common,
        )
        # A detached seal is an attestation OVER the root, so the same content
        # yields the same root identity regardless of seal state.
        assert unsealed.root_identity() == verified.root_identity()

    def test_envelope_member_is_not_in_its_own_inventory(self) -> None:
        rows = [row_from_closure_entry(_entry())]
        envelope = build_envelope(
            run_id="run-1",
            bundle_profile="p",
            limits_profile="l",
            seal=_unsealed(),
            rows=rows,
            schemas=[],
            projections=[],
            limitations=[],
            validation_disclosures=[],
        )
        member = envelope_member(envelope)
        assert member.bundle_path == "bundle.json"
        assert "bundle.json" not in {row.bundle_path for row in envelope.inventory}
