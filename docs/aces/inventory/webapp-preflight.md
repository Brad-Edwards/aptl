# Webapp ACES Inventory Preflight

This note is the local architecture preflight for SCN-010 / issue #330 after
`gc_codex_architecture_preflight` timed out twice on 2026-05-21. It is a
binding implementation guardrail for the webapp steady-state inventory, not a
replacement for ADR-035 or the ACES asset-inventorying methodology.

## Architecture Decisions

- The completion artifact is an ACES inventory bundle under
  `docs/aces/inventory/webapp/`, using the same ledger schema and validation
  CLI as the existing `shuffle-backend` proof pass.
- The inventory captures the realized `aptl-webapp` container at one
  steady-state point. It does not claim byte-identical rebuildability, dynamic
  attack-state coverage, or clean-lab proof unless the evidence says that was
  performed.
- Current ACES SDL can express webapp node identity, OS, source, resources,
  network service, runtime mounts, process identity, package inventory,
  dependency manifests, scanner findings, and declared CWE weaknesses. These
  fields belong in `scenarios/techvault.sdl.yaml`.
- APTL-specific realization and public start-path interpretation remain owned
  by the SCN-010 follow-up series, especially #321 and #324. This issue may
  cite those gaps; it must not implement a TechVault-only backend shortcut.
- `docs/aces/parity-inventory.yaml` remains the audit router for SCN-010.
  Update rows only to point at the new webapp inventory/SDL evidence; do not
  turn the parity inventory into a runtime input schema.

## Cross-Cutting Concerns To Reuse

- Inventory methodology and ledger validator:
  `docs/aces/inventory/asset-inventory-methodology.md`,
  `src/aptl/core/aces_inventory.py`, and
  `tests/test_aces_inventory_methodology.py`.
- Existing evidence-bundle shape:
  `docs/aces/inventory/shuffle-backend/README.md`,
  `docs/aces/inventory/shuffle-backend/mapping-ledger.yaml`, and the
  `evidence/` manifest/checksum pattern.
- Webapp realization owners:
  `docker-compose.yml` service `webapp`, `containers/webapp/Dockerfile`,
  `containers/webapp/entrypoint.sh`, `containers/webapp/supervisord.conf`,
  `containers/webapp/requirements.txt`, and `containers/webapp/app/`.
- ACES SDL authority: sibling `../aces-sdl` parser/model documentation and
  the closed ACES #354 runtime-surface gap. Do not parse
  `techvault.sdl.yaml` with `aptl.core.sdl`.
- Secret and evidence safety: ADR-029, `aptl.utils.redaction`, the existing
  test pattern that blocks raw secret assignments, and redacted evidence files.

## Security And Validation Gates

- Evidence committed to git must redact operator/control-plane secrets. The
  webapp's intentional participant-visible fixture secrets are allowed only
  when they are scenario facts already present in checked-in source or Compose
  configuration.
- Runtime evidence must cite the command/source that produced each claim:
  Docker inspect/history/network/volume/top, in-container runtime baseline,
  package manifests, filesystem hashes, and scanner output when available.
- `mapping-ledger.yaml` must validate through `aptl aces-inventory validate`
  with every captured fact assigned an ACES/APTL disposition and no temporary
  `needs_gap_triage` rows.
- Tests must fail if the webapp bundle omits required evidence, if evidence
  checksums drift, if raw secret assignments leak, if the ledger loses the
  ACES #354 / APTL #321 / APTL #324 handoff, or if
  `scenarios/techvault.sdl.yaml` stops declaring the ACES-expressible webapp
  runtime fields.
- The issue changes executable tests and YAML artifacts, so the documentation
  carve-out does not apply. The documentation carve-out does not apply. Run
  focused pytest while iterating, then the
  required `pytest` and `pre-commit run --all-files` gates.

## Extensibility Seam

The seam is the versioned inventory ledger plus ACES runtime fields on the
TechVault SDL node. Later per-asset inventory issues should be able to add
their own bundle by reusing the same validator and tests with a different asset
fixture, without adding new parser branches or a second inventory schema.

When APTL later consumes these ACES fields, the generic interpreter work must
land behind the ACES backend boundary in #321/#324, not in this evidence pass.

## Non-Goals

- Do not run a destructive `aptl lab stop -v && aptl lab start` unless the user
  explicitly authorizes resetting the current lab.
- Do not implement the ACES backend interpreter, default-scenario flip, legacy
  SDL deletion, scenario archive move, or public start-path routing.
- Do not add a second scenario model, second inventory validator, or
  TechVault-name-dispatch shortcut.
- Do not edit `CHANGELOG.md`; if this becomes user-visible executable source
  work, add a towncrier fragment instead.
