# ACES SDL Parity Inventory (SCN-010)

This directory holds the authoritative parity inventory that the
SCN-010 specification issues (#319 – #324) and the eventual ACES-SDL
cutover PR must cite when claiming TechVault parity. It is scoped by
ADR-035, sections **Parity Inventory Boundary** and **ACES Backend
Integration Guardrails**.

The canonical artifact is the machine-readable YAML:

```
docs/aces/parity-inventory.yaml
```

This page explains the schema, the row taxonomy, and how to add or cite
a row.

## What this inventory is — and is not

This inventory is an **audit surface**. It is:

- a row-per-legacy-field map from APTL's current scenario / lab /
  defensive-stack surfaces to the post-cutover owner;
- the document SCN-010 implementation issues cite to prove they have
  not silently dropped a legacy capability;
- the gate the Phase B cutover PR uses to demonstrate parity.

It is **not**:

- a runtime schema (the runtime side is ACES SDL + the APTL backend
  manifest);
- a second `ScenarioDefinition` (Pydantic models stay in
  `aptl.core.sdl` until cutover, then are deleted, per ADR-035);
- a duplicate `docker-compose.yml` parser (the canonical compose
  inventory is the file itself, queried by `tests/test_consistency.py`);
- a parallel secret taxonomy, readiness taxonomy, or exception
  envelope.

## Categories (closed enum)

Every row sits in exactly one of these owning categories. They are the
five buckets ADR-035 enumerates:

| Category | Meaning |
| --- | --- |
| `aces_sdl` | The authored scenario can express this surface directly through the ACES parser, schemas, semantic validators, and compiled `RuntimeModel`. |
| `aces_schema_profile_gap` | The concept belongs in ACES rather than APTL but is not yet covered. Row MUST cite an upstream ACES follow-up or an APTL issue blocked on one. |
| `aptl_backend_responsibility` | Backend realization detail: Docker Compose profiles, generated config, lab-managed TLS, SOC seed material, deployment inventory, readiness classification, snapshots, run archive persistence, or host/container interaction. |
| `validation_gate` | The surface is not authored but must be proven by conformance, static parity tests, live lab validation, snapshots, or run-archive assertions. |
| `cutover_only_archive` | The legacy field is retained only as reference material after the Phase B move to `scenarios/archive/`. |

Adding a category is a deliberate change to ADR-035 *and*
`tests/test_parity_inventory.py` *and* `parity-inventory.yaml`'s
`categories:` list. That triple-edit is the intentional friction.

## Surfaces (closed set)

Every row also belongs to one of these legacy-surface buckets. The
schema test asserts that every bucket carries at least one row, so the
inventory cannot silently drop a surface area:

- `scenarios_yaml` — top-level keys of files under `scenarios/*.yaml`
- `docker_compose_topology` — profiles, networks, named volumes
- `aptl_config` — `AptlConfig` / `ContainerSettings` / `LabSettings`
- `env_vars_and_secrets` — `EnvVars` fields and the placeholder gate
- `lab_lifecycle` — `_LAB_START_STEPS` and ADR-030 readiness taxonomy
- `deployment_backend` — `DeploymentBackend` protocol methods
- `snapshots_and_runstore` — `RangeSnapshot` and `RunManifest` fields
- `defensive_stack_configs` — `config/` subdirectories
- `test_and_validation` — conformance and parity gates

## Row schema

Each row in `rows[]` is a mapping with the following required keys:

| Key | Meaning |
| --- | --- |
| `id` | Stable kebab / dot-segmented anchor used for citation (e.g. `parity#scen.recon-nmap-scan.metadata`). |
| `surface` | One of the surfaces above. |
| `legacy_source` | Canonical owner — file path plus symbol or field name. The inventory does not store data; it routes to the existing owner. |
| `legacy_field` | The specific field, key, or method name being mapped. |
| `category` | One of the categories above. |
| `aces_target` | ACES SDL element / contract / profile, or `n/a`. |
| `runtime_owner` | APTL owner symbol when the row is backend or validation. |
| `validation_evidence` | Test path or conformance suite proving parity. |
| `blocking_followup` | Issue reference (`#NNN`) or upstream pointer; `n/a` only when nothing is blocking. `aces_schema_profile_gap` rows MUST cite a concrete follow-up. |
| `notes` | Short prose, one line preferred. |

The full schema is enforced by `tests/test_parity_inventory.py`. The
test uses pure-Python assertions so the inventory does not import any
APTL Pydantic model — that would re-introduce the duplicate
`ScenarioDefinition` ADR-035 forbids.

## Citing a row

Implementation issues, PR descriptions, and the cutover PR cite rows
by id, in the form `parity#<id>`. Reviewers grep the inventory for the
id to verify the row exists and that its category and follow-up are
accurate. Example PR-description line:

> Covers `parity#scen.recon-nmap-scan.objectives` — moved from
> `aces_schema_profile_gap` to `aces_sdl` once #312 promotes the
> backend to `orchestration-evaluation`.

## Adding a row

1. Decide the surface bucket. If none fits, the surface is missing
   from the closed set — that is a deliberate change requiring a
   deliberate edit to `surfaces:` and to ADR-035, not a workaround.
2. Decide the category. The same caveat applies.
3. Choose a stable, anchor-safe `id` (ASCII alphanumeric plus `.`,
   `-`, `_`). IDs MUST be unique; the schema test enforces it.
4. Cite the existing owner in `legacy_source`. Do not re-state the
   field's contents; the inventory is a map, not a copy.
5. Populate every required key. Use `n/a` only when truly nothing
   applies. `aces_schema_profile_gap` rows MUST cite a follow-up.
6. Run `pytest tests/test_parity_inventory.py -q` to confirm the
   schema gates stay green.

## Related ADRs

- **ADR-035** — ACES SDL adoption and the parity-inventory boundary
  (the binding document).
- **TechVault ACES SDL authoring preflight** —
  `docs/aces/techvault-sdl-authoring-preflight.md` records the SCN-010B
  authoring guardrails for issue #319. The ACES-authored document that
  satisfies those guardrails is `scenarios/techvault.sdl.yaml`; its
  parser / compile / surface-coverage gates live in
  `tests/test_techvault_sdl.py` and execute against the sibling
  `Brad-Edwards/aces` checkout the `python-tests` CI job sets up.
- **ADR-028** — Runtime-rendered service config (generated-secret
  boundary referenced by `env_vars_and_secrets` rows).
- **ADR-029** — Snapshot / runstore redaction boundary.
- **ADR-030** — Lab startup partial-readiness classification (owner of
  `StartupOutcome`, `DiagnosticImpact`, `DiagnosticSeverity`,
  `StartupDiagnostic`, `LabResult` — *not* duplicated here).
- **ADR-034** — Generated-secret materialization (paired with ADR-028).
- **ADR-036** — Endpoint-registry boundary (snapshot serialization).
- **ADR-037** — Docker Compose backend cohesion.
