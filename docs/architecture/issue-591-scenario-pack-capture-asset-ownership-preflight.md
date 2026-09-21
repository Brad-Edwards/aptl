# Issue #591 Scenario-Pack Capture Asset Ownership Preflight

This note records the APTL-side ownership decision for the capture-era assets
named by issue #591. It is guidance, not an asset migration or an
implementation plan. Most source paths below exist only in repository history:
the capture SDL was removed in #745, and the remaining inventory/parity tree
was removed in #690/#757.

No new ADR is needed. ADR-035 assigns portable scenario meaning to RAES,
ADR-046 records removal of APTL's capture inventory, issue #589 separates RAES,
environment-pack, scenario-author, and APTL runtime ownership, and issue #592
owns current versus historical terminology.

## Ownership Decision And Source Inventory

The historical ACES and `Brad-Edwards/aces-scenario-packs` names below are
source locators, not current ownership claims. Current portable semantics are
RAES-owned, and the current environment-pack format/tooling owner is
`OpenRAE/env-packs`.

| Historical APTL source | What it was | Target owner and disposition |
| --- | --- | --- |
| `docs/aces/inventory/asset-inventory-methodology.md` and `methodology-assurance-report.md` | Portable capture methodology and its assurance rationale | RAES-owned. APTL had already replaced these with upstream references in #374 before deleting the shims in #757. Do not republish a copy in APTL or an environment pack. |
| `.github/ISSUE_TEMPLATE/scn-010-{asset,composition}-inventory.md` | APTL issue workflow wrapped around the portable method | Split by concern. Reusable environment-pack authoring guidance belongs to `OpenRAE/env-packs`; capture semantics and inventory methodology belong to RAES. The APTL issue labels, TechVault gates, paths, and backend-gap process are not transferable. Any generalized successor must be accepted and authored in the owning repository rather than copied wholesale. |
| `docs/aces/inventory/*/capture-evidence.sh` and `normalize-syft-cyclonedx.jq` | Per-service Docker/Compose capture programs and normalizers | The reusable capability belongs with the RAES inventory-capture method/skill. These particular scripts are rejected migration inputs: they embed APTL container, network, volume, credential, path, and lifecycle assumptions and bypass current APTL backend/security boundaries. Re-create only a genuinely portable behavior in RAES through its public contracts. |
| `docs/aces/inventory/*/mapping-ledger.yaml`, `src/aptl/{core,cli}/aces_inventory.py`, and `tests/test_aces_inventory_methodology.py` | APTL's duplicate ledger schema, validation, CLI, and contract tests | RAES owns portable inventory/evidence semantics and validation. The APTL implementation was deliberately removed and must not be moved to the environment-pack repository or revived as an adapter. Consume RAES public models and diagnostics instead. |
| `tools/decompose_techvault_sdl.py` | A one-off TechVault authoring conversion script | Rejected migration input. It was scenario-named, rewrote a fixed section list, imported private ACES APIs, and patched then-current composition gaps locally. General composition belongs to RAES public parser/compiler tooling; pack layout and validation belong to `OpenRAE/env-packs`. |
| `scenarios/techvault.sdl.yaml`, `scenarios/techvault/**`, `scenarios/aces.lock.json`, `tests/techvault_sdl.py`, and the per-service inventory assertions removed with #745 | A capture-derived, imports-composed observational blob and tests that pinned captured APTL facts into it | Not reusable authoring material. It was removed in #745 because it was mistaken for the scenario that drives APTL. Current tests whose names end in `_inventory.py` are not part of this historical set. Do not publish the retired material as a pack, schema example, runtime contract, evidence model, or reusable fixture corpus. |
| `docs/aces/techvault-sdl-{authoring-preflight,classification-audit}.md` | Point-in-time guidance for reconciling captured TechVault facts into the retired blob | Historical APTL transition guidance. Preserve it in history only. Current portable semantic authoring uses RAES public contracts; environment-pack assembly uses `OpenRAE/env-packs`; current APTL realization follows ADR-046. Do not transfer obsolete private imports, parity-ledger workflow, or TechVault-specific classification conclusions. |
| `docs/aces/inventory/*/README.md`, `docs/aces/inventory/*/evidence/**`, `docs/aces/inventory/*-preflight.md`, and `docs/aces/inventory/techvault-inventory-volatility.md` | Frozen observations from particular APTL/TechVault runs | Historical APTL evidence only, recoverable from git history. It is neither portable scenario intent nor a distributable environment pack. Do not migrate captured host/container output, credentials, paths, logs, SBOMs, scan output, or checksums. |
| `docs/aces/parity-inventory.{yaml,md}`, `check_parity_manifest`, `required_surface_coverage`, and `tests/test_parity_inventory.py` | APTL cutover accounting and gate logic | Historical APTL-only review evidence. It is not RAES semantics, an environment-pack schema, or a runtime validation contract. ADR-046 forbids reintroducing it. |
| `bin/install-aces-inventory-skill.sh`, now `bin/install-raes-inventory-skill.sh` | APTL host-side reference adapter for the upstream-owned skill | Keep the current installer in APTL as integration guidance. The skill source remains RAES-owned; the installer is not the methodology and must not become pack content. |
| Current `containers/kali/scripts/{aptl-capture-client,aptl-wrap-shell.sh}` and the corresponding `OpenRAE/env-packs/packs/techvault/assets/content/{kali-capture-client,kali-wrap-shell.sh}` artifacts | APTL capture-consumer adapter source plus the TechVault pack placement derived from it | The pack placement already exists in `OpenRAE/env-packs`; its manifest records APTL source provenance and its README explicitly defines the **Capture consumer contract**. The `APTL_*` capability, sidecar protocol, and wrapper behavior remain because these two files are explicit APTL backend adapters, not portable RAES capture semantics or reusable authoring guidance. Do not generalize them by renaming variables or erasing the security contract. |
| Current `containers/kali-capture/**`, `mcp/aptl-mcp-common/src/captures.ts`, `mcp/mcp-red/src/capture.ts`, and `src/aptl/core/experiment/**` capture code | APTL runtime observation, transport, capability binding, and evidence acquisition | APTL-owned runtime apparatus. These are not scenario-pack authoring assets and are outside any migration. |

The related ACES issue #624 and companion placement issue #14 remain historical
decision locators. They do not authorize copying a git-history artifact or turn
a documentation hyperlink into a package source, trust root, or runtime input.
The current repository and TechVault pack authority is
[`OpenRAE/env-packs`](https://github.com/OpenRAE/env-packs), with the current
pack at
[`packs/techvault`](https://github.com/OpenRAE/env-packs/tree/main/packs/techvault),
not the historical companion repository. The current decision is therefore
primarily a reference-and-rejection record: the only identified pack placement
already exists and is explicitly documented as an APTL adapter; there is no
additional APTL asset to move in this issue.

## Transfer And Scrubbing Guardrails

If an owning repository later accepts a reusable successor, transfer the
behavior or guidance only after that explicit ownership decision. Do not move a
file merely because some lines look generic. The receiving repository owns the
new artifact, path, schema, validation, release, and maintenance policy.

Before any transfer, remove or replace all of these APTL assumptions:

- `aptl` commands, Python imports, project layout, issue labels, requirement
  IDs, static/live gate names, and backend-gap statuses;
- TechVault identities, scenario paths, container/service names, Compose
  profiles, project labels, networks, IPs, volumes, mounts, and host paths;
- `.env` keys, fixture credentials, API headers, generated config, SSH/TLS
  material, session identifiers, local URLs, and captured response bodies;
- direct Docker/Compose/SSH/curl commands and assumptions about Linux tools,
  the Docker socket, package managers, scanners, or network reachability;
- the removed mapping-ledger schema, parity vocabulary, fixed SDL section list,
  private RAES/ACES imports, and local workarounds for upstream composition;
- frozen evidence, checksums, timestamps, image/container identities, raw logs,
  vulnerability results, SBOMs, and filesystem/process/network inventories.

Preserve provenance by citing the historical APTL path and decision issue in
the new repository's review record, not by retaining APTL compatibility fields
or copying unsafe sample data. The target repository's license, secret scan,
schema validation, docs checks, and release gates are authoritative for the new
artifact. APTL's removed GitGuardian/Vale/private-key exceptions must never be
restored to make a transfer pass.

## Required Incumbents And Cross-Cutting Passage

This issue changes documentation only. It adds no auth surface, endpoint,
config field, environment binding, subprocess, persistence record, or error
envelope. Its repository gates are `tools/vale-lint-all.sh`, `mkdocs build
--strict`, the architecture navigation, and
`tests/test_scenario_pack_ownership_contract.py`'s documentation inventory.

Any later APTL work that references or consumes an environment-pack or capture
contract must pass these existing layers rather than creating migration-local
ones:

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Ownership and terminology | ADR-035, ADR-046, issue #589, and issue #592. Keep portable semantics, pack format, authored scenario content, and APTL runtime apparatus as separate owners. |
| Pack ingress and shape | Strict `ScenarioSourceConfig`; `resolve_scenario_bundle()`; `ScenarioBundle`; `env_pack_bundle()`; `read_contained_nofollow`; env-packs `validate_pack()` and `validate_pack_content_manifest()`; and RAES `parse_sdl_file` plus compiler/planner diagnostics. A reference never bypasses identity/digest checks, immutable contained staging, or public semantic validation. |
| Capture admission | RAES experiment/capture models and the code-owned `CollectorRegistry`/immutable `CaptureBinding` chain. A pack selects a declared capture requirement, never a command, import, collector class, backend method, environment name, URL, credential, or output path. |
| Runtime and OS effects | `create_aptl_manifest()`, `create_aptl_runtime_target()`, `start_raes_scenario()`, the lab lifecycle, and `DeploymentBackend`. Pack or migrated data never reaches shell text, process argv, raw Docker/Compose/SSH/curl, the Docker socket, or an unrestricted filesystem path. |
| Config and secrets | Strict `AptlConfig`, `EnvVars`, placeholder validation, generated-config owners, ADR-029, Python/TypeScript `redact`, and `curl_safe`. No authoring asset carries control-plane secrets or selects an environment/config key; designed-vulnerable fixtures remain explicitly classified and bounded. |
| Persistence and observability | `LocalRunStore`, `RangeSnapshot.to_dict()`, referenced evidence under ADR-044, `get_logger`, and bounded RAES diagnostics. Store or log safe identities, counts, codes, and digests only; never raw pack bytes, historical capture payloads, validation inputs, backend stderr, or secret-bearing paths/URLs. |
| API/auth and errors | No endpoint is added. A future API must retain `verify_token`, `WebAuthSettings`, BFF host/CSRF/session checks, request limits, narrow projections, existing scenario exceptions, generic HTTP details, `LabResult`, and RAES diagnostic envelopes. It must not expose source paths, raw parser exceptions, pack bytes, or archive locations. |
| Repository security and workflow | Existing private-key/secret scanning, `.gitguardian.yaml`, `.pre-commit-config.yaml`, `.vale.ini`, `tools/vale-lint-all.sh`, `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, and strict MkDocs. Do not add evidence-path exclusions or weaken a gate to admit historical capture output. |

There is no new validation schema, DTO, controller, service, repository,
exception hierarchy, logger, persistence model, or workflow state for this
boundary. In particular, the removed `MappingLedger`/`aces-inventory` model is
not an incumbent to preserve; RAES public contracts supersede it.

## Extensibility Seam

The portable seams already exist: RAES capture requirements express meaning;
environment-pack public validation owns packaged bytes; APTL admits a pack as
`(pack identity, version, digest, scenario entry point)` and runtime capture as
`(RAES requirement, CaptureBinding, registration_id, trusted source adapter)`.
The next pack, scenario, capture kind, or source adapter varies those declared
values and bounded registries. It must not require another APTL asset tree, a
pack-name branch, a copied shell script, or a second schema.

If reusable authoring guidance needs a parameter, it belongs in the owning
repository at the published pack/capture contract boundary. APTL-specific
realization remains an explicitly named adapter behind `DeploymentBackend`,
not a default embedded in the portable artifact.

## Gotchas And Anti-Patterns

- Do not confuse capture methodology, capture intent, admitted capability,
  acquired evidence, scenario content, and pack layout. They are different
  contracts with different owners.
- Do not mine deleted evidence or the capture-derived SDL for a supposedly
  canonical scenario. Current pack/source contracts are authoritative.
- Do not move an APTL-specific script and call its variables an abstraction;
  direct Docker access and renamed container/path parameters remain an APTL
  adapter.
- Do not copy or fork RAES/env-packs schemas, controlled vocabularies,
  validators, diagnostics, exception hierarchies, or workflow logic.
- Do not treat a human-facing repository link as a runtime resolver, trust
  decision, import source, or permission to access another checkout.
- Do not restore inventory/parity trees, legacy CLIs, scanner exclusions, or
  capture-only tests to make historical material look maintained.
- Do not claim that a valid pack, admitted capture requirement, healthy
  collector, non-empty response, persisted file, or checksum proves all later
  stages succeeded. Preserve the existing fail-closed lifecycle distinctions.

## Non-Goals And Implementation Boundary

- No asset migration, deletion, restoration, or modification of runtime code.
- No inspection or modification of RAES or environment-pack repositories.
- No new scenario/pack distribution, acquisition, schema, catalog, capture,
  inventory, evidence, parity, workflow, API, CLI, or persistence surface.
- No redesign of `DeploymentBackend`, lab lifecycle, collector registry,
  Kali/MCP capture, run storage, exporter, auth, config, logging, or redaction.
- No rewrite of historical issue names, links, ADRs, changelog records, or git
  history; current prose may explain their successor ownership.
