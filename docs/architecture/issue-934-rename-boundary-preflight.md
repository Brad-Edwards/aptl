# Issue #934 APTL-To-LilRAE Rename Boundary Preflight

This note fixes the architecture boundary for the rename audit. It does not
perform the audit, rename a runtime identity, or define a delivery sequence.
The issue's 2026-09-05 review disposition is the current contract; the older
acceptance text remains useful for identifying the incorrect model.

## Identity decision

- APTL and LilRAE are one product before and after a rename. They are not peer
  backends, nested products, a host and plugin, or separate user experiences.
- TechVault is a scenario pack. Its topology, vulnerable applications, seeded
  content, selected integrations, and verification policy remain pack-specific,
  but they do not form an APTL product or an "experience layer" on LilRAE.
- RAES remains the separate owner of portable scenario/runtime semantics, and
  `OpenRAE/env-packs` remains the owner of the pack format and current
  TechVault pack bytes. Neither is renamed by this issue.
- Terms such as core, optional integration, participant tooling, research
  apparatus, web UI, and appliance delivery may describe dependency or
  packaging boundaries. They must not be promoted into product identities.
- A remaining `aptl` literal is a technical compatibility identity only when
  the inventory says so. Its existence is not evidence that APTL and LilRAE
  coexist.

No new ADR should preserve the rejected model. Proposed ADR-054 through
ADR-058 and their #962 disposition entries are editable proposals: correct the
false statements in those records directly. Keep ADR numbers stable. If an ADR
filename is retained for incoming-link compatibility after its title changes,
record that path explicitly as a legacy locator rather than treating its words
as architecture.

## Baseline and useful history

The #962 review is an incumbent input, not a current complete inventory. Its
`tracked-file-inventory.tsv` covers 1,467 paths at the recorded review
baseline. At preflight commit `d48d2b7e`, the repository has 1,505 tracked
paths: 38 current paths are absent from that TSV and no TSV path has
disappeared. Most of the delta is the review/ADR material itself plus the
post-baseline orchestration-authority split. Closure evidence must name its
source commit and reconcile this delta; it must not silently relabel the old
ledger as a current snapshot.

History anchors that explain the present boundaries include:

- `00fe44bd` / #660: bundled the tracked lab tree into the installable wheel;
- `ced66dcc` / #846: the ACES-to-RAES namespace migration and public-import
  precedent;
- `7b21cdbd` / #890: the TechVault realization contract and verifier seam;
- `4dcf07bd` / #908: consumption of TechVault through the env-pack;
- `ebb4db29` / #927: the pack/backend serving-interaction seam; and
- `c1497e42`, `2f8d282c`, and `d48d2b7e` / #971: creation, correction, and
  integration of the #962 readiness review.

Use repository Git history as the history record. Do not duplicate known-false
prose merely to preserve it: Git already does that. Signed, sealed,
content-addressed, or externally published evidence bytes are different and
remain immutable.

## Inventory contract

Keep the #962 tracked-path and ADR-disposition ledgers as named inputs. The
rename audit needs one complementary identity-disposition ledger, not another
copy of every tracked path. One row represents one independently versioned or
retired identity surface; multiple occurrences of the same contract belong in
that row.

Each row must carry these facts:

| Field | Required meaning |
| --- | --- |
| Surface and kind | A stable row id and one kind such as product prose, repository, distribution, import root, CLI, config/env, backend target, plugin, telemetry, persisted schema, state path, native resource, image, static route, scenario pack, or historical record |
| Current identity and locations | Exact case-sensitive literal plus all owning source/config/doc locations; a glob or generated occurrence report may supplement, not replace, named owners |
| Semantic owner | LilRAE product, TechVault pack, RAES, env-packs, external service, repository governance, or immutable historical evidence |
| History | Introduction/change commit or an explicit reason history is immaterial |
| Disposition | Correct now, retain technical identity, rename later, version with reader, historical immutable, retire after parity, externally owned, or blocked on coordination |
| Compatibility boundary | The single reader, shim, accessor, entry-point group, or resolver that contains compatibility; empty when no compatibility is allowed |
| Retirement evidence | Released replacement, consumer/import proof, data-reader window, parity proof, migration guidance, and removal condition as applicable |
| Coordination owner | #970, #880, OpenRAE/lilrae#3, another named issue, or this audit; never an unowned “later” |

The `kind` field is the extensibility seam. A later repository move, CLI alias,
or schema generation can add a row without adding brand-specific columns or
changing the meaning of existing rows. Reconciliation succeeds when every
candidate has a disposition and every location agrees with its canonical row;
it does not require zero `APTL` strings.

The current #962 categories `experience-mcp`, `experience-plugin`,
`split-core-experience`, and rules referring to “experience docs/modules” are
not acceptable final semantic owners. Replace their conceptual meaning with
scenario-pack integration, optional product capability, research apparatus,
or another concrete technical owner. Do not mechanically replace every use of
the ordinary word “experience”; classify what the sentence asserts.

## Canonical incumbents to reuse

| Concern | Existing owner and guardrail |
| --- | --- |
| Repository-wide coverage | `git ls-files`, the #962 tracked-file TSV, its baseline commit, and an explicit current delta. Generated `site/`, local `runs/`, caches, and untracked state are not source inventory. |
| Current prose and decisions | README, current docs/navigation, code comments, package descriptions, ADR-054 through ADR-058, `migration-inventory.md`, `adr-disposition.md`, and `backlog-disposition.md`. Correct false claims in place; do not add a superseding identity ADR. |
| Product distribution/import/CLI | `pyproject.toml` owns `aptl-labs`, `src/aptl`, `aptl`, and `aptl-misp-suricata-sync`; `release-please-config.json`, `.release-please-manifest.json`, release workflows, and `hatch_build.py` consume those exact identities. This audit inventories them and does not create `lilrae` aliases. |
| RAES imports | The pinned RAES packages and `tests/test_raes_namespace_cutover.py` are the incumbent dependency/import policy. Extend that AST-based check when public replacements exist; do not add a second import scanner or compatibility package. |
| Config and environment | Strict nested `AptlConfig`/`load_config()`, `ScenarioSourceConfig`, `EnvVars`, dotenv hydration, placeholder checks, host-port binding, `WebAuthSettings`, and `ServiceConfig.from_env()` own Python-side `aptl.json`/environment input. `mcp/aptl-mcp-common/src/config.ts` owns the shared `docker-lab-config.json`/dotenv loader for every MCP. Its `LabConfig` interface is compile-time only and its current runtime checks are shallow; do not mistake that interface for a shape gate or fork validation into each MCP. A brand alias must never bypass `extra="forbid"`, the common MCP loader, or create two sources of truth. |
| Pack acquisition and identity | `ScenarioBundle`, `ScenarioSourceKind`, `PackIdentity`, env-packs public validation, `ScenarioCatalog`, and RAES parsing/planning are the only pack/source shape. TechVault remains an ordinary exact pack identity, version, and digest. |
| Plugins | `aptl.scenario_verifiers` and `aptl.pack_backend_interactions`, their compatibility metadata, installed distribution provenance, and fail-closed discovery are the only plugin seams. The current verifier's empty content-digest list is a known compatibility gap, not an exact-match precedent. Installed entry points are trusted executable code, not a product layer or sandbox. |
| Persistence | Versioned `aptl.*`/`aptl-*` schema ids, `.aptl`, run stores, archive sealing, provenance/correlation, appliance records, and `core/archival/legacy_manifest.py` are data contracts. Preserve bytes and centralize any later compatibility read. |
| Errors and observability | RAES `Diagnostic`, `LabResult`, `StartupDiagnostic`, existing domain errors, `aptl.utils.redaction.redact`, and `get_logger()` remain the vocabularies. A rename does not justify duplicate exception trees, log pipelines, or response envelopes. |
| Runtime/native identity | `BackendIdentity`, the serialized RAES target, Compose `deployment.project_name`, labels, container/network/image names, MCP server ids, and telemetry attributes are operational contracts. Names do not establish ownership, and this audit does not mutate them. |
| Workflow and quality | `.ground-control.yaml`, `.gc/plan-rules.md`, `.pre-commit-config.yaml`, `.github/workflows/checks.yml`, and `.github/workflows/release-please.yml` remain canonical. Reuse pytest, strict MkDocs, Vale, the RAES static/live gates, all MCP consumer builds, installed-wheel checks, locked dependency exports, and release provenance rather than adding a rename-only workflow. |

The current public-import audit must explicitly record four private RAES uses:
`raes._source.ArtifactIdentity`,
`raes_processor.compiler.addresses._node_address` in two runtime modules, and
`raes_runtime.control_plane_store._snapshot_payload`. It must also record the
older-package `ImportError` fallback for
`BACKEND_SUPPORTED_CONTRACT_IDS` in `raes_manifest.py`. These are migration
blockers or compatibility decisions for the owning work, not invitations to
copy upstream code, use dynamic imports, or swallow import failure here.

## Security and cross-cutting passage

The intended #934 change is documentation, inventory, and reconciliation
evidence. It adds no runtime input or side effect. That narrow design passes the
cross-cutting layers as follows:

| Layer | Required passage |
| --- | --- |
| Audit input and secret boundary | Inspect repository-tracked paths and Git history only. Do not inspect generated `.env`, `.aptl`, `runs`, credentials, private keys, local caches, or user secret stores. Inventory variable/key names, never values. |
| Auth surface | Add no API, web, websocket, MCP tool, listener, or auth alias. `verify_token`, `WebAuthSettings`, BFF Host/CSRF/session checks, request limits, and terminal tickets remain unchanged. |
| Config and shape validation | Change no config key, parser, default, or environment binding. Current literals remain subject to strict `AptlConfig`, `EnvVars`, `WebAuthSettings`, `ServiceConfig`, host-port, scenario-catalog, RAES/env-pack, plugin-metadata, and Pydantic shape gates, plus the common MCP config loader. The MCP `LabConfig` interface supplies no runtime validation beyond that loader's checks. A ledger disposition cannot authorize a runtime alias. |
| Filesystem and pack ingress | Add no path resolver. Existing no-follow containment in `pathsafe`/`ScenarioBundle`, env-pack validation, and project-root checks remain authoritative. A renamed path string in prose cannot become an accepted pack or host path. |
| OS/process exposure | Add no executable, shell call, Docker/Compose action, environment export, port, socket, or process argument. In particular, do not put credentials or private paths in argv to support a compatibility shim. |
| Error envelopes and logs | Preserve error codes, redacted/bounded diagnostics, generic HTTP authentication failures, logger hierarchy, and telemetry attribute contracts. Terminology edits must not expose raw validation input, paths, stderr, plugin exceptions, or secrets. |
| Persistence and export | Do not rewrite archives, signatures, digests, run records, `.aptl` state, appliance manifests, or exported bundles. A later writer rename requires a schema version plus one bounded legacy reader; aliases must not make ambiguous records valid. |
| Supply chain and plugin trust | Change no distribution, dependency, entry-point group, or package lookup. Any later identity cut must update locked metadata, wheel/import tests, SBOM and vulnerability workflows together and retain exact plugin compatibility/provenance checks. |

## Static-path retirement boundary

The old static path is not one file. It includes the explicit
`project-tree` source in `ScenarioSourceConfig`/`ScenarioSourceKind`,
`project_tree_bundle()`, root `docker-compose.yml` lookup in the Compose
realization/profile paths, mixed/legacy realization, named profile fallbacks,
and broad wheel bundling/materialization through `_asset_manifest.py`,
`hatch_build.py`, `core/assets.py`, and `cli/lab_init.py`.

Retirement is coordinated with #880 and #970 and is allowed only when the same
released, digest-identified pack path proves acquisition, admission,
realization, observation, reset, teardown, and installed-wheel behavior; user
data has a named reader/migration policy; and no current config, CLI, test, or
packaging route silently selects the static path. Absence of
`docker-compose.yml` must not itself change authority. Unsupported legacy input
fails with the existing bounded diagnostics; it must not fall back to nearby
TechVault bytes or a second lifecycle.

## Gotchas and anti-patterns

- Do not use a blanket APTL-to-LilRAE replacement. A prose brand, PyPI
  distribution, Python package, CLI, config filename, env key, schema id,
  logger, container, repository URL, and historical byte string have different
  compatibility contracts.
- Do not create a LilRAE wrapper around APTL, dual active backends, mirrored
  `lilrae` DTO/config/schema/error hierarchies, or a second lifecycle for a tiny
  pack.
- Do not call TechVault a product, experience, platform layer, runtime, or
  retained APTL surface. Optional MCPs/verifiers are integrations selected for
  a scenario pack, not evidence of another product boundary.
- Do not preserve false current prose under “historical” labels when Git
  already preserves it. Conversely, never rewrite sealed or content-addressed
  evidence merely to modernize branding.
- Do not treat the #962 owner category as proof of import safety, scenario
  independence, data compatibility, or current-file coverage.
- Do not rename plugin groups or backend target strings without an exact
  producer/consumer inventory. Do not allow config, pack data, or CLI strings
  to choose Python imports.
- Do not add permissive config aliases, catch broad import/parse errors, accept
  both schema sections, use last-one-wins behavior, or silently fall back to an
  old static path.
- Do not treat the MCP `LabConfig` interface as runtime validation or add
  per-server rename parsers. Any later config cut belongs in the shared loader,
  with fail-closed shape checks and every dependent MCP rebuilt.
- Do not treat an empty verifier content-digest list as proven compatibility;
  it is an existing gap that later plugin qualification must close.
- Do not move lifecycle responsibilities while correcting terminology. Record
  mixed ownership for #970; this issue does not decompose `core/lab.py`.
- Do not infer that a temporary `aptl` technical identifier denotes a separate
  architecture. Its ledger disposition is the authority.

## Non-goals and implementation boundary

This audit does not choose the final repository, PyPI distribution, Python
import root, CLI, config/env, backend target, plugin group, telemetry namespace,
schema id, state directory, Compose project, container/image, or release
identity. It does not ship compatibility aliases, migrate user data, retire the
static Compose/project-tree path, move TechVault again, decompose the lifecycle,
change RAES/env-packs contracts, alter auth/secret/error/logging behavior, or
qualify a release. Those identities receive explicit dispositions and named
owners so later work can change them without recreating the false product
model.
