# Issue #592 Scenario-Pack Terminology Preflight

This note fixes the terminology boundary for issue #592. It does not rename a
runtime identifier, migrate an asset, or change pack acquisition. The issue
predates the ACES-to-RAES project rename and the companion repository's current
`OpenRAE/env-packs` identity. Its architectural intent remains current: APTL
documentation must use the portable system's current vocabulary and must not
present an APTL-private catalog concept as a companion contract.

No new ADR is required. ADR-035 assigns portable scenario meaning to RAES,
ADR-053 owns pack/backend interaction, issue #589 records the four-way capture
and pack-ownership boundary, and issue #934 governs current versus historical
identity wording.

## Terminology decision

| Meaning | Canonical wording | Boundary |
| --- | --- | --- |
| Portable authored meaning | RAES scenario, RAES SDL, or RAES runtime contract | `OpenRAE/rae` owns the schemas, parser, semantic validation, compilation, planning, diagnostics, and controlled vocabulary. |
| Reusable packaged scenario material | RAES environment pack or environment pack | `OpenRAE/env-packs` owns the pack format, schemas, validation, tooling, and released pack bytes. Use *scenario pack* only as the broader domain category, in an issue or historical title, or when distinguishing TechVault as pack-specific rather than product-owned. |
| APTL operator selection index | APTL startup catalog or curated scenario catalog | `scenarios/catalog.json` and `aptl.core.scenario_catalog.ScenarioCatalog` are an APTL-owned alias and card-metadata index. They are not a portable RAES schema, a pack registry, or the companion repository. |
| One admitted source | scenario source, `ScenarioBundle`, and, when present, validated pack identity/version/digest | APTL stages and admits a selected source. Do not call an arbitrary URL, directory, package index, or repository a catalog entry accepted by the runtime. |
| Exact compatibility identity | The literal identifier, for example `env-pack`, `raes-env-packs`, `raes_env_packs`, `ScenarioSourceKind.ENV_PACK`, `scenario_catalog`, or `scenarios/catalog.json` | Code, config, package, CLI, telemetry, and persisted identifiers are contracts rather than prose. Issue #592 does not rename them. |
| Historical evidence | The name recorded at the time, including ACES and `Brad-Edwards/aces-scenario-packs` | Accepted ADRs, requirements, issue titles, changelog entries, and sealed evidence retain historical identity. Current guidance may explain the successor name; it must not rewrite history. |

The unqualified statement that "catalogs" own scenario content is too broad.
Current prose must name the actual owner: RAES owns portable meaning;
`OpenRAE/env-packs` owns the environment-pack contract and released pack bytes;
the scenario author owns the authored scenario; and APTL owns its local startup
catalog and runtime realization. APTL's catalog must not be generalized into a
cross-repository catalog abstraction.

## Repository documentation inventory

The repository-scoped terminology inventory at this preflight has these
surfaces. Generated dependency files and source/test identifiers are excluded
from the documentation inventory, but their contracts are named below because
prose must not accidentally rename them.

| Surface | Files | Disposition |
| --- | --- | --- |
| Current user and authoring guidance | `README.md`, `docs/index.md`, `docs/sdl/index.md`, `docs/testing/smoke-test-plan.md` | Treat `docs/sdl/index.md` as the exemplar: companion authoring and format links are separate from the APTL-owned operator catalog and runtime section. Qualify nearby catalog prose as APTL startup selection when context is not explicit. |
| Accepted realization and pack-boundary decisions | `docs/adrs/adr-035-raes-sdl-adoption.md`, `docs/adrs/adr-046-dynamic-raes-scenario-realization.md`, `docs/adrs/adr-053-pack-backend-deployment-serving-interaction-seam.md` | Preserve decision history. Add current clarification around historical names instead of mechanically rewriting accepted records. |
| Proposed product and release decisions | `docs/adrs/adr-054-lilrae-core-and-experience-ownership.md`, `docs/adrs/adr-058-adoption-and-security-release-gates.md` | Keep TechVault pack-specific and APTL runtime-specific concerns distinct. Replace ambiguous ownership by unnamed "catalogs" only when editing current prose. |
| Current architecture guidance | `docs/architecture/issue-1000-manual-release-qa-preflight.md`, `docs/architecture/issue-589-scenario-pack-capture-ownership-preflight.md`, `issue-591-scenario-pack-capture-asset-ownership-preflight.md`, `issue-866-techvault-realization-contract-preflight.md`, `issue-875-scenario-content-declaration-preflight.md`, `issue-878-scenario-verification-plugin-seam-preflight.md`, `issue-913-shuffle-post-realization-mutation-preflight.md`, `issue-934-rename-boundary-preflight.md`, `issue-949-orborus-control-authority-preflight.md`, `issue-951-fresh-env-pack-start-preflight.md` | Reuse their ownership, admission, realization, validation, and historical-identity decisions. Do not create a second terminology or pack-ownership model. |
| Extension documentation | `src/aptl_techvault/README.md` | A plugin may be compatible with an exact pack binding; it is neither the pack, RAES, an APTL startup-catalog entry, nor a new catalog authority. |
| Historical requirements and review evidence | `docs/requirements/SCN-010/requirement.md`, `docs/reviews/962-lilrae-readiness/` | Preserve historical names and exact recorded links. The review's backlog and identity dispositions provide current interpretation without changing the underlying evidence. |
| Terminology record and navigation labels | `docs/architecture/issue-592-scenario-pack-terminology-preflight.md`, `docs/architecture/index.md`, `mkdocs.yml` | Titles may preserve an issue's or file's historical locator. Descriptive labels for current contracts use the terminology above. |

The inventory identified three current-prose hazards for issue #592 to resolve:
the tautological rename sentence at the start of the issue #589 preflight, the
unqualified "Catalogs and env-packs" owner in ADR-054, and README wording in
which "The catalog ships" immediately follows the companion-repository
paragraph. The implementation clarifies the current project name, names each
content and runtime owner, and qualifies the catalog as APTL's startup catalog.
None justifies changing a code or persisted identifier.

## Required incumbent boundaries

This is a documentation-only change. It adds no security, configuration,
network, persistence, or OS exposure. Companion hyperlinks are references for
humans; they are not runtime source URLs, trust roots, resolver inputs, or
authorization grants.

Any implementation that expands beyond prose is outside issue #592 and must
reuse, rather than duplicate, these incumbents:

| Cross-cutting layer | Canonical incumbent and required passage |
| --- | --- |
| Local selection shape | `ScenarioCatalog`, `ScenarioCatalogEntry`, and `ScenarioCatalogMetadata` in `aptl.core.scenario_catalog`, including strict Pydantic shapes, unique IDs, project containment, and RAES parsing. Do not mirror this schema in docs, the API, or a pack model. |
| Pack ingress and validation | `ScenarioSourceConfig`, `resolve_scenario_bundle()`, `ScenarioBundle`, `env_pack_bundle()`, env-packs `validate_pack()` / `validate_pack_content_manifest()`, and `aptl.utils.pathsafe`. An external documentation link never bypasses installed-package acquisition, exact identity/digest validation, contained immutable staging, or no-follow path checks. |
| Portable semantic validation | RAES public SDL models, `parse_sdl_file`, compiler/planner diagnostics, `RuntimeModel`, and `ExecutionPlan`. APTL does not create a scenario-pack DTO, vocabulary, parser, or validation fork. |
| Capability and lifecycle handoff | `create_aptl_manifest()`, `create_aptl_runtime_target()`, `start_raes_scenario()`, `DeploymentBackend`, and the existing lab lifecycle. Do not dispatch on a repository name, catalog label, pack display name, or nearby file. |
| API and error envelope | The existing authenticated `/api/scenarios` router, narrow response DTOs, `ScenarioNotFoundError` / `ScenarioValidationError`, generic HTTP details, and redacted projection errors remain the only catalog API surface. Do not expose catalog paths, raw RAES objects, parser errors, or pack bytes. |
| Auth, secrets, and configuration | `verify_token`, `WebAuthSettings`, BFF host/CSRF/session protections, strict `AptlConfig`, `EnvVars`, placeholder validation, and generated-config owners remain unchanged. Pack or catalog prose never selects credentials, environment keys, host paths, providers, commands, or policy. |
| Logging and observability | `get_logger`, `redact`, bounded RAES diagnostics, and `LabResult` remain authoritative. No raw source content, internal path, credential, parser payload, backend stderr, URL token, or plugin metadata is added to logs or error envelopes. |
| Persistence | Existing snapshot/run-store and content-addressed evidence boundaries remain unchanged. Terminology is not a schema migration and must not rewrite persisted source kinds, pack identities, historical evidence, or archive readers. |
| OS/process exposure | None for this issue. No repository link or pack/catalog field may flow to shell text, process argv, Docker/Compose commands, SSH, `curl`, import strings, or unrestricted filesystem access. |

The extensibility seam remains `(pack identity, version, digest, scenario entry
point)` admitted through `ScenarioBundle`, with APTL startup aliases as a
separate optional projection. A future pack source varies behind the authorized
resolver and trust-root policy; it does not add another catalog schema or make
the source kind, repository name, or pack identity a dispatch branch.

## Guardrails and anti-patterns

- Do not globally replace ACES with RAES or rewrite immutable historical
  records, links, schema keys, import roots, issue titles, or changelog entries.
- Do not call `OpenRAE/env-packs` a private catalog, make APTL's startup catalog
  a portable pack contract, or imply that catalog listing proves acquisition,
  admission, realization, readiness, qualification, or semantic verification.
- Do not collapse a RAES scenario, an environment pack, an APTL catalog alias,
  a `ScenarioBundle`, a verifier plugin, and a running lab into one concept.
- Do not introduce a pack/catalog DTO, validator, exception hierarchy, logger,
  resolver, workflow engine, persistence record, API route, or compatibility
  alias for a terminology-only issue.
- Do not move product-specific container, Compose, credential, host path, MCP,
  readiness, evidence, or lifecycle language into RAES or environment-pack
  authoring sections. Keep it in explicitly APTL-owned sections.
- Do not turn documentation hyperlinks into package acquisition or runtime
  trust configuration.

## Non-goals and implementation boundary

- No scenario, environment-pack, capture, inventory, plugin, or evidence asset
  migration.
- No change to RAES or env-packs contracts, dependencies, package coordinates,
  schemas, validation, controlled vocabularies, or repository ownership.
- No rename of source, config, CLI, API, telemetry, persistence, or error
  identifiers, and no compatibility layer for old prose.
- No change to APTL scenario selection, pack acquisition, lab realization,
  authentication, secret handling, logging, observability, or persistence.
- No claim that the historical companion repository remains a current runtime
  source. Current documentation links and runtime trust are separate concerns.
