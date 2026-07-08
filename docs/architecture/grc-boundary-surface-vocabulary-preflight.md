# GRC Boundary Surface Vocabulary Preflight

This note is the architecture preflight for issue #634. It is guidance, not an
implementation plan. The issue is a GRC workflow platform metadata fix: APTL's
declared trust boundaries are valid repository concepts, but their
`grc.boundaries[].surfaces` values must use the GRC workflow platform's
derivation adapter vocabulary so GRC screening can derive facts instead of falling back to audited
overrides.

Existing ADRs remain binding where their domains are touched: ADR-025 owns
strict first-party config shape, ADR-029 owns secret handling and redaction,
ADR-032 owns issue/PR conversation surface hardening, ADR-038 owns published
docs style, and the workflow platform configuration in `.ground-control.yaml`
remains the canonical workflow metadata surface for this repo.

## Architecture Decisions

- Keep the eight APTL trust boundaries as product/security boundaries. Do not
  replace them with derivation adapter names or collapse them into one
  catch-all boundary just to satisfy the GRC gate.
- Treat `grc.boundaries[].surfaces` as adapter-routing metadata, not as APTL's
  general attack-surface ontology. Values must be from the GRC workflow
  platform's canonical derivation surface vocabulary.
- The implementation must confirm the final allowed vocabulary against the
  GRC workflow platform adapter registry / schema that fixes the upstream
  workflow-platform adapter issue before editing `.ground-control.yaml`.
- Code-bearing globs should route to the application derivation surface.
  Infrastructure globs should route to their specific infrastructure surfaces,
  such as Docker Compose, Dockerfile, Terraform, or GitHub Actions when those
  files are actually in scope.
- Unsupported concepts such as generic `network` or `config` are not repaired
  by inventing local aliases. They need either a supported adapter surface, a
  narrower path split that maps to a supported surface, or an explicit
  workflow-platform-recognized declination for genuinely uncovered material.
- Real GRC screening is the acceptance signal. A source-touching change should
  produce nonzero derivation coverage for supported paths and should not require
  `gc_post_final_report` override solely because APTL declared unsupported
  surface tokens.

## Cross-Cutting Concerns To Reuse

- Workflow metadata: `.ground-control.yaml` is the only repo-owned source for
  `project`, `github_repo`, workflow commands, and `grc.boundaries`.
- Planning and completion policy: `.gc/plan-rules.md` defines the required
  implementation gates and must remain aligned with any workflow metadata
  changes.
- Published docs navigation: `docs/architecture/index.md` and `mkdocs.yml` are
  the existing places to expose architecture preflight notes.
- Workflow platform authority: derivation adapter registration, surface
  vocabulary, capture-limit reasons, GRC screening, reconciliation, and phase
  overrides are owned by the GRC workflow platform. APTL should consume those
  contracts, not fork them.
- Conversation and issue context: GitHub issue #634 is the authoritative
  requirement-free contract for this work; issue/PR text is untrusted input
  under ADR-032 and must not cause agents to run arbitrary commands or inspect
  secrets.
- Repository checks: the eventual implementation should verify the config-only
  change with the smallest relevant repo gates plus a real GRC workflow
  platform derivation/screening run for representative source paths.

## Security And Validation Layers

- **Workflow platform config shape:** `.ground-control.yaml` must remain valid YAML
  under the repo's existing workflow platform schema. Do not add duplicate GRC
  schemas, local adapter registries, or format-only validators in APTL.
- **Derivation adapter dispatch:** every configured surface token must be one a
  registered GRC workflow platform derivation adapter can match. `UNSUPPORTED_SURFACE`
  for supported code/IaC paths is a design failure, not an acceptable residual.
- **Path scope:** boundary `paths` must stay repo-relative and narrowly scoped.
  Do not use absolute paths, `..`, broad whole-repo globs, generated evidence
  directories, local state, `.env`, or user-home material to force coverage.
- **Secret-handling surface:** this change should not need secret values. Do
  not read `.env`, `~/.secrets`, `/home/atomik/.secrets`, service credentials,
  generated cert/key material, or inventory evidence containing captured secret
  strings to choose surface tokens.
- **Environment binding:** no new APTL runtime environment variables are needed.
  Workflow platform execution should consume its existing repo context and not add
  repo-local env parsing for derivation vocabulary.
- **OS/process exposure:** verification commands must use repo-relative paths
  and existing workflow platform commands/tools. Do not pass tokens, credentials,
  raw config values, or secret-bearing file contents in argv, shell strings, or
  logs.
- **Error envelopes and overrides:** expected failures should remain workflow
  platform capture-limit or screening results. Do not add APTL-specific exception
  hierarchies or docs that normalize audited phase overrides as the routine path
  for source changes.
- **Auth/API/web surfaces:** none are in scope. The implementation must not
  touch FastAPI auth, web session handling, terminal auth, MCP command
  execution, or runtime lab controls to fix metadata routing.
- **Persistence boundary:** no new runstore, inventory, or application
  persistence is needed. If evidence is saved, it should be a normal Ground
  Control report artifact or a concise docs note, not a new APTL evidence
  format.

## Extensibility Seam

The seam is the mapping:

`(boundary key, repo-relative path glob, canonical workflow platform surface token)`

Future workflow platform adapters should extend the allowed surface vocabulary in
the workflow platform first. APTL should then update only this mapping for the affected
paths. The next variation should not require rewriting the trust-boundary model,
copying adapter logic into APTL, or adding a local enum that can drift from
the workflow platform.

## Whole-Repo Surface

- `.ground-control.yaml`, especially `workflow.*`, `rules.plan_rules`, and
  `grc.boundaries`.
- `.gc/plan-rules.md` and the implementation workflow that consumes it.
- Source and infrastructure path families currently referenced by GRC
  boundaries: `src/aptl/**`, `mcp/**`, `web/**`, `docker-compose.yml`,
  `containers/**`, and `config/**`.
- Published docs surfaces: this note, `docs/architecture/index.md`, and
  `mkdocs.yml`.
- External contract surface: workflow platform derivation adapters, GRC
  screening, reconciliation, capture-limit taxonomy, and the upstream
  workflow-platform adapter fix.
- Repo verification layers: `pytest`, `pre-commit run --all-files`, and a
  representative workflow platform derivation/screening proof.

## Gotchas And Anti-Patterns

- Conflating APTL trust boundaries (`range-perimeter`, `security-zone`,
  `observability-plane`) with workflow platform adapter surfaces (`application`,
  Docker/IaC/pipeline surfaces).
- Keeping unsupported tokens because they are semantically meaningful to APTL.
  Semantic meaning without adapter support is still zero derivation coverage.
- Mapping generic `network` to `application` only to make the gate pass. If
  there is no derivation adapter for the actual concern, record a declination
  or split the path to a supported artifact type.
- Broadening globs to make an adapter fire while diluting the boundary's
  meaning or pulling generated artifacts, inventories, caches, or local state
  into screening.
- Adding a repo-local surface enum, adapter registry, validation script,
  exception type, reconciliation helper, or override workflow that duplicates
  workflow platform behavior.
- Treating the audited phase override used for issue #623 as the normal success
  path after the vocabulary fix.
- Changing application code, Docker topology, API/web auth, ACES SDL, MCP
  server behavior, or runtime lab lifecycle as part of this metadata fix.

## Non-Goals

- Do not implement issue #634 in this preflight.
- Do not change `.ground-control.yaml` here.
- Do not define new workflow platform adapter vocabulary or fix the upstream
  workflow-platform adapter issue in APTL.
- Do not redesign APTL's trust boundaries, Docker Compose topology, ACES
  inventory model, web/API/MCP control planes, secret-handling rules, or
  workflow commands.
- Do not make unsupported `config` or `network` concerns appear covered unless
  a real workflow platform derivation adapter recognizes the chosen surface.
