# Issue #851 First-Time User Documentation Preflight

This note fixes the architecture boundary for issue #851. It is guidance, not
an implementation plan, and it does not rewrite the user documentation. No new
ADR is needed: ADR-038 already owns the prose gate and the single published
GitHub Pages site. The Read the Docs and badge work is deferred to issue #1114
and must not create a second documentation site in this issue.

## Decisions And Information Boundaries

The documentation has two entry surfaces with different responsibilities:

- `docs/index.md` is the canonical published task hub. A new user must be able
  to move from installation through start, scenario selection, inspection,
  troubleshooting, and teardown without opening an ADR, specification,
  requirement record, review, or preflight.
- `README.md` is the GitHub and PyPI gateway because `pyproject.toml` publishes
  it as package metadata. It may carry the shortest verified released-package
  journey and safety warning, but it points to the task hub instead of becoming
  a second manual.

Keep the task path and the reference corpus separate. Getting-started pages
explain one tested journey. CLI, MCP, and web reference pages describe the
supported public surfaces. Deployment and troubleshooting pages explain
operation and recovery. Architecture records remain linked and searchable, but
they do not define steps a first-time user must discover.

The published landing page explains the lab in operator terms and links
directly to one stable instruction target for each acceptance task:
prerequisites/install, start, scenario selection and activity, result
inspection, troubleshooting, and teardown. Contribution and private
vulnerability-reporting links point to the repository's canonical root files;
the site does not copy those policies into a second version.

The primary journey is the released artifact boundary:

```text
pipx install aptl-labs
        -> aptl lab init <project-directory>
        -> aptl lab start
        -> aptl lab status / aptl lab info
        -> scenario activity and result inspection
        -> aptl lab stop or explicit destructive aptl lab stop -v
```

The source-checkout path is contributor guidance, not an interchangeable first
step. Manual `docker compose` startup is a troubleshooting detail, not a
supported substitute for `aptl lab start`; it bypasses configuration rendering,
scenario realization, port resolution, readiness, MCP setup, and run recording.

Keep these user-visible concepts distinct:

| Concept | Documentation meaning |
| --- | --- |
| Installation | Acquire the released Python distribution and materialize its bundled lab assets. It is not a source checkout or a container deployment. |
| Lab project | The directory produced by `aptl lab init`; it owns `aptl.json`, generated local state, and the selected deployment identity. It is not the repository checkout. |
| Scenario selection | A validated acquired-pack catalog identity selected through `aptl lab scenarios` and `--scenario`, or an explicit project-local SDL path for development. It is not a copied list of Compose profiles. |
| Startup result | The structured `LabResult` and `StartupOutcome` contract. A running container is not proof that the lab is ready. |
| Access information | Runtime-derived URLs, remapped ports, usernames, and credential locations reported by `aptl lab info`. It is not a table of compile-time ports or static passwords. |
| Results | Run records and the scenario's realized inspection surfaces. Lab status, service data, alerts, and run archives are different observations and must not be presented as one generic result. |
| Normal stop | Project-scoped teardown that preserves volumes. It is not a credential reset or full cleanup. |
| Volume cleanup | The explicit, confirmed `aptl lab stop -v` path that destroys lab data. It is not equivalent to emergency `aptl kill` or daemon-wide pruning. |

## Canonical Incumbents To Reuse

Documentation is a projection of executable contracts. It must not become a
parallel command, schema, validation, or workflow authority.

| Concern | Canonical owner and required reuse |
| --- | --- |
| Released installation | `pyproject.toml`, `hatch_build.py`, `src/aptl/_asset_manifest.py`, `src/aptl/core/assets.py`, and `aptl lab init` define the wheel and materialized-project boundary. The `clean-install-lab-boot` job in `.github/workflows/checks.yml` and `docs/testing/smoke-test-plan.md` are the evidence sources for released-package claims. |
| CLI surface | Typer registrations and help in `src/aptl/cli/main.py` and `src/aptl/cli/*.py`, with behavior in `src/aptl/core/` and CLI tests, own public commands, options, exit behavior, and destructive confirmations. Reference prose may group commands by task, but exact flags come from `aptl <group> <command> --help`. |
| Configuration | `load_config()` and the closed `AptlConfig` models in `src/aptl/core/config.py` own durable non-secret configuration. `load_dotenv()`, `env_vars_from_dict()`, and placeholder checks in `src/aptl/core/env.py` own runtime environment values. Do not document an unvalidated configuration key or a second JSON shape. |
| Scenarios | The installed RAES parser and environment-pack catalog, `src/aptl/core/scenario_catalog.py`, `aptl lab scenarios`, and the selected pack adapter own available identities and semantics. Issue #954 owns reconciliation of stale scenario claims. Do not make `scenarios/catalog.json`, a README table, or Compose profiles a second supported-product catalog. |
| Lifecycle and access | `orchestrate_lab_start()`, `stop_lab()`, `clean_boot_lab()`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, `src/aptl/cli/lab_render.py`, runtime port inventory, and the project lifecycle lock own start, readiness, access, and teardown behavior. Use `lab status` and `lab info` as discovery surfaces instead of hard-coded runtime facts. |
| Run persistence | `src/aptl/core/runstore.py`, run manifests, snapshots, and `aptl runs` own experiment records. Documentation may explain how to inspect them, but it must not introduce a documentation-only result schema or call a service screenshot a run record. |
| MCP surface | `mcp/build-all-mcps.sh`, generated `.mcp.json`, the eight `mcp/*/docker-lab-config.json` files, `aptl-mcp-common` tool generators/handlers, and their tests own server availability, names, inputs, transport, TLS, and errors. A built server is not necessarily enabled for the selected scenario. |
| Web surface | `src/aptl/cli/web.py`, `src/aptl/api/`, `web/src/`, the `aptl-web-api` and `aptl-web-ui` Compose services, ADR-039, and `docs/specs/web-gui-design-preflight.md` own supported delivery and security behavior. A user reference must not use the design specification as an operating manual. |
| Support and security reporting | `CONTRIBUTING.md`, `SUPPORT.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md` are the existing human workflow contracts. Link them directly; do not copy their policy text into several pages. |
| Site and prose validation | `mkdocs.yml`, `.vale.ini`, `tools/vale-lint-all.sh`, `requirements/docs.txt`, `.github/workflows/checks.yml`, and `.github/workflows/docs-deploy.yml` implement ADR-038. Keep one navigation tree and the existing strict build and Vale gates. |

No new docs generator, command manifest, port registry, credential table,
exception hierarchy, DTO, or navigation schema is warranted. The existing
public help, typed models, runtime discovery commands, and MkDocs navigation are
the seams.

## Security And Cross-Cutting Passage

This issue changes prose and navigation, not runtime code. Product validators
are therefore authorities for examples and claims rather than new execution
paths. Every documented journey must still pass the following layers when a
reader runs it:

| Layer | Required fit |
| --- | --- |
| Package and project shape | The installed wheel must pass its existing asset-manifest/build checks, and `aptl lab init` must create the project consumed by the same strict config loader as every other CLI path. Instructions must not depend on files available only in a source checkout. |
| Config validation | `AptlConfig` and nested `extra="forbid"` models validate `aptl.json`; environment parsing and placeholder validation own `.env`. Examples use existing keys and commands rather than bypassing the validators with hand-written Compose or ad hoc environment shapes. |
| Scenario validation | Catalog selection passes the installed pack identity and RAES parse/admission path. Documentation names only released, qualified scenarios and uses `aptl lab scenarios` for runtime discovery instead of promising every repository SDL or historical profile. |
| Authentication | MCP API clients keep the configured API/TLS authentication in `aptl-mcp-common`. Web calls remain behind the FastAPI Host, session, CSRF/origin, and terminal-ticket gates. Instructions must not replace these with direct unauthenticated API calls. |
| Secret handling | ADR-029, `src/aptl/utils/redaction.py`, and `mcp/aptl-mcp-common/src/redaction.ts` remain authoritative. Prose may name `.env` keys or `.mcp.json` as credential locations, but must not publish values, static default passwords, private keys, bearer headers, cookies, session factors, or unredacted evidence. |
| Environment binding | Web secrets remain runtime environment settings, including `APTL_API_TOKEN`; web exposure settings remain at the existing `APTL_ALLOWED_HOSTS`, `APTL_WEB_PUBLIC_ORIGIN`, and asset-root seams. They do not become `aptl.json` fields. MCP endpoint and credential substitutions stay in generated private client configuration, not command examples. |
| OS and process exposure | `aptl lab start` reaches the selected Docker engine and intentionally vulnerable workloads; the direct-host and disposable-seat isolation choices must remain explicit. Do not put durable/API secrets in process arguments, shell history, URLs, or copied support commands. The generated one-time web login URL is the narrow session-bootstrap exception; keep it private, and do not fabricate, persist, or paste it into a shell command. |
| Network exposure | Runtime port inventory and `aptl lab info` own host URLs because defaults may be remapped and scenarios may omit services. The operator web control plane remains loopback-bound by default. Browser TLS guidance must use generated trust roots and the service's valid hostname; it must not tell readers to click through certificate errors or disable validation. |
| Error envelopes | Startup uses `LabResult` and bounded diagnostics; API actions use the existing Pydantic response models; MCP uses common handler errors. Troubleshooting may quote stable, redacted operator messages and safe recovery commands, but not raw backend output, environment values, tracebacks, or a duplicate error taxonomy. |
| Logging and support | `get_logger()`, startup progress/diagnostics, MCP common telemetry, and container logs remain the observability paths. Support guidance requests sanitized output and version/runtime facts; it does not ask users to attach `.env`, `.mcp.json`, browser storage, auth headers, private keys, or unreviewed archives. |
| Persistence and cleanup | `.env`, `.mcp.json`, `.aptl/`, run storage, and Docker resources keep their existing owners and permissions. Teardown guidance stays project-scoped and preserves the distinction between normal stop and confirmed volume destruction. Never recommend `docker system prune` as ordinary APTL cleanup. |
| Documentation validation | Markdown and navigation pass `bash tools/vale-lint-all.sh` and `mkdocs build --strict` under the locked docs toolchain. `pre-commit run --all-files` remains the repository hygiene gate. Do not weaken Vale, add blanket exclusions, or remove historical pages to silence strict-build warnings. |

## Reference Boundaries

The CLI reference describes the public command groups registered by Typer and
identifies destructive, developer, maintainer, and ordinary operator surfaces.
It does not duplicate every option string in prose or treat hidden options as a
support promise. Examples must match `--help`, exit behavior, project-directory
resolution, and the shared core lifecycle contract.

The MCP reference separates three facts: artifacts that the package can build,
servers written into the generated client configuration for the realized
scenario, and tools a connected server actually advertises. It uses fully
qualified tool names generated from each server's `toolPrefix`; it does not
call a common capability such as `run_command` a literal tool name. API-backed
servers use the declared query/tool configurations and TLS policy, while SSH
servers reuse the common session tools and restricted transport.

The web reference separates the APTL operator UI, the intentionally vulnerable
TechVault web application, and third-party SOC web interfaces. It describes the
supported `aptl web serve` or Compose delivery, required optional dependencies
or built assets, the default loopback boundary, the generated one-time login
flow, and safe remote-proxy constraints. It does not tell users to run an
unprotected development server as the shipped interface.

## Extensibility And Whole-Repository Scope

The primary extensibility seam is runtime discovery, not more prose constants:

- scenario variation enters through the validated `--scenario <catalog-id>` or
  `--scenario-path <project-local-file>` selection boundary;
- deployment-location variation enters through the existing project-directory
  option and configured deployment backend;
- host-port variation is projected by `aptl lab info` and snapshot inventory;
- interface evolution enters through Typer command registration, MCP tool
  definitions/config, and typed API schemas before reference prose changes.

This keeps one obvious future scenario, deployment provider, MCP server, or web
route from requiring a rewrite of the installation journey. A new capability
gets a reference entry and a task link only when its executable contract and
qualification exist; it does not become a new onboarding taxonomy.

The whole-repository review surface for issue #851 is:

- `README.md`, `docs/index.md`, `docs/getting-started/`, `docs/deployment.md`,
  `docs/troubleshooting/`, user-facing component/reference pages, and the
  historical architecture/specification corpus;
- `mkdocs.yml`, `.vale.ini`, `tools/vale-lint-*.sh`, `requirements/docs.txt`,
  the docs check, Pages deploy workflow, and ADR-038;
- packaging and installed-project owners in `pyproject.toml`, `hatch_build.py`,
  `src/aptl/_asset_manifest.py`, `src/aptl/core/assets.py`, and clean-install
  qualification;
- CLI registrations, core configuration/environment validation, lifecycle
  results, runtime endpoint/port projection, scenario catalog/admission, run
  storage, and their tests;
- MCP build/config/tool/redaction/TLS owners and the generated client config;
- web CLI, FastAPI/BFF/session/schema/router boundaries, Svelte client/types,
  Compose web services, and web/API tests;
- `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md`, and the
  release QA manual.

## Gotchas And Anti-Patterns

- Do not publish `admin/SecretPassword` or another checked-in placeholder as a
  working credential. Point to the generated key in `.env` through `lab info`.
- Do not hard-code host ports, container IPs, optional service presence, or a
  complete scenario topology in the first-time path. Ports remap and scenario
  realization determines what exists.
- Do not promise that every catalog file, curated slice, built MCP server, or
  Compose profile is released and qualified. Reconcile those claims with issue
  #954 and the release evidence.
- Do not conflate `running`, `ready`, service health, scenario validation, and
  successful result inspection.
- Do not conflate the operator web UI, the vulnerable target web application,
  Wazuh Dashboard, or other SOC interfaces under the label "web interface."
- Do not conflate normal stop, destructive volume cleanup, emergency MCP kill,
  container force-stop, credential reset, or daemon-wide cleanup.
- Do not send a first-time user through architecture records, contributor
  setup, raw Compose, direct Docker commands, manual certificate generation, or
  hand-edited generated configuration.
- Do not copy command flags, tool schemas, errors, support policy, or security
  policy into several pages when a canonical owner can be linked.
- Do not use fixed credentials, disabled TLS verification, certificate-warning
  click-throughs, broad non-loopback binds, or API tokens in URLs to make a
  quick start appear easier.
- Do not add a second docs host, migration scaffolding, badge acceptance logic,
  versioned-docs machinery, analytics, or a custom docs application under this
  issue.
- Do not rewrite or delete historical ADRs, requirements, reviews, or design
  specifications to make the navigation look user-focused. Move them behind
  the task-oriented entry points while preserving stable links.
- Do not weaken strict MkDocs or Vale checks, add per-page lint waivers, or
  exclude user docs from the full-corpus gate to land the rewrite.

## Non-Goals And Implementation Boundary

Issue #851 does not change CLI, MCP, API, web, scenario, lifecycle, packaging,
logging, persistence, authentication, or validation behavior. It does not add
new commands, configuration fields, schemas, DTOs, controllers, services,
repositories, exception types, log formats, telemetry, or runtime state.

It does not migrate to Read the Docs, earn or register a badge, change GitHub
Pages, add versioned documentation, or decide hosting again. Those goals remain
in issue #1114. It does not qualify unsupported scenarios or platforms, repair
runtime defects discovered while checking examples, change release policy, or
replace the release QA procedure. Such gaps must be reported against their
owning runtime or qualification work rather than papered over in prose.
