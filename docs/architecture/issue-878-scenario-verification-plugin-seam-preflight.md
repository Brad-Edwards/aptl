# Issue #878 Scenario Verification Plugin Seam Preflight

This note fixes the APTL architecture boundary for semantic scenario
verification. It is guidance, not an implementation plan. The issue contract
decides the ownership change: APTL core provides a scenario-agnostic framework
and discovers installed extensions, while an extension owns the semantic
answer key for one scenario and one backend. Core ships no such extension.

This decision narrowly supersedes older guidance that called
`run_participant_mcp_smoke()` a core incumbent or rejected dynamic discovery
for every extension category. It does not weaken the closed registries used for
participant implementations, evidence collectors, or RAES realization. Those
registries select trusted apparatus for different contracts and remain closed.

## Initial Reconciliation Gaps (2026-09-05)

The existing `scenario_verification.py` and
`scenario_verification_discovery.py` seam was the implementation to reconcile;
no replacement seam was required. At preflight, the repository did not yet
support closing the issue for these concrete reasons:

- Core still owns verification answer keys. `_live_gate_telemetry.py` and
  `_live_gate_probes.py` choose the Kali/nmap/failed-SSH trigger, Wazuh and
  Suricata sources, the correlation marker, and the evidence matcher.
  `_live_gate_operations.py` hides that answer key behind the apparently generic
  `detection_evidence()` method. `participant_mcp_smoke.py` separately fixes the
  TechVault MCP tools, command, Wazuh rule query, and result matchers.
  `techvault_live_gate.py` maps plugin check IDs into TechVault/Kali categories.
- Discovery checks only that the loaded object structurally resembles the
  protocol. It does not validate or bound IDs, distributions, compatibility
  claims, report members, diagnostics, collection sizes, or aggregate status.
  A plugin can currently return `passed` alongside an unmet prerequisite, a
  failed check, no checks, or non-enum values and have the report copied through.
  The live-gate projection then collapses a valid `blocked` report into ordinary
  boolean failures, so its CLI/report surface no longer distinguishes no verdict
  from a semantic disproof.
- Compatibility is not exact. The live gate derives identity from an SDL
  filename, always reports `project-tree`, permits an empty digest claim, and
  discovery ignores backend target version, provider, and transport. It also
  loads unrelated verifier entry points before it knows whether they can match.
- Existing module docs claim core-owned prerequisite sequencing, but a one-operation
  `run(context)` contract necessarily leaves scenario-specific sequencing with
  the trusted plugin. Core can enforce admission prerequisites and report
  invariants, not prove the internal order of in-process Python. This ownership
  must be stated honestly. Separately, `deadline_seconds` is neither an absolute
  deadline nor enforced by the discovery runner or operations surface.
- Installed-artifact proof is optional today. The only separate-distribution
  test skips when `aptl-techvault-verifier` is absent, and the normal Python CI
  job does not install that distribution. The current tests also search a
  curated handful of modules, so they do not detect the answer keys above.

These are reconciliation gaps in the delivered seam, not reasons to replace its
entry-point group or public concepts. Closure requires the existing contract,
discovery host, live-gate integration, and artifact tests to tell one consistent
story.

## Reconciliation Outcome (2026-09-05)

The implementation now closes those gaps while preserving the original seam:

- core filters the exact non-executable entry-point selector before loading,
  validates and bounds context, metadata, prerequisites, checks, diagnostics,
  and aggregate status, matches every scenario/backend dimension exactly, and
  records distribution provenance from the installed entry point;
- canonical `ScenarioBundle`/`PackIdentity` and backend-manifest identities feed
  both plugin admission and the single versioned `VerificationReport`; terminal
  `blocked` survives live-gate, CLI, and persisted status projection;
- the separately built TechVault plugin owns the required-node declarations,
  target priority, nmap/failed-SSH activity, participant MCP operations, and
  Wazuh correlation matcher, while core exposes only bounded generic operations,
  deadline-clamped execution, polling, collection, redaction, and persistence;
- participant qualification resolves its exact smoke plan through the installed
  `aptl.participant_mcp_smoke_plans` entry point, so production callers do not
  import the TechVault distribution by name and core retains no default plan;
  and
- the non-skipping artifact gate builds independent core/plugin wheels, proves a
  core-only install blocks, proves the installed plugin happy path and
  host-observed provenance, and inspects both core wheel payload locations for
  the known answer keys.

`LiveGateReport` remains only as a compatibility constructor name for callers;
it returns `VerificationReport` and is not a second persisted report schema.

## Ownership And Concept Boundaries

Keep these concerns separate:

| Concern | Owner |
| --- | --- |
| Portable scenario intent, assertions, workflows, and evidence semantics | RAES and the authored scenario or pack |
| Backend capability and runtime realization | The RAES backend manifest, APTL RAES adapters, and `DeploymentBackend` |
| Scenario-and-backend semantic answer key | One installed scenario-verification plugin |
| Windows, deadlines, polling, framework admission prerequisites, evidence handling, report shape, discovery, and failure normalization | APTL core |
| Signed participant qualification and release evidence | The existing participant-profile and appliance qualification contracts |

An answer key is executable backend realization knowledge: tool names and
arguments, commands, concrete endpoint/container/IP assumptions, vendor
queries or rule IDs, correlation markers, response-shape matchers, and
scenario-specific prerequisite logic. Authored scenario semantics, catalog
identity, participant narrative, RAES assertions, generic contract
conformance, and operator runbooks are not themselves plugins. Core must not
turn any of them into an answer key with a scenario-name branch.

The current split identifies the remaining ownership work:

- `src/aptl/validation/participant_mcp_smoke.py` contains the guided
  TechVault/APTL answer key: exact MCP tools, the failed-SSH command and target,
  Wazuh rule query, and result interpretation.
- `src/aptl/validation/_live_gate_telemetry.py` and the event-generation and
  correlation helpers in `_live_gate_probes.py` contain another TechVault/APTL
  semantic adapter.
- `src/aptl/validation/_live_gate_operations.py` delegates its generic-looking
  detection method to that adapter, while `techvault_live_gate.py` owns a
  TechVault-specific plugin-check mapping and a second report schema.
- `techvault_live_gate.py`, `_live_gate_checks.py`,
  `_live_gate_readiness.py`, `core.services`, `core.evidence`,
  `core.correlation`, and `core.runstore` contain reusable mechanics that
  should converge on the core framework rather than be copied into a plugin.

Generic static parse/compile/conformance checks, model-derived realization
comparison, container readiness, range snapshots, RAES runtime contract
validation, and participant qualification are not semantic answer keys merely
because TechVault is a current test input. They stay in core when they remain
parameterized by validated scenario/backend inputs and contain no
scenario-specific verdict logic.

## Extension Contract

### Installed discovery

Use Python distribution entry points under the single group
`aptl.scenario_verifiers`. The core distribution declares no entry in that
group. Reuse ADR-053's `pack_interaction_discovery.py` pattern: an extension
distribution registers a bounded, non-executable family selector, core filters
entry-point metadata before loading code, and then validates a stable plugin ID
on the loaded object. The target loads a side-effect-free runner object or
factory. Runtime selection uses installed distribution metadata; scenario data,
`aptl.json`, environment variables, CLI values, and participant profiles never
supply a module, class, file, URL, command, or import string.

Discovery is fail closed:

- validate and bound the extension API version, plugin ID, host-observed
  distribution metadata, callable/runner shape, scenario match, backend match,
  and every returned report member before use;
- bind to the canonical identity and source kind already returned by the
  admitted `ScenarioBundle`, plus its exact SDL/content identity; do not rebuild
  identity from a filename, display name, or staging path;
- bind backend compatibility to the canonical RAES target manifest
  name/version and declared profile/capabilities. Empty compatibility claims are
  not wildcards. Keep
  `DeploymentConfig.provider` as a separate transport fact unless a plugin
  explicitly requires one provider;
- require exactly one compatible installed plugin. No match, incompatible
  versions, a load failure, or duplicate matches produces `blocked`, never a
  silent skip, first-one-wins selection, or fallback adapter;
- record the host-observed distribution name/version and entry-point/plugin ID
  in the report. Do not trust self-reported package provenance alone.

Installing a Python plugin grants code execution with the APTL process's
authority. Entry-point discovery is not a sandbox. Installation therefore
remains an explicit operator/package-management action; core must not download,
auto-install, scan a range directory, or add the current working directory to
an import search. A future untrusted or out-of-process plugin model requires a
separate isolation, authentication, IPC, and resource-governance design.

### Context And Runner

The discovered runner has one public operation:

`run(verification_context) -> verification_report`.

The immutable context is constructed by core after scenario, backend, config,
run, and attempt identity validation. It carries only:

- validated run/attempt identity;
- scenario catalog/bundle identity, source kind, and exact content digest;
- backend target name/version, manifest/profile identity, deployment provider,
  and the narrow admitted capability bindings needed by the run;
- an absolute monotonic deadline, bounded polling/window policy, and the existing
  `ClockProvider` seam;
- core-owned, narrow operation/capture services that preserve existing MCP,
  deployment, HTTP/TLS, snapshot, and evidence boundaries.

It does not expose `LocalRunStore`, destination paths, raw `AptlConfig`,
`EnvVars`, `.env` mappings, credential-bearing MCP registrations, the process
environment, a generic subprocess/shell client, or an unrestricted backend
handle. The framework owns credential use and persistence. A trusted in-process
extension can still bypass that convention with ordinary Python; conformance
tests and package review enforce it, while the installation trust warning
remains explicit.

The plugin owns its scenario-specific prerequisite declarations/evaluation and
must sequence them before its semantic actions. It also owns operation ordering,
trigger/probe content, backend-specific result parsing, and semantic verdict.
The framework owns admission prerequisites, deadlines and cancellation,
polling, evidence limits, correlation context, report-invariant validation,
redaction, persistence, and exception normalization; any reported unmet
prerequisite makes the normalized outcome `blocked`. Core callback or service
APIs must be capability oriented and scenario-neutral. A narrow admitted-node
argv operation or an existing source collector is a capability;
`detection_evidence()` that embeds a Kali/SSH/Wazuh answer key is not. Adding a
second scenario/backend plugin must not require a new Wazuh-, SSH-, TechVault-,
container-, rule-, or plugin-check-ID branch in core.

### Prerequisites And `blocked`

Prerequisites are typed report data with a stable ID, status, and bounded safe
diagnostic. They are not shell commands, import locators, environment-variable
names, paths, or free-form executable policy. All required prerequisites run
before the plugin performs a scenario action. An unavailable plugin, unsupported
scenario/backend revision, missing admitted capability, unavailable released
tool, missing credential binding, or unready required source prevents the
semantic runner from starting and yields `blocked`.

`blocked` means no complete semantic verdict was possible. It is terminal and
non-successful; it must never be projected as passed, skipped, empty success,
degraded lab readiness, or a semantic failure. `failed` means the semantic
verification ran far enough to disprove a required expectation. `passed`
requires every required prerequisite and semantic check to pass. Internal
loader/runner exceptions and malformed reports are normalized to a stable
blocked framework diagnostic unless a valid semantic failure was already
established; raw exceptions never become report text.

### One Core Report Shape

Generalize the useful identity/check/diagnostic parts of `LiveGateReport` into
one versioned core verification report. Do not leave a second live-gate report
schema beside it. The report needs:

- the `passed`, `failed`, or `blocked` status as the single authoritative
  outcome;
- core API version plus plugin/distribution identity;
- scenario identity/digest, backend target/version/profile/provider, run and
  attempt IDs, and observed window/clock context;
- typed prerequisite and semantic-check results with stable codes;
- evidence references, digests, counts, loss/truncation disclosure, and bounded
  diagnostics, not raw evidence payloads or storage paths.

Do not persist a separate boolean named `passed`. The current shared redactor
explicitly allow-lists that exact key, so redaction is not the reason; one
versioned `status` value is required because it cannot contradict a second
outcome field and cleanly represents `blocked`. Do not shape the report around
an incidental redactor heuristic or preserve the live gate's `ok` workaround.

This report is APTL operational evidence, not a RAES portable contract, a
`RangeSnapshot`, a RAES `RuntimeSnapshot`, an experiment evidence record, a
`LabResult`, or a signed participant qualification report. Existing
qualification/release models may reference or consume a completed verification
result, but `blocked` prevents qualification rather than being collapsed into
false semantic evidence or forcing an unversioned change to the signed
qualification schema.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Extension discovery | `backends/pack_interaction.py` and `pack_interaction_discovery.py` are the accepted installed-entry-point incumbent: pre-load family selection, bounded identifiers, exact version/digest/profile matching, factory containment, immutable result copying, stable codes, host-observed provenance, and duration/count logging. Reuse that pattern while preserving scenario verification's distinct `blocked` report outcome; do not share the two domain schemas or introduce a third discovery framework. |
| Scenario ingress and identity | `ScenarioSourceConfig`, `ScenarioCatalog`, `resolve_scenario_selection()`, the returned `ScenarioBundle`/`PackIdentity`, no-follow containment in `pathsafe`, participant-profile digest binding where applicable, `raes.parse_sdl_file`, semantic compilation, `RuntimeManager.plan()`, and planner diagnostics. Carry the admitted bundle through; discovery occurs only after this path. Plugins do not parse a second scenario shape, choose a path, or reconstruct source identity from `sdl_path.name`. |
| Backend identity and authority | `create_aptl_manifest()`, its backend-manifest-v2 target name/version/profile/capabilities, `create_aptl_runtime_target()`, `AptlRealization`, and `DeploymentBackend`. A deployment provider is transport, not a substitute for semantic backend identity. Container, Compose, SSH, and host effects stay behind the backend. |
| Participant/readiness contracts | `ParticipantReadinessSuite`, `ResolvedParticipantProfile`, workbench `ServerProfile` tool inventories, profile digest validation, and existing participant qualification/attestation models remain authoritative for their scopes. The plugin implements named semantic checks; it does not redefine the profile, tool inventory, signed report, or release schema. |
| MCP execution | Keep `mcp_protocol.call_mcp_tool()` as the bounded initialize/list/call exchange. Released argv, working directory, exact tool inventory, timeout, stderr suppression, and credential-bearing child environment remain host-owned. A plugin supplies scenario/backend tool intent through the narrow runner service; it does not receive registrations or launch processes itself. |
| Polling, windows, and clocks | Evolve/reuse `core.services.wait_for_service()` for monotonic deadlines and injectable sleep rather than copying `_collect_until_evidence()` loops. Its current debug path logs `str(exc)`; do not pass plugin-controlled failures through it until that path is redaction-safe. Use `core.correlation.clock.ClockProvider`/`ClockContext` for evidence timestamps and uncertainty. Wall-clock timestamps never enforce a timeout or imply causality by proximity. |
| Evidence acquisition | Reuse `core.evidence` outcome/loss vocabulary and narrow source-adapter principles where they fit, existing collectors for source acquisition, `RangeSnapshot.to_dict()` for backend inventory, and correlation identities/clock context. Do not claim a RAES capture requirement or evidence record when semantic verification is the actual concept. Empty best-effort collector output is not success. |
| Persistence | `RunStorageBackend`/`LocalRunStore` own run-ID and path validation, redacting JSON/JSONL writes, create-once canonical records, and content-addressed evidence. Core derives fixed run-scoped locations; a plugin never supplies a path. Use create-once for a deliberately secret-free authoritative report and redacting structured writes/content storage for captured observations. Exporter remains packaging-only. |
| Configuration and environment | ADR-025 `AptlConfig` remains the strict durable non-secret shape. `load_dotenv()`, `env_vars_from_dict()`, `find_placeholder_env_values()`, generated-config owners, and dedicated web/workbench secret parsers retain environment authority. Do not add plugin module paths, import names, arbitrary option maps, commands, credentials, or URLs to `aptl.json`. |
| Secrets and process exposure | ADR-029, `redact()`, TypeScript redaction parity, `curl_safe`, generated owner-only files, argv-list subprocess construction, and existing workbench/MCP process admission remain mandatory. Control-plane secrets do not enter plugin context, tool arguments, URLs, process argv, logs, reports, OTel attributes, or evidence. Target activity arguments may be scenario data but never carry operator credentials. |
| Errors and observability | Use stable verification codes, `get_logger()`, shared redaction, bounded messages, and the existing CLI/core projection style. Log validated plugin/distribution ID, stage, status, duration, counts, and exception class only. Audit reused helpers such as `wait_for_service()` and legacy collectors whose debug/warning paths still interpolate exception text; a caller-side `redact()` after they log is too late. Never log entry-point targets, raw exceptions/tracebacks, full reports, backend stderr, MCP results, captured payloads, env/config, or host paths. Do not create a public plugin exception hierarchy; expected outcomes are report data. |
| API/auth | Issue #878 adds no HTTP, SSE, or WebSocket route. Any later API projection must use `verify_token`, `WebAuthSettings`, `BFFMiddleware` Host/CSRF/session gates, strict Pydantic response models, loopback defaults, request limits, and generic error envelopes. It must not expose raw plugin objects, evidence bytes, filesystem paths, or install/import controls. |
| Packaging and supply chain | Discovery uses the standard library and should add no core dependency. `pyproject.toml`, `uv.lock`, hashed requirements, `hatch_build.py`, and `_asset_manifest.py` remain the core distribution authorities. `_asset_manifest.ASSET_ROOTS` includes `src`, so a core answer key is shipped both as importable code and as `_labdata/src`; inspecting only entry-point metadata is insufficient. The `aptl-labs` wheel registers and bundles zero semantic adapters. An extension distribution owns its dependencies, release, provenance, and integration tests. |
| Workflow and quality gates | Python changes require focused pytest coverage, the fast suite and scenario static gate from `.ground-control.yaml`, the Ruff complexity gate, `pre-commit run --all-files`, and CI/Sonar checks. MCP-common changes still rebuild every dependent MCP. Compose, Dockerfile, or `config/` changes still require the clean-lab gate; the seam itself should not need those changes. |

## Security And Host-Layer Guardrails

- **Installed-code trust:** entry-point loading executes installed Python. Record
  package provenance, fail on ambiguity, and keep installation explicit. Do not
  describe discovery as isolation or authorization.
- **Scenario and backend validation:** match only after contained scenario
  resolution, exact digest verification, RAES parsing/planning, strict config,
  and backend-manifest construction. A catalog/display name or
  `deployment.provider` alone grants no match.
- **Secret handling and environment:** core owns `.env`, MCP child environments,
  web auth, service credentials, and generated config. The plugin receives
  capability calls, not values. Redaction is defense in depth, not permission to
  hand an extension every secret.
- **OS/process surface:** retain released executable admission, fixed argv
  construction, bounded output/time, process cleanup, `curl_safe` header/body
  files, backend-scoped container calls, TLS/CA policy, and SSH host-key policy.
  No plugin-controlled host shell, executable, working directory, environment,
  URL authority, or destination path is admitted by the interface.
- **Report and error envelope:** validate and redact the returned structure
  before log, CLI, OTel, persistence, export, or future API projection. Bound
  item counts and string/byte sizes; replace malformed output or an exception
  with a stable blocked code, not `str(exc)`.
- **Evidence visibility:** semantic answer-key data and evaluator-only evidence
  remain outside participant projections. A plugin cannot widen RAES
  observation boundaries or treat access to core capture services as authority
  to disclose raw SOC or control-plane evidence.

## Extensibility And Whole-Repository Scope

The extensibility key is:

`(extension API version, scenario identity + content digest, backend target identity + compatible version/profile)`.

One exact installed runner binds to that key. A plugin may declare several
explicitly supported scenario/backend revisions, but no wildcard silently
claims unknown revisions. A second backend for one scenario or a second
scenario for one backend adds another installed entry point and its own
conformance/live tests; it does not edit the core selector, report schema,
poller, persistence layout, exception handling, or CLI/API projections.

The context also carries the deployment provider and bounded window/poll policy
as parameters, so local versus SSH transport and a future evidence-latency
variation do not require a new core concept. Provider-specific behavior belongs
in prerequisites or the plugin's match declaration, not in a core scenario
branch.

The implementation must audit the whole repository surface:

- current answer-key and framework code under `src/aptl/validation/`;
- scenario/profile/catalog inputs under `scenarios/` and
  `participant-profiles/`, without turning them into import selectors;
- RAES target/manifest and realization adapters under `src/aptl/backends/`;
- `src/aptl/core/{config,env,scenario_catalog,scenario_bundle,services,runstore,
  collectors,snapshot,telemetry}.py`, `core/evidence/`, `core/correlation/`,
  `core/deployment/`, `utils/{pathsafe,redaction,logging,curl_safe}.py`, and
  workbench/MCP process boundaries;
- CLI live-validation and profile-qualification projections, and future API
  projections only through the existing auth/BFF/schema boundary;
- `pyproject.toml`, `uv.lock`, hashed requirements, build/asset packaging, docs,
  tests, pre-commit, GitHub Actions, Sonar, and Ground Control plan rules;
- the active Python environment and distribution metadata, process argv/env,
  project and run-store filesystems, Docker/SSH/container operations, SOC
  HTTP/TLS, OTel, and archive/export readers.

## Closure Evidence Standard

Closure evidence must exercise artifacts rather than an editable checkout and
must not skip when the verifier is missing:

- build the core and verifier wheels independently with the repository's locked
  build-toolchain convention;
- prove the core wheel has no `aptl.scenario_verifiers` registration, verifier
  package, or verification answer key in either the importable package or the
  bundled `_labdata/src` copy;
- install only the core wheel in an otherwise clean environment and prove that
  semantic verification returns terminal, non-successful `blocked`;
- then install the separately built verifier wheel and prove discovery records
  its host-observed distribution/version and runs the one compatible verifier;
- cover no match, unrelated installed entries, duplicate compatible entries,
  malformed metadata/report members, inconsistent aggregate outcomes, loader
  and runner exceptions, unsatisfied prerequisites, and elapsed deadlines; and
- combine a transitive import/ownership check of every semantic-verification
  entry path with an explicit inventory of the known TechVault triggers,
  queries, correlation matchers, and plugin check mappings. A keyword scan of a
  hand-picked module tuple is not proof that core ships zero adapters.

This evidence is distinct from full live-range qualification. Issue #878 proves
the seam, ownership, artifact boundary, and failure semantics; scenario-specific
live proof belongs to the separately installed plugin's compatibility evidence.

## Gotchas And Anti-Patterns

- Leaving the TechVault query/command/matcher in core and wrapping it with a
  nominal plugin interface.
- Shipping a built-in fallback, example, test-only, default, or disabled
  scenario adapter in the core wheel. Zero adapters means zero adapters.
- Selecting a plugin by scenario filename, display name, current directory,
  class/module string, `getattr`, environment variable, mutable config, or
  first-discovered ordering.
- Loading every entry point before filtering the non-executable family selector,
  treating `isinstance(..., Protocol)` as returned-shape validation, accepting an
  empty digest/version claim as a wildcard, or trusting plugin-authored
  provenance.
- Confusing an installed semantic verifier with a deployment backend,
  participant implementation, evidence collector, RAES evaluator, workbench
  profile, qualification attestation, or scenario pack.
- Mirroring RAES SDL/backend schemas, cloning `LiveGateReport`, extending the
  signed qualification schema without a version, or adding another exception,
  validation, logging, polling, clock, redaction, or run-storage framework.
- Treating no plugin, a missing prerequisite, empty evidence, collector
  unavailability, timeout, a plugin crash, or a malformed report as pass or
  semantic fail. Those are blocked/no-verdict conditions unless evidence
  independently established a valid failure.
- Using wall-clock time for deadlines, fixed sleeps for eventually consistent
  evidence, or timestamp proximity as causality without a correlation rule and
  clock context.
- Passing `EnvVars`, raw MCP registration environments, `AptlConfig`,
  `LocalRunStore`, destination paths, full backend handles, or generic
  subprocess/shell capability to the runner.
- Letting a plugin write files directly, choose archive paths, log raw backend
  output, put secrets in argv/URLs/tool arguments, weaken TLS or SSH trust, or
  return raw evidence inside the report.
- Reclassifying plugin failure in a CLI, API, qualification, or exporter layer
  instead of projecting the single validated core report.
- Calling a skipped installed-plugin test or an editable source-tree import
  proof of the released distribution boundary.

## Non-Goals And Implementation Boundary

- No new scenario verification adapter, example adapter, fallback adapter, or
  second extension contract is designed here. The existing
  `aptl-techvault-verifier` distribution is the current seam proof and must not
  become a core dependency or bundled core asset.
- No decision is made about whether a range maintainer keeps a plugin beside a
  range, in another repository, or in a standalone package. It only has to be
  installed into the same Python environment and registered through the
  documented group.
- No RAES schema, scenario-pack format, participant contract, backend manifest,
  deployment backend, MCP protocol, workbench profile, signed qualification
  schema, run archive, exporter, API route, or auth system is redesigned.
- No untrusted plugin sandbox, remote plugin service, auto-install/update
  mechanism, marketplace, dependency resolver, or plugin-specific secret store
  is introduced.
- No efficiency design is implied: SDL-derived image prebuilds, golden-range
  reuse, cached/persistent lab pools, and their invalidation/attestation models
  remain separate work.
- No claim is made that generic startup/readiness, RAES conformance, evidence
  capture, or participant qualification equals scenario semantic
  verification. They are prerequisites or consumers, not substitutes.
