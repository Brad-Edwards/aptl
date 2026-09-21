# Issue #980 Pack Adapter Install Seam Preflight

This note is the architecture preflight for issue #980. It is guidance, not an
implementation plan. At this preflight's baseline (`3ce89ad5`), APTL already
selects installed scenario startup, runtime-parameter, pack/backend interaction,
verification, and participant-smoke providers through entry points. Capture,
several product-specific lifecycle choices, operator-group vocabulary, and a
release compatibility shim still bypass that boundary.

The change must complete those seams without creating a general plugin object,
a second capture model, or a second lifecycle controller. ADR-047 and EXP-010
remain authoritative for capture admission and evidence persistence; ADR-053
remains authoritative for data-only pack/backend serving; the
[issue #970 preflight](issue-970-generic-lab-lifecycle-preflight.md) remains
authoritative for lifecycle coordination. Issue #980 narrowly changes
ADR-053's current assumption that operator-group labels come from APTL's static
configuration fields: the admitted scenario/adapter mapping is now the source
of that bounded vocabulary.

## Architecture Decisions And Guardrails

### Select one exact adapter set once

All issue #980 hooks are selected from the already admitted `PackIdentity`, not
from a default pack name, an SDL path, a registration ID, or the set of every
installed provider. The selection key is the exact pack ID plus backend profile;
the provider contract also validates pack version and set digest. Discovery
filters an entry-point name before importing it, admits exactly one compatible
provider, and records host-observed distribution name/version and entry-point
name. Duplicate, malformed, incompatible, or load-failed candidates fail closed
with stable bounded diagnostics.

Reuse `aptl.backends.pack_interaction_discovery` as the strongest incumbent for
that protocol. `scenario_startup`, `scenario_runtime_parameters`, and
`scenario_verification_discovery` supply the adjacent patterns. Do not create a
repository-wide plugin registry or make provider discovery a mutable global.
Installed Python is trusted executable code, not a sandbox boundary; APTL does
not auto-install a provider merely because an authored pack asks for one.

The normalized selections are request-scoped and travel with the admitted
scenario start. They are reused through planning, realization, capture,
verification, retry, and teardown. Restart-safe state pins the same pack and
host-observed provider provenance so a later process does not silently bind a
different installed release.

### Keep purpose-specific contracts separate

The new capture entry-point group is `aptl.scenario_capture`; its selector is
`<pack_id>.<backend_profile>`. Its provider exposes a typed, immutable capture
contribution. Keep these parts distinct inside that contribution:

- declaration data: a tuple of core `CollectorRegistration` values;
- executable source construction/finalization behind a narrow typed runtime
  context; and
- evidence interpretation metadata needed to corroborate admitted propositions.

`CollectorRegistration` remains declaration-only. It must not acquire factories,
callbacks, import strings, commands, paths, credentials, or backend handles.
Core owns its schema and validation; `aptl_techvault` instantiates it. This keeps
registration admission deterministic and keeps executable authority out of the
capture plan.

Pack-release planning compatibility uses a separate typed installed-provider
contract, selected with the same exact identity. Use the entry-point group
`aptl.scenario_planning_compatibility`, also keyed by
`<pack_id>.<backend_profile>`. It must not be folded into capture, verification,
runtime parameters, serving interaction, or a catch-all scenario adapter.

The existing `aptl.scenario_startup` contract remains the home for fixed
lifecycle hook slots. The existing `aptl.pack_backend_interactions` contract
remains data-only. The existing `aptl.scenario_verifiers` contract remains the
semantic verdict boundary. Different authority and failure semantics are the
reason these seams stay separate even when one distribution implements all of
them.

### Capture admission is one immutable path

The selected capture contribution constructs the `CollectorRegistry` used by
the whole admitted run. A scenario-backed run must use that same registry for:

- the RAES backend manifest's aggregate observation projection;
- `compile_scenario_capture_demands()` matching and `CaptureBinding` creation;
- capture-plan digesting and create-once persistence;
- runtime source/collector construction; and
- transcript parsing, finalization, readback, and proposition corroboration.

Do not aggregate registrations from all installed packs. Do not retain
import-time or default-argument references to `DEFAULT_COLLECTOR_REGISTRY` on
the admitted-scenario path. A core-only scenario has an honest empty registry
unless a substrate-generic core registration is independently justified; it
must not receive TechVault registrations by fallback.

`build_collectors` may bind a generic `WindowedQueryCollector` for any ID in the
admitted registry/bindings. It must still reject a source key that is absent
from that admitted set. “Any admitted registration” does not mean “any caller
supplied string.” Preserve the coordinator's independent check that a
collector's registration ID equals the pinned `CaptureBinding` ID.

Reuse `validate_registration_id`, `CollectorRegistry`, `CaptureBinding`,
`CaptureLimits`, `CaptureVisibility`, `CapturePlan`, and the existing canonical
digest. Registration IDs remain non-executable labels. Duplicate IDs fail at
provider admission; limits, media types, contract versions, sensitivity,
redaction, retention, and loss disclosure remain core-validated.

The current `NATIVE_EVIDENCE_CAPABILITIES` map is a second TechVault schema for
facts already related by evidence requirement, capture offer/binding, and
proposition metadata. A second pack must not require another map under
`src/aptl`. Derive corroboration from the exact admitted binding and normalized
provider interpretation metadata, validating every authored semantic axis.
Never infer proposition truth from a registration ID alone or treat receipt of
a record as proof of its claim.

If capture-plan or run-record projection gains provider provenance, evolve the
existing versioned schema and canonical digest. Do not create a parallel
scenario-capture plan or repository. Persisted active-transcript authority must
pin enough exact adapter provenance to finalize safely after process restart;
current configuration or “whichever provider is installed now” is not durable
authority.

### Move behavior, not only filenames

All twelve `core/evidence/adapters/techvault*.py` modules move under
`aptl_techvault`. The boundary is transitive: no module under `src/aptl` may
import their types or functions. In particular, transcript parsing, native
evidence acquisition, proposition truth, and volume-reset cleanup currently
contain indirect TechVault dependencies that must consume the selected typed
contract instead.

Core continues to own the collector protocol, coordinator, typed outcomes,
redaction, quotas, persistence, and backend effects. The adapter owns product
API queries, product response parsing, readiness probes, transcript semantics,
and product-specific reset work. Teardown invokes only the adapter selected for
the persisted run; it must not broadcast reset callbacks to all installed
providers.

The current transitive leaks are part of the boundary, not incidental cleanup:

- `backends/_raes_transcript_parsing.py` imports TechVault transcript/source
  types;
- `backends/raes_evidence_acquisition.py` exports a fixed native-registration
  set and TechVault owner;
- `backends/_raes_native_evidence_acquisition.py` constructs that owner;
- `core/lab.py` projects credentials and activates capture from the fixed set;
- `core/deployment/_compose_stop.py` imports TechVault baseline cleanup; and
- `backends/_raes_native_proposition_truth.py` decides claims from a TechVault
  table.

Replacing the twelve module imports while leaving any of these identity-gated
handoffs in core would not satisfy the second-pack acceptance case.

### Startup hooks express work, not product nouns

`StartupCapability` retains only substrate-generic lab mechanics. `WAZUH`,
`SOC`, and `WAZUH_REPAIR` are not renamed to vague generic flags; they disappear
from core. Their behavior is supplied by the selected startup provider through
fixed typed hook slots such as preparation, bounded retry repair, and reset.
Core retains phase order, deadlines, cancellation, diagnostics, retry count,
and the rule that retry uses the same admitted plan.

Hooks may not add an arbitrary stage graph, invoke the planner, change the
backend, mutate admitted resources, select services by core configuration field
name, or return shell fragments. Product credential requirements are explicit
validated declarations. They do not justify passing the whole `.env`,
`os.environ`, `AptlConfig`, run store, or project filesystem to provider code.

Removing enum members is incomplete if equivalent branches remain. Audit the
admitted route for named `wazuh`, `soc`, `techvault`, container, registration,
and SDL-path conditions, including retry, certificate generation, capture
activation, stop/reset, and recovery. Unrelated repository-wide identifier
enforcement remains #1121.

### Operator groups come from admitted component mappings

The serving provider still returns a total, exact mapping for the admitted
component addresses; it cannot invent or omit components. Normalize that
mapping first, then derive the run's operator-group vocabulary from its group
values. `ContainerSettings.model_fields` is not an adapter vocabulary and must
not be passed to the provider as one.

Each non-null group is a bounded safe Compose-profile token: non-empty, unique
after normalization, length-limited, and free of path, control, whitespace,
shell, and option-prefix forms. Core passes it to `DeploymentBackend` as a
separate argv value. The legacy enabled-profile fields do not filter
pack-defined groups; they have no vocabulary for an independently installed
pack. Any future operator policy for those groups must itself be admitted
against the selected mapping rather than inferred from `ContainerSettings`. A
pack may map every component to no group.

Stop, kill, and recovery must use the selected/persisted run's groups and
backend ownership evidence, not `ALL_KNOWN_PROFILES`, the current
`ContainerSettings` fields, or the default adapter. This change does not make
`ContainerSettings` an arbitrary dictionary and does not weaken its strict
Pydantic validation.

### Compatibility hooks return bounded data

Core remains the only RAES compiler/planner/apply authority. It compiles once,
invokes the exact selected compatibility hook once, validates the returned
typed decision, and plans once. A compatibility provider cannot call RAES
planning, suppress diagnostics, change addresses/resources/operations/capture
or evaluation demands, or mutate module globals.

The existing TechVault shim's allowed transformations form the maximum initial
authority: release-scoped changes to the named runtime requirement axes and a
bounded runtime node-limit decision. Core owns the `RLock`, temporary limit
application, and `finally` restoration. The provider supplies data; it never
sets RAES globals itself. Unsupported releases get no transformation and fail
normally rather than falling through an identity heuristic.

## Cross-Cutting Layers The Design Must Pass

| Layer | Canonical incumbent and required behavior |
|---|---|
| Web/API authentication | `verify_token`, `WebAuthSettings`, BFF Host/Origin/CSRF/session enforcement remain unchanged. This issue adds no route and passes no bearer/session material to an adapter. |
| First-party configuration | `AptlConfig` and nested Pydantic models keep `extra="forbid"`; `ScenarioSourceConfig`, deployment config, and project-name validation remain canonical. No entry-point name, Python import, command, or filesystem path becomes user-selectable configuration. |
| Pack admission | `resolve_scenario_bundle`, `env_pack_bundle`, environment-pack `validate_pack`, content manifests, and no-follow staging establish exact `PackIdentity` before provider loading. An adapter cannot replace or weaken pack validation. |
| RAES shape and policy | Public RAES parser, instantiation, compiler, planner, manifest validation, capture-demand compiler, and runtime disclosure remain authoritative. Provider output is revalidated and cannot waive a RAES diagnostic. |
| Installed extension admission | Reuse exact pre-load selector filtering, API/pack version and digest checks, backend compatibility, unique-match admission, host distribution provenance, bounded immutable results, and stable errors from the existing discovery modules. |
| Capture validation | Reuse `validate_registration_id`, duplicate detection, governed vocabulary projection, exact demand matching, config digests, immutable bindings/plans, coordinator identity/media/deadline/quota checks, and typed outcomes. |
| Secrets and environment | Reuse `hydrate_dotenv`, `load_dotenv`, `EnvVars`, declared key/alias validation, and redaction. Pass only explicitly required values. Secrets never appear in entry-point metadata, argv, URLs, logs, exception messages, adapter results, capture plans, or run evidence. Existing header/stdin/private-file transports remain canonical. |
| Filesystem and persistence | Reuse `ScenarioBundle.read_asset`, path-safe helpers, `LocalRunStore`, create-once plan persistence, content-store checksums, and secure atomic local state. Providers do not choose archive paths or write an alternate run database. |
| OS/backend exposure | `DeploymentBackend` remains the only Docker/Compose/SSH effect boundary. Use argv arrays without a shell, validate operator groups before use, bound subprocess time/output, and keep registration IDs and provider selectors non-executable. |
| Error envelopes and observability | Reuse RAES `Diagnostic`, `StartupDiagnostic`, `CollectorStatus`, `AcquisitionDisposition`, `LabResult`, `get_logger`, and `redact`. Log stable code, selector/provenance, counts, duration, and exception class; do not expose raw response bodies, stderr, paths, environment values, or exception text. |
| Packaging and supply chain | `pyproject.toml` owns entry points and wheel package inclusion; Hatch's bundled `src` copy, `uv.lock`, hashed requirements, asset-manifest generation, and pre-commit secret checks remain in scope. A clean install must work without network discovery or dynamic package installation. |

The auth layer is deliberately a no-op passage for this work, not an omitted
security concern. The executable trust boundary is installation of Python code;
contract validation limits accidental or confused authority but does not sandbox
a malicious installed distribution.

## Canonical Incumbents To Reuse

- Capture declaration/admission: `core.experiment.capture_registry`,
  `capture_plan`, `raes_evidence`, and `raes_manifest`.
- Acquisition: `core.evidence.protocol`, `sources`, `coordinator`, `outcomes`,
  redaction, `LocalRunStore`, and the content store.
- Pack identity/discovery: `scenario_bundle`, `scenario_startup`,
  `scenario_runtime_parameters`, `pack_interaction_discovery`, and
  `scenario_verification_discovery`.
- Lifecycle and effects: `orchestrate_lab_start`, `AdmittedScenarioStart`,
  `AdmittedStartSurface`, `DeploymentBackend`, lifecycle locks, and existing
  startup diagnostics/results.
- Serving: `PackBackendInteraction`, its total-address validation and copied
  immutable projection. Its schema should evolve rather than gain a parallel
  mapping DTO.
- Planning: the public RAES runtime model, compiler/planner, and the current
  lock/restore discipline in `raes_planning_compat`; only provider selection and
  bounded decision data move.
- Persistence/provenance: existing capture plan, run record/backend evidence,
  active transcript authority, and canonical digests. Do not add a repository.

## Whole-Repository Surfaces In Scope

The implementation must inspect and keep consistent at least these surfaces:

- `pyproject.toml`, wheel inclusion, bundled lab-data source copy, and packaging
  artifact tests;
- `src/aptl_techvault` providers and all five existing entry-point contracts;
- capture registry/plan/manifest/admission and every import-time default registry
  reference under `src/aptl`;
- evidence wiring, native acquisition, transcript authority/parsing,
  proposition truth, reset, and stop/finalization paths;
- startup capability normalization, `.env` hydration, retry/repair, certificate
  preparation, capture activation, stop, kill, and recovery in the lab route;
- pack/backend component mapping, enabled-profile policy, Compose argv lowering,
  persisted ownership, and the `ALL_KNOWN_PROFILES` fallback;
- planning compatibility in both plan and apply routes; and
- verifier discovery/execution and run-record provenance used by the acceptance
  path.

The obvious next extension is another pack release or backend profile with a
different registration set, operator-group labels, startup preparation, and no
planning workaround. The required parameter is therefore the one admitted
`PackIdentity` plus backend profile, carried through all purpose-specific
selections and durable authorities. Adding that variation must require only a
new installed distribution and authored environment pack, not a new core enum,
configuration field, registration table, proposition map, or conditional.

## Acceptance And Regression Guardrails

The second-pack proof uses a real separately built and installed adapter
distribution with actual entry-point metadata in a clean subprocess/virtual
environment. It exercises pack admission, startup selection, capture
registration and acquisition, and verifier selection end to end. Monkeypatched
`entry_points()`, fake `_EntryPoint` objects, or direct provider injection are
useful unit tests but do not satisfy the issue.

Build and install from repository-local fixtures without network access. Assert
the fixture pack's token does not appear under `src/aptl`. Also prove duplicate,
missing, malformed, wrong-version/digest, wrong-backend, provider-exception,
unknown-source-ID, restart/provenance-drift, unsafe operator-group, and redacted
error paths fail closed. Preserve a core-only minimal scenario test and the real
TechVault wheel path.

Because the wheel bundles the tracked source tree beneath `aptl/_labdata`,
boundary tests must inspect both importable modules and bundled copies. Merely
moving Python packages while leaving old tracked modules in the bundled source
does not complete the boundary.

## Gotchas And Anti-Patterns

- Do not merge every installed registration into a process-global registry.
- Do not cache selection without pack version, set digest, backend, and host
  distribution provenance.
- Do not bind an adapter from a registration ID, SDL filename, current config,
  or default TechVault identity.
- Do not let default arguments retain the old global registry after admission.
- Do not put executable factories into `CollectorRegistration` or serialize
  callables/import paths into plans.
- Do not accept arbitrary collector source keys merely because wiring is no
  longer a fixed-ID allowlist.
- Do not duplicate RAES, capture, serving, error, or persistence schemas in the
  adapter package.
- Do not equate a successful API response or evidence record with proposition
  truth without exact semantic validation.
- Do not pass raw environment/config/store/path/backend authority when a narrow
  validated DTO suffices.
- Do not rename Wazuh/SOC branches to generic-sounding branches while retaining
  the same product test in core.
- Do not replace fixed lifecycle hook slots with an adapter-defined stage graph.
- Do not derive teardown profiles from static config or invoke all installed
  adapters during cleanup.
- Do not allow a compatibility provider to plan, apply, suppress diagnostics,
  or mutate RAES globals.
- Do not leak secret-bearing provider errors, response bodies, subprocess
  output, or paths through diagnostics or logs.

## Non-Goals And Implementation Boundaries

- This preflight does not implement issue #980 or prescribe task sequencing.
- Repository-wide identifier enforcement, the ownership ledger, and removal of
  the default pack identity remain issue #1121.
- Broad decomposition of `lab.py` remains issue #970; #980 changes only the
  adapter-facing ownership needed to remove product branches from the admitted
  route.
- This issue does not add dynamic package installation, untrusted-code
  sandboxing, arbitrary plugins, a generalized event bus, or user-authored
  lifecycle stages.
- It does not redesign RAES contracts, relax strict first-party configuration,
  add new HTTP/MCP auth surfaces, or turn `ContainerSettings` into a plugin
  schema.
- It does not move generic coordination, validation, redaction, persistence,
  diagnostics, retry policy, backend effects, or verification orchestration out
  of core.
- Unrelated historical TechVault identifiers may remain until #1121, but no new
  issue #980 path may depend on them and the real second-pack path may not reach
  an identity-gated fallback.
