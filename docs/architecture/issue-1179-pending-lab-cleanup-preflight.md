# Issue #1179: durable lab cleanup preflight

This note fixes the ownership and compatibility boundaries for pending cleanup
after `aptl lab stop -v`. The issue contract governs the implementation; this
is architecture guidance, not an implementation plan. It narrows the reset
ownership guidance in the [issue #980 preflight](issue-980-pack-adapter-install-seam-preflight.md):
the generated Wazuh enrollment baseline is APTL-owned realization state even
though TechVault currently deletes it through a startup adapter hook.

## Decisions and invariants

- Model cleanup as a small, stable, versioned **action**. Use a new
  `aptl-cleanup-action/v1` receipt envelope and the fixed
  `aptl.wazuh-enrollment-baseline.clear/v1` action for this host artifact. Each
  receipt has an explicit owner, action version, admitted pack identity, and
  recorded provider provenance for
  audit. An installed distribution version is evidence of admission, not the
  executable authority required to finish a later cleanup. Keep pack ID,
  version, set digest, admission identity, and original provider distribution,
  version, and entry point where known. The action key, rather than a provider
  callback name or free-form import path, determines what may execute.
- Core owns removal of `.aptl/realization/wazuh-agent-identity/baseline.json`
  after a proven volume reset. Move the operation's ownership to the APTL
  realization/lifecycle boundary; preserve its already-absent-is-complete
  behavior. Do not make it conditional on a currently installed TechVault
  distribution or a currently selected scenario. A new baseline must have
  durable pending cleanup authority before it can outlive the start attempt.
- Pack-owned actions remain behind the existing `aptl.scenario_startup`
  installed entry-point boundary, or a narrow evolution of its fixed reset
  slot. A handler must explicitly declare supported action version and exact
  admitted pack identity/digests, or a reviewed migration from those identities.
  Resolve one compatible handler; missing, ambiguous, malformed, and
  incompatible handlers leave the action pending. A matching public pack ID
  alone never authorizes dispatch. Do not demand that an older distribution
  version remain installed when a current handler explicitly supports its
  historical action. The present `StartupHookContext(backend)` grants broad
  backend access; pack cleanup needs a narrower declared effect and context,
  with validated target scope and no arbitrary project-root deletion.
- Retain `startup-reset-v1` receipt bytes and existing completion markers.
  Authenticate their canonical content address and parse the actual released
  v1 variants, including admission-field differences if historical fixtures
  show them. Translate only known legacy semantics: a verified historical
  TechVault reset receipt maps to the APTL baseline action; other v1 receipts
  need an explicit pack-owned compatibility declaration. Do not infer that all
  v1 resets cleared the baseline. Multiple pack versions, digests, admissions,
  and completed receipts coexist; process each independently. Unknown schema,
  malformed content, unknown action, and unsupported migration remain pending
  with a bounded recovery reason. Never delete, rewrite, or silently skip an
  original receipt to make a retry pass.
- A completion marker means the corresponding action succeeded. Persist it
  with the existing create-once, fsynced, no-follow pattern before retiring a
  legacy parent receipt. If one legacy hook expands into several actions,
  retain independently recorded action completions and retire the v1 receipt
  only when all succeed. A crash can occur after an effect and before its
  marker: execution is therefore **at least once**, while each action becomes
  complete exactly once in recorded state. Every cleanup effect must be
  idempotent, and an absent target is success. Never mark a failed or merely
  attempted effect complete.
- The project lifecycle lock covers Docker teardown, pending-action reads,
  execution, and completion writes. Run host cleanup after successful volume
  removal, and retry pending cleanup on later `stop -v` calls even when Docker
  resources are already absent. A Docker teardown failure and a host cleanup
  failure have different result codes. When Docker cleanup is verified complete
  but host work remains, report partial teardown, the bounded failed action,
  and `aptl lab stop -v --yes` as the supported retry. Do not claim Docker
  absence if the backend could not verify it. Clean boot must remain blocked by
  incomplete required cleanup.

## Required cross-cutting passage

| Layer | Existing contract and guardrail |
| --- | --- |
| Lifecycle and backend | `core.lab.stop_lab()`, `_stop_lab_owned()`, `clean_boot_lab()`, `lifecycle_mutation_lock()`, `DeploymentBackend.stop()`, and `_compose_stop` own order and one project identity. `_compose_volume_cleanup` owns bounded volume inventory and removal. Do not add a second controller, direct Docker call in core, or a CLI-only retry. Retain Docker/SSH backend selection and remote transport identity. |
| Persistence and validation | Evolve `core.startup_reset_state` rather than add a parallel ledger. Reuse `utils.pathsafe` create-once, contained no-follow reads/listing, canonical bytes, digest filenames, and completion markers. Validate bounded receipt bytes, exact keys and types, schema/action versions, lengths, names, digests, receipt-to-marker binding, and supported legacy shapes before any effect. Malformed state must not escape as an unhandled parser/type exception or become an empty queue. |
| Pack identity and executable selection | Reuse `core.scenario_bundle.PackIdentity`, `backends.scenario_startup` entry-point discovery/provenance, API-version and identity checks, and normalized `ScenarioStartupProviderError`. A legacy provenance record is audit evidence; current compatibility must be a separate, bounded and validated declaration. Installed Python is trusted executable code, not a sandbox. `pyproject.toml` remains the entry-point and wheel-inclusion authority. |
| Host state | The baseline now written by `aptl_techvault.evidence.techvault_enrollment_baseline` uses `core.credentials` generated-path checks and secure writes. Cleanup must use project-contained, no-follow filesystem operations and refuse symlinked parents or leaves; extend the canonical `utils.pathsafe` surface for contained deletion if needed, rather than copying a lexical check. Preserve the distinction between absent, unreadable, and unsafe. It may remove only the fixed APTL-owned baseline, never another pack's state or an entire realization directory. |
| Configuration and environment | `AptlConfig`/`DeploymentConfig` and `validate_compose_project_name()` remain the strict, `extra="forbid"` configuration and destructive project-identity gates. `core.env` owns `.env` parsing and binding. No new config field, environment value, secret, provider import path, or user-supplied executable selector belongs in a cleanup receipt. Stop's existing invalid-present-config refusal remains in force. |
| Auth and public errors | CLI `cli.lab.stop`, `LabResult`, API `LabActionResponse`, `api.deps.verify_token`, and BFF Host/Origin/CSRF/session gates remain the public path. The API stop route currently has no volume-reset option; this issue needs no new route or auth bypass. Normalize errors in core so CLI and any future API projection distinguish Docker failure, host-action failure, and invalid/unsupported pending state without a duplicate DTO or exception hierarchy. |
| Logging and secrets | Use `utils.logging.get_logger`, `utils.redaction.redact`, and ADR-029. Log bounded action IDs, state classification, pack identity/digest prefix where useful, and exception **class**, not raw adapter exception text, receipt bytes, absolute host path, Docker stderr, config, environment, or credentials. Keep these out of `LabResult`, CLI/API errors, telemetry, and process argv. Cleanup needs no shell, token, or new subprocess argument. |
| Workflow and tests | `.ground-control.yaml`, `.gc/plan-rules.md`, `tools/run-targeted-tests.sh`, and staged `pre-commit run` govern local verification; CI owns full suites and clean-lab gates. Extend focused Python tests in `tests/` for historical receipt bytes, independent digests/admissions, interruption/retry, absent baseline, handler incompatibility, malformed state, and verified volume removal followed by host failure. Exercise CLI/core result projection and clean-boot blocking. |

## Migration and failure gotchas

- The current v1 reader requires an exact canonical JSON object including
  `admission_id` and sorts/deduplicates returned authorities. Historical bytes
  must be sampled as fixtures before defining a legacy parser. Do not
  deserialize, normalize, and overwrite them; content addresses and completed
  history depend on original bytes. A malformed receipt or completion marker
  must not make other pending records disappear. Content addressing detects
  corruption and accidental substitution; it is not a signature against an
  attacker who can write the project root. Keep lifecycle state owner-only
  (`0700` directories, `0600` files) and under the existing project trust
  boundary.
- Current `_reset_selected_scenario_state()` catches failure and returns the
  generic `Scenario adapter reset failed.`; `_stop_lab_owned()` invokes it only
  after `backend.stop()` succeeds. Preserve the distinction between verified
  Docker cleanup and host cleanup pending, including when a later stop finds
  no containers or volumes. The backend's `LabResult` and host action result
  must not overwrite each other's failure facts.
- Avoid matching a new installed provider merely by entry-point name, current
  `aptl.json`, current pack selection, or distribution name. Do not auto-install
  historic wheels, execute serialized callables/import paths, broadcast reset
  to all providers, or turn a current handler's broad pack-ID claim into
  authority over an old digest.
- Never treat `FileNotFoundError` at the target and a path containment failure
  as the same outcome. Do not delete whole `.aptl` trees, hand-edit receipts,
  prune Docker globally, or silently drop an unsupported action. A targeted
  operator recovery path can report the action/record identifier and request a
  compatible current handler or supported APTL upgrade; it cannot claim an
  unsafe automatic migration succeeded.

## Implemented contract

- `core.startup_reset_state` writes one content-addressed
  `aptl-lifecycle-cleanup-action/v1` record per action and admission under
  `.aptl/lifecycle/cleanup-actions-v1/`. Its completion markers live in
  `cleanup-actions-completed-v1/`. The action vocabulary is
  `aptl.wazuh-enrollment-baseline.clear` (APTL-owned, recorded for every
  admission) and `pack.reset` (recorded only when the admitted plan declares
  `StartupHook.RESET`), both at action version `1`.
- `startup-reset-v1` receipts are read in place. An `aptl-labs` receipt for
  `techvault` or `techvault-participant-study` maps to the APTL baseline
  action. Every build that wrote such a receipt implemented its reset as that
  removal alone. Any other v1 receipt maps to `pack.reset`. Both are retired
  with the original `startup-reset-completed-v1` marker.
- `core.lifecycle_cleanup` runs APTL actions in core and removes the baseline
  through `utils.pathsafe.remove_contained_nofollow`. It dispatches
  `pack.reset` through `run_persisted_startup_reset`. That function selects
  the one handler registered under the recorded entry-point name that accepts
  the exact admitted pack ID, version, and set digest. The handler must be the
  unchanged admitting installation, or it must declare
  `supported_reset_action_versions` containing the recorded version. The
  TechVault adapter no longer declares a reset hook.
- `aptl lab stop -v` reports `[lifecycle-docker-teardown-failed]` or
  `[lifecycle-host-cleanup-pending]`. Each names the pending actions, their
  bounded reasons, and the `aptl lab stop -v --yes` retry.

## Scope limit and extension seam

This change covers pending cleanup on explicit volume reset and recovery of
released v1 receipts. It does not redefine normal stop, pack admission,
Docker ownership, RAES evidence, API authentication, or arbitrary pack data
retention. It does not promise that side effects run exactly once across process death.

The extension seam is an APTL-validated `(action kind, action version, admitted
pack identity)` compatibility decision. A future pack release or second cleanup
action should add a bounded handler declaration or migration at that seam,
without changing core configuration, receipt authenticity rules, lifecycle
order, or public error envelopes.
