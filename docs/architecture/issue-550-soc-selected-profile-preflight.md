# Issue #550: SOC selected-profile scoping preflight

This note records architecture guardrails for scoping SOC startup recovery and
prime seeding to the ACES scenario's realized Compose profiles. It is design
guidance, not an implementation plan. No new ADR is needed: the change applies
ADR-005, ADR-030, ADR-031, ADR-044, and ADR-046 to a remaining lab-start path.

## Decision

Keep these two profile concepts distinct:

- `AptlConfig.containers.enabled_profiles()` and
  `public_start_profiles(config)` are the operator-configured capability ceiling.
- `AcesStartOutcome.selected_profiles` and its orchestration cache,
  `_LabStartContext.selected_profiles`, are the scenario-realized runtime
  surface after `select_backend_profiles()` intersects that ceiling with the
  ACES realization (plus core profiles).

Scenario-dependent work and recovery must use the realized runtime surface.
Consequently:

- A failed first container start receives the attempt's selected profiles before
  deciding whether the SOC-specific wait/restart/retry path applies. The ACES
  handoff computes `AcesStartOutcome.selected_profiles` before backend apply, so
  a Compose/apply failure can still carry the authoritative set. A literal
  `"soc" in ctx.selected_profiles` replacement while the context is populated
  only after success would silently disable the full-scenario retry.
- After each handoff attempt, derive the context cache from the returned
  `AcesStartOutcome`; do not independently parse/plan a second time when the
  outcome already carries the answer. The existing no-side-effect
  `selected_profiles_for_scenario()` remains the compatibility/best-effort seam,
  not a second source of truth.
- SOC seeding is an intentional no-op, with no degradation diagnostic, when
  `soc` is absent from the selected set. Never fall back to the global config
  flag when selected-profile resolution is empty or unavailable; side effects
  fail closed.
- Prime seed eligibility and the missing-profile diagnostic compare
  `_PRIME_REQUIRED_PROFILES` with the selected set. If `soc` is selected but the
  rest of the prime surface is not, retain the existing non-fatal
  `CAPABILITY`/`WARNING` classification and name the profiles missing from the
  selected surface. Operator guidance must account for both causes: a profile
  can be disabled in `aptl.json` or intentionally omitted by the scenario.
- `required_profiles_enabled()` remains a config-bound contract predicate. Do
  not broaden it to accept either an `AptlConfig` or an arbitrary collection;
  that would conflate configured capability with runtime selection. At this
  boundary, ordinary set containment against `_PRIME_REQUIRED_PROFILES` is the
  clearer incumbent.

The full `techvault-operational` scenario selects the complete prime profile
set under the default config and therefore retains its existing SOC retry and
seed behavior. Reduced scenarios inherit no scenario-name branches: their ACES
content and the existing profile selector determine behavior.

## Canonical incumbents

- Repository inputs: `aptl.json` for the configured profile ceiling,
  `scenarios/catalog.json` plus the selected `scenarios/*.sdl.yaml` for scenario
  identity/content, `docker-compose.yml` for profile-to-service topology, `.env`
  for runtime secrets, and `scripts/seed-prime.sh` for the existing seed action.
  None receives a new shape in this issue.
- Scenario selection and containment: `resolve_scenario_selection()`, the
  strict `ScenarioCatalog` models, `_resolve_project_file()`, and the ACES SDL
  parser.
- Planning and profile authority: `RuntimeManager.plan()`,
  `interpret_provisioning_plan()`, `select_backend_profiles()`,
  `public_start_profiles()`, `ComposeProfileIndex`, and
  `AcesStartOutcome.selected_profiles`.
- Startup workflow: `_LabStartContext`, `_step_start_containers()`,
  `_step_seed_soc()`, `_emit_missing_prime_profiles()`, and the ordered
  `_LAB_START_STEPS` short-circuit convention.
- Result and observability surfaces: `LabResult`, `StartupOutcome`,
  `StartupDiagnostic`, `_emit_diagnostic()`, `get_logger()`, and `redact()`.
- Side-effect boundaries: `DeploymentBackend` for container operations and
  `run_shell_script()` for the cross-platform seed script invocation.
- Persistence: `AcesStartOutcome` plus the ADR-044 reproducibility record and
  `LocalRunStore` redacting structured writes. Selected profiles are already
  persisted as backend realization evidence; no seed-specific schema is needed.
- Test conventions: extend `tests/test_lab.py` for orchestration/diagnostic
  behavior and retain `tests/test_techvault_curated_variants.py` as the
  content-driven selected-profile contract. Do not create a parallel startup
  harness.

Do not add a profile DTO, a second ACES parser/realizer, a scenario-name table,
a seed service/repository, a new exception hierarchy, or a parallel diagnostic
shape for this change.

## Cross-cutting and security layers

- **CLI/catalog/path validation:** `--scenario` continues through the strict
  catalog, project-root containment, and ACES parse validation. Profile gates
  consume the validated/planned result, never raw CLI strings or catalog data.
- **Config validation:** `aptl.json` continues through strict Pydantic
  `AptlConfig` / `ContainerSettings`; `select_backend_profiles()` continues to
  enforce the configured upper bound. This change adds no config key and does
  not weaken `extra="forbid"`.
- **ACES validation:** parse, planning diagnostics, provisioning realization,
  dependency closure, and backend conformance remain ACES/APTL adapter-owned.
  Do not locally shape-check `selected_profiles` beyond normalizing the outcome's
  existing list into the context set.
- **Environment and secret binding:** `.env` remains owned by
  `hydrate_dotenv()`, `load_dotenv()`, `env_vars_from_dict()`, and placeholder
  rejection. The seed receives secrets in the child environment through
  `run_shell_script()`, not in process argv; profile names and scenario paths are
  non-secret.
- **Deployment and host boundary:** the SOC retry watchdog continues through
  `DeploymentBackend`; no raw `docker`, SSH, or Compose subprocess is introduced.
  The seed command argv contains only the script/shell path. Local and
  SSH-Compose behavior outside the existing recovery boundary is unchanged.
- **Auth surface:** no API route or request shape changes. API-triggered default
  starts remain protected by `verify_token` through the router dependency; the
  CLI path remains a local operator action.
- **Errors and diagnostics:** preserve `LabResult` and ADR-030 diagnostics.
  Intentional omission of `soc` is neither a warning nor degraded readiness.
  Missing prime profiles are a narrow capability diagnostic, while fatal ACES
  or backend failures retain the existing redacted error envelopes.
- **Logging and OS exposure:** log selected profile names or counts only; never
  env values, argv with credentials, or raw seed output. In particular,
  `_execute_seed_soc_script()` currently logs `seed_result.stderr` directly and
  `aptl.utils.logging` has no automatic redaction filter. That adjacent
  ADR-029 hazard is not a pattern to copy or rely on; any touched logging must
  use a narrow status or explicit `redact()` and diagnostics must continue
  through `_emit_diagnostic()`.
- **Persistence:** no database/repository transaction is involved. Do not add a
  seed-attempt field or another profile copy to the run record; the outcome's
  selected profiles remain the persisted realization evidence.

## Extensibility seam

The seam is the selected-profile collection carried by the ACES start outcome
and cached on the startup context, plus the parameterized
`_PRIME_REQUIRED_PROFILES` set. A future scenario or another scenario-scoped
post-start capability should consume that same collection rather than add a
config-flag or scenario-id branch.

If a later issue scopes pre-start work such as certificate generation, image
pulling, bind-mount checks, or host-port planning, resolve the selected surface
once in an explicit pre-start boundary after config/backend initialization and
reuse it. Do not scatter extra parse/plan calls across those steps. That broader
pre-start refactor is not required for issue #550.

## Verification contracts

- With global `soc: true` and a selected set without `soc`, no seed script,
  seed-failure diagnostic, SOC wait, Wazuh restart, or second start attempt is
  attributable to the SOC path.
- With `soc` selected and the prime set incomplete, the diagnostic is derived
  from selected profiles and remains non-fatal.
- With the full prime selected set, the existing seed subprocess, timeout,
  redaction, and diagnostic behavior is preserved.
- Retry coverage must use an `AcesStartOutcome` carrying selected profiles on a
  failed first apply, proving the ordering contract rather than pre-populating a
  test-only context accidentally.
- Existing readiness-scoping tests remain the model: selected profiles override
  permissive global flags. Curated variant tests continue to prove selection is
  content-driven rather than catalog-name-driven.

## Non-goals and anti-patterns

- Do not redesign Compose profiles, ACES realization, startup ordering as a
  whole, the seed script, SOC TLS, generated credentials, MCP config sync,
  deployment backends, run records, API/web contracts, or readiness taxonomy.
- Do not scope unrelated pre-start preparation steps in this issue.
- Do not interpret `skip_seed` as profile selection; it remains an explicit
  operator override after selection.
- Do not emit a missing-prime warning for a scenario that intentionally omits
  `soc`, and do not tell an operator merely to edit `aptl.json` when the selected
  scenario itself omits a required profile.
- Do not use an empty/unresolved selected set as permission to seed or retry.
- Do not duplicate the profile intersection, hardcode TechVault catalog ids, or
  scrape CLI/log text to infer what started.
