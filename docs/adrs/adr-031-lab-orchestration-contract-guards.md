# ADR-031: Lab Orchestration Contract Guards

## Status

accepted

## Date

2026-05-12

## Context

Issue #214 asks for `icontract` preconditions, and optionally postconditions, on
critical lab CLI and core lab functions. The bug class is invalid orchestration
state reaching an operation that then fails open: collectors running before
project `.env` has been loaded, or scenario/lab startup continuing without the
profiles needed for the requested operation.

The repository already has the validating layers that define the state being
guarded:

- `src/aptl/core/env.py` owns `.env` parsing, required secret validation,
  typed `EnvVars`, and placeholder rejection.
- `src/aptl/core/config.py` owns the strict first-party `AptlConfig` /
  `ContainerSettings` schema and `enabled_profiles()`.
- `src/aptl/core/lab.py` owns lab-start ordering through `_LabStartContext`
  and `_LAB_START_STEPS`.
- `src/aptl/core/lab_types.py` owns the lifecycle result envelope shared by
  core, deployment backends, CLI, API, and web.
- `src/aptl/core/deployment/` owns Docker/Compose access through
  `DeploymentBackend`; container state checks must not bypass it.
- `src/aptl/utils/redaction.py`, ADR-029, and `curl_safe` own redaction and
  process-argv secret safety.

## Decision

Use `icontract` as a fail-fast guard over already-defined lab orchestration
state. Contracts must make impossible call states explicit, but they must not
become a second config schema, a second env parser, a second deployment layer,
or a new exception/result envelope.

Contracts belong at stable core boundaries where a caller can otherwise bypass
the normal ordered orchestration:

- functions that start containers from an `AptlConfig`;
- functions or steps that consume `_LabStartContext.env`,
  `_LabStartContext.config`, `_LabStartContext.backend`, or
  `_LabStartContext.ssh_key_path`;
- run assembly or collector orchestration entrypoints, if present, that require
  env-backed SOC credentials to have been loaded before telemetry collection.

Contract predicates should be pure, cheap checks over provided arguments or
context fields. They may compare profile sets derived from
`AptlConfig.containers.enabled_profiles()`, but they must not perform Docker,
network, filesystem mutation, API, or secret-reading work inside the decorator.
Operational readiness probes remain explicit orchestration steps that return
`LabResult` diagnostics.

Contract failure handling must preserve the existing user-facing surfaces:

- core functions may raise the `icontract` violation at the breach point;
- contract descriptions must be narrow labels that do not interpolate
  `_LabStartContext`, `EnvVars`, raw env dictionaries, subprocess results, or
  any object whose `repr()` can contain secrets;
- CLI and API entrypoints that expose those functions must convert unexpected
  contract failures into the existing `LabResult` / `LabActionResponse` /
  Typer exit shape, with a narrow redacted message;
- do not introduce an `AptlContractError` hierarchy or a parallel response DTO.

## Guardrails

- Reuse `load_dotenv`, `env_vars_from_dict`, `EnvVars`, and
  `find_placeholder_env_values`; a contract may assert that typed env exists,
  but it must not parse or validate raw `.env` itself.
- Reuse `AptlConfig`, `ContainerSettings.enabled_profiles()`, and
  `ALL_KNOWN_PROFILES`; do not duplicate Docker profile names in a second schema.
- Keep scenario or operation-specific profile requirements data-driven at the
  operation boundary. The prime scenario's required set is a value to pass into
  a reusable profile precondition, not a hardcoded special case buried in lab
  startup.
- Reuse `LabResult`, `StartupOutcome`, and `StartupDiagnostic` for user-facing
  failures. Contract failures are fatal state bugs, not partial-readiness
  warnings.
- Route container and Docker state through `DeploymentBackend`; do not add raw
  `docker compose` probes to contract predicates.
- Redact before messages cross logs, CLI output, API responses, telemetry, or
  persistence. Contract messages may name missing variable names, profile
  names, steps, and components, but never values from `.env`, generated config,
  API headers, cookies, private keys, command lines with credentials, or raw
  subprocess stderr. Do not forward raw `icontract` violation strings from
  predicates over secret-bearing objects.

## Security Layers

- **Environment binding:** `.env` remains parsed by `load_dotenv`, shaped by
  `EnvVars`, and placeholder-checked by `find_placeholder_env_values`.
  Contracts assert that this binding has happened before credential consumers
  run.
- **Config shape:** profile state comes from strict `AptlConfig` /
  `ContainerSettings`; unknown profile/config fields still fail through
  Pydantic, not through contracts.
- **Deployment boundary:** Docker lifecycle and container checks remain behind
  `DeploymentBackend`, preserving local and SSH-remote behavior.
- **OS/process exposure:** contracts must not move secrets into argv, command
  strings, or decorator messages. SOC HTTP access keeps using `curl_safe`.
- **Error envelopes:** CLI/API/web continue to receive `LabResult` and
  `LabActionResponse` shapes. A contract violation is represented as an
  existing fatal result at those edges.
- **Serialization and observability:** any contract text entering logs,
  diagnostics, traces, snapshots, or run archives must pass the ADR-029
  redaction boundary.

## Extensibility

The extensibility seam is a reusable, parameterized predicate for required
profile sets and a small set of state predicates for initialized context
fields. A future operation should supply its required profile set or required
context fields to the same predicate rather than adding a new one-off validator
or hardcoding scenario names.

## Non-Goals

- Do not reintroduce the retired `aptl scenario` runtime while adding
  contracts.
- Do not redesign lab startup ordering, Docker Compose profiles, deployment
  backends, run archive layout, or SOC collectors.
- Do not make non-fatal readiness warnings fatal unless the operation truly
  cannot produce correct output.
- Do not add broad postconditions that perform live Docker/API reads merely to
  prove services stayed healthy.

## Anti-Patterns

- Duplicating `.env` parsing, required variable lists, profile names, or config
  models inside contract predicates.
- Catching every exception and labeling it a contract violation.
- Depending on Python `assert` for production preconditions that must survive
  optimized execution.
- Returning raw `icontract` messages containing `repr()` of secret-bearing
  objects to CLI/API users.
- Scraping English error text, logs, or Docker output to decide whether a
  contract passed.
