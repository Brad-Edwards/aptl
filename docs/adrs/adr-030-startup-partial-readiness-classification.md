# ADR-030: Startup Partial-Readiness Classification

## Status

accepted

## Date

2026-05-11

## Context

`aptl lab start` deliberately treats some late startup checks as non-fatal:
image pre-pull misses, service readiness timeouts, SSH probes, snapshot capture,
MCP build, SOC seeding, and MCP config sync are not all equivalent. Some are
cosmetic or recoverable, while others materially reduce scenario usability,
detection fidelity, telemetry, or run-data trust.

The current envelope, `LabResult(success, message, error)`, cannot express that
distinction. The result is a concept leak: the core orchestrator knows a step
degraded, but the CLI/API/web surfaces mostly see a success boolean plus log
warnings. Automation then has to scrape text or trust a startup that may be
missing important evidence-producing services.

Relevant incumbents already exist:

- `src/aptl/core/lab_types.py` owns lifecycle result/status dataclasses shared
  by the core, deployment backends, CLI, and API.
- `src/aptl/core/lab.py` owns startup ordering through `_LabStartContext` and
  `_LAB_START_STEPS`.
- `src/aptl/core/services.py` owns readiness polling and returns
  `ServiceResult`.
- `src/aptl/core/deployment/` owns Docker/Compose execution through
  `DeploymentBackend` (ADR-013 and ADR-023).
- `src/aptl/api/schemas.py`, `src/aptl/cli/lab.py`, and `web/src/lib/types.ts`
  are the current user-facing action/status envelopes.
- `src/aptl/utils/redaction.py`, ADR-012, and ADR-029 own serialization,
  observability, CLI, API, and log redaction boundaries.

## Decision

Startup partial readiness must be represented as a first-class lifecycle result
contract in the Python control plane, not as ad hoc warning text in individual
steps.

The canonical structured contract belongs in `src/aptl/core/lab_types.py` and
is then projected into API schemas, CLI output, and web types. Do not create a
parallel startup schema in the API or web layer that reclassifies core results.

The contract should keep three concepts separate:

- **Outcome:** the overall machine-readable startup state, with a closed set
  such as `ready`, `degraded_usable`, `degraded_unusable`, and `failed`.
- **Diagnostic impact:** what a warning affects, with at least `cosmetic` and
  `telemetry`, and room for capability/readiness impact without changing every
  caller.
- **Severity / operator action:** whether the issue is informational,
  warning-level, or error-level, independent of whether the already-started lab
  can still be used.

`LabResult.success` may remain for backward compatibility, but it must not be
the only semantic field. Map it from the structured outcome rather than letting
callers infer partial readiness from text. In particular, a
`degraded_unusable` startup should be distinguishable from both a hard startup
failure and a usable-but-degraded startup.

Each startup step that can degrade should emit a diagnostic through a single
core-owned path. Step bodies may still log, but logs are secondary; CLI/API/web
must render the structured diagnostics. The implementation must characterize
the current live behavior before changing classifications so existing
"non-critical" steps are not silently promoted or demoted.

### Amendment: Persisted Wazuh Credential Mismatch

Wazuh Indexer authentication readiness crosses two existing states: the current
run's intended credentials from `.env`/`EnvVars`, and the persisted OpenSearch
security state inside the Compose-managed `wazuh-indexer-data` volume. Docker
health only proves that the HTTP listener responds; it is not proof that the
current `.env` credentials match the live security database.

When the indexer auth probe fails with HTTP 401 while the indexer container is
running/healthy, lab startup should emit a specific structured diagnostic on
the existing `wait_for_services/wazuh_indexer` surface. The operator action
should point to the existing clean-state recovery path (`aptl lab stop -v` or
`aptl lab start --clean`) rather than introduce a second volume-reset workflow.
The normal start path must not mutate the persisted Wazuh security database,
rewrite `internal_users.yml`, or delete volumes to make `.env` and the old
volume agree.

Any probe that handles `.env` credentials must satisfy ADR-029: no password in
process argv, logs, exception text, API envelopes, or diagnostics. If the
existing readiness helper cannot distinguish HTTP status safely, extend the
shared readiness / curl-safe boundary instead of adding one-off raw `curl`
subprocesses. If a future credential fingerprint is stored to warn before live
startup, it must be advisory, non-reversible, versioned service metadata under
ignored state (for example `.aptl/`) and never a replacement for the live auth
probe.

### Amendment: Wazuh Readiness Is Startup-Fatal

Issue #1002 reclassifies Wazuh indexer and manager API readiness from a
telemetry-impacting warning to a fatal startup failure. A scenario that selects
the `wazuh` profile uses Wazuh to meet its goals: without the SIEM, detection
and evidence collection do not work, so a lab that starts without it is not
usable for that scenario. This supersedes the non-fatal classification of the
Wazuh readiness wait in the original decision and the `degraded_usable`
outcome of the persisted-credential amendment above. The #623 credential
diagnosis and its `aptl lab stop -v` recovery guidance remain, but they now
arrive in the fatal error.

The policy is the same on every path that starts Wazuh:

- For a Wazuh service that consumes a scenario-declared generated artifact,
  the deployment backend's post-start authenticated readiness gate is the
  single authority. It fails the realization closed and records boolean
  `authenticated_readiness` evidence. Lab startup does not authenticate that
  service again.
- For a Wazuh service the backend did not prove, such as one in a scenario that
  declares no Wazuh generated artifacts, the lab `wait_for_services` step polls
  it under the same fail-closed policy. Both paths probe the controller's
  published loopback ports, which is sound because `aptl lab start` refuses
  the SSH-remote backend before any container starts.
- Each path polls within one bounded budget and does not probe again after the
  deadline. The failure reason is the last observation made inside the budget:
  the service, the probe phase (`transport`, `authentication`,
  `manager_status`), a normalized category such as `tls_handshake` or
  `credentials_rejected`, and the numeric curl exit or HTTP status. The reason
  never includes credentials, tokens, response bodies, or curl stderr.
- Expected warm-up attempts log at debug level only. A persistent state at the
  deadline is the only terminal signal.

### Amendment: Wazuh Startup Gate Attests Declared Realization

Issue #957 narrows and grounds the Wazuh amendment above. Startup failure
remains mandatory, but authenticated readiness is no longer the fact being
proved. The reason APTL may connect to the manager API or indexer is to attest
the admitted realization's declared native facts.

- The deployment backend's post-start observation is the single owner. It is
  driven by the admitted `DeploymentRealizationSpec` and semantic Wazuh
  identity, not by a profile name, familiar container name, or the presence of
  a generated artifact.
- Generic node, listener, and published-port observations retain their existing
  owners. The native Wazuh observation adds only facts that require the manager
  API or indexer API, including the indexer's declared partitions, templates,
  and mappings.
- Successful transport or authentication is a precondition, not proof. The
  backend records a structured, secret-free observation of every declared fact.
  A boolean `authenticated_readiness` may be a temporary compatibility
  projection, but it is not an attestation and cannot disclose a RAES concern.
- The existing RAES observation and exact-concern gate consume those
  observations. An unreachable service, malformed response, absent fact, or
  mismatched fact withholds the affected concern and fails realization through
  the existing RAES diagnostic envelope.
- `Lab` does not repeat a Wazuh login after backend observation. All native
  checks share one bounded polling budget and one owner.
- No declared Wazuh fact means no authority for the APTL control plane to make
  that connection. Participant MCP access is separate and remains available
  through its declared loopback publications.
- Evidence collection is also separate. It follows the admitted source and
  channel declarations and does not reuse the attestation connection as an
  evidence source.

Pack-declared Wazuh credentials used by this attestation are scenario fixtures,
not APTL operator secrets. Their values and provenance come from the admitted
pack and travel through the existing scenario-startup, environment-validation,
and secret-safe transport boundaries. They must not be copied into core
profiles, templates, probe defaults, or diagnostics. Release-specific fallback
knowledge for facts not yet declared by the pack belongs only to the exact
TechVault adapter and does not acquire pack provenance.

The detailed reuse, validation, and boundary rules are recorded in
`docs/architecture/issue-957-wazuh-attestation-evidence-credentials-preflight.md`.

Other late startup checks keep their original classification, including SSH
reachability, MCP build, SOC seeding, and snapshot capture.

## Guardrails

- Keep lab-start orchestration in `core.lab` as a flat sequence of `_step_*`
  functions and `_LAB_START_STEPS`. Add classification at the step boundary or
  shared context boundary; do not replace the orchestrator with a workflow
  engine.
- Reuse `ServiceResult` for readiness probe details and `DeploymentBackend`
  for deployment interactions. Do not shell out directly from a new
  classification helper.
- Reuse `LabResult` / `LabStatus` as the lifecycle DTO boundary. If new nested
  dataclasses or enums are needed, define them beside those types in
  `lab_types.py`.
- Keep API models in `api.schemas` as projections of the core DTO, not a
  second source of classification truth.
- Keep web TypeScript interfaces aligned with API schemas; do not infer
  degraded state from English messages in the Svelte layer.
- Preserve `AptlConfig` / `.env` validation ownership. Classification must not
  add unvalidated config flags, environment-variable bypasses, or a second
  config schema.
- Redact diagnostics before they cross CLI, API, log, telemetry, snapshot, or
  persistence boundaries. Diagnostic details may name a step, component, path,
  container, or service, but must not include `.env` values, API keys, bearer
  tokens, cookies, private keys, generated config contents, or full command
  lines containing credentials.

## Security Layers

- **Config/env binding:** startup still uses `AptlConfig`, `load_dotenv`,
  `env_vars_from_dict`, and `find_placeholder_env_values`. New classification
  fields are runtime result data, not durable config knobs.
- **Deployment boundary:** Docker and remote-Compose interactions stay behind
  `DeploymentBackend`; this preserves SSH-remote behavior and avoids leaking
  transport-specific details into result classification.
- **OS/process exposure:** readiness probes and subprocess failures can include
  sensitive argv or stderr. Structured diagnostics must store narrow labels and
  redacted summaries, not raw argv or command output.
- **Error envelopes:** `LabResult`, `LabActionResponse`, CLI output, SSE/API
  status payloads, and web action errors must preserve structure while applying
  the ADR-029 redaction invariant.
- **Observability/persistence:** if startup diagnostics are later traced,
  snapshotted, archived, or written to run storage, the existing
  `redact()`/`LocalRunStore` boundaries remain authoritative.

## Extensibility

The extensibility seam is a small, closed diagnostic taxonomy plus per-step
diagnostic emission metadata in the core startup context. A future startup step
should add a diagnostic code, impact, and outcome contribution without editing
every CLI/API/web caller. A future deployment backend should receive the same
structured result shape without emulating Docker-specific warning text.

## Non-Goals

- Do not redesign Docker Compose profiles, deployment providers, or container
  health checks.
- Do not make every warning fatal.
- Do not add a second exception hierarchy for startup classification.
- Do not add a general workflow engine or requirement/status engine to lab
  startup.
- Do not persist startup diagnostics in run archives as part of this
  classification unless a later issue explicitly owns that artifact contract.

## Anti-Patterns

- Scraping log text or CLI output to decide readiness.
- Adding `is_degraded`, `partial`, `telemetry_ok`, or similar booleans in
  multiple layers instead of one canonical outcome plus diagnostics.
- Returning raw subprocess stderr, curl output, Docker command lines, or
  generated config content in user-facing diagnostics.
- Reclassifying the same core result separately in the CLI, API, and web UI.
- Treating telemetry-impacting, SOC/detection-impacting, SSH-readiness, and
  cosmetic display warnings as the same "warning" concept.
