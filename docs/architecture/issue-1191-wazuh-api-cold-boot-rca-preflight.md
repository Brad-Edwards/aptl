# Issue #1191 Wazuh API Cold-Boot RCA Preflight

This note narrows the follow-up to issue #1188. It is architecture guidance,
not an implementation plan, and changes no runtime behavior. No new ADR is
needed: ADR-029 owns secret-safe diagnostics, ADR-030 owns fail-closed startup,
ADR-034 owns Wazuh TLS policy, ADR-046 owns realized-state observation, and the
issue #1188 preflight owns the exact-pack recovery and identity boundary.

## Findings And Causal Limit

The initiating cause of the preserved-seat `wazuh-apid` exits is not established
by the retained evidence. The record proves that the manager container and
other Wazuh daemons remained alive, the API log reached certificate generation
and RBAC integrity work without a later listening marker, Docker did not report
the manager container as OOM-killed, and an in-place `wazuh-control start`
restored service. It does not retain the API child's exit status or signal, a
fatal/traceback record after the last phase marker, the launcher's disposition,
or cgroup memory-event counters correlated to that exact process transition.

Consequently, certificate generation, the absent API-configuration volume,
RBAC work, OOM, and an external signal are hypotheses, not causes. Docker's
container-level `State.OOMKilled` is especially not proof that a child process
was neither killed nor terminated for another reason. Recovery success is also
not causal evidence.

The Wazuh 4.12.0 control command has a status protocol, not a conventional
zero-means-observed/nonzero-means-command-failed contract:

- exit `0` means every daemon considered by the command is running;
- exit `1` is a completed status observation with at least one stopped daemon,
  including an optional daemon such as `wazuh-maild`; and
- any other exit, timeout, exception, missing output, or contradictory output
  is an unknown observation and cannot authorize mutation.

An API-only recovery observation is therefore exit `1` plus the exact complete
stdout line `wazuh-apid not running...` while the container is running and the
existing process-count probe proves that other Wazuh daemons exist. Exit `1`
alone is not an API failure. Exit `0` plus a stopped-daemon line contradicts
the qualified image contract and must fail closed rather than becoming a
second accepted dialect. Do not inspect stderr, use a substring match, or
treat every nonzero result as execution failure.

## Architecture Decisions And Guardrails

1. **Keep recovery in the exact-pack hook.**
   `TechVaultStartupProvider.before_backend_retry()` remains the only owner of
   this Wazuh 4.12.0 repair. It uses the existing `DeploymentBackend` and fixed
   command argv. Core does not learn Wazuh status text, and no generic repair
   command, exception hierarchy, status DTO, or hook type is added.
2. **Classify before mutating.** The running-container check, nonzero daemon
   count, status result, and exact API line form one conjunction. Unknown or
   inconsistent observations do nothing. Preserve issue #732's separate
   zero-daemon container-restart predicate; API-only absence still uses
   `wazuh-control start`, never a container restart.
3. **Capture once, immediately before repair.** When that conjunction is met,
   capture a bounded, secret-safe observation before `wazuh-control start`
   changes the evidence. The observation may contain only: the known status
   class and exit code; API-present/absent and other-daemons-present booleans;
   container running/restart/OOM booleans or integer counters from inspect;
   available cgroup `memory.events` OOM counters; API-log byte size and the
   captured tail's starting offset; recognized lifecycle phases; bounded
   warning/error/critical/traceback counts; and a strictly parsed exception
   class, signal number, exit number, or errno when present. Missing fields are
   `unknown`, never false.
4. **Never retain arbitrary log text.** Bound the API-log read at the source
   with fixed list-form argv and an explicit byte limit, then normalize in
   memory through an allowlist. Raw stdout/stderr, log lines, traceback text,
   API bodies, headers, tokens, configuration, certificates, and private keys
   must not reach logs, diagnostics, run storage, snapshots, or test failure
   output. An unrecognized fatal record becomes a safe
   `unclassified_fatal=true` fact. Its byte offset leaves the original retained
   Wazuh log available for later authorized inspection without copying it into
   a new artifact.
5. **Use existing observability, not a forensic subsystem.** Emit at most one
   bounded structured log summary through `get_logger()` for the single
   admitted retry. Apply `redact()` as defense in depth after constructing the
   allowlisted fields. Capture unavailability is logged as a safe category and
   does not suppress the repair; the existing readiness gate still decides the
   outcome. Do not add a database, run-record schema, public API field, metrics
   store, or raw-log attachment for this intermittent startup fact.
6. **Keep one retry and one success authority.** `_apply_with_backend_retry()`
   continues to own the sole retry of the same admitted plan and pack identity.
   The hook contains no polling, sleep, recursive Compose operation, or nested
   retry. Successful `start` is only a repair attempt; declared listener and
   authenticated manager readiness remain authoritative and fail closed.
7. **Preserve identity and state.** The repair and capture are read-only except
   for the fixed in-container start command. They do not replace the container,
   recreate the Compose project, delete or rename volumes, change generated
   realization, clean a lab, or replace a VM/overlay disk. `heron1` and
   `heron2` remain untouched while in use.

## Required Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Pack and workflow selection | `ScenarioBundle`, exact `PackIdentity`, `select_scenario_startup()`, `_validated_plan()`, fixed `StartupHook.BEFORE_BACKEND_RETRY`, and `StartupHookContext` remain the admission boundary. This behavior must not activate from a scenario name, loose image tag, or user setting. |
| Backend and ownership | `DeploymentBackend.container_inspect()` and `container_exec()` keep Docker/SSH transport, project ownership, timeout, and result behavior behind one interface. Do not call `docker`, traverse host cgroups, or accept an arbitrary container name in the provider. |
| Status validation | The Wazuh 4.12.0 status classifier is release-local: exit `0` is all-running, exit `1` is parseable partial status, other exits are unknown, and only exit `1` plus the exact stdout line authorizes API repair. Keep the process-count and API-status predicates distinct. |
| Evidence minimization | Fixed byte/line/time bounds, an allowlisted normalizer, safe scalar fields, and one summary are mandatory. `container_file_read()` and `container_logs_capture()` do not by themselves make arbitrary bytes safe; neither raw API logs nor unbounded Docker logs may cross the observability boundary. |
| Secrets and process exposure | ADR-029, `aptl.utils.redaction.redact()`, fixed list-form argv, backend timeouts, and class-only exception logging remain canonical. The capture and repair require no `.env` value, API credential, auth header, shell interpolation, host bind, capability, or secret-bearing argv. |
| Config and environment shapes | `AptlConfig`, strict `EnvVars`, dotenv hydration/loading, placeholder rejection, and `techvault_wazuh_environment()` remain unchanged. No environment variable, config field, operator-supplied regex/path/command, or duplicate validator is justified. |
| Readiness and TLS | `await_declared_listeners()`, `_compose_stateful_readiness`, `ReadinessPolling`, `probe_manager_api()`, `WazuhApiProbe`, and `curl_safe` retain transport/authentication/token/status semantics. The existing Wazuh-only TLS policy and loopback publication do not change. |
| Errors and public projections | `LabResult`, `StartupDiagnostic`, RAES diagnostics, CLI/API projections, and web authentication/error envelopes remain unchanged. A recovery observation is internal safe logging, not a new readiness outcome or public DTO. |
| Persistence and runtime identity | Existing workspace/resource receipts, generated Compose readback, retained-volume identity, manager container, and seat overlay remain authoritative. The static `docker-compose.yml` API volume does not authorize a generated-path volume injection. |
| Verification workflow | Focused pytest coverage belongs with the existing TechVault retry contracts in `tests/test_lab.py`; `bash tools/run-targeted-tests.sh` and staged `pre-commit run` are the local gates. Hosted CI owns full suites and clean-lab lifecycle verification. |

The APTL web authentication surface is a no-op passage: API token,
Host/Origin/CSRF/session, response-schema, and BFF gates are not edited. Wazuh
manager authentication remains a lab readiness concern and must not be
conflated with control-plane web authentication.

## Regression Contract

Tests must use the reproduced command shape: exit `1`, an optional stopped
daemon, and the exact missing-API line. They must also prove that exit `1` with
only an optional daemon stopped does not repair; exit `0` with a running API
does not repair; exit `0` with contradictory stopped output and exit `2` with
plausible text fail closed; missing/empty output, timeout, and exceptions do
not repair; only stdout exact lines are considered; and the capture occurs
before the single start command.

Capture tests must prove source bounds, discard raw log and exec output, retain
only allowlisted scalars, represent absent cgroup/log evidence as unknown,
avoid secrets in logs and failures, and allow readiness to fail after an
apparently successful repair. Lifecycle coverage must continue proving the
same backend/container, no Compose teardown, no volume removal, and only one
admitted-plan retry.

## Extensibility Seam

The seam is a private, exact-pack-selected status classifier and evidence
normalizer whose inputs are the completed status result, bounded log bytes,
safe inspect fields, and explicit limits. A future qualified Wazuh release may
supply different accepted exit codes, exact status lines, log markers, or
limits behind its new `PackIdentity` without changing core retry, readiness,
backend, persistence, or public schemas. Bounds and timeouts stay explicit
constants/arguments, not hidden defaults or user-controlled commands.

## Gotchas And Anti-Patterns

- Do not write `returncode == 0` as a generic guard for `status`, and do not
  authorize recovery from exit `1` without the exact API line.
- Do not weaken the predicate to substring, regex-only, stderr, a process-count
  delta, open port, Docker health, HTTP 401, or an English readiness error.
- Do not describe missing container OOM evidence as proof that the child was
  not signaled or killed, and do not label the last API phase as the cause.
- Do not log/persist a tail and rely on `redact()` to make arbitrary workload
  text safe. Normalize first; redact safe structure again at the boundary.
- Do not place raw evidence in `LabResult`, `StartupDiagnostic`, RAES
  diagnostics, snapshots, run archives, telemetry spans, API responses, or
  GitHub artifacts.
- Do not add a second Wazuh readiness probe, retry loop, timeout budget,
  exception family, config schema, status DTO, or evidence repository.
- Do not patch static or generated Compose, add the missing API volume, alter
  certificates, or change the image/pack from correlation alone.
- Do not use `lab start --clean`, `stop -v`, container/volume replacement, or
  seat reprovisioning to reproduce or repair this issue.

## Non-Goals And Boundaries

- This issue does not claim an upstream Wazuh root cause without new correlated
  evidence; it fixes the proven status-contract defect and preserves the facts
  needed to classify a recurrence.
- It does not redesign Wazuh supervision, certificates, RBAC, cgroups, health
  checks, authenticated readiness, generic lifecycle retry, scenario hooks,
  stateful-resource schemas, or evidence/run-storage architecture.
- It does not add operator-configurable recovery, broad process monitoring,
  raw forensic retention, new public diagnostics, or a general daemon-status
  parser.
- It does not mutate or interrogate live participant seats for development.
  Reproduction remains limited to source, retained notes, and disposable
  environments using the qualified image/pack identity.
