# Issue #1188 Wazuh API Cold-Boot Preflight

This note fixes the architecture boundary for issue #1188. It is guidance, not
an implementation plan, and it does not change runtime behavior. No ADR is
needed: ADR-029 owns secret-safe process and diagnostic handling, ADR-030 owns
startup outcomes, ADR-046 owns realized-state observation, issue #980's
preflight owns pack-specific lifecycle hooks, and issue #1002's preflight owns
the phased, fail-closed Wazuh readiness contract.

## Repository Findings And Causal Standard

The current repository proves a recovery gap and shows one persistence
difference that warrants recording:

- Static `docker-compose.yml` retains `/var/ossec/api/configuration` in the
  `wazuh_api_configuration` volume. The acquired TechVault 0.1.0 pack from
  `raes-env-packs==6.1.0` declares retained manager volumes only for
  `/var/ossec/etc` and `/var/ossec/logs`; its manager has no `runtime.mounts` and
  declares no persistent-volume consumer for `/var/ossec/api/configuration`.
- This difference reaches the runtime unchanged by design.
  `raes_stateful_realization` lowers only authored persistent-volume resources,
  and `_compose_stateful_model` emits and validates only those mounts. The
  backend deliberately does not inject Wazuh volumes in
  `_compose_stateful_services`.
- `TechVaultStartupProvider.before_backend_retry()` already owns the exact-pack
  Wazuh repair boundary. It restarts a running manager only when *no* Wazuh
  daemons exist. A running manager with other daemons but no `wazuh-apid` is
  intentionally outside that predicate. Core then correctly fails the declared
  listener and authenticated manager readiness gates.

These facts establish the recovery gap and a persistence difference. They do
not, by themselves, prove that the difference or certificate generation causes
`wazuh-apid` to exit.
The implementation may claim that cause only from a repeatable cold-start
comparison which correlates all of the following without exposing secrets:

- the effective mount at `/var/ossec/api/configuration` and the retained Docker
  volume identity;
- whether API TLS material was absent, generated, or reused;
- the exact presence/absence of `wazuh-apid` while the container and other
  Wazuh daemons remain running;
- bounded API-log phase markers through certificate generation and RBAC
  integrity checking;
- the credential-free HTTP/TLS transport result and the later authenticated
  manager result; and
- container restart count plus cgroup OOM/OOM-kill counters.

A successful manual `wazuh-control start` is recovery evidence, not proof of
the initiating cause. Likewise, curl exit 35 proves an incomplete TLS exchange,
not that certificate generation, trust, OOM, or a particular TLS library was at
fault. Preserve that distinction in code, tests, logs, and the final issue
record.

## Architecture Decisions

1. **The pack owns any justified manager API state persistence.** A disposable
   Wazuh 4.12.0 manager with a new API certificate and no retained API
   configuration mount started its API successfully. Missing persistence and
   certificate generation alone are therefore insufficient to reproduce the
   exit seen in the seats. If later controlled reproduction confirms the mount
   is causal, the TechVault environment pack must
   declare a `retain`, single-writer persistent volume consumed by the Wazuh
   manager at `/var/ossec/api/configuration`. APTL consumes the new exact pack
   identity through its existing stateful-resource pipeline. Do not inject the
   volume from `aptl_techvault`, a Compose service policy, a generated
   `runtime.mount`, or a Wazuh special case in core. Static Compose is already
   correct and is not the generated-path authority.
2. **Recovery remains exact-pack lifecycle behavior.** Extend the existing
   TechVault `BEFORE_BACKEND_RETRY` behavior for the observed partial state:
   the receipt-resolved manager container is running, `wazuh-apid` is absent,
   and other Wazuh daemons may remain alive. The recovery action is the fixed,
   bounded in-container `/var/ossec/bin/wazuh-control start` invocation that
   recovered both seats. Preserve the existing zero-daemon container-restart
   branch for issue #732; do not collapse the two predicates or replace both
   with unconditional restart.
3. **Core keeps the one retry budget.** `_apply_with_backend_retry()` remains
   the only retry owner: one admitted-plan retry, the existing delay, the same
   backend, and the same admitted `PackIdentity`. The hook contains no sleep,
   polling loop, recursive Compose call, re-planning, volume cleanup, or second
   retry. A repair command completing successfully is not readiness.
4. **Readiness remains fail-closed and semantic.** The second apply must still
   pass declared listener observation and `_compose_stateful_readiness`'s
   credential-free transport, API authentication, token shape, manager-status
   shape, and declared-component attestation. Container running, process
   presence, an open TCP port, HTTP 401, or a successful control command are
   intermediate facts only.
5. **Recovery preserves runtime identity and data.** Neither automated repair
   nor live-seat intervention may use `lab start --clean`, `stop -v`, volume
   removal, VM disk replacement, overlay replacement, container replacement,
   or a fresh Compose project. Reuse the existing workspace/daemon receipts,
   manager container, retained volumes, and seat overlay. The existing failed
   Compose-up rollback rule (`remove_volumes=False`) remains mandatory.
6. **Transient evidence stays bounded.** Record safe phase/category/action
   facts and final readiness, not raw container logs, API bodies, headers,
   credentials, private keys, complete process listings, or per-poll history.
   Do not turn an expected first-start repair into a public DTO or durable error
   schema.

## Required Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Pack acquisition and identity | `env_pack_bundle()`, env-pack manifest validation, `ScenarioBundle`, exact `PackIdentity`, and the installed provider selectors remain authoritative. A pack bump updates the dependency lock and every exact version/digest qualification atomically; do not add a third release-identity table or accept a version wildcard. |
| Stateful schema and validation | If future evidence warrants API configuration persistence, RAES persistent-volume schema, `realize_stateful_resources()`, `_persistent_volume()`, consumer resolution, lifecycle/access enums, destination-conflict checks, `stateful_realization_errors()`, and effective Compose readback own that mount. The API configuration is data state, not a generated certificate artifact or node-local `runtime.mounts`. |
| Compose persistence and ownership | `stateful_override_payload()`, `_append_volume_mounts()`, retained-volume labels, effective volume identity checks, `WorkspaceOwnership`/`ResourceReceipt`, and project-scoped volume names remain canonical if persistence is later justified. This recovery must preserve the existing container and retained volumes across the failed attempt and successful retry. |
| Pack-specific lifecycle | `TechVaultStartupProvider.before_backend_retry()`, `StartupHook.BEFORE_BACKEND_RETRY`, `StartupHookContext`, `_prepare_raes_backend_retry()`, and `_apply_with_backend_retry()` are the existing boundary. Use `DeploymentBackend.container_inspect()` / `container_exec()` / `container_restart()`; do not add a core Wazuh branch, arbitrary hook stage, raw Docker subprocess, or generic repair-command schema. |
| Listener and authenticated readiness | `await_declared_listeners()`, `ReadinessPolling`, `probe_manager_api()`, `WazuhApiProbe`, `curl_request()`, `_compose_stateful_readiness`, and declared Wazuh attestation remain the only success path. The issue changes neither timeout authority nor the meaning of `authenticated_readiness`. |
| Credentials and config shape | `hydrate_dotenv()`, `load_dotenv()`, strict `EnvVars`, placeholder rejection, `techvault_wazuh_environment()`, and exact fixture validation remain unchanged. Recovery requires no credential, environment key, `AptlConfig` field, or user-configurable command. |
| Secret transport and TLS | `curl_safe`'s mode-0600 header files, list-form argv, bounded timeout, cleanup, and ADR-034's Wazuh-only insecure probe remain canonical. API TLS private material stays inside the manager container's API configuration path; it is never copied into logs, run evidence, host argv, Compose healthchecks, or pack content. |
| OS/backend exposure | Recovery uses a fixed list-form in-container command with a timeout and a receipt-resolved semantic container. It adds no shell interpolation, host bind, capability, socket, network attachment, published port, or all-interface exposure; port 55000 remains loopback-published on the host. |
| Errors and observability | `get_logger()`, `redact()`, RAES `Diagnostic`, `LabResult`, `StartupDiagnostic`, and issue #1002's secret-free phase/category/code summaries remain the envelopes. Log that a bounded repair was attempted and its safe result; never log exec stdout/stderr or API/certificate material. Hook/probe uncertainty must not be represented as success. |
| Seat lifecycle | Appliance first boot, lifecycle locks, the admitted run, terminal container attestation, seat overlay persistence, and existing hosted-seat verification surfaces stay in force. Live intervention is in-place recovery plus read-only verification, not reprovisioning. |
| Verification workflow | Target the pack-contract, stateful-model, exact adapter-hook, backend-retry, phased-readiness, ownership/rollback, and seat smoke suites. Repository policy keeps local runs targeted and leaves clean full-lab lifecycle coverage to CI/CD. |

The web/API authentication layer is a no-op passage for this issue: no route or
response model changes. Existing API-token, Host/Origin/CSRF/session, and BFF
gates remain untouched. The Wazuh API authentication described above is a lab
service readiness boundary, not APTL web authentication; do not conflate them.

## Regression And Live-Evidence Contract

Coverage for the observed process failure must distinguish these states
without treating a mocked successful command as a ready service:

- the current pack does not mount `/var/ossec/api/configuration`; a disposable
  first start with new API TLS material nevertheless reaches a listening API,
  so that omission is not treated as the proven cause of this process exit;
- a running manager with `wazuh-apid` present performs no repair;
- a running manager with other Wazuh daemons present but no `wazuh-apid`
  invokes `wazuh-control start` once, through the backend, before the sole
  admitted-plan retry;
- the prior zero-daemon state still uses its existing one-time container
  restart, while stopped, unknown, failed-probe, and foreign-container states
  cause no guessed mutation;
- recovery-command failure or an API that remains absent/auth-rejecting still
  fails the listener/authenticated-readiness path;
- failed first apply plus successful retry uses the same backend and existing
  container and never requests volume deletion or Compose teardown.

If a future controlled reproduction proves API configuration persistence is
needed, its separate pack release must test the exact retained mount and TLS
reuse across cold restart. Those tests are not a gate for this recovery fix.

The live-seat record for both `heron1` and `heron2` identifies their preserved
VM overlays and running Compose workspaces after the in-place intervention.
There is no pre-intervention byte-for-byte baseline, so it does not claim one.
The record must include the completed seat readiness result, active Wazuh
agents, indexer and dashboard reachability, and manager API request success.
HTTP 401 at the unauthenticated manager root is transport evidence, not an
authenticated manager-ready verdict.

## Extensibility Seam

The extension seam for this fix is the existing exact `PackIdentity`-selected
TechVault startup provider. Keep the
release-local recovery inputs explicit and non-secret: semantic manager
container, exact API process name, fixed control argv, and timeout. A future
pack/Wazuh release can change those inputs behind a newly qualified pack
identity without changing core retry, readiness, stateful schemas, or adding a
user-supplied command. Additional durable Wazuh state is expressed as more
authored persistent-volume consumers through the same RAES contract.

## Gotchas And Anti-Patterns

- Do not claim the missing mount caused the exit merely because both were
  observed. Prove first-start generation, process loss, recovery, and retained
  reuse as one controlled comparison.
- Do not patch generated `.aptl/realization` Compose files or the existing seat
  containers. They are outputs/evidence, not source authority.
- Do not add the volume through `compose_service_policy()`. That policy aliases
  author-owned files to image-native paths; it is not a hidden persistence
  schema and must not override the pack's deliberately closed mount scope.
- Do not generalize Wazuh recovery into core, a generic command hook, or an
  exception hierarchy. The exact content-qualified adapter already owns it.
- Do not restart a healthy API, restart the whole container for an API-only
  absence, or run `wazuh-control start` on every boot. Predicate the narrow
  observed state and preserve issue #732's separate zero-daemon behavior.
- Do not move retry into `curl_safe`, listener polling, the provider, or the
  control command. Nested retries hide the admitted-plan retry count and can
  multiply mutation.
- Do not weaken TLS/authentication, accept container health as API health, or
  turn persistent failure into degraded/telemetry-only startup.
- Do not delete or rename existing manager/indexer/dashboard or seat volumes to
  make a test pass. Test preservation positively with identities and markers.
- Do not expose private keys, credentials, response bodies, raw API logs, exec
  output, or secret-bearing exception text in diagnostics or evidence.
- Do not update only `pyproject.toml`/`uv.lock`: exact pack digest gates in the
  TechVault startup, runtime-parameter, capture, build-cache, planning, and
  verifier surfaces must continue to agree with the acquired bytes.

## Non-Goals And Boundaries

- This issue does not redesign Wazuh certificates, rotate credentials, enforce
  CA verification for the existing Wazuh compatibility probe, or change API
  exposure.
- It does not redesign generic readiness, listener discovery, RAES stateful
  resources, provider discovery, Compose ownership, retry policy, or seat
  provisioning.
- It does not make every `/var/ossec` subdirectory persistent by inference.
  Only authored, causally justified state belongs in the pack contract.
- It does not reset or replace live-seat disks, lab volumes, overlays, Compose
  projects, or unrelated Wazuh data.
- It does not add web/API DTOs, settings, environment variables, metrics
  storage, or operator-selectable recovery commands.
- It does not present the recovery hook as proof that API configuration is
  persistent or that certificate generation caused this exit. The hook is the
  APTL fix for the proven unhandled API-only process failure.
