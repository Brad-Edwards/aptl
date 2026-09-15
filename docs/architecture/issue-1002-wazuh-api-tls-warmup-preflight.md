# Issue #1002 Wazuh API TLS Warm-Up Preflight

This note fixes the architecture boundary for issue #1002. It is guidance, not
an implementation plan, and it does not change startup behavior. No new ADR is
needed: ADR-029 owns secret-safe process and diagnostic handling, ADR-030 owns
startup/readiness outcomes, ADR-031 owns contract and validation reuse, ADR-034
owns the Wazuh-specific TLS exception, and ADR-046 owns authenticated readiness
as part of realized deployment state.

## Findings And Decisions

The repository evidence proves an ordering and classification gap, but it does
not prove a specific Wazuh-internal root cause:

- `check_manager_api_ready()` attempts authenticated JSON exchange as its first
  API-listener observation. `curl_json()` logs every non-zero curl exit as a
  warning and then reduces transport, HTTP, and JSON failures to `None`.
- `wait_for_realized_health()` treats a running container without a health
  status as settled. The checked-in `docker-compose.yml` has a Wazuh health
  check, but generated env-pack Compose need not have one. Changing only the
  static Compose health check therefore cannot fix the default realization
  path.
- The probe uses curl's insecure TLS mode under ADR-034's existing Wazuh-only
  exception. Exit 35 therefore means the TLS handshake did not complete; it is
  not evidence of a CA-chain or hostname-verification rejection, and it does
  not distinguish listener initialization, reset/reload, or protocol failure.
- `ensure_ssl_certs()` validates generated Wazuh inter-component certificate
  files before startup. That does not establish that the independently managed
  API listener on port 55000 has loaded its runtime TLS configuration. Do not
  conflate certificate-file readiness with API-listener readiness.
- Graph-owned Wazuh services are authenticated in RAES backend post-start and
  are then polled again by the later lab service-readiness step. The two loops
  currently duplicate authentication and do not share a terminal reason.

Keep these states distinct:

| State | Contract |
| --- | --- |
| Workload settled | The backend observes the container as running and, when a health status exists, healthy. This is not API readiness. |
| API transport ready | A credential-free request completes TCP/TLS and receives a syntactically valid HTTP status from the Wazuh API listener. The particular path/method must have a stable unauthenticated contract. |
| Authentication ready | The existing authentication request succeeds and returns the existing, shape-checked non-empty token. |
| Manager semantically ready | The authenticated manager-status response passes its existing mapping/list shape checks. |
| Startup ready | The owning bounded readiness gate succeeds and the remaining startup workflow reaches its normal terminal outcome. |

The following decisions apply:

1. **Gate authentication on transport readiness.** Ordinary listener warm-up is
   observed first with a credential-free, full TLS-and-HTTP exchange. A TCP
   connect alone is too weak, and certificate-file existence is the wrong
   boundary. Authentication may start only after that prerequisite succeeds.
2. **Classify attempts without guessing at root cause.** The canonical
   `curl_safe` boundary needs one normalized, secret-free result seam that can
   preserve curl's numeric exit code and HTTP status while retaining the
   current `curl_json()` / `curl_status()` compatibility contracts for other
   callers. Exit 35 may be named `tls_handshake`; it must not be described as a
   certificate reload, trust failure, or protocol mismatch without correlated
   evidence. Do not parse curl's platform-dependent stderr text.
3. **Put retry logging at the readiness owner.** During the existing bounded
   warm-up window, a classified transport failure is an expected pending state:
   log it at debug or as a rate-bounded/state-transition progress message, not
   as a warning on every poll. Preserve the current default warning behavior
   for one-shot `curl_safe` consumers. Recovery is not proof that every exit 35
   is benign; the same last state at the deadline is a terminal failure.
4. **Preserve a single retry budget.** Reuse the monotonic
   `ReadinessPolling` / `wait_for_service()` timeout and injectable clock/sleep
   seams. Do not add retries inside curl, an unbounded loop, or a second backoff
   budget. The admitted-plan retry remains the outer lifecycle policy.
5. **Fail closed with the last safe phase and reason.** Persistent listener
   TLS failure, authentication rejection, malformed token, or malformed/status
   failure must make the authoritative Wazuh readiness gate fail. Its terminal
   diagnostic names the phase, normalized category, numeric curl or HTTP code
   when available, and elapsed/timeout context. It never contains credentials,
   response bodies, stderr, headers, commands, or token material.
6. **Use one authority per realized service.** RAES backend post-start remains
   the fail-closed owner for graph-owned Wazuh services and records the existing
   boolean `authenticated_readiness` evidence. The later lab step must consume
   or recognize that success rather than re-authenticating. Any supported
   non-RAES/legacy Wazuh path must use the same probe contract and fail startup
   on a persistent TLS/authentication failure; it must not retain a warning-only
   duplicate policy.
7. **Keep normal warm-up out of durable error schemas.** A concise progress
   message may say that the Wazuh API listener is warming up. It is not a
   `StartupDiagnostic`, run-record error, or new public API state. Persist only
   the final boolean readiness evidence and the existing terminal outcome.
8. **Correlate before changing certificate or container policy.** A clean-boot
   investigation may compare bounded phase transitions and numeric curl codes
   with backend-observed container restart state and redacted manager events.
   Do not dump container logs or persist raw observations. Changing certificate
   generation, mounts, Wazuh configuration, or health checks requires evidence
   that the corresponding layer is causal.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Transport and secret handling | `aptl.utils.curl_safe`, its mode-0600 header/body temporary files, list-form subprocess argv, bounded timeout, and `finally` cleanup remain the only host curl boundary. Extend that boundary; do not create a Wazuh subprocess runner or put Basic/Bearer values in a URL, argv, stderr, or log. |
| Service semantics | `check_manager_api_ready()` and the existing authentication/token/`manager/status` shape checks in `aptl.core.services` remain canonical. Keep indexer readiness separate; do not turn one generic HTTP status into proof that both services are semantically ready. |
| Polling | `ReadinessPolling`, `wait_for_service()`, monotonic deadlines, injected clock/sleep, and the existing progress callback own bounded retries and deterministic tests. A single request result is not a `ServiceResult`, and a whole-wait result is not a curl transport result. |
| Deployment ownership | `_compose_post_start`, `wait_for_realized_health()`, `_compose_stateful_readiness`, `DeploymentBackend`, actual published-port inspection, and RAES selected/realized service identity own the graph path. Do not key authority from a scenario name, config feature flag, container-name guess, or hard-coded host port. |
| Configuration and credentials | Strict `AptlConfig` / `ContainerSettings`, `EnvVars`, `hydrate_dotenv()`, `load_dotenv()`, `env_vars_from_dict()`, and placeholder rejection remain the binding and validation chain. This issue needs no new setting or environment variable. |
| Certificates and TLS policy | `ensure_ssl_certs()` and certificate/mount validation remain the generated-file gate. ADR-034's Wazuh-specific insecure probe is isolated from lab-CA SOC clients. Do not weaken verification globally or infer API-listener state from the generated bundle. |
| Lifecycle and errors | `orchestrate_lab_start()`, `_LabStartContext`, `_LAB_START_STEPS`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, `_emit_diagnostic()`, RAES `diagnostic()` / `render_raes_diagnostics()`, and `redact()` remain the only public failure envelope. Do not add a readiness exception hierarchy or expose a transport object through CLI/API/web schemas. |
| Observability and persistence | `get_logger()`, existing progress reporting, `authenticated_readiness`, `RangeSnapshot`, and redacting `LocalRunStore` writers remain canonical. Retain final boolean evidence; do not store tokens, bodies, raw curl output, per-attempt histories, or container logs. |
| Host/runtime topology | Loopback-only Wazuh publication, resolved host ports, backend Docker inspection, static Compose, and generated RAES Compose are all in scope. Generated `.aptl/realization` output is evidence, not a source file to patch. A static-Compose-only fix is incomplete. |
| User-facing projections | CLI rendering, `LabActionResponse`, BFF Host/CSRF/session protections, API-token dependency, SSE projection, and web types continue to project core lifecycle outcomes. No endpoint, response DTO, or frontend-derived readiness state is needed. |
| Verification workflow | Focused service/curl/stateful-readiness pytest suites, repository pytest/pre-commit gates, the Ubuntu clean-install lab boot, and cross-platform Python tests in `.github/workflows/checks.yml` remain authoritative. Docker clean boot is Linux-only today; deterministic readiness tests provide the Linux/macOS coverage required by the issue. |

## Security And Error-Surface Guardrails

- The environment passes through typed `EnvVars`, strict dotenv parsing, and
  placeholder rejection before a credential reaches the probe. A missing or
  placeholder API credential is a configuration failure, not TLS warm-up.
- Basic and Bearer headers remain in permission-restricted temporary files.
  They must not appear in process argv, a query string, Compose health-check
  command text, exception messages, test snapshots, or diagnostic context.
- A normalized transport result contains only bounded fields needed for policy:
  success/category, numeric curl exit code, HTTP status, and optionally the
  stable request phase. It must not retain `CompletedProcess`, URL, stdout,
  stderr, body, header values, or temporary paths.
- Logger messages and both lifecycle error envelopes are redaction boundaries,
  not permission to log a secret and clean it later. Construct diagnostics
  from safe fields, then apply the established redaction helpers before
  rendering or persistence.
- The probe stays on the backend-resolved loopback publication with a bounded
  timeout. No new all-interface bind, remote endpoint, shell command, or raw
  Docker invocation is introduced.
- `-k` is an existing, narrowly scoped Wazuh compatibility policy. This issue
  must neither generalize it to other SOC services nor claim that it validates
  certificate identity. Any future trust-enforcing Wazuh mode belongs behind
  an explicit TLS-policy seam and separate acceptance evidence.

## Extensibility Seam

The seam is a service-level phased readiness probe backed by one canonical,
secret-free `curl_safe` transport outcome. Its endpoint/path and method,
readiness predicate, polling policy, and clock/sleep are injected or passed at
the existing boundaries. That permits a future Wazuh API path/version change or
another authenticated service phase without duplicating curl, credential, or
retry logic.

If clean-boot evidence shows that one successful HTTP exchange can precede a
listener reload, a required-consecutive-success/stability threshold belongs in
the polling policy. Do not hard-code such a threshold without that evidence,
and do not make it a user-facing config knob for this issue.

## Regression Contract

Deterministic tests must distinguish at least these cases without depending on
real-time sleeps or platform-specific curl text:

- exit 35 during the transport phase followed by HTTP, authentication, and
  manager-status success: startup readiness succeeds and emits no warning for
  each warm-up attempt;
- exit 35 until the monotonic deadline: readiness fails with a bounded,
  actionable `tls_handshake` terminal reason;
- transport success followed by authentication rejection, malformed token, or
  invalid manager-status shape: failure remains attributed to the correct
  non-transport phase;
- secret-bearing headers remain absent from argv, logs, results, and errors,
  and temporary files are removed on every subprocess outcome;
- graph-owned authenticated readiness is not probed a second time by the lab
  layer, while any supported legacy owner remains fail-closed.

Unit/contract coverage belongs in `tests/test_curl_safe.py`,
`tests/test_services.py`, and
`tests/test_deployment_stateful_realization.py`, with lifecycle ownership
coverage in `tests/test_lab.py` only where needed. The existing clean-install
boot job supplies Linux integration evidence; ordinary test jobs exercise the
deterministic contract on Linux and macOS.

## Gotchas And Anti-Patterns

- Do not globally suppress curl exit 35. Outside an active bounded readiness
  window it is a real transport error, and at the deadline it is fatal.
- Do not classify all `None` results as TLS warm-up. Current `curl_json()` also
  uses `None` for HTTP errors, invalid JSON, timeouts, and execution failures.
- Do not parse curl/OpenSSL/Secure Transport stderr. Numeric curl result codes
  and HTTP status are the portable diagnostic surface.
- Do not use `sleep()` in a request helper, stack request retries beneath the
  readiness loop, reset the deadline on phase changes, or repeatedly recheck a
  service after it is proven ready.
- Do not make Docker `running`, optional image health, open TCP, a 2xx/401 HTTP
  response, successful authentication, and valid manager status synonyms.
- Do not solve only `docker-compose.yml`; generated env-pack Compose is the
  normal path and may expose no health status. Do not edit generated
  `.aptl/realization` files.
- Do not duplicate env parsing, credential shape checks, token validation,
  result DTOs, exception hierarchies, retry loops, or CLI/API error rendering.
- Do not persist transient attempt history or raw Wazuh logs merely to make the
  intermittent issue diagnosable. Safe phase/code transitions are sufficient
  for regression and terminal diagnosis.
- Do not convert normal warm-up into degraded startup, and do not convert a
  persistent TLS/authentication failure into a non-fatal telemetry warning.

## Non-Goals And Boundaries

- This preflight does not assert whether Wazuh reloads a certificate, restarts
  its API process, or negotiates a particular TLS protocol during clean boot.
- It does not replace Wazuh certificates, alter the API's TLS policy, change
  credentials, expose port 55000 beyond loopback, or modify upstream images or
  environment packs without causal evidence.
- It does not redesign generic service readiness, add a general HTTP client,
  add public API/web schemas, add telemetry storage, or change unrelated MISP,
  TheHive, Shuffle, collector, or indexer probe behavior.
- It does not remove bounded retries or the outer admitted-plan recovery
  policy. It only requires one authoritative, phase-aware, fail-closed Wazuh
  readiness decision per realized service.
