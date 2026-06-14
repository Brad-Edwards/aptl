# ADR-039: Web Control Plane Authentication and Loopback Exposure

## Status

accepted

## Date

2026-06-14

## Context

The optional web profile adds an operator-facing FastAPI control plane and
terminal relay on top of the same lab lifecycle code used by the CLI. That API
can start, stop, inspect, and kill the lab, and the API container intentionally
mounts the host Docker socket so it can drive Docker Compose. This is not a
deliberately vulnerable target service; it is a control plane with
host-equivalent Docker reach.

Existing boundaries already own parts of the design:

- `src/aptl/api/main.py` owns FastAPI application assembly, CORS, mounted
  routers, and `/api/health`.
- `src/aptl/api/deps.py` owns API-wide dependencies and environment-derived
  API constants such as allowed origins and project directory resolution.
- `src/aptl/api/schemas.py` owns Pydantic response shapes projected from core
  models; web types mirror those wire shapes.
- `src/aptl/core/config.py` and ADR-025 own durable, non-secret first-party
  configuration in `aptl.json`.
- `src/aptl/core/env.py`, `src/aptl/utils/placeholders.py`, and the
  `ServiceConfig.from_env()` pattern in
  `src/aptl/services/misp_suricata_sync/config.py` own parse-then-validate
  environment binding for runtime service settings.
- `src/aptl/utils/redaction.py` and ADR-029 own control-plane secret handling
  before values cross logs, API responses, CLI output, telemetry, or persisted
  artifacts.
- `src/aptl/core/deployment/` and ADR-023/ADR-037 own Docker and Docker Compose
  access through typed backend methods, not generic command passthroughs.

CORS and the existing WebSocket `Origin` allow-list are browser controls. They
do not authenticate non-browser clients, local processes, LAN peers, or forged
WebSocket handshakes.

## Decision

The web control plane must be protected by two independent defaults:

1. **Loopback exposure by default.** The API and UI host publishes must bind to
   `127.0.0.1` by default in Docker Compose, and host-run API serving must keep
   `127.0.0.1` as its default bind address. Any non-loopback exposure is an
   explicit operator risk decision, not the default profile behavior.
2. **Authentication on the whole API surface.** Every HTTP request under
   `/api`, including `/api/health`, SSE endpoints, and state-changing routes,
   requires the web control-plane token before route logic runs. The terminal
   WebSocket requires the same token before `accept()`. Unknown `/api/*` paths
   should not become an unauthenticated route-enumeration side channel; an
   unauthenticated caller should see the auth failure before any route-specific
   result.

The token is a control-plane/operator secret under ADR-029. It belongs in
runtime environment binding, not in `aptl.json`, checked-in config, generated
client bundles, URL examples, logs, or command-line arguments. The auth settings
shape should follow the existing strict env-to-Pydantic pattern used by
`ServiceConfig.from_env()`: parse once, validate once, reject missing or
placeholder-like values with name-attributed errors, and expose a narrow typed
object to the API layer.

HTTP and WebSocket enforcement must share one canonical auth helper in the API
boundary, preferably `aptl.api.deps`. That helper owns token extraction,
constant-time comparison, and safe error construction. Do not copy bearer
parsing into individual routers, and do not create a second exception
hierarchy or response schema for auth failures. HTTP failures use FastAPI's
existing `401` error envelope with a narrow `WWW-Authenticate: Bearer` header;
WebSocket failures close with policy violation before the SSH relay is opened.

Bearer authorization headers are the primary HTTP carrier. Browser constraints
must not weaken the design:

- Native `EventSource` cannot set an `Authorization` header, so SSE must use a
  header-capable client path such as fetch streaming, a small EventSource
  replacement, or a same-origin server-side proxy. Do not put the token in the
  event-stream URL.
- Browser WebSocket constructors cannot set arbitrary headers, so the terminal
  path needs a non-URL carrier such as an authenticated same-origin proxy or a
  validated `Sec-WebSocket-Protocol` token convention. `Origin` remains a CSWSH
  defense only, not an auth credential.
- If a future design uses cookies instead of bearer headers, it must add an
  explicit CSRF design and revisit CORS credentials. Do not silently flip
  `allow_credentials=True`.

CORS remains an allow-list convenience for browser calls. It is not an
authorization layer. If bearer headers are used, `Authorization` is an allowed
header; wildcard origins remain out of scope for the operator control plane.

The Docker socket mount remains high risk even after auth and loopback binding.
This ADR does not make raw Docker control safe for arbitrary API expansion.
Future socket reduction should use a least-privilege socket proxy or typed
`DeploymentBackend` operations. Do not add generic "run docker args" endpoints.

## Security Layers

| Layer | Requirement |
| --- | --- |
| Auth surface | A single API auth boundary covers HTTP `/api/*`, `/api/health`, SSE, and the terminal WebSocket before router/core logic runs. |
| Secret handling | The token is an ADR-029 control-plane secret. Logs, exceptions, API error text, telemetry, snapshots, and docs examples must never include its value. Use `redact()` before any auth-bearing text crosses a boundary. |
| Env binding | Token settings are runtime environment settings validated through one strict parser. Reuse `contains_placeholder()` semantics; do not store the token in `AptlConfig` or overload `EnvVars` with unrelated web auth state. |
| OS/process exposure | Pass the token through environment or server-side state, not process argv, URL query strings, command strings, or access-log-visible paths. |
| Network exposure | Docker Compose port publishes and host-run serving default to loopback. Non-loopback exposure is explicit and documented. |
| Browser carrier | REST and SSE keep token-bearing auth out of URLs; WebSocket auth uses a non-URL carrier or authenticated proxy. `Origin` and CORS remain browser defenses only. |
| Error envelope | HTTP returns a narrow 401 envelope; WebSocket closes with policy violation. Neither path reports whether the token was missing, malformed, or wrong beyond the generic auth failure. |
| Docker boundary | API routes still delegate lab work to existing core services and `DeploymentBackend`; auth does not justify new raw Docker/socket passthroughs. |

## Extensibility

The extensibility seam is a small, typed web-auth settings and carrier parser at
the API boundary. Future changes such as token rotation, a socket proxy, a
same-origin UI proxy, or a different credential carrier should replace that
boundary without editing every router.

The network-exposure seam is the bind host in deployment and serving
configuration, with `127.0.0.1` as the default. A future documented remote UI
mode may parameterize that value, but it must not scatter `0.0.0.0` literals
across Dockerfiles, Compose services, tests, and docs.

## Non-Goals

- Do not implement multi-user accounts, RBAC, OAuth/OIDC, sessions, password
  login, or long-lived browser identity.
- Do not redesign the SvelteKit application architecture or resurrect removed
  scenario API routes as part of auth hardening.
- Do not remove the Docker socket mount in this issue; treat a socket proxy as a
  follow-up hardening track.
- Do not move web auth secrets into `aptl.json`, checked-in config, or generated
  source-owned files.
- Do not redesign `DeploymentBackend`, lab lifecycle result DTOs, API response
  schemas, or redaction policy.

## Anti-Patterns

- Treating CORS, allowed origins, loopback binding, or "local lab" comments as
  authentication.
- Adding per-router auth snippets instead of one canonical API auth boundary.
- Leaving `/api/health`, SSE, WebSocket, or unknown `/api/*` paths outside the
  auth check.
- Passing tokens in query strings, WebSocket URLs, curl examples, process argv,
  logs, exception details, OpenAPI examples, or access-log-visible paths.
- Hardcoding a default token, accepting empty tokens, or allowing
  `.env.example` placeholder values to start the control plane.
- Reusing the Wazuh-oriented `EnvVars` dataclass as a generic web settings bag.
- Creating new API DTOs, exception hierarchies, validation helpers, or Docker
  command wrappers when existing FastAPI, Pydantic, redaction, and deployment
  boundaries already cover the need.

## References

- [ADR-011](adr-011-web-ui.md): Notebook-style web UI.
- [ADR-023](adr-023-container-interaction-in-deployment-backend.md): typed
  deployment backend methods.
- [ADR-025](adr-025-strict-first-party-config-schema.md): strict first-party
  config schema.
- [ADR-029](adr-029-control-plane-secret-handling.md): control-plane secret
  handling.
- [ADR-037](adr-037-docker-compose-backend-cohesion.md): Docker Compose backend
  cohesion.
- Issue #415: unauthenticated web API on non-loopback publish with Docker socket
  access.
