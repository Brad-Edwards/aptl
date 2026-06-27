# Web GUI Design Preflight Guardrails

## Scope

This note is the architecture preflight for UI-007. It is not the UI-007 design
specification and does not define the final information architecture, route map,
or page wireframes. The UI-007 design specification must derive those details
from the approved UI-006 product scope and must leave a direct handoff target
for UI-008 implementation.

The design work must treat the current Svelte pages as an MVP surface, not as
binding product authority. Existing architecture decisions and code boundaries
remain binding.

## Canonical Incumbents

Use the existing owners below before adding a new schema, helper, exception
type, route contract, or workflow concept.

| Concern | Canonical owner |
| --- | --- |
| Web product paradigm | `docs/adrs/adr-011-web-ui.md` |
| API assembly, CORS, route mounting | `src/aptl/api/main.py` |
| Web auth, auth env binding, project-dir binding | `src/aptl/api/deps.py` |
| API response DTOs | `src/aptl/api/schemas.py` |
| Svelte API fetch boundary and SSE subscription | `web/src/lib/api.ts` |
| Svelte wire-type mirror | `web/src/lib/types.ts` |
| Svelte server-side bearer-token proxy | `web/src/hooks.server.ts` |
| WebSocket terminal token carrier data | `web/src/routes/+layout.server.ts` |
| Lab lifecycle and startup diagnostics | `src/aptl/core/lab.py`, `src/aptl/core/lab_types.py`, ADR-030 |
| Endpoint display and terminal target metadata | `src/aptl/core/endpoints.py`, ADR-036, ADR-040 |
| Docker and Docker Compose access | `src/aptl/core/deployment/`, ADR-023, ADR-037 |
| Durable first-party config | `src/aptl/core/config.py`, ADR-025 |
| Runtime environment and placeholder checks | `src/aptl/core/env.py`, `src/aptl/utils/placeholders.py`, `WebAuthSettings.from_env()` |
| Secret redaction and serialization safety | `src/aptl/utils/redaction.py`, `mcp/aptl-mcp-common/src/redaction.ts`, ADR-029 |
| Scenario catalog and SDL validation | `src/aptl/core/scenario_catalog.py`, ACES parser authority, ADR-035 |
| Logging | `src/aptl/utils/logging.py` and module-local `get_logger(...)` |
| Run artifact persistence | `src/aptl/core/runstore.py` |
| Web component inventory | `web/src/lib/components/` and `web/src/lib/components/workbench/` |
| Web tests | `web/tests/**` with `npm test` / `vitest run` |
| Python API and core tests | `tests/test_api_*.py`, `tests/test_endpoints.py`, `pytest` |
| Completion gate | `.ground-control.yaml`, `.gc/plan-rules.md`, `pre-commit run --all-files` |

## Security Layers

The design specification must name how each in-scope page passes these layers.

| Layer | Required fit |
| --- | --- |
| Auth surface | All `/api/*` HTTP and SSE traffic stays behind `verify_token` through `src/aptl/api/main.py`. Browser REST/SSE calls go through the SvelteKit proxy in `web/src/hooks.server.ts`; the browser must not place the API token in fetch headers or URLs. |
| WebSocket terminal auth | Terminal access uses ADR-039's `Sec-WebSocket-Protocol` token convention from `web/src/routes/+layout.server.ts` and `verify_ws_token(...)`. `Origin` remains an extra browser defense, not a credential. |
| Secret handling | API tokens, cookies, private keys, generated config secrets, and replayable session identifiers remain ADR-029 control-plane secrets. Designs must not show secret values in examples, error states, logs, screenshots, run artifacts, OpenAPI examples, or route URLs. |
| Env binding | Web control-plane settings stay runtime-env owned. `APTL_API_TOKEN`, `APTL_API_URL`, `APTL_API_HOST`, and `APTL_ALLOWED_ORIGINS` are not `aptl.json` fields. Durable non-secret config goes through `AptlConfig`. |
| Config validation | Any first-party config surfaced in the UI must come from `load_config()` / `AptlConfig` projections. Unknown first-party fields are errors under ADR-025; do not add pass-through config dictionaries for UI convenience. |
| OS/process exposure | Tokens, passwords, cookies, private keys, and generated secret content must not appear in process argv, query strings, shell strings, access-log-visible paths, or terminal prefill text. Docker actions stay typed backend calls, not raw command submission. |
| Error envelopes | HTTP auth failures use the generic FastAPI `401` envelope with `WWW-Authenticate: Bearer`; proxy errors stay narrow; terminal errors use the existing WebSocket error message shape; lab actions use `LabActionResponse`. |
| Terminal trust | Interactive terminals must satisfy ADR-040: container allow-list, lab-running check, endpoint projection from `ENDPOINT_REGISTRY`, and pinned `known_hosts` before `asyncssh.connect`. |
| Redaction and observability | Logs may name route, component, step, and validation layer, but not secret values or raw secret-bearing payloads. New persistence or export paths must use the existing redaction/runstore boundaries. |
| Network exposure | The default operator web surface remains loopback-bound per ADR-039. Any non-loopback design must be explicit about the operator risk decision and must not rely on CORS as authorization. |

## Design Guardrails

- Distinguish human-investigation surfaces from read-only status surfaces in
  the spec. Terminals, SIEM exploration, command execution, lab start/stop, and
  kill flows are control or investigation surfaces; lab status badges,
  container summaries, startup diagnostics, and config summaries are read-only
  status surfaces unless the page explicitly defines a mutation.
- Keep the ADR-011 notebook/workbench paradigm. Do not drift into an enterprise
  SOC dashboard: no mission-control tile wall, icon-only sidebar, status-dot
  matrix, or dense product-console chrome.
- Reuse the current component families before inventing new ones:
  `NavBar`, `LabStatusBadge`, `ContainerGrid`, `LabStartNotice`, `Terminal`,
  and workbench blocks. If a new recurring UI primitive is needed, document
  which existing component pattern it extends.
- Keep API DTOs server-owned. Add or change Python response models in
  `src/aptl/api/schemas.py` first, then mirror the stable wire shape in
  `web/src/lib/types.ts`; do not let the Svelte layer infer core state from
  English messages.
- Treat startup state as ADR-030 structured data. Do not collapse
  `ready`, `degraded_usable`, `degraded_unusable`, and `failed` into a single
  boolean or a color-only badge.
- Treat endpoint metadata as display and reachability projection only.
  `ENDPOINT_REGISTRY` does not authorize terminal access and does not own
  host-published ports or credentials.
- Treat ACES SDL and `scenario_catalog.py` as scenario authority. The legacy
  `/api/scenarios` endpoints are intentionally absent today; a design that
  includes scenario browsing must define a new canonical API projection instead
  of resurrecting the removed in-tree scenario schema by accident.
- Keep page-local logic thin. Shared fetch behavior belongs in
  `web/src/lib/api.ts`, shared lab status in `web/src/lib/stores/lab.ts`, and
  scenario workbench shaping in `web/src/lib/workbench.ts`.

## Extensibility Seams

The design specification should include a compact page contract table for each
route. Each row should state:

- route path and page purpose;
- surface class: read-only status, human investigation, control action, or
  terminal;
- API data source and DTO owner;
- mutation capability, if any;
- auth carrier: proxy HTTP/SSE or terminal WebSocket subprotocol;
- primary component family; and
- future variation parameter.

Use existing extension points for obvious follow-up changes:

- new lifecycle or startup fields extend `LabResult` / `LabActionResponse`;
- new endpoint display data extends `ENDPOINT_REGISTRY` by target port and
  protocol, not host port;
- new workbench content extends the `WorkbenchBlock` discriminated union and
  block renderer;
- new scenario browsing data uses a narrow ACES/catalog projection rather than
  a local scenario parser; and
- new runtime web settings extend the typed env settings boundary, not
  `aptl.json`.

## Anti-Patterns

- Treating CORS, loopback binding, allowed origins, or "local lab" as
  authentication.
- Putting bearer tokens in URLs, WebSocket URLs, browser-visible examples,
  shell snippets, process argv, logs, screenshots, or stored design fixtures.
- Adding per-router auth snippets, duplicate bearer parsing, a new auth error
  schema, or a second web-auth settings object.
- Creating a duplicate route map in Svelte that disagrees with mounted FastAPI
  routers or tests.
- Reintroducing removed `/api/scenarios` behavior without an explicit ACES
  projection contract.
- Parsing `docker-compose.yml` from a UI route or Svelte page to discover
  containers, ports, or terminal targets.
- Mixing target fixture credentials with control-plane/operator secrets.
- Adding UI-only booleans that reclassify startup readiness, terminal
  availability, or degraded SOC telemetry.
- Building a generic "run Docker command" or "run shell command" web endpoint.
- Persisting user-entered commands, terminal output, API errors, or
  investigation notes without a redaction and artifact-boundary design.

## Non-Goals

- Do not implement UI-007 or UI-008 in this preflight.
- Do not choose the final UI-007 route map, wireframes, or per-page copy here.
- Do not add multi-user accounts, RBAC, OAuth/OIDC, password login, or browser
  sessions.
- Do not redesign the deployment backend, Docker socket model, ACES SDL,
  scenario startup, run archive layout, or endpoint registry.
- Do not make the web GUI the source of truth for lab topology, scenario
  semantics, credentials, or startup readiness.
- Do not widen the current web control plane beyond the approved UI-006 scope.
