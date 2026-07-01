# Web GUI Design Preflight Guardrails

## Scope

This note is the architecture preflight for UI-007 and the binding guardrail
set for UI-008 implementation slices. It is not the UI-007 design
specification and does not define the final information architecture, route
map, or page wireframes. The UI-007 design specification must derive those
details from the approved UI-006 product scope and must leave a direct handoff
target for UI-008 implementation.

The design work must treat the current Svelte pages as an MVP surface, not as
binding product authority. Existing architecture decisions and code boundaries
remain binding.

## Canonical Incumbents

Use the existing owners below before adding a new schema, helper, exception
type, route contract, or workflow concept.

| Concern | Canonical owner |
| --- | --- |
| Web product paradigm | `docs/adrs/adr-011-web-ui.md` |
| API assembly, CORS, route mounting, and shipped asset mounting | `src/aptl/api/main.py` |
| Web auth, auth env binding, project-dir binding | `src/aptl/api/deps.py` |
| API response DTOs | `src/aptl/api/schemas.py` |
| Svelte API fetch boundary and SSE subscription | `web/src/lib/api.ts` |
| Svelte wire-type mirror | `web/src/lib/types.ts` |
| Legacy split-profile Svelte server-side bearer-token proxy | `web/src/hooks.server.ts` |
| Legacy split-profile WebSocket token carrier data | `web/src/routes/+layout.server.ts` |
| `aptl web serve` bind/runtime contract | `src/aptl/cli/web.py` |
| Split web Compose profile | `docker-compose.yml` services `aptl-web-api` and `aptl-web-ui` |
| Web build artifact contract | `web/package.json`, `web/svelte.config.js`, `web/vite.config.ts` |
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
| Auth surface | All `/api/*` HTTP and SSE traffic stays behind the canonical FastAPI auth boundary in `src/aptl/api/main.py` / `src/aptl/api/deps.py` before route logic. In the shipped `aptl web serve` model, the FastAPI BFF owns server-side control-plane authority. In the split dev/preview profile, the SvelteKit hook may remain the compatibility proxy. In both modes, browser REST/SSE calls must not place the API token in fetch headers or URLs. |
| CSRF/origin gate | Mutating browser requests (`POST`, `PUT`, `PATCH`, `DELETE`) must pass a same-origin gate before any server path adds or accepts control-plane authority. Preserve the existing `Origin` plus `Sec-Fetch-Site` semantics from `web/src/hooks.server.ts`, but move the shipped boundary into FastAPI instead of duplicating it in each router. |
| WebSocket terminal auth | Terminal access uses either ADR-039's non-URL `Sec-WebSocket-Protocol` token convention plus `verify_ws_token(...)`, or an equivalent same-origin FastAPI terminal carrier that keeps the token server-side. `Origin` remains an extra browser defense, not a credential, and the token must not be rendered into static page code in the shipped model. |
| Secret handling | API tokens, cookies, private keys, generated config secrets, and replayable session identifiers remain ADR-029 control-plane secrets. Designs must not show secret values in examples, error states, logs, screenshots, run artifacts, OpenAPI examples, or route URLs. |
| Env binding | Web control-plane settings stay runtime-env owned. `APTL_API_TOKEN`, `APTL_API_URL`, `APTL_API_HOST`, and `APTL_ALLOWED_HOSTS` are not `aptl.json` fields. `APTL_API_URL` and `APTL_API_HOST` are split-profile compatibility knobs, not the shipped `aptl web serve` API contract. (UI-008a removed the `APTL_ALLOWED_ORIGINS` allow-list: cross-origin is now a strict same-origin check, and `APTL_ALLOWED_HOSTS` extends the loopback Host allow-list for DNS-rebinding defence.) Durable non-secret config goes through `AptlConfig`. |
| Config validation | Any first-party config surfaced in the UI must come from `load_config()` / `AptlConfig` projections. Unknown first-party fields are errors under ADR-025; do not add pass-through config dictionaries for UI convenience. |
| OS/process exposure | Tokens, passwords, cookies, private keys, and generated secret content must not appear in process argv, query strings, shell strings, access-log-visible paths, generated static bundles, rendered page data, or terminal prefill text. Docker actions stay typed backend calls, not raw command submission. |
| Error envelopes | HTTP auth failures use the generic FastAPI `401` envelope with `WWW-Authenticate: Bearer`; proxy errors stay narrow; terminal errors use the existing WebSocket error message shape; lab actions use `LabActionResponse`. |
| Terminal trust | Interactive terminals must satisfy ADR-040: container allow-list, lab-running check, endpoint projection from `ENDPOINT_REGISTRY`, and pinned `known_hosts` before `asyncssh.connect`. |
| Redaction and observability | Logs may name route, component, step, and validation layer, but not secret values or raw secret-bearing payloads. New persistence or export paths must use the existing redaction/runstore boundaries. |
| Network exposure | The default operator web surface remains loopback-bound per ADR-039. Any non-loopback design must be explicit about the operator risk decision and must not rely on CORS as authorization. |

## Design Guardrails

- For UI-008a, `aptl web serve` is the shipped delivery contract: one FastAPI
  process, default loopback bind, built UI assets, and `/api/*` on one origin.
  The split `aptl-web-api` plus `aptl-web-ui` Compose profile remains a
  dev/preview path and must not become the only path that preserves auth or
  CSRF behavior.
- Mount API routes before any static-asset or SPA fallback route. Unknown
  `/api/*` paths must still pass the API auth boundary before returning a
  route-specific result, not fall through to static asset handling.
- Keep the BFF authority server-side. Page code should use relative same-origin
  API paths and a same-origin terminal connection contract; it must not receive
  `APTL_API_TOKEN`, synthesize `Authorization` headers, or move the bearer
  token into URLs, local storage, stores, route data, or TypeScript types.
- Put the shipped CSRF/origin gate in one FastAPI-owned cross-cutting layer
  before router logic and before any control-plane authority is added or
  accepted. Do not copy the gate into each mutating route.
- Define the web build artifact root once at the FastAPI app/serve boundary so
  packaging, editable installs, tests, and future relocation do not grow
  separate path guesses. A missing build artifact should fail with a narrow
  operator/developer diagnostic, not change API auth behavior.
- The current SvelteKit build uses the Node adapter. UI-008a must make the
  FastAPI-mountable asset contract explicit before mounting files; do not
  assume a server bundle is a static asset directory.
- Distinguish human-investigation surfaces from read-only status surfaces in
  the spec. Terminals, SIEM exploration, command execution, lab start/stop, and
  kill flows are control or investigation surfaces; lab status badges,
  container summaries, startup diagnostics, and config summaries are read-only
  status surfaces unless the page explicitly defines a mutation.
- Keep the ADR-011 notebook/workbench paradigm. Do not drift into an enterprise
  SOC dashboard: no mission-control tile wall, icon-only sidebar, status-dot
  matrix, or dense product-console chrome.
- Keep the visual language specific to a local purple-team lab workbench. Do
  not use marketing heroes, purple gradients, decorative glow, glassmorphism,
  bento grids, nested card walls, fake analytics charts, or oversized rounded
  icon tiles.
- Reuse the current component families before inventing new ones:
  `NavBar`, `LabStatusBadge`, `ContainerGrid`, `LabStartNotice`, `Terminal`,
  and workbench blocks. If a new recurring UI primitive is needed, document
  which existing component pattern it extends.
- Use Tailwind v4 tokens and a small APTL component kit as the design-system
  base. External component primitives may be used for accessible behavior such
  as dialogs, menus, popovers, tabs, and tooltips, but they must not replace
  APTL's route structure, palette, density, or security copy.
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
- Target WCAG 2.2 AA for shipped routes. Keyboard access, visible focus,
  target sizing, contrast, non-color status cues, accessible dialogs, and
  screen-reader-safe live updates are implementation requirements, not polish.
- Keep UI copy localization-ready even while v1 ships English-only. Centralize
  user-facing strings, use shared date/time/count formatters, avoid sentence
  concatenation, and avoid layouts that depend on English-length labels.
- Treat persistent settings as browser-local non-secret preferences only. Do
  not persist tokens, terminal input/output, copied commands, raw SIEM custom
  queries, scenario answers, or investigation notes in v1.
- Include a local-use and privacy notice before controlled actions. Do not add
  cookie-consent or terms-wall patterns unless non-essential analytics,
  third-party embeds, or legally approved terms text are introduced.

## UI-008b Component Kit Guardrails

UI-008b should create a small APTL component kit from the current Svelte and
Tailwind surface, not a parallel design system.

- Treat `web/src/app.css` as the canonical token source. Promote the existing
  Tailwind v4 `@theme` variables into documented color, type, spacing, radius,
  status, focus, and density conventions there or in adjacent design docs. Do
  not introduce a second Tailwind config, JavaScript token mirror, CSS-in-TS
  theme object, or copied admin-template token set.
- The component kit is a presentation and interaction layer. It must not own
  API fetching, auth carrier construction, DTO parsing, lifecycle semantics,
  scenario shaping, terminal ticket flow, SIEM query validation, config
  validation, logging, persistence, or redaction.
- Keep the app shell anchored on `web/src/lib/components/NavBar.svelte` and
  `web/src/routes/+layout.svelte`: top navigation, text labels, compact lab
  status, and constrained content regions. Do not add an icon-only sidebar,
  mission-control nav rail, or wholesale Tailwind UI shell.
- Keep primitive props semantic and content-model-oriented. A status badge
  should accept a known status/severity/label shape, not arbitrary color class
  strings. Tables should accept rows, columns, captions, loading/empty/error
  state, and bounded row actions; they should not infer backend states from
  English messages.
- Use existing component families as incumbents: `LabStatusBadge`,
  `LabStartNotice`, `ContainerGrid`, `ContainerCard`, `ScenarioCard`,
  `Terminal`, `TerminalBlock`, and the workbench blocks. New primitives should
  factor repeated recipes out of those components without changing their data
  authority.
- Centralize repeated status styling currently duplicated across
  `LabStatusBadge`, `ContainerCard`, `ScenarioCard`, `WorkbenchStatusBar`,
  `ObjectiveBlock`, and `ContainerStatusBlock`. Reuse
  `web/src/lib/container-state.ts` or evolve it into a narrow UI-state helper
  instead of adding one-off switch statements per component.
- Dialogs, drawers, menus, popovers, tabs, and tooltips need accessible
  behavior. A small headless Svelte primitive or dependency is acceptable only
  for focus management, ARIA semantics, keyboard handling, and portal/overlay
  mechanics; the APTL kit still owns tokens, density, copy, and content
  structure.
- Treat `NarrativeBlock` plus `renderMarkdown()` / DOMPurify as the only
  existing sanctioned raw-HTML path. Generic primitives should render text or
  Svelte children, not add new `{@html}` surfaces.
- Preserve SvelteKit's static SPA and strict CSP posture from
  `web/src/routes/+layout.ts` and `web/svelte.config.js`: no remote assets,
  no inline-script-dependent component behavior, no API token in route data,
  generated bundles, local storage, examples, screenshots, or style tokens.
- Kit tests belong under `web/tests/components/` and should assert behavior,
  semantics, and variants: roles, accessible names, focus/keyboard behavior,
  disabled/loading/empty/error states, non-color status labels, and density
  class selection. Do not rely on snapshots as the only evidence.
- If the kit adds local preferences such as density, color mode, motion, locale,
  time display, or terminal font size, put the schema-versioned browser-local
  preferences seam behind one helper/store. Persist only the non-secret keys
  allowed by `web-gui-design.md`; never persist auth material, terminal I/O,
  raw SIEM custom queries, copied command history, hints viewed, or notes.
- A user-visible kit change needs a `changelog.d/<issue>.<type>.md` fragment.
  Docs-only preflight changes do not.

## UI-008c Lab Home Guardrails

UI-008c (`/`) is a composition of existing control-plane and component-kit
boundaries. It must answer whether the lab is usable and what the operator can
do next; it must not become a second lifecycle, scenario, terminal, or Docker
authority.

- Keep all HTTP and SSE traffic behind `web/src/lib/api.ts` and
  `web/src/lib/stores/lab.ts`. Do not fetch authenticated `/api/*` routes
  directly from `+page.ts` / route components unless the shared session-header
  boundary is still used.
- Keep `/api/lab/events` on fetch streaming with `X-APTL-Session`; do not switch
  back to native `EventSource`, which cannot send the port-scoped session
  factor.
- `GET /api/lab/status` currently owns running/container/error state only.
  `POST /api/lab/start` owns ADR-030 startup outcome and diagnostics. If Lab
  Home needs startup diagnostics after a reload or from SSE, add that structured
  field at the core/API DTO boundary first; do not infer readiness from
  container health, colors, stale browser state, or English messages.
- Reuse `LabActionResponse` for start/stop and add/use a mirrored
  `KillActionResponse` for kill. Do not overload one action envelope with the
  other's fields, and do not parse backend messages to decide success.
- Lifecycle controls are single-flight from the UI perspective. Disable or
  otherwise serialize start, stop, and kill while one action is pending, refresh
  status from the shared store/API afterward, and avoid optimistic state changes
  that contradict the next SSE event.
- `POST /api/lab/kill` is the existing emergency path with the existing
  `containers` scope parameter. The UI confirmation state belongs in a small
  `KillConfirmDialog` built from the kit `Dialog` and `Button`; do not add a
  generic command-confirmation system or a second modal primitive.
- Scenario entry points must come from a new narrow ACES/catalog API projection
  when this slice needs them. The current Python tests deliberately assert the
  removed legacy `/api/scenarios` routes are absent, so UI-008c must replace
  that absence with explicit DTOs in `src/aptl/api/schemas.py` backed by
  `src/aptl/core/scenario_catalog.py` / the ACES parser, not by reviving the old
  in-tree scenario model from `src/aptl/core/scenarios.py`.
- Scenario summary DTOs should expose only card/list facts: id, name,
  description, mode, difficulty, estimated time, tags, required containers, and
  validation/status summary. Workbench detail, scoring, SIEM query execution,
  and terminal session state stay out of the Lab Home summary contract.
- Terminal links on container cards must remain a projection of
  `ENDPOINT_REGISTRY` / terminal allow-list semantics. Do not hardcode a new
  SSH container set in the route when the endpoint registry already owns
  terminal target identity.
- Use component-kit semantics for controls and status: `Button` variants for
  primary/destructive actions, `Dialog` for confirmation, shared status/badge
  tones, `LabStartNotice` for diagnostics, `ContainerGrid` for containers, and
  `ScenarioCard` for scenario summaries. Do not add page-local color switch
  statements or an alternate card/button system.
- Catalog, status, and action error states need stable user-facing categories
  and redacted details. API routes may name the route, validation layer,
  scenario id, or component, but must not return raw stack traces, `.env`
  values, bearer/session credentials, private keys, or secret-bearing command
  output.
- Tests for this slice should cover the route/component behavior, not only leaf
  helpers: kill confirmation focus/escape/cancel/confirm, single-flight action
  disabling, start diagnostics rendering for every ADR-030 outcome, catalog
  loading/error/empty states, SSE-driven status updates, and the API client
  carrying the session header on every `/api/*` call.

## Extensibility Seams

The design specification should include a compact page contract table for each
route. Each row should state:

- route path and page purpose;
- surface class: read-only status, human investigation, control action, or
  terminal;
- API data source and DTO owner;
- mutation capability, if any;
- auth carrier: FastAPI BFF HTTP/SSE, split-profile proxy HTTP/SSE, or
  terminal WebSocket/same-origin carrier;
- primary component family; and
- future variation parameter.

Use existing extension points for obvious follow-up changes:

- new lifecycle or startup fields extend `LabResult` / `LabActionResponse`;
- new endpoint display data extends `ENDPOINT_REGISTRY` by target port and
  protocol, not host port;
- new workbench content extends the `WorkbenchBlock` discriminated union and
  block renderer;
- new scenario browsing data uses a narrow ACES/catalog projection rather than
  a local scenario parser;
- new runtime web settings extend the typed env settings boundary, not
  `aptl.json`; and
- the web asset root, bind host, and allowed origins are parameterized at the
  app/serve/runtime-settings boundary; future remote/shared modes must change
  that boundary deliberately instead of scattering path, host, or origin
  literals through routers, Svelte clients, Compose, and tests.

## Anti-Patterns

- Treating CORS, loopback binding, allowed origins, or "local lab" as
  authentication.
- Putting bearer tokens in URLs, WebSocket URLs, browser-visible examples,
  shell snippets, process argv, logs, screenshots, or stored design fixtures.
- Adding per-router auth snippets, duplicate bearer parsing, a new auth error
  schema, or a second web-auth settings object.
- Adding per-router CSRF snippets, frontend-only CSRF checks, or a second
  origin parser when the FastAPI BFF can own the shipped gate centrally.
- Rendering `APTL_API_TOKEN` or a derived bearer credential into static HTML,
  Svelte route data, browser stores, local storage, WebSocket URLs, or generated
  client bundles.
- Mounting a SPA catch-all before `/api/*`, or letting `/api/*` misses return
  static assets without first satisfying the API auth boundary.
- Running a hidden Node/SvelteKit server as the real shipped `aptl web serve`
  delivery path instead of making FastAPI the BFF and asset owner.
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
- Do not choose a remote/shared deployment auth model for UI-008a.
- Do not choose the final UI-007 route map, wireframes, or per-page copy here.
- Do not add multi-user accounts, RBAC, OAuth/OIDC, or password login. (Amended
  for UI-008a: a single-user, server-issued two-factor session credential (an
  HttpOnly cookie plus a port-scoped `sessionStorage` header token) bootstrapped
  from a one-time launch token IS in scope and required, because
  loopback binding and forgeable Fetch-Metadata/Origin headers are not
  authentication, and a host-scoped cookie alone leaks across loopback ports. See
  the shipped-implementation note in `web-gui-design.md`.)
- Do not redesign the deployment backend, Docker socket model, ACES SDL,
  scenario startup, run archive layout, or endpoint registry.
- Do not make the web GUI the source of truth for lab topology, scenario
  semantics, credentials, or startup readiness.
- Do not widen the current web control plane beyond the approved UI-006 scope.
