# APTL Web GUI Design Specification

## Purpose

This document is the UI-007 design specification for the APTL web GUI. It also
records the UI-006 product scope baseline that this design depends on, because
the scope issue has no separate decision record yet.

The implementation target is UI-008. This document is not an implementation
ticket and does not add routes, components, or API endpoints by itself.

Binding guardrails live in
[Web GUI Design Preflight Guardrails](web-gui-design-preflight.md). In short:
keep the ADR-011 workbench paradigm, keep ADR-039 web auth and loopback
defaults, keep ADR-040 terminal trust gates, keep ADR-030 startup readiness
semantics, and reuse the existing API, Svelte, endpoint, deployment, redaction,
and logging owners.

## Product Scope

### Target User

The v1 GUI is for one local lab operator who is actively running and
investigating an APTL exercise. That user may be a learner, instructor,
developer, or evaluator, but the interaction model is the same: one operator at
one workstation, against a local lab.

The GUI is not a shared SOC console, not a multi-user case system, and not the
primary agent loop. The MCP loop and CLI remain the automation and scripting
surfaces.

### Jobs the GUI Serves

The GUI exists where a browser workbench is materially better than the CLI or
MCP loop:

- See whether the lab is ready, degraded, stopped, or failed without reading
  raw terminal output.
- Start, stop, and kill local lab activity from a visible operator surface.
- Browse the approved scenario catalog and open a scenario without knowing file
  paths.
- Work through a scenario as a notebook-style investigation: narrative,
  terminal access, expected detections, objectives, hints, and live status in
  one flow.
- Run approved SIEM queries and inspect returned alerts without switching to a
  separate dashboard for every check.
- Open a controlled terminal to allowed lab containers when human
  investigation needs direct shell access.
- Review current non-secret configuration and service access facts.

### Representative User Stories

The GUI must be designed from operator tasks rather than from generic dashboard
widgets. UI-008 should use these stories as its first usability checklist:

| User | Story | Design implication |
| --- | --- | --- |
| Learner | As a learner, I want to know whether the lab is usable before I start a scenario. | Lab Home must lead with readiness, startup diagnostics, and next action, not a chart wall. |
| Learner | As a learner, I want scenario steps, terminal entry points, hints, and expected detections in one place. | Scenario Workbench stays document-first with lazy tools inside the flow. |
| Instructor | As an instructor, I want to see which prerequisites and containers a scenario needs before recommending it. | Scenario cards and detail headers show required containers, mode, difficulty, duration, and validation state. |
| Evaluator | As an evaluator, I want evidence that detections fired without switching among several products. | SIEM Explorer provides curated query packs, bounded live execution, and expandable alert details. |
| Developer | As a developer, I want to debug a failed lab start from structured diagnostics. | Startup diagnostics preserve ADR-030 severity, component, and remediation detail. |
| Operator | As an operator, I want destructive actions to be obvious and reversible only where the backend supports it. | Stop and kill are visually distinct, require confirmation, and name their blast radius. |
| Keyboard user | As a keyboard-only user, I want every route and modal to work without pointer input. | Navigation, dialogs, tables, terminals, and disclosure controls must pass keyboard checks. |
| Low-vision user | As a low-vision user, I want readable contrast, visible focus, and adjustable terminal text. | Theme tokens, focus rings, status labels, and terminal preferences are first-class requirements. |
| Non-English future user | As a future localized user, I want UI copy, dates, numbers, and text direction to be adaptable. | Copy must be centralized and layout must avoid fixed text widths and direction-specific assumptions. |

### V1 Capabilities

V1 includes these capabilities:

| Capability | Surface class | Notes |
| --- | --- | --- |
| Lab status and startup diagnostics | Read-only status | Preserve ADR-030 `ready`, `degraded_usable`, `degraded_unusable`, and `failed` outcomes. |
| Lab start, stop, and emergency kill | Control action | Use existing typed API routes and narrow confirmation states. |
| Scenario catalog browsing | Read-only status | Use a narrow ACES/catalog projection. Do not revive legacy in-tree scenario schemas by accident. |
| Scenario workbench | Human investigation | Notebook-style route with narrative, step, objective, status, SIEM, and terminal blocks. |
| Focused terminal | Terminal | Allowed containers only, with ADR-039 auth and ADR-040 host-key verification. |
| Live SIEM query execution | Human investigation | Deliver DET-003 inside this surface as curated query execution and result inspection. |
| Configuration summary | Read-only status | Show non-secret settings only. Do not display tokens, private keys, generated secrets, or raw `.env` values. |

### Non-Goals for V1

V1 does not include:

- multi-user accounts, RBAC, OAuth, OIDC, or password login;

> **Amended (UI-008a):** an earlier draft of this Non-Goal also excluded "browser
> sessions" outright. That was wrong for a local code-execution tool: loopback
> binding is not a security boundary (any local process/user can reach the port),
> and forgeable `Sec-Fetch-*`/`Origin` headers are a CSRF-isolation signal, not a
> credential. Following the Jupyter model, V1 **does** use a single-user,
> server-issued **session credential** (no accounts, no login form) bootstrapped
> from a one-time launch token, so the browser holds a non-forgeable credential a
> sibling process cannot obtain. The credential is two-factor (an HttpOnly cookie
> plus a port-scoped header token) so it survives the cross-port cookie leak; see
> "Shipped implementation (UI-008a)" above.
- remote shared deployment as a default mode;
- generic Docker command, shell command, or arbitrary API execution endpoints;
- full replacement of Wazuh Dashboard, TheHive, MISP, Shuffle, or Cortex;
- in-browser editing of SDL or ACES artifacts;
- persisted operator notes, terminal transcripts, or investigation notebooks;
- case-management workflow;
- raw run-archive browsing beyond a bounded status/history summary;
- a dense enterprise SOC dashboard layout.

### Shipping Model

The shipped operator surface is `aptl web serve` on a single loopback origin.
The implementation should mount built web assets through the FastAPI
application and keep `/api/*` on the same origin. The current split
`aptl-web-api` plus `aptl-web-ui` Compose profile remains useful for dev and
preview work, but it is not the final operator delivery contract.

The implementation must preserve the security posture from ADR-039:

- default bind address is `127.0.0.1`;
- all API routes require web control-plane auth before route logic;
- browser REST and stream calls do not put the API token in URLs;
- terminal WebSocket auth uses the existing non-URL subprotocol carrier or an
  equivalent same-origin server carrier;
- mutating requests have a CSRF/origin gate before the server adds or accepts
  control-plane authority.

If static asset mounting removes the current SvelteKit server hook, UI-008 must
replace it with an equivalent same-origin backend-for-frontend boundary in
FastAPI rather than pushing bearer-token handling into page code.

**Shipped implementation (UI-008a).** The SvelteKit app builds to a static SPA
(`adapter-static`, `fallback: index.html`) that `aptl web serve` mounts behind
the FastAPI app. A single FastAPI-owned cross-cutting layer
(`src/aptl/api/middleware/bff.py`) is the BFF boundary, with these concerns kept
distinct (rather than conflated, which was the flaw in the original
SvelteKit-hook posture):

- **Authentication** is a server-issued **two-factor session credential**, not a
  header bearer. Because loopback binding is not a security boundary and
  `Sec-Fetch-*`/`Origin` are client-forgeable, the operator bootstraps a session
  via the Jupyter-style handshake: `aptl web serve` prints a one-time launch URL
  (`GET /api/auth/login?token=…`, the only unauthenticated `/api` route) to the
  operator's terminal. Visiting it sets an `HttpOnly`, `SameSite=Strict`
  `aptl_session` cookie **and** hands the SPA a second factor: a port-scoped
  header token delivered in the redirect URL fragment, which the SPA stores in
  `sessionStorage` and echoes as `X-APTL-Session` on every `/api/*` call. The BFF
  injects the API bearer server-side **only** when BOTH factors are valid, so the
  browser never holds the API token. Two factors are required because cookies are
  scoped by host, not port: the `aptl_session` cookie is also sent to any other
  `127.0.0.1:<port>`, so a sibling local process that lures the browser to its
  port could steal it. The header token lives in `sessionStorage` (scoped by
  origin *including* port, never auto-sent on navigation), so a cross-port
  attacker who steals the cookie still cannot forge the header, and an XSS payload
  that reads the header token still cannot read the HttpOnly cookie. The two
  values are independent HMAC tags of one per-process master secret, so neither
  reveals the other (`src/aptl/api/session.py`).
- **CSRF defence** is a strict same-origin `Sec-Fetch-Site`/`Origin` gate on
  mutating `/api/*` requests. Origin must equal the request's own origin, with
  no allow-list bypass, because the session cookie is a host credential
  `SameSite` sends across ports. This is a CSRF-isolation signal only, never an
  auth decision.
- **DNS-rebinding defence** is a `Host` allow-list (loopback by default) on
  `/api/*`.
- **XSS / clickjacking hardening** is a strict CSP plus frame/MIME headers.
  Because the header-token factor lives in XSS-readable `sessionStorage`, the SPA
  ships a strict CSP (`script-src 'self'` with SvelteKit-hashed bootstrap, no
  `unsafe-inline` scripts; `default-src`/`connect-src 'self'`) delivered as a
  `<meta>` tag so it applies behind both `aptl web serve` and the Caddy proxy.
  `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` are sent as
  response headers (a `<meta>` CSP cannot carry `frame-ancestors`).

`/api/*` routes (including an authenticated catch-all for unknown API paths)
mount before the SPA fallback, which only serves files contained within the
asset root. The terminal WebSocket carrier is server-side too: a same-origin
`GET /api/terminal/ticket` (cookie-authenticated like any other `/api` call)
returns a single-use, ~30 s ticket presented as the `aptl-token.<ticket>`
subprotocol; the WS gate accepts a valid ticket (or a real token, for direct
clients) and enforces the same strict same-origin check. The split `aptl-web-api` +
`aptl-web-ui` Compose profile remains for dev/preview as a static SPA served
behind a same-origin reverse proxy, with the control-plane token held only by
the API container (which also mints the session secrets and logs the launch URL).
In that profile the API runs `--api-only` behind the Caddy UI origin, so it is
told the browser-facing origin via `APTL_WEB_PUBLIC_ORIGIN` (`--public-origin`)
and prints the launch URL for the UI origin (`127.0.0.1:3000`) rather than its own
bind address. The operator opens that URL so the session header token is stored
for the origin the SPA actually runs on.

**Asset delivery contract.** APTL ships as a cloned-and-run repository, not as a
wheel that bundles a pre-built GUI, so there are two supported deliveries of the
built SPA and `aptl web serve` fails hard (exit 1) rather than silently degrading
when neither is present:

- **Docker (`aptl lab start`, web profile):** the `aptl-web-ui` image builds the
  SPA and serves it (Caddy) at the single origin, reverse-proxying `/api/*` to the
  `aptl-web-api` container, which runs `aptl web serve --api-only` (deliberately
  GUI-less behind the proxy).
- **Local single-origin (`aptl web serve`):** the operator builds the frontend
  (`cd web && npm run build`) and the server mounts the repo-relative `web/build`
  output; `--web-root` or `APTL_WEB_ROOT` override the location. Run without a
  build and without `--api-only`, the command exits 1 with build instructions
  rather than starting a browser-broken API-only server.

`get_web_asset_root` resolves, in precedence order, `--web-root` → `APTL_WEB_ROOT`
→ the packaged `aptl/web_static` resource → repo-relative `web/build`. The
`web_static` candidate is forward-compatible with a future combined-wheel delivery
and resolves to nothing in the current clone-and-run / Docker models.

**Remote access.** The default bind is `127.0.0.1`, and that loopback model is the
intended path for almost all use. When an operator needs the GUI from another
device (for example over a Tailscale tailnet), the recommended setup keeps the
server on loopback and puts a same-host TLS proxy in front:

1. Run `tailscale serve --bg https / http://127.0.0.1:8400` (or a co-located
   Caddy) so the proxy terminates TLS and forwards to the loopback server.
2. Start the server with the browser-facing origin and host allow-list:
   `APTL_ALLOWED_HOSTS=<machine>.<tailnet>.ts.net aptl web serve
   --public-origin https://<machine>.<tailnet>.ts.net`.

The server trusts `X-Forwarded-Proto` only from a loopback proxy, so behind that
TLS front `request.url.scheme` resolves to `https`: the session cookie is issued
`Secure` and the CSRF origin gate matches the browser's `https` origin.

A direct non-loopback bind without a TLS front (`aptl web serve --host
<address>`) also works for an environment whose transport is already encrypted,
such as a tailnet. It still needs `APTL_ALLOWED_HOSTS` and `--public-origin`. The
session cookie's `Secure` flag follows the request scheme, so over plain HTTP the
cookie is delivered without `Secure` (a `Secure` cookie would be withheld by the
browser and the two-factor session would never complete). The launch token and
two-factor session still gate every request, but confidentiality then depends on
the transport, not on the application. Prefer the TLS-fronted setup above.

## Design Inputs and Visual Direction

The visual target is a quiet operational workbench: readable, dense enough for
repeated use, and specific to APTL's purple-team lab context. It should feel
closer to a restrained developer/security tool than a marketing SaaS page.

Use Tailwind v4 as the design-system foundation because the repo already ships
Tailwind tokens in `web/src/app.css`. UI-008 should formalize those tokens into
an APTL component kit rather than importing a wholesale admin template. Tailwind
UI application-shell patterns are acceptable references for spacing, tables,
forms, menus, dialogs, and responsive behavior, but the implementation must
adapt them to APTL's content model and existing Svelte components.

If UI-008 adds a component primitive library, choose one for accessible
headless behavior only, such as dialogs, menus, popovers, tabs, and tooltips.
Do not let a library replace APTL's route structure, palette, density, or
security copy. Any new icon package should be small and purposeful; icons must
support scannability and have text labels or accessible names.

Design anti-patterns to avoid:

- no full-screen hero, marketing headline, testimonial, pricing, or "unlock
  the power" copy;
- no purple gradient background, gradient text, decorative blobs, glow, neon,
  glassmorphism, or fake depth;
- no bento grid, nested cards, or "everything is a card" layout;
- no oversized rounded tiles with giant icons above short headings;
- no one-note purple/violet palette. Purple may remain an APTL accent, but
  status and hierarchy must use semantic colors, spacing, and labels;
- no fake analytics charts, mocked activity feeds, or decorative sparklines;
- no low-contrast gray text on dark panels;
- no icon-only sidebar or mystery controls;
- no animations that imply progress when the backend has not reported it.

Layout rules:

- use a top app shell with constrained content width on document routes and
  full-width utility regions only when the data needs it;
- keep page sections unframed unless they are repeated records, dialogs, or
  tool panes;
- use tables for alert and config facts where comparison matters;
- use compact cards only for scenario summaries, container summaries, and
  repeated workbench blocks;
- keep typography restrained: route headings are page-sized, panel headings are
  compact, terminal and command text use the mono stack only where appropriate.

Reference set for UI-008:

- Tailwind UI application-shell and component patterns for practical Tailwind
  layout references: <https://tailwindcss.com/plus>.
- Nielsen Norman Group complex-application guidance for keeping expert tools
  workflow-led: <https://www.nngroup.com/articles/complex-application-design/>.
- W3C WCAG 2.2 for accessibility requirements:
  <https://www.w3.org/TR/WCAG22/>.
- WAI-ARIA modal dialog pattern for confirmation, settings, and notice dialogs:
  <https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/>.
- W3C internationalization guidance for language and direction metadata:
  <https://www.w3.org/TR/international-specs/>.
- Current AI-generated design anti-pattern discussions as a smell checklist,
  not as product authority:
  <https://uxplanet.org/how-to-spot-ai-generated-design-697aaabe76c8> and
  <https://prg.sh/ramblings/Why-Your-AI-Keeps-Building-the-Same-Purple-Gradient-Website>.

## Interaction Affordances

The GUI should expose useful controls without turning into a command console.

Required affordances:

- global top navigation with current-route state and lab status summary;
- breadcrumb or back link on scenario and terminal routes;
- scenario search, tag filters, mode filter, difficulty filter, and clear
  filter reset;
- sort controls where lists can exceed one screen: scenario name, difficulty,
  duration, and validation status;
- copy buttons for command snippets with success/error feedback, but no
  auto-run behavior;
- inline refresh controls for status and SIEM results, with live updates when
  SSE is active;
- expandable raw JSON for SIEM alerts, hidden by default;
- loading, empty, partial, offline, unauthorized, and stale-data states for
  every data region;
- clear destructive-action confirm dialogs for Stop and Kill;
- persistent settings access from a small labeled control in `NavBar`, not a
  primary top-level work route.

Keyboard shortcuts may be added only after the visible controls exist. They
must be discoverable from a Help or Shortcuts dialog and must not shadow
terminal input while focus is inside `Terminal`.

## Settings and Persistence

Persistent settings make sense for local operator preferences, not for lab
state. The app is accountless in v1, so settings should be browser-local and
resettable.

Add a settings dialog or drawer reachable from `NavBar`. Do not make Settings
a primary route unless UI-008 finds that mobile layout or future settings volume
requires it.

Persist only non-secret UI preferences in a versioned browser key such as
`aptl.web.preferences.v1`:

| Setting | Values | Persistence rule |
| --- | --- | --- |
| Color mode | system, dark, light, high contrast | Local preference only; default to system. |
| Density | comfortable, compact | Affects tables, lists, cards, and workbench blocks. |
| Motion | system, reduced | Must honor `prefers-reduced-motion` even without a stored setting. |
| Locale | browser default, explicit locale | Stores a locale tag only, not translated content. |
| Time display | browser local time, UTC | Applies to SIEM alerts, run status, and diagnostics timestamps. |
| SIEM default time range | bounded choices such as 15m, 1h, 24h | Backend still enforces maximums. |
| SIEM row limit | bounded choices within backend cap | Backend remains authoritative. |
| Terminal font size | bounded numeric range | Applies to xterm rendering only. |
| Terminal scrollback | bounded choices | Must not persist terminal output. |
| Legal notice acknowledgement | notice version and timestamp | Stores only that a local notice was acknowledged. |

Do not persist API tokens, bearer headers, service credentials, terminal input,
terminal output, raw SIEM custom queries, copied command history, scenario
answers, hints viewed, or user notes in v1. If UI-008 introduces server-side
preferences later, that is a new product and security scope decision.

The settings store must be schema-versioned. Unknown keys are ignored or reset,
and a visible "Reset preferences" action returns to defaults.

## Accessibility

UI-008 should target WCAG 2.2 AA for the shipped routes. The design work must
make that practical:

- all interactive targets meet WCAG 2.2 target-size guidance, with larger
  targets for destructive and high-frequency controls;
- every button, icon button, link, menu item, tab, disclosure, and terminal
  control has an accessible name;
- focus is visible, never hidden behind sticky headers or dialogs, and returns
  to the invoking control after a modal closes;
- modal dialogs trap focus while open, close through Escape where safe, and
  expose title and description semantics;
- color is never the only status cue. ADR-030 states, SIEM severity, and
  terminal errors need text labels;
- contrast is checked for normal text, muted text, borders used as state, focus
  outlines, charts, and terminal themes;
- live lab/SIEM updates use polite `aria-live` regions where useful, without
  flooding screen readers during rapid event streams;
- tables have captions or headings, column headers, and row expansion controls
  with announced state;
- terminal routes provide keyboard focus management, visible connection state,
  and an accessible non-terminal error/log summary for connection failures;
- copy-to-clipboard controls announce success and failure;
- layouts must reflow at narrow widths without overlapping controls or hiding
  essential state.

Accessibility acceptance for UI-008 should include keyboard-only route walks,
automated accessibility checks in web tests where practical, and manual review
of the terminal, modal, and SIEM table flows.

## Language and Locale Readiness

The first implementation can ship English-only text, but it must not block
localization.

Rules for UI-008:

- keep user-facing copy in a small message catalog or translation-ready module
  rather than scattering strings through route components;
- never concatenate translated sentence fragments around variables;
- format dates, times, durations, counts, and severities through shared helpers;
- store locale as a BCP 47 language tag preference when the user overrides the
  browser default;
- avoid fixed-width text containers for labels and buttons. German-length
  labels and long scenario titles must wrap or truncate intentionally;
- avoid layout assumptions that break right-to-left direction later. Direction
  does not need to ship in v1, but spacing and icon placement should use
  logical properties where practical;
- keep operator-auth and security error copy short and translatable.

## Legal and Privacy UX

APTL is a local lab operator tool, not a public SaaS service. Do not add a
marketing-style cookie banner or blocking terms wall by default.

V1 should include a concise local-use notice and privacy notice:

- a first-run "Authorized local lab use" acknowledgement before the first
  mutating lab action or terminal launch, with the acknowledged notice version
  stored as a non-secret preference;
- a persistent Privacy link in Help or the footer area of the app shell;
- notice text that states the browser stores local UI preferences, does not
  store API tokens, and does not persist terminal input/output in v1;
- notice text that explains local API/server logs may record route names,
  timestamps, status codes, and redacted error categories;
- no non-essential analytics, tracking pixels, or third-party scripts in v1.

If future builds add analytics, crash reporting, third-party embeds, or
non-essential cookies/local storage, then UI-008 or a follow-up issue must add a
real consent manager with Accept, Reject, and Manage choices before collection
starts. A consent banner is not required for strictly essential local storage
such as the preference key above, but the privacy notice still has to disclose
it.

## Information Architecture

The v1 nav is deliberately small:

- **Lab**: default route and operator status.
- **Scenarios**: catalog access, surfaced on Lab Home and deep-linked by
  scenario route.
- **SIEM**: live detection query explorer.
- **Config**: non-secret lab and web settings.
- **Terminal**: not a global nav tab; opened from container cards or scenario
  steps.
- **Settings**: a dialog or drawer, not a primary route in v1.
- **Help/Privacy**: a small secondary menu area, not a primary route.

No icon-only sidebar. Keep the top navigation pattern from `NavBar.svelte`.

## Route Contracts

| Route | Purpose | Surface class | API data source | Mutation | Auth carrier | Component family | Future variation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `/` | Lab Home with readiness, lifecycle controls, key containers, and scenario entry points. | Read-only status plus control action. | `/api/lab/status`, `/api/lab/events`, `/api/lab/start`, `/api/lab/stop`, `/api/lab/kill`, catalog summary. DTOs in `src/aptl/api/schemas.py`; mirrors in `web/src/lib/types.ts`. | Start, stop, kill. | Same-origin HTTP/SSE proxy or equivalent FastAPI BFF. | `NavBar`, `LabStatusBadge`, `LabStartNotice`, `ContainerGrid`, `ScenarioCard`. | Add readiness filters or grouped container bands without changing lifecycle DTOs. |
| `/scenarios/[id]` | Scenario workbench for the selected catalog item. | Human investigation with terminal blocks. | New narrow scenario detail projection from ACES/catalog authority; lab status stream; terminal WebSocket; SIEM query endpoint. | Terminal input; SIEM query execution; hint reveal is local unless scoring later persists it. | HTTP/SSE proxy for data; terminal subprotocol for PTY. | Workbench blocks: narrative, status, step, objective, SIEM query, terminal. | Extend `WorkbenchBlock` for new block types. |
| `/siem` | Open-ended but bounded SIEM query explorer for approved queries. | Human investigation. | New `/api/siem/queries`, `/api/siem/query`, and result DTOs backed by the existing Wazuh/OpenSearch integration owner. | Execute query. | Same-origin HTTP proxy or equivalent FastAPI BFF. | `SiemQueryBlock` extended into query list, editor, results, and alert detail components. | Add saved query packs by ID, not arbitrary shell or raw OpenSearch passthrough. |
| `/terminal/[container]` | Focused terminal for an allowed target. | Terminal. | `/api/terminal/ws/{container}` and endpoint registry projection. | PTY input and resize only. | WebSocket subprotocol token carrier or equivalent same-origin terminal carrier. | `Terminal` and `TerminalBlock`. | Add split panes only after session lifecycle and redaction boundaries are designed. |
| `/config` | Non-secret configuration and web profile status. | Read-only status. | `/api/config`, web serve metadata, allowed-origin summary, service URL summaries with secrets removed. | None in v1. | Same-origin HTTP proxy or equivalent FastAPI BFF. | New summary rows that follow `ContainerCard` density and `LabStartNotice` severity language. | Later edit flow must use `AptlConfig` validation, not pass-through dictionaries. |

## Page Designs

### Lab Home

Goal: answer "Can I use the lab now, and where do I start?"

Low-fidelity layout:

```text
+--------------------------------------------------------------+
| APTL          Lab | Scenarios | SIEM | Config   Help Settings |
+--------------------------------------------------------------+
| Lab Home                                                     |
| ready/degraded/stopped headline       [Start] [Stop] [Kill]  |
| Startup diagnostics, grouped by impact, if present           |
|                                                              |
| Containers                                                   |
| [security group] [dmz group] [internal group] [red team]      |
|                                                              |
| Scenarios                                                    |
| [scenario card] [scenario card] [scenario card]               |
+--------------------------------------------------------------+
```

Interaction details:

- Start and stop use existing `LabActionResponse` and render all diagnostic
  severities. Do not reduce degraded states to a single yellow badge.
- Emergency kill is a destructive action. It needs a modal confirmation that
  names whether containers will also be stopped. It must not be a one-click
  header button.
- Container cards group by role or network when enough metadata exists. Until
  then, keep the current responsive grid.
- Terminal links appear only for registry-approved targets and only when the
  lab state allows opening a terminal.
- Scenario cards show name, mode, difficulty, time, tags, and required
  containers. They link to `/scenarios/[id]`.

States:

- Stopped: primary action is Start; containers are absent; scenario catalog is
  still browsable.
- Starting: action buttons are disabled; the page keeps showing the last known
  status plus progress copy.
- Degraded usable: show the scenario entry point, but keep diagnostics visible.
- Degraded unusable or failed: keep diagnostics and suggested operator action
  visible above scenario cards.
- Missing web token: show a narrow service-configuration error. Do not show the
  token value or suggest putting it in a URL.

### Scenario Workbench

Goal: let a person investigate a scenario in one scrollable document.

Low-fidelity layout:

```text
+--------------------------------------------------------------+
| <- Lab  Scenario name            mode  containers  points     |
+--------------------------------------------------------------+
| Scenario title, summary, MITRE metadata                      |
| Required container status pills                              |
| Attack chain narrative                                       |
|                                                              |
| Step 1: technique                                            |
| description                                                  |
| commands + copy                                              |
| expected detections                                          |
| [Open terminal]                                              |
|                                                              |
| Objective: blue detection                                    |
| query summary [Run Query] results inline                     |
| hints                                                        |
+--------------------------------------------------------------+
```

Interaction details:

- The workbench remains document-first. Use cards only for repeated blocks,
  not for full page sections.
- Steps use `AttackStepBlock`; objectives use `ObjectiveBlock`; query snippets
  use `SiemQueryBlock`; terminals are lazy-mounted with `TerminalBlock`.
- Command copy is local browser behavior. The GUI must not auto-run command
  text in a shell.
- Hint reveal stays local in v1 unless UI-008 adds a scoring persistence
  contract.
- Scenario loading uses a new backend projection from ACES/catalog authority.
  The missing `/api/scenarios` routes are an implementation gap, not a reason
  to resurrect old removed scenario models.

States:

- Unknown scenario: route-level 404 with a short message and Lab link.
- Catalog parse error: page-level error that names the catalog source, not raw
  stack traces.
- Lab stopped: workbench content is readable; terminals and live queries are
  disabled with a clear lab-stopped reason.
- Query failure: inline query result error with a stable error kind and a
  redacted detail string.

### SIEM Explorer

Goal: make DET-003 useful in the GUI without building a whole SIEM clone.

Low-fidelity layout:

```text
+--------------------------------------------------------------+
| SIEM                                                         |
+------------------------------+-------------------------------+
| Query packs                  | Results                       |
| - scenario detections        | time | rule | host | severity |
| - recent alerts              | expandable alert details      |
| - custom bounded query       |                               |
+------------------------------+-------------------------------+
```

Interaction details:

- Provide curated query packs first: current scenario objectives, recent Wazuh
  alerts, Suricata-related events, and red-team command telemetry where
  available.
- A custom query mode may exist only if the backend owns validation, time-range
  limits, row limits, and redaction. It must not expose raw OpenSearch
  passthrough by default.
- Results are tables with expandable detail rows. Keep raw JSON behind a
  disclosure control.
- Query execution belongs to a typed FastAPI route with pytest coverage and a
  mirrored Svelte type. It is not a disabled button plus local mock.

States:

- SIEM offline: show dependency status and a next operator action.
- No results: show query metadata and time range, not an error.
- Partial results: show count, truncation, and time range.
- Backend validation error: preserve user input enough to edit it, but do not
  echo secrets or raw backend exception text.

### Focused Terminal

Goal: give controlled shell access for human investigation.

Low-fidelity layout:

```text
+--------------------------------------------------------------+
| <- Scenario or Lab        Terminal: workstation     connected |
+--------------------------------------------------------------+
| Target facts: container, role, lab state, host-key state      |
| connection status / error reason                             |
| +----------------------------------------------------------+ |
| | terminal viewport                                        | |
| |                                                          | |
| +----------------------------------------------------------+ |
| [Reconnect] [Copy selected text] [Settings: font/scrollback] |
+--------------------------------------------------------------+
```

Interaction details:

- Entry points are container cards and scenario steps, not a global list of
  every container.
- The route uses the existing `Terminal` component.
- The server validates token, origin, container allow-list, lab-running state,
  runtime endpoint availability, and pinned `known_hosts` before SSH.
- Error text stays narrow: unauthorized, origin rejected, lab stopped,
  container unavailable, host keys missing, or SSH connection failed.
- The GUI must not persist terminal input or output in v1.

States:

- Lab stopped or target unavailable: show the reason before attempting a PTY.
- Host keys missing: tell the operator to restart the lab. Do not offer a
  browser-side trust bypass.
- WebSocket closed: preserve the terminal surface and show reconnect controls.

### Config

Goal: expose enough non-secret configuration for orientation.

Low-fidelity layout:

```text
+--------------------------------------------------------------+
| Config                                                       |
+--------------------------------------------------------------+
| Lab profile                                                  |
| name | subnet | run storage | enabled families               |
|                                                              |
| Web serve                                                    |
| bind mode | allowed origins | build version | API origin      |
|                                                              |
| Service links                                                |
| service | local URL | status | notes                         |
|                                                              |
| Secrets                                                      |
| tokens and credentials are intentionally hidden              |
+--------------------------------------------------------------+
```

Interaction details:

- Show lab name, network subnet, enabled container families, run storage
  backend, web serve bind mode, allowed origin summary, and links to published
  service URLs where those URLs are non-secret.
- Do not show `APTL_API_TOKEN`, private key paths with sensitive context,
  service passwords, cookies, generated secrets, or raw `.env` content.
- This page is read-only in v1.

### Settings Dialog

Goal: let a local operator adapt the workbench without changing the lab.

Low-fidelity layout:

```text
+---------------- Settings ----------------+
| Appearance                               |
| color mode      [system v]              |
| density         [comfortable v]         |
| motion          [system v]              |
|                                          |
| Locale and time                          |
| language        [browser default v]     |
| time display    [local time v]          |
|                                          |
| SIEM defaults                            |
| time range      [1 hour v]              |
| row limit       [100 v]                 |
|                                          |
| Terminal                                 |
| font size       [-] 14 [+]              |
| scrollback      [1000 lines v]          |
|                                          |
| [Reset preferences]              [Done] |
+------------------------------------------+
```

Interaction details:

- Settings open from `NavBar` and return focus to the triggering control when
  closed.
- The dialog is not a substitute for configuration. It changes local UI
  presentation only.
- Controls use selects, segmented controls, toggles, or steppers. Avoid free
  text except where the value is naturally textual.
- Preference writes are immediate, local, schema-versioned, and reversible
  through Reset.
- Invalid stored preferences fall back to defaults with no blocking error.

### Local Use and Privacy Notice

Goal: make local-lab privacy and authorized-use boundaries explicit without
adding a SaaS consent pattern.

Low-fidelity layout:

```text
+---------- Authorized local lab use ----------+
| APTL controls a local security lab. Use this |
| surface only for authorized lab activity.    |
|                                              |
| This browser stores local UI preferences. It |
| does not store API tokens or terminal output |
| in v1. Server logs may contain redacted route |
| and status metadata.                         |
|                                              |
| [Privacy details]             [Acknowledge] |
+----------------------------------------------+
```

Interaction details:

- Show this notice before the first mutating lab action, terminal launch, or
  SIEM query execution, not on every page load.
- Acknowledgement stores only the notice version and timestamp in local
  preferences.
- Privacy details can be a help panel or static route. They must be reachable
  after acknowledgement.
- If the user resets preferences, the notice can appear again before the next
  controlled action.

## Component Inventory

Existing components to reuse:

| Component | Role in v1 |
| --- | --- |
| `NavBar` | Top-level navigation and lab status entry point. |
| `LabStatusBadge` | Compact running/stopped status. Extend only if ADR-030 outcome labels are needed in a compact control. |
| `LabStartNotice` | Authoritative startup/degraded/failure diagnostics rendering. |
| `ContainerGrid` and `ContainerCard` | Lab Home container summary and terminal entry points. |
| `ScenarioCard` | Catalog entry summary. |
| `Terminal` | xterm.js terminal implementation. |
| `WorkbenchStatusBar` | Sticky scenario context, container pills, points. |
| `NarrativeBlock` | Markdown narrative. |
| `AttackStepBlock` | Scenario step, copy command, detection expectations, lazy terminal. |
| `ObjectiveBlock` and `HintToggle` | Red/blue objectives and progressive hints. |
| `SiemQueryBlock` | Starting point for query display and live execution. |
| `TerminalBlock` | Inline terminal frame within a scenario. |

New or expanded components for UI-008:

| Component | Purpose | Based on |
| --- | --- | --- |
| `RoleGroupedContainerGrid` | Group containers by lab role or network when endpoint metadata supports it. | `ContainerGrid`, `ContainerCard`. |
| `KillConfirmDialog` | Confirm emergency kill scope. | Existing button and notice styling. |
| `ScenarioCatalogFilters` | Filter scenario cards by tag, mode, and difficulty. | `ScenarioCard`. |
| `SiemQueryExplorer` | Query pack list, editor, run control, and results shell. | `SiemQueryBlock`. |
| `SiemResultsTable` | Bounded alert rows with expandable details. | Existing table/card density from workbench blocks. |
| `ConfigSummaryList` | Read-only config facts with secret-safe omission states. | `ContainerCard` density and `LabStartNotice` severity language. |
| `SettingsDialog` | Local preferences for appearance, density, locale, time display, SIEM defaults, and terminal rendering. | `NavBar` action plus accessible dialog primitive. |
| `LocalUseNoticeDialog` | First-run acknowledgement for authorized local lab use and privacy summary. | Accessible dialog primitive and existing notice severity language. |
| `PrivacyDetailsPanel` | Persistent help/privacy disclosure for local storage and redacted server logging facts. | Help menu or secondary app-shell panel. |

Do not introduce a component library reset or a new theme. Continue the current
Tailwind v4 token names in `web/src/app.css`. The current palette is acceptable
because it is already the repo's ADR-011 workbench identity; avoid expanding it
into a one-color purple dashboard. UI-008 should also audit `web/src/app.css`
for system-font fallback, contrast, semantic status colors, reduced-motion
behavior, and high-contrast overrides before adding new visual tokens.

## API and Data Contracts

Existing contracts:

| Contract | Status |
| --- | --- |
| `GET /api/health` | Exists and is bearer-protected. |
| `GET /api/lab/status` | Exists; drives status, container cards, and SSE baseline. |
| `GET /api/lab/events` | Exists; SSE stream for lab status changes. |
| `POST /api/lab/start` | Exists; returns ADR-030 diagnostics. |
| `POST /api/lab/stop` | Exists. |
| `POST /api/lab/kill` | Exists; needs destructive UI confirmation. |
| `GET /api/config` | Exists; returns non-secret configuration projection. |
| `WS /api/terminal/ws/{container}` | Exists; validates auth, origin, allow-list, lab state, endpoint projection, and host-key pins. |

Required UI-008 contracts:

| Contract | Owner | Notes |
| --- | --- | --- |
| `GET /api/scenarios` | New FastAPI router with DTOs in `src/aptl/api/schemas.py`. | Narrow ACES/catalog summary projection. Include id, name, description, mode, difficulty, time, tags, required containers, and validation/status summary. |
| `GET /api/scenarios/{id}` | Same router. | Workbench detail projection. Source stays ACES/catalog authority. |
| `GET /api/siem/queries` | New or existing SIEM integration owner. | Curated query packs, including scenario-linked packs. |
| `POST /api/siem/query` | Same owner. | Bounded query execution with validation, time range, row cap, stable errors, and redacted details. |
| `GET /api/web/status` | Optional. | Read-only shipped web metadata such as bind mode and asset build version. Do not expose secrets. |

Rules:

- Python DTOs own the wire contract. Svelte types mirror them.
- API routes call existing core helpers and typed deployment/backend owners.
- No route accepts raw Docker args, raw shell args, or unbounded OpenSearch
  query bodies.
- Local preference settings do not need an API in v1. Keep them browser-local
  unless a later issue explicitly scopes synchronized preferences.
- All new Python routes get pytest coverage in `tests/`.
- All new Svelte behavior gets vitest coverage in `web/tests/`.

## Authentication and Security UX

The GUI should make secure operation understandable without exposing secrets.

Required states:

- API token missing: show a service configuration error and a safe generation
  hint. Never print the current value.
- Unauthorized API request: show a generic auth-required state. Do not say
  whether the token was missing, malformed, or wrong.
- Cross-origin mutating request rejected: keep the generic proxy error text in
  the browser path. The operator does not need attacker-origin details in UI.
- Non-loopback bind, if a future mode supports it: show an explicit risk banner
  that names the operator decision. This is not a default mode.
- Terminal rejected: show one of the narrow terminal reasons listed above.

Security invariants:

- No token in URLs, route params, query strings, screenshots, examples, logs,
  browser local storage, or command strings.
- No private key contents or generated secret values in UI state.
- No generic command execution from the browser.
- No terminal trust bypass.
- No CORS-as-auth claim.
- No UI-only readiness reclassification.

## UI-008 Acceptance Checklist

The implementation issue can use this checklist:

- `aptl web serve` serves the built GUI and API from a single loopback operator
  origin.
- `/` renders lab state, startup diagnostics, lifecycle controls, container
  summary, and scenario entry points.
- `/scenarios/[id]` renders the scenario workbench from a backend-owned
  catalog projection.
- `/siem` executes bounded live SIEM queries and renders results.
- `/terminal/[container]` and inline terminal blocks preserve ADR-039 and
  ADR-040 gates.
- `/config` shows non-secret configuration only.
- `SettingsDialog` persists only non-secret local UI preferences and offers a
  reset control.
- Local-use and privacy notice appears before the first controlled action and
  remains reachable after acknowledgement.
- Destructive actions require confirmation.
- UI satisfies the accessibility requirements above, including keyboard route
  walks, focus management, non-color status cues, contrast, target sizing, and
  accessible modal behavior.
- UI copy is translation-ready and date/time/count formatting goes through
  shared helpers.
- Visual implementation avoids the documented generic AI-design anti-patterns.
- Every new API DTO has a Svelte mirror and tests.
- Every new source path has pytest or vitest coverage as required by
  `.gc/plan-rules.md`.
- Documentation and the Conventional Commit PR title describe the shipped behavior.

## Requirement Mapping

| UI-007 clause | Design coverage |
| --- | --- |
| Information architecture | Information Architecture and Route Contracts sections. |
| Route map | Route Contracts section. |
| Per-page interaction design | Page Designs section. |
| Human investigation versus read-only status | Product Scope, Route Contracts, and each page's surface class. |
| Component inventory | Component Inventory section. |
| Existing Svelte alignment | Component Inventory and API/Data Contracts reuse existing `web/src/lib` owners. |
| Auth and security UX | Authentication and Security UX section. |
| Accessibility and localization groundwork | Accessibility and Language/Locale Readiness sections. |
| Persistent local settings | Settings and Persistence plus Settings Dialog sections. |
| Terms/privacy UX | Legal and Privacy UX plus Local Use and Privacy Notice sections. |
| Professional visual direction | Design Inputs and Visual Direction section. |
| Derived from UI-006 | Product Scope section records the scope baseline. |
| Build specification for UI-008 | UI-008 Acceptance Checklist and API/Data Contracts sections. |
