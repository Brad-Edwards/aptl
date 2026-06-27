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

- multi-user accounts, RBAC, OAuth, OIDC, password login, or long-lived browser
  sessions;
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

## Information Architecture

The v1 nav is deliberately small:

- **Lab**: default route and operator status.
- **Scenarios**: catalog access, surfaced on Lab Home and deep-linked by
  scenario route.
- **SIEM**: live detection query explorer.
- **Config**: non-secret lab and web settings.
- **Terminal**: not a global nav tab; opened from container cards or scenario
  steps.

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
| APTL                  Lab | Scenarios | SIEM | Config  status |
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

Interaction details:

- Show lab name, network subnet, enabled container families, run storage
  backend, web serve bind mode, allowed origin summary, and links to published
  service URLs where those URLs are non-secret.
- Do not show `APTL_API_TOKEN`, private key paths with sensitive context,
  service passwords, cookies, generated secrets, or raw `.env` content.
- This page is read-only in v1.

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

Do not introduce a component library reset or a new theme. Continue the current
Tailwind v4 token names in `web/src/app.css`. The current palette is acceptable
because it is already the repo's ADR-011 workbench identity; avoid expanding it
into a one-color purple dashboard.

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
- Destructive actions require confirmation.
- Every new API DTO has a Svelte mirror and tests.
- Every new source path has pytest or vitest coverage as required by
  `.gc/plan-rules.md`.
- Documentation and changelog fragments describe the shipped behavior.

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
| Derived from UI-006 | Product Scope section records the scope baseline. |
| Build specification for UI-008 | UI-008 Acceptance Checklist and API/Data Contracts sections. |
