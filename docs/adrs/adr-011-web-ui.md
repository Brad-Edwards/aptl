# ADR-011: Notebook-Style Web UI (SvelteKit + FastAPI)

## Status

accepted

## Date

2026-03-20

## Context

APTL's primary interface is a Python CLI ([ADR-007](adr-007-python-cli-control-plane.md)). While effective for lab lifecycle management and scenario execution, the CLI has limitations for:

1. **Scenario execution**: Following multi-step attack/defense scenarios requires switching between terminal windows (Kali SSH, victim SSH, SIEM queries) and mentally correlating events across them.
2. **SIEM data visualization**: Wazuh Dashboard provides some visualization, but correlating SIEM alerts with scenario steps, network IDS events, and case management data requires multiple browser tabs.
3. **Data collection review**: Run archives from the scenario engine ([ADR-009](adr-009-scenario-engine.md)) are JSON files on disk. Comparing runs requires manual inspection.

### Design Constraint

The UI must be **visually distinct from enterprise SOC/XDR-style mission control dashboards** — the dark tile grids with icon sidebars, status dot matrices, and pill buttons used by products like Cortex XDR, Splunk SOAR, or SecurityOnion. Those suit enterprise demo platforms but are the wrong paradigm for a personal training lab. APTL needs something that feels like a different product category entirely.

This constraint comes from the user's concurrent work on an enterprise security product (`../shifter`) — APTL's UI must not look or feel like a second version of the same thing.

## Decision (Proposed)

Adopt an **interactive workbench** paradigm — closer to a Jupyter notebook or VS Code than a SOC console. The user works through a linear, scrollable document that interleaves narrative context, live system state, interactive controls, and terminal output.

### Why This Paradigm

- A training lab is inherently **sequential and educational** — the user follows scenarios step by step. A notebook captures this flow naturally.
- Unlike an enterprise dashboard where operators monitor passively, APTL users **actively do things** — run commands, read output, correlate results. The workbench puts actions and results in a single scrollable flow.
- It avoids the visual language of enterprise security products entirely — no tile grids, no icon-only sidebars, no status dot matrices.
- It naturally supports **mixed content**: markdown instructions, live terminal embeds, SIEM query results, container status widgets, all inline.

### Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Frontend | **SvelteKit** | Lighter than Next.js, excellent for interactive document-style UIs, SSR, distinct ecosystem choice |
| Language | TypeScript | Shared types with MCP servers |
| Components | **Skeleton UI** + Tailwind CSS | Clean Svelte component library with good theming |
| Real-time | **SSE** + WebSocket | SSE for one-way streams (container status, log tailing, alerts). WebSocket only for bidirectional terminal I/O via xterm.js. |
| Terminal | **xterm.js** | In-browser terminal for SSH sessions |
| Markdown | mdsvex or unified/remark | Render scenario content as rich markdown with embedded interactive components |
| Charts | LayerChart or Pancake | Svelte-native charting, no React dependency |
| Backend | **FastAPI** | Python backend sharing `src/aptl/core/` domain logic. Same core modules used by CLI and web API. |

### Key Views

**Lab Home**: Minimal landing page. Lab state (running/stopped), active containers, scenario list as cards with difficulty badges. Large Start/Stop button.

**Scenario Workbench** (core experience): Scrollable document with interleaved content blocks:
- Narrative blocks (markdown scenario instructions)
- Terminal blocks (xterm.js connected to specific containers)
- SIEM query blocks (inline OpenSearch queries with results tables)
- Container status blocks (live health indicators)
- Hint toggles (progressive disclosure of guidance)

**Container Inspector**: Slide-over panel (not a separate page) with container details, live log stream, quick terminal access, restart/rebuild actions.

**SIEM Explorer**: Dedicated page for open-ended SIEM exploration — query builder, alert timeline, results with expandable rows. Closer to Kibana's Discover tab than a SOC dashboard.

### Design Language

- **Dark theme primary**: Dark surfaces with warm neutrals (slate/zinc tones, not pure black `#000`). Light theme available as toggle.
- **Color accent: indigo/violet**: Purple team identity. Indigo for primary actions, violet for red team markers, teal for blue team/defensive markers.
- **Typography**: Inter or IBM Plex Sans for UI text; JetBrains Mono for code/terminal/data
- **Generous whitespace**: Learning environment — readability over information density
- **Rounded corners, soft shadows**: Approachable, not industrial. Think Notion or Linear, not Splunk.
- **Top navigation bar**: Simple text navigation, not a collapsible icon sidebar

### Real-Time Architecture

```
Browser (SvelteKit)
    ├── REST API (initial load, mutations)
    │   └── FastAPI backend
    │       ├── Docker SDK (container management)
    │       ├── OpenSearch client (Wazuh alerts/logs)
    │       └── Scenario runner (subprocess for setup/cleanup)
    ├── SSE (one-way server push)
    │   ├── Container status events
    │   ├── Log streams
    │   ├── SIEM alert feed
    │   └── Scenario step progress
    └── WebSocket (bidirectional, terminal only)
        └── xterm.js ↔ SSH via asyncssh
```

### How This Differs from Enterprise Dashboards

| Aspect | Enterprise SOC / Mission Control | APTL Workbench |
|--------|----------------------------------|----------------|
| Layout | Fixed grid of tiles/cards | Scrollable document with inline blocks |
| Navigation | Icon sidebar with submenu panels | Top bar or simple text sidebar |
| Theme | Cold industrial dark (#000/#151515) | Warm dark (slate/zinc tones) |
| Typography | Dense system sans-serif | Inter/Plex, generous spacing |
| Primary metaphor | Control room / monitoring wall | Lab notebook / interactive textbook |
| Information density | High (many widgets visible) | Progressive (expand on demand) |
| Color language | Green/red/amber status dots | Indigo/violet/teal palette |
| Interaction model | Click tiles, monitor passively | Scroll, type, read, learn |

## Consequences

### Positive

- **Unified experience**: Scenario instructions, terminal access, SIEM queries, and container management in one scrollable view instead of multiple windows/tabs
- **Shared backend**: FastAPI imports `src/aptl/core/` directly — no duplication of lab management logic between CLI and web
- **Distinct identity**: The notebook paradigm and indigo/violet palette are visually unrelated to enterprise SOC dashboards
- **Educational fit**: The document-first approach naturally supports the scenario-driven, step-by-step learning model

### Negative

- **Development effort**: A full web UI is a significant new surface area — frontend framework, backend API, real-time infrastructure, terminal integration, authentication
- **Maintenance burden**: Two interfaces (CLI + web) must stay in sync as core functionality evolves
- **SvelteKit ecosystem**: Smaller ecosystem than React/Next.js. Fewer pre-built components, fewer tutorials, smaller hiring pool.

### Risks

- Scope creep: The web UI could absorb unlimited development time. Must be scoped to a focused MVP (Lab Home + Scenario Workbench) before expanding to SIEM Explorer and Container Inspector.
- xterm.js + WebSocket SSH is a complex integration with security implications (SSH sessions from browser to containers). Requires careful authentication and session management.
- The SSE + WebSocket dual approach adds complexity compared to WebSocket-only, but SSE is simpler for the common one-way streaming case and gracefully handles reconnection.
