---
id: UI-003
title: "xterm.js Terminal for Container SSH"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 5
created_at: 2026-03-20T06:12:49.163849Z
updated_at: 2026-03-21T03:52:23.815068Z
---

# UI-003 — xterm.js Terminal for Container SSH

## Statement

The web UI shall provide in-browser terminals via xterm.js connected to container SSH sessions over WebSocket, enabling command execution within scenario workbench blocks.

## Rationale

Terminal access within the workbench eliminates switching to external terminal windows.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-011-web-ui.md` (ADR-011: Web UI)
- IMPLEMENTS → GITHUB_ISSUE `221` (UI-003: xterm.js Terminal for Container SSH)
- IMPLEMENTS → CODE_FILE `src/aptl/api/routers/terminal.py` (WebSocket terminal endpoint (asyncssh PTY relay))
- IMPLEMENTS → CODE_FILE `web/src/lib/components/Terminal.svelte` (xterm.js terminal Svelte component)
- IMPLEMENTS → CODE_FILE `web/src/routes/terminal/[container]/+page.svelte` (Terminal page route)
- IMPLEMENTS → CODE_FILE `web/src/lib/components/ContainerCard.svelte` (ContainerCard with Terminal link for SSH containers)
- TESTS → TEST `tests/test_api_terminal.py` (WebSocket terminal endpoint tests (8 tests))
