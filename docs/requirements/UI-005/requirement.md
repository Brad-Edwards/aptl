---
id: UI-005
title: "SSE + WebSocket Real-Time Architecture"
status: ACTIVE
type: NON_FUNCTIONAL
priority: COULD
wave: 5
created_at: 2026-03-20T06:12:54.875473Z
updated_at: 2026-03-21T06:50:09.082290Z
---

# UI-005 — SSE + WebSocket Real-Time Architecture

## Statement

The web UI shall use Server-Sent Events (SSE) for one-way streams (container status, scenario progress) and WebSocket only for bidirectional terminal I/O.

## Rationale

SSE is simpler for the common one-way streaming case and handles reconnection gracefully. SIEM alert streaming and log tailing are removed — humans use Wazuh Dashboard for alert investigation and docker logs for tailing.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-011-web-ui.md` (ADR-011: Web UI)
- IMPLEMENTS → CODE_FILE `src/aptl/api/routers/terminal.py` (WebSocket endpoint for bidirectional terminal I/O)
