---
id: OBS-001-DUP-1
title: "OpenTelemetry Integration"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:50:32.168003Z
updated_at: 2026-03-22T00:06:14.737359Z
---

# OBS-001-DUP-1 — OpenTelemetry Integration

## Statement

The platform shall replace custom JSONL tracing with OpenTelemetry SDK instrumentation using GenAI SIG semantic conventions, enabling telemetry ingestion by standard observability backends (Grafana, Jaeger, Honeycomb).

## Rationale

Custom JSONL traces are not ingestible by any standard observability tool. OpenTelemetry GenAI SIG is defining standard semantic conventions for AI agent observability (tasks, actions, agents, artifacts, memory).

## Traceability

- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/telemetry.ts` (TypeScript OTel telemetry module)
- IMPLEMENTS → CONFIG `config/otel/otel-collector-config.yaml` (OTel Collector configuration)
- TESTS → TEST `mcp/aptl-mcp-common/tests/telemetry.test.ts` (TypeScript OTel telemetry tests)
- IMPLEMENTS → CONFIG `pyproject.toml` (pyproject.toml (OTel Python dependencies))
- IMPLEMENTS → CONFIG `config/otel/grafana-datasources.yaml` (Grafana datasources (Tempo integration))
- TESTS → TEST `tests/test_session.py` (Session tests (OTel instrumented))
- IMPLEMENTS → CODE_FILE `src/aptl/core/session.py` (Python session management (OTel instrumented))
- IMPLEMENTS → CODE_FILE `src/aptl/core/collectors.py` (Python collectors (OTel instrumented))
- IMPLEMENTS → CODE_FILE `src/aptl/core/runstore.py` (Run store (OTel instrumented))
- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/server.ts` (MCP common server (OTel instrumented))
- IMPLEMENTS → CONFIG `config/otel/tempo-config.yaml` (Grafana Tempo configuration)
- IMPLEMENTS → CONFIG `docker-compose.yml` (Docker Compose (OTel Collector + Tempo services))
- DOCUMENTS → ADR `docs/adrs/adr-012-opentelemetry-integration.md` (ADR-012: OpenTelemetry Integration)
- TESTS → TEST `tests/test_telemetry.py` (Python OTel telemetry tests)
- IMPLEMENTS → GITHUB_ISSUE `PR #226` (OBS-001 OpenTelemetry Integration Full Refactor)
- IMPLEMENTS → CONFIG `mcp/aptl-mcp-common/package.json` (MCP common package.json (OTel dependencies))
- IMPLEMENTS → CODE_FILE `src/aptl/core/telemetry.py` (Python OTel telemetry module)
- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/index.ts` (MCP common index (OTel exports))
- TESTS → TEST `tests/test_collectors.py` (Collector tests (OTel instrumented))
