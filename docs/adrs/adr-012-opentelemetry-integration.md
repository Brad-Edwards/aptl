# ADR-012: OpenTelemetry Integration

**Status:** Accepted
**Date:** 2026-03-21
**Deciders:** Brad Edwards

## Context

APTL had two custom JSONL tracing systems:

1. **Python `EventLog`** — per-scenario JSONL files recording lifecycle events
   (start, stop, preconditions, objectives, hints, evaluations).
2. **TypeScript `ToolTracer`** — per-MCP-server JSONL files recording every
   tool invocation with arguments, responses, timing, and errors.

At run assembly, `collect_mcp_traces()` read JSONL files from disk and merged
them into the run archive. Events were serialized as a list of dicts.

Neither system was queryable in real-time, neither followed a standard format,
and neither supported distributed tracing across the Python CLI and TypeScript
MCP server processes.

## Decision

Replace both custom systems with [OpenTelemetry](https://opentelemetry.io/).
OTel becomes the single tracing path with no JSONL fallback or dual code paths.

### Span Hierarchy

```
[Scenario Run]  aptl.scenario.run        (root span, backdated at stop)
  +-- [Precondition]  aptl.precondition   (child span from CLI)
  +-- [Objective]     aptl.objective      (child span from CLI)
  +-- [Alert Match]   (span event)
  +-- [Hint Request]  (span event)
  +-- [Evaluation]    aptl.evaluation     (child span from CLI)
  +-- [Tool Call]     execute_tool        (child span from MCP server)
```

### Cross-Process Propagation

MCP servers are started by the AI agent host (Claude Desktop), not the CLI.
They are already running when `scenario start` is called. Propagation uses a
shared file:

1. `scenario start` generates `trace_id` + `span_id`, writes `.aptl/trace-context.json`
2. MCP servers read this file on each tool call; if present, tool spans use
   that `trace_id` as parent
3. `scenario stop` creates a synthetic root span with `start_time=session.started_at`
4. After flushing, `scenario stop` queries Tempo for all spans, writes to run archive

### Transport

Both Python and TypeScript use **HTTP/protobuf on port 4318** to avoid native
gRPC binding issues in Node.js. The standard `OTEL_EXPORTER_OTLP_ENDPOINT`
env var controls the endpoint.

### Infrastructure

The OTel stack is always-on lab infrastructure (not optional):

- **OTel Collector** (`otel/opentelemetry-collector-contrib`) — receives OTLP,
  batches, forwards to Tempo
- **Grafana Tempo** — trace storage with 72h retention
- **Grafana** — trace visualization at `http://localhost:3100`

All services run under the `otel` Docker Compose profile, automatically
included by `aptl lab start`.

### GenAI SIG Conventions

MCP tool spans follow the [OpenTelemetry GenAI SIG](https://github.com/open-telemetry/semantic-conventions/tree/main/docs/gen-ai)
attribute conventions: `gen_ai.operation.name`, `gen_ai.tool.name`,
`gen_ai.agent.name`.

## Consequences

### Positive

- Industry-standard tracing format; queryable via Tempo API and Grafana UI
- Distributed tracing links Python CLI and TypeScript MCP server spans
- Real-time visibility into running scenarios (not just post-hoc)
- Run archives contain complete trace data in `traces/spans.json`
- OTel SDK gracefully degrades — if Collector is unreachable, spans are silently dropped

### Negative

- **Breaking change**: Old run archives have `scenario/events.jsonl` and
  `agents/traces.jsonl`; new archives have `traces/spans.json`. No migration
  tool provided (old archives remain readable by hand).
- Three additional Docker containers (~1 GB combined memory)
- OTel SDK adds dependencies to both Python and TypeScript packages

### Files Removed

- `src/aptl/core/events.py` (EventLog, EventType, Event, make_event)
- `mcp/aptl-mcp-common/src/tracing.ts` (ToolTracer, ToolTrace)
- `tests/test_events.py`

### Files Added

- `src/aptl/core/telemetry.py` — Python OTel module
- `mcp/aptl-mcp-common/src/telemetry.ts` — TypeScript OTel module
- `config/otel/*.yaml` — Collector, Tempo, Grafana configs
- `tests/test_telemetry.py` — Python telemetry tests

### Run Archive Format Change

| Old | New |
|---|---|
| `scenario/events.jsonl` | *(removed)* |
| `agents/traces.jsonl` | *(removed)* |
| *(none)* | `traces/spans.json` |
| manifest lacks `trace_id` | manifest includes `trace_id` |
