# ADR-012: OpenTelemetry Integration

**Status:** Accepted
**Date:** 2026-03-21
**Updated:** 2026-09-11
**Deciders:** Brad Edwards

## Context

APTL had two custom JSONL tracing systems:

1. **Python `EventLog`**—per-scenario JSONL files recording lifecycle events
   (start, stop, preconditions, objectives, hints, evaluations).
2. **TypeScript `ToolTracer`**—per-MCP-server JSONL files recording every
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

The OTel stack is backend-owned lab infrastructure. Its activation is subject
to scope and minimum-intrusion admission, superseding the earlier unconditional
"always-on" policy:

- **OTel Collector** (`otel/opentelemetry-collector-contrib`)—receives OTLP,
  batches, forwards to Tempo
- **Grafana Tempo**: trace storage with 72h retention
- **Grafana**: trace visualization at `http://localhost:3100` (bound to
  localhost only; username `admin`, with the generated password recorded in
  the operator `.env` file)

All services run under the `otel` Docker Compose profile. The local deployment
backend owns their Compose definition and lifecycle, independently of whether
an env-pack has a Compose file or image-backed nodes. They are not scenario
nodes. The backend's default profile selection is filtered by evidence and
scope admission; it is neither unconditional authority to add apparatus nor a
reason to make scenario data the topology authority for these services.

Host-published observability surfaces are operator/control-plane infrastructure,
not target attack surface. Per ADR-034 and ADR-039, the default Compose host
publishes for the Collector OTLP receivers, Tempo HTTP API, and Grafana UI bind
to `127.0.0.1`. Container-side listeners may remain wildcard-bound for
Docker-network peers; remote OTLP ingestion or Tempo access requires an explicit
documented deployment mode with authentication or network controls rather than
scattered `0.0.0.0` host publishes.

Loopback is a reachability boundary, not producer authentication. The local
OTLP receivers and the Collector-to-Tempo hop are unauthenticated, so this
deployment does not establish signed origin, exclusive-producer integrity, or
chain of custody. Capture admission and evidence records must retain that
distinction; a content checksum proves retained bytes, not who emitted them.
Grafana and Tempo are operator surfaces and must not enter participant endpoint
or credential projections.

Tempo's 72-hour storage is a bounded operational query buffer, not the
retention contract for admitted evidence. Evidence that satisfies an authored
retention requirement is finalized through the existing capture coordinator
and content-addressed `LocalRunStore`; Grafana is an operator view, not an
evidence repository. Authored availability or deletion obligations also apply
to retained buffer copies; the 72-hour default cannot override them. Collector
logs must not become a second trace sink.

### Evidence-Capture Contract

Running Collector, Tempo, and Grafana proves only that the apparatus is
available. It does not prove that an authored `evidence_requirements` entry was
captured or that its redaction, integrity, retention, or loss-disclosure terms
were met.

The existing versioned collector registry admits normalized RAES capture
demands into immutable `CaptureBinding` values; the evidence coordinator
acquires them and persists public RAES evidence records. Issue #992 connects
scenario evidence intent through RAES 4.1's public
`compile_scenario_capture_demands()` boundary, preserving its distinct
vocabulary and references. This ADR does not claim that arbitrary retention
semantics are implemented beyond the exact registered policies.
The Tempo trace adapter is one trusted source behind that boundary; the
presence of the OTel stack must not make it match a different channel or media
contract. Scenario evidence intent and experiment capture contracts remain
RAES-owned shapes and must not be copied into a local OTel schema.

Redaction occurs at the shared producer/serialization and evidence-persistence
boundaries described below, before sensitive structured data is exported or
stored. Retention policies must be enforced by their exact admitted semantics,
not by treating a generic capability flag or Tempo's TTL as equivalent.
Required loss disclosure must distinguish an empty successful capture from
export failure, source unavailability, drops, truncation, timeout, and
finalization failure. A best-effort OTel SDK path may degrade silently only
when no admitted requirement depends on it.

Backend ownership does not bypass RAES open/closed scope semantics. Capture
must satisfy every SDL evidence requirement. Closed scopes prohibit intrusion
into the scenario's in-principle visible world. Open scopes require the least
intrusive supported option that genuinely meets the need, not every addition
the scope would permit. Prefer existing native readback over added logging
agents or a stack whenever that readback meets the full evidence contract.
Fail admission if no compliant option does so; never weaken evidence promises
or widen a closed scope to obtain admission.

In particular, TechVault's host-root-equivalent Docker authority makes a
same-daemon stack visible despite its private network. Its `raes-env-packs`
6.0.0 requirements cover Cortex enrichment readback, Suricata local-rule
readiness, correlated Suricata/Wazuh SQLi evidence, and the red-team session
transcript. They have native source boundaries and do not activate OTel. Omit
the stack even in an open scope and report the absent operator view. This does
not permit permanent rejection as a substitute for implementing those required
native sources. Report every actual observability addition through runtime
observation, including anything not explicitly requested by the SDL, with
native evidence of what was realized rather than a plan echo.
The [issue #992 preflight](../architecture/issue-992-backend-observability-ownership-preflight.md)
records the cross-cutting guardrails and remaining contract gaps.

### GenAI SIG Conventions

MCP tool spans follow the [OpenTelemetry GenAI SIG](https://github.com/open-telemetry/semantic-conventions/tree/main/docs/gen-ai)
attribute conventions: `gen_ai.operation.name`, `gen_ai.tool.name`,
`gen_ai.agent.name`.

### Security Guardrail: No Secrets in Telemetry or Run Artifacts

Telemetry and run archives are analysis artifacts, not credential stores. Values
written to OTel span attributes, `snapshot.json`, CLI JSON output, or exported
run archives must be redacted before serialization. File permissions such as
`0600` are defense in depth, not a substitute for redaction, because run
artifacts are routinely viewed, exported, copied, and attached to issue reports.

Use one shared redaction policy per language boundary rather than ad hoc
call-site filtering:

- Python snapshot/archive serialization should sanitize at the `RangeSnapshot`
  DTO boundary, so every caller of `to_dict()` receives the same safe shape.
- TypeScript MCP telemetry should sanitize inside the common telemetry wrapper
  before setting span attributes, so individual tool handlers do not own
  tracing-specific redaction.
- Redaction must recurse through dict/object and list/array values, preserve
  non-secret diagnostic structure, and replace secret values with a stable
  marker such as `[REDACTED]`.
- Treat key names containing credential material (`password`, `pass`, `secret`,
  `token`, `api_key`, `apikey`, `authorization`, `cookie`, `jwt`, `key`,
  `credential`) as sensitive, and keep path-like public references such as
  SSH key paths distinct from private key material.
- Tests must assert both the safe output shape and absence of representative
  known lab defaults/API tokens in JSON and span attributes.

## Consequences

### Positive

- Industry-standard tracing format; queryable via Tempo API and Grafana UI
- Distributed tracing links Python CLI and TypeScript MCP server spans
- Real-time visibility into running scenarios (not just post-hoc)
- Run archives contain complete trace data in `traces/spans.json`
- Best-effort tracing can remain available when the Collector is unreachable;
  admitted evidence capture must instead report the resulting unavailability
  or loss through the evidence outcome contract

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

- `src/aptl/core/telemetry.py`: Python OTel module
- `mcp/aptl-mcp-common/src/telemetry.ts`: TypeScript OTel module
- `config/otel/*.yaml`: Collector, Tempo, Grafana configs
- `tests/test_telemetry.py`: Python telemetry tests

### Run Archive Format Change

| Old | New |
|---|---|
| `scenario/events.jsonl` | *(removed)* |
| `agents/traces.jsonl` | *(removed)* |
| *(none)* | `traces/spans.json` |
| manifest lacks `trace_id` | manifest includes `trace_id` |
