"""OpenTelemetry tracing for APTL.

Provides the single tracing path for both scenario lifecycle events
(from the Python CLI) and MCP tool calls (from TypeScript servers,
via shared trace context). Replaces the former EventLog and ToolTracer
JSONL systems.

Span hierarchy:
    [Scenario Run]  aptl.scenario.run       (root, backdated at stop)
      +-- [Precondition]  aptl.precondition  (child)
      +-- [Objective]     aptl.objective     (child)
      +-- [Alert Match]   (span event on root)
      +-- [Hint Request]  (span event on root)
      +-- [Evaluation]    aptl.evaluation    (child)
      +-- [Tool Call]     execute_tool       (child from MCP server)
"""

import json
import os
import secrets
from pathlib import Path

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    SpanKind,
    StatusCode,
    TraceFlags,
)

from aptl.utils.logging import get_logger

log = get_logger("telemetry")

# ---------------------------------------------------------------------------
# Span name constants (replacing EventType enum)
# ---------------------------------------------------------------------------

SPAN_SCENARIO_RUN = "aptl.scenario.run"
SPAN_PRECONDITION = "aptl.precondition"
SPAN_OBJECTIVE = "aptl.objective"
SPAN_EVALUATION = "aptl.evaluation"
EVENT_ALERT_MATCHED = "alert_matched"
EVENT_HINT_REQUESTED = "hint_requested"

# Module-level provider reference for shutdown
_provider: TracerProvider | None = None


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def init_tracing(service_name: str = "aptl-cli") -> None:
    """Configure OTel TracerProvider with OTLP HTTP exporter.

    Safe to call multiple times — subsequent calls are no-ops if
    already initialized. If the Collector is unreachable,
    BatchSpanProcessor silently drops spans (not fatal).
    """
    global _provider
    if _provider is not None:
        return

    endpoint = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"
    )

    resource = Resource.create({"service.name": service_name})
    _provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces")
    _provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(_provider)

    log.debug("OTel tracing initialized: service=%s endpoint=%s", service_name, endpoint)


def shutdown_tracing() -> None:
    """Force-flush and shutdown the TracerProvider."""
    global _provider
    if _provider is not None:
        _provider.force_flush()
        _provider.shutdown()
        _provider = None
        log.debug("OTel tracing shut down")


def get_tracer(name: str = "aptl") -> trace.Tracer:
    """Return a Tracer from the current provider."""
    return trace.get_tracer(name)


# ---------------------------------------------------------------------------
# Cross-process trace context
# ---------------------------------------------------------------------------

_TRACE_CONTEXT_FILENAME = "trace-context.json"


def generate_trace_context() -> dict:
    """Generate a fresh trace_id and span_id for a new scenario run.

    Returns:
        Dict with ``trace_id``, ``span_id``, and ``trace_flags`` as
        zero-padded hex strings.
    """
    trace_id = secrets.token_hex(16)  # 32 hex chars = 128-bit
    span_id = secrets.token_hex(8)    # 16 hex chars = 64-bit
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "trace_flags": "01",  # sampled
    }


def write_trace_context(path: Path, trace_id: str, span_id: str) -> None:
    """Write trace context to a JSON file for MCP servers to read.

    Args:
        path: Directory to write ``trace-context.json`` into.
        trace_id: 32-char hex trace ID.
        span_id: 16-char hex span ID.
    """
    path.mkdir(parents=True, exist_ok=True)
    ctx_file = path / _TRACE_CONTEXT_FILENAME
    ctx_file.write_text(
        json.dumps(
            {"trace_id": trace_id, "span_id": span_id, "trace_flags": "01"},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    log.debug("Wrote trace context to %s", ctx_file)


def load_trace_context(path: Path) -> SpanContext | None:
    """Load trace context from the JSON file written by ``scenario start``.

    Args:
        path: Directory containing ``trace-context.json``.

    Returns:
        An OTel SpanContext, or None if the file doesn't exist or is invalid.
    """
    ctx_file = path / _TRACE_CONTEXT_FILENAME
    if not ctx_file.exists():
        return None

    try:
        data = json.loads(ctx_file.read_text(encoding="utf-8"))
        return SpanContext(
            trace_id=int(data["trace_id"], 16),
            span_id=int(data["span_id"], 16),
            is_remote=True,
            trace_flags=TraceFlags(int(data.get("trace_flags", "01"), 16)),
        )
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        log.warning("Could not load trace context from %s: %s", ctx_file, exc)
        return None


def make_parent_context(trace_id: str, span_id: str) -> Context:
    """Build an OTel Context with a remote parent span.

    Useful for CLI commands that need to create child spans under
    the scenario root (which lives as trace context, not as an
    active span in this process).
    """
    parent_span_context = SpanContext(
        trace_id=int(trace_id, 16),
        span_id=int(span_id, 16),
        is_remote=True,
        trace_flags=TraceFlags(0x01),
    )
    parent_span = NonRecordingSpan(parent_span_context)
    return trace.set_span_in_context(parent_span)


# ---------------------------------------------------------------------------
# Scenario spans
# ---------------------------------------------------------------------------


def create_root_span(
    tracer: trace.Tracer,
    scenario_id: str,
    run_id: str,
    start_time: int,
    end_time: int,
    trace_id: str,
    span_id: str,
) -> None:
    """Create and immediately end the synthetic root span for a scenario run.

    Called at ``scenario stop`` with backdated timestamps covering the
    full scenario duration. Uses the trace context generated at start.

    Args:
        tracer: OTel Tracer instance.
        scenario_id: Scenario identifier.
        run_id: Unique run identifier.
        start_time: Nanosecond epoch for span start.
        end_time: Nanosecond epoch for span end.
        trace_id: 32-char hex trace ID from session.
        span_id: 16-char hex span ID from session.
    """
    parent_ctx = make_parent_context(trace_id, span_id)
    span = tracer.start_span(
        name=SPAN_SCENARIO_RUN,
        context=parent_ctx,
        kind=SpanKind.INTERNAL,
        attributes={
            "aptl.scenario.id": scenario_id,
            "aptl.run.id": run_id,
        },
        start_time=start_time,
    )
    span.set_status(StatusCode.OK)
    span.end(end_time=end_time)
    log.debug("Created root span for scenario %s run %s", scenario_id, run_id)


def record_event(
    tracer: trace.Tracer,
    parent_ctx: Context,
    event_name: str,
    attributes: dict | None = None,
) -> None:
    """Record a span event on a lightweight child span.

    Used for alert matches, hint requests, and other point-in-time
    events that don't have meaningful duration.
    """
    span = tracer.start_span(
        name=event_name,
        context=parent_ctx,
        kind=SpanKind.INTERNAL,
    )
    if attributes:
        span.set_attributes(attributes)
    span.set_status(StatusCode.OK)
    span.end()


def create_child_span(
    tracer: trace.Tracer,
    parent_ctx: Context,
    name: str,
    attributes: dict | None = None,
) -> trace.Span:
    """Start a child span under the given parent context.

    The caller is responsible for ending the span.

    Returns:
        The started Span (still open).
    """
    span = tracer.start_span(
        name=name,
        context=parent_ctx,
        kind=SpanKind.INTERNAL,
        attributes=attributes or {},
    )
    return span
