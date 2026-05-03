"""Tests for the OpenTelemetry tracing module.

Tests exercise trace context generation, file round-trip, parent context
construction, span creation, and the init/shutdown lifecycle using
InMemorySpanExporter to verify spans are correctly produced.
"""

import json
from pathlib import Path

import pytest

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry import trace


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_telemetry():
    """Ensure telemetry module state is clean for each test."""
    import aptl.core.telemetry as mod
    mod._provider = None
    yield
    # Clean up after test
    if mod._provider is not None:
        try:
            mod._provider.shutdown()
        except Exception:
            pass
        mod._provider = None


@pytest.fixture
def memory_exporter(monkeypatch):
    """Set up an InMemorySpanExporter for testing span output.

    Patches get_tracer to return a tracer from our test provider
    so spans are captured regardless of the global provider state.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    import aptl.core.telemetry as mod

    # Patch get_tracer to use our test provider
    monkeypatch.setattr(mod, "get_tracer", lambda name="aptl": provider.get_tracer(name))
    mod._provider = provider

    yield exporter

    provider.shutdown()
    mod._provider = None


# ---------------------------------------------------------------------------
# generate_trace_context
# ---------------------------------------------------------------------------


class TestGenerateTraceContext:
    """Tests for trace context ID generation."""

    def test_produces_valid_hex_ids(self):
        from aptl.core.telemetry import generate_trace_context

        ctx = generate_trace_context()
        assert len(ctx["trace_id"]) == 32
        assert len(ctx["span_id"]) == 16
        int(ctx["trace_id"], 16)  # should not raise
        int(ctx["span_id"], 16)

    def test_produces_unique_ids(self):
        from aptl.core.telemetry import generate_trace_context

        ctx1 = generate_trace_context()
        ctx2 = generate_trace_context()
        assert ctx1["trace_id"] != ctx2["trace_id"]
        assert ctx1["span_id"] != ctx2["span_id"]

    def test_includes_sampled_flag(self):
        from aptl.core.telemetry import generate_trace_context

        ctx = generate_trace_context()
        assert ctx["trace_flags"] == "01"


# ---------------------------------------------------------------------------
# write / load trace context
# ---------------------------------------------------------------------------


class TestTraceContextRoundTrip:
    """Tests for writing and loading trace context files."""

    def test_round_trip(self, tmp_path):
        from aptl.core.telemetry import (
            generate_trace_context,
            load_trace_context,
            write_trace_context,
        )

        ctx = generate_trace_context()
        write_trace_context(tmp_path, ctx["trace_id"], ctx["span_id"])

        loaded = load_trace_context(tmp_path)
        assert loaded is not None
        assert format(loaded.trace_id, "032x") == ctx["trace_id"]
        assert format(loaded.span_id, "016x") == ctx["span_id"]
        assert loaded.is_remote is True

    def test_creates_parent_dirs(self, tmp_path):
        from aptl.core.telemetry import write_trace_context

        nested = tmp_path / "deep" / "nested"
        write_trace_context(nested, "a" * 32, "b" * 16)
        assert (nested / "trace-context.json").exists()

    def test_load_missing_file_returns_none(self, tmp_path):
        from aptl.core.telemetry import load_trace_context

        assert load_trace_context(tmp_path / "nonexistent") is None

    def test_load_corrupt_json_returns_none(self, tmp_path):
        from aptl.core.telemetry import load_trace_context

        (tmp_path / "trace-context.json").write_text("not json")
        assert load_trace_context(tmp_path) is None

    def test_load_missing_fields_returns_none(self, tmp_path):
        from aptl.core.telemetry import load_trace_context

        (tmp_path / "trace-context.json").write_text('{"trace_id": "abc"}')
        assert load_trace_context(tmp_path) is None

    def test_write_produces_valid_json(self, tmp_path):
        from aptl.core.telemetry import write_trace_context

        write_trace_context(tmp_path, "a" * 32, "b" * 16)
        data = json.loads((tmp_path / "trace-context.json").read_text())
        assert data["trace_id"] == "a" * 32
        assert data["span_id"] == "b" * 16
        assert data["trace_flags"] == "01"


# ---------------------------------------------------------------------------
# make_parent_context
# ---------------------------------------------------------------------------


class TestMakeParentContext:
    """Tests for constructing OTel parent contexts."""

    def test_creates_valid_context(self):
        from aptl.core.telemetry import make_parent_context

        ctx = make_parent_context("a" * 32, "b" * 16)
        span = trace.get_current_span(ctx)
        span_ctx = span.get_span_context()
        assert span_ctx.trace_id == int("a" * 32, 16)
        assert span_ctx.span_id == int("b" * 16, 16)
        assert span_ctx.is_remote is True


# ---------------------------------------------------------------------------
# Span creation with InMemorySpanExporter
# ---------------------------------------------------------------------------


class TestCreateRootSpan:
    """Tests for the synthetic root span."""

    def test_creates_span_with_correct_attributes(self, memory_exporter):
        from aptl.core.telemetry import create_root_span, get_tracer

        tracer = get_tracer()
        trace_id = "a" * 32
        span_id = "0" * 16

        start_ns = 1_000_000_000_000
        end_ns = 2_000_000_000_000

        create_root_span(
            tracer=tracer,
            scenario_id="test-scenario",
            run_id="test-run",
            start_time=start_ns,
            end_time=end_ns,
            trace_id=trace_id,
            span_id=span_id,
        )

        spans = memory_exporter.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.name == "aptl.scenario.run"
        assert span.attributes["aptl.scenario.id"] == "test-scenario"
        assert span.attributes["aptl.run.id"] == "test-run"
        assert span.start_time == start_ns
        assert span.end_time == end_ns


class TestRecordEvent:
    """Tests for span events."""

    def test_creates_event_span(self, memory_exporter):
        from aptl.core.telemetry import (
            get_tracer,
            make_parent_context,
            record_event,
        )

        tracer = get_tracer()
        parent_ctx = make_parent_context("a" * 32, "b" * 16)

        record_event(tracer, parent_ctx, "alert_matched", {
            "rule_id": "1234",
            "severity": "high",
        })

        spans = memory_exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "alert_matched"
        assert spans[0].attributes["rule_id"] == "1234"

    def test_event_without_attributes(self, memory_exporter):
        from aptl.core.telemetry import (
            get_tracer,
            make_parent_context,
            record_event,
        )

        tracer = get_tracer()
        parent_ctx = make_parent_context("a" * 32, "b" * 16)
        record_event(tracer, parent_ctx, "hint_requested")

        spans = memory_exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "hint_requested"


class TestCreateChildSpan:
    """Tests for child span creation."""

    def test_creates_child_span(self, memory_exporter):
        from aptl.core.telemetry import (
            create_child_span,
            get_tracer,
            make_parent_context,
        )

        tracer = get_tracer()
        parent_ctx = make_parent_context("a" * 32, "b" * 16)

        span = create_child_span(tracer, parent_ctx, "aptl.precondition", {
            "precondition.name": "file-check",
        })
        span.end()

        spans = memory_exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "aptl.precondition"
        assert spans[0].attributes["precondition.name"] == "file-check"

    def test_child_span_caller_must_end(self, memory_exporter):
        from aptl.core.telemetry import (
            create_child_span,
            get_tracer,
            make_parent_context,
        )

        tracer = get_tracer()
        parent_ctx = make_parent_context("a" * 32, "b" * 16)
        span = create_child_span(tracer, parent_ctx, "test-span")

        # Before ending, no finished spans
        assert len(memory_exporter.get_finished_spans()) == 0

        span.end()
        assert len(memory_exporter.get_finished_spans()) == 1


# ---------------------------------------------------------------------------
# init / shutdown lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    """Tests for init_tracing / shutdown_tracing."""

    def test_init_is_idempotent(self):
        from aptl.core.telemetry import init_tracing, shutdown_tracing
        import aptl.core.telemetry as mod

        init_tracing("test-svc")
        provider1 = mod._provider
        init_tracing("test-svc-2")
        assert mod._provider is provider1  # not replaced

        shutdown_tracing()

    def test_shutdown_clears_provider(self):
        from aptl.core.telemetry import init_tracing, shutdown_tracing
        import aptl.core.telemetry as mod

        init_tracing("test-svc")
        assert mod._provider is not None
        shutdown_tracing()
        assert mod._provider is None

    def test_shutdown_without_init_is_safe(self):
        from aptl.core.telemetry import shutdown_tracing

        shutdown_tracing()  # should not raise


# ---------------------------------------------------------------------------
# Span name constants
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify span name constants are defined."""

    def test_span_names(self):
        from aptl.core.telemetry import (
            EVENT_ALERT_MATCHED,
            EVENT_HINT_REQUESTED,
            SPAN_EVALUATION,
            SPAN_OBJECTIVE,
            SPAN_PRECONDITION,
            SPAN_SCENARIO_RUN,
        )

        assert SPAN_SCENARIO_RUN == "aptl.scenario.run"
        assert SPAN_PRECONDITION == "aptl.precondition"
        assert SPAN_OBJECTIVE == "aptl.objective"
        assert SPAN_EVALUATION == "aptl.evaluation"
        assert EVENT_ALERT_MATCHED == "alert_matched"
        assert EVENT_HINT_REQUESTED == "hint_requested"
