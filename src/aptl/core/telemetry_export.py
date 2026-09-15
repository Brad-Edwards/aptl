"""Mandatory redaction immediately before an OTel exporter receives spans."""

from collections.abc import Sequence

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import Link, Status

from aptl.utils.redaction import redact


class _RedactedSpan(ReadableSpan):
    """Detached exporter view; never mutate spans seen by other processors."""

    def __init__(self, span: ReadableSpan) -> None:
        scope = span.instrumentation_scope
        self._drop_counts = (
            span.dropped_attributes,
            span.dropped_events,
            span.dropped_links,
        )
        super().__init__(
            name=redact(span.name),
            context=span.context,
            parent=span.parent,
            kind=span.kind,
            start_time=span.start_time,
            end_time=span.end_time,
            attributes=redact(dict(span.attributes or {})),
            resource=Resource(
                redact(dict(span.resource.attributes)),
                schema_url=redact(span.resource.schema_url),
            ),
            status=Status(
                span.status.status_code, description=redact(span.status.description)
            ),
            events=[
                Event(
                    redact(event.name),
                    redact(dict(event.attributes or {})),
                    event.timestamp,
                )
                for event in span.events
            ],
            links=[
                Link(link.context, redact(dict(link.attributes or {})))
                for link in span.links
            ],
            instrumentation_scope=InstrumentationScope(
                redact(scope.name),
                redact(scope.version),
                redact(scope.schema_url),
                redact(dict(scope.attributes or {})),
            )
            if scope is not None
            else None,
        )

    @property
    def dropped_attributes(self) -> int:
        return self._drop_counts[0]

    @property
    def dropped_events(self) -> int:
        return self._drop_counts[1]

    @property
    def dropped_links(self) -> int:
        return self._drop_counts[2]


class RedactingSpanExporter(SpanExporter):
    """Apply the shared redactor to every span, including automatic exceptions."""

    def __init__(self, exporter: SpanExporter) -> None:
        self._exporter = exporter

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self._exporter.export(tuple(_RedactedSpan(span) for span in spans))

    def shutdown(self) -> None:
        self._exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._exporter.force_flush(timeout_millis)
