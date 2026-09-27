/** Mandatory shared redaction at the final span-export boundary. */
import type { Attributes } from '@opentelemetry/api';
import { resourceFromAttributes } from '@opentelemetry/resources';
import type { ReadableSpan, SpanExporter } from '@opentelemetry/sdk-trace-node';
import { redact } from './redaction.js';

function safeAttributes(attributes: Attributes | undefined): Attributes {
  return redact(attributes ?? {}) as Attributes;
}

function safeSpan(span: ReadableSpan): ReadableSpan {
  // Explicit public projection: spreading the SDK's Span object would retain
  // private processor state and unsanitized copies of attributes/resources.
  return {
    name: redact(span.name) as string,
    kind: span.kind,
    spanContext: () => span.spanContext(),
    parentSpanContext: span.parentSpanContext,
    startTime: span.startTime,
    endTime: span.endTime,
    duration: span.duration,
    ended: span.ended,
    status: { ...span.status, message: redact(span.status.message) as string | undefined },
    attributes: safeAttributes(span.attributes),
    events: span.events.map(event => ({
      ...event, name: redact(event.name) as string, attributes: safeAttributes(event.attributes),
    })),
    links: span.links.map(link => ({ ...link, attributes: safeAttributes(link.attributes) })),
    resource: resourceFromAttributes(safeAttributes(span.resource.attributes), {
      schemaUrl: redact(span.resource.schemaUrl) as string | undefined,
    }),
    instrumentationScope: {
      ...span.instrumentationScope,
      name: redact(span.instrumentationScope.name) as string,
      version: redact(span.instrumentationScope.version) as string | undefined,
      schemaUrl: redact(span.instrumentationScope.schemaUrl) as string | undefined,
    },
    droppedAttributesCount: span.droppedAttributesCount,
    droppedEventsCount: span.droppedEventsCount,
    droppedLinksCount: span.droppedLinksCount,
  };
}

export class RedactingSpanExporter implements SpanExporter {
  constructor(private readonly exporter: SpanExporter) {}

  export(spans: ReadableSpan[], callback: Parameters<SpanExporter['export']>[1]): void {
    this.exporter.export(spans.map(safeSpan), callback);
  }

  shutdown(): Promise<void> {
    return this.exporter.shutdown();
  }

  async forceFlush(): Promise<void> {
    await this.exporter.forceFlush?.();
  }
}
