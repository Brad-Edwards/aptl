/**
 * OpenTelemetry tracing for APTL MCP servers.
 *
 * Replaces the former ToolTracer JSONL system with OTel spans exported
 * via OTLP HTTP/protobuf to the OTel Collector.
 *
 * Cross-process propagation: reads `.aptl/trace-context.json` written
 * by `aptl scenario start` so that MCP tool spans share the same
 * trace_id as scenario lifecycle spans from the Python CLI.
 */

import { readFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';

import { context, trace, Tracer, Context, SpanStatusCode, SpanKind } from '@opentelemetry/api';
import { Resource } from '@opentelemetry/resources';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-proto';
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';

let provider: NodeTracerProvider | null = null;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/**
 * Configure OTel TracerProvider with OTLP HTTP exporter.
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export function initTracing(serverName: string): void {
  if (provider !== null) return;

  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318';

  const resource = new Resource({
    [ATTR_SERVICE_NAME]: serverName,
  });

  provider = new NodeTracerProvider({ resource });

  const exporter = new OTLPTraceExporter({
    url: `${endpoint}/v1/traces`,
  });

  provider.addSpanProcessor(new BatchSpanProcessor(exporter));
  provider.register();

  console.error(`[OTel] Tracing initialized: service=${serverName} endpoint=${endpoint}`);
}

/**
 * Force-flush and shutdown the TracerProvider.
 */
export async function shutdownTracing(): Promise<void> {
  if (provider !== null) {
    await provider.forceFlush();
    await provider.shutdown();
    provider = null;
    console.error('[OTel] Tracing shut down');
  }
}

/**
 * Return a Tracer from the current provider.
 */
export function getTracer(name: string = 'aptl-mcp'): Tracer {
  return trace.getTracer(name);
}

// ---------------------------------------------------------------------------
// Cross-process context
// ---------------------------------------------------------------------------

interface TraceContextFile {
  trace_id: string;
  span_id: string;
  trace_flags: string;
}

/**
 * Read the trace context written by `aptl scenario start`.
 * Returns an OTel Context with the remote parent, or undefined if
 * no active scenario context exists.
 */
export function loadParentContext(): Context | undefined {
  const traceDir = process.env.APTL_STATE_DIR || '.aptl';
  const ctxPath = resolve(traceDir, 'trace-context.json');

  if (!existsSync(ctxPath)) {
    return undefined;
  }

  try {
    const raw = readFileSync(ctxPath, 'utf-8');
    const data: TraceContextFile = JSON.parse(raw);

    const spanContext = {
      traceId: data.trace_id,
      spanId: data.span_id,
      traceFlags: parseInt(data.trace_flags, 16),
      isRemote: true,
    };

    // Validate hex lengths
    if (spanContext.traceId.length !== 32 || spanContext.spanId.length !== 16) {
      console.error('[OTel] Invalid trace context dimensions, ignoring');
      return undefined;
    }

    const parentSpan = trace.wrapSpanContext(spanContext);
    return trace.setSpan(context.active(), parentSpan);
  } catch (err) {
    console.error(`[OTel] Could not load trace context from ${ctxPath}: ${err}`);
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Tool call tracing (replaces ToolTracer.trace())
// ---------------------------------------------------------------------------

const MAX_ATTR_SIZE = 50_000;

/**
 * Truncate a value to a string suitable for a span attribute.
 */
function truncateAttr(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized && serialized.length > MAX_ATTR_SIZE) {
    return serialized.slice(0, 2000) + `... [truncated from ${serialized.length} bytes]`;
  }
  return serialized;
}

/**
 * Wrap a tool handler call with OTel span instrumentation.
 *
 * Creates a span with GenAI SIG conventions, records timing, errors,
 * and truncated arguments/responses as attributes.
 */
export async function traceToolCall<T>(
  toolName: string,
  serverName: string,
  args: Record<string, unknown>,
  handler: () => Promise<T>,
): Promise<T> {
  const tracer = getTracer();
  const parentContext = loadParentContext() || context.active();

  return tracer.startActiveSpan(
    'execute_tool',
    {
      kind: SpanKind.INTERNAL,
      attributes: {
        'gen_ai.operation.name': 'execute_tool',
        'gen_ai.tool.name': toolName,
        'gen_ai.agent.name': serverName,
        'aptl.tool.arguments': truncateAttr(args),
      },
    },
    parentContext,
    async (span) => {
      try {
        const result = await handler();
        span.setAttribute('aptl.tool.response', truncateAttr(result));
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (err) {
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: err instanceof Error ? err.message : String(err),
        });
        if (err instanceof Error) {
          span.recordException(err);
        }
        throw err;
      } finally {
        span.end();
      }
    },
  );
}
