/** Export-boundary protection must apply even to spans outside tool helpers. */
import { describe, expect, it, vi } from 'vitest';
import { trace } from '@opentelemetry/api';
import type { ReadableSpan } from '@opentelemetry/sdk-trace-node';

const exported = vi.hoisted(() => [] as ReadableSpan[]);
vi.mock('@opentelemetry/exporter-trace-otlp-proto', () => ({
  OTLPTraceExporter: class {
    export(spans: ReadableSpan[], callback: (result: { code: number }) => void): void {
      exported.push(...spans);
      callback({ code: 0 });
    }
    async shutdown(): Promise<void> {}
  },
}));

describe('mandatory export redaction', () => {
  it('removes secrets from resources, nested attributes, events and exceptions', async () => {
    const secret = 'fixture-typescript-export-secret-992';
    trace.disable();
    const { initTracing, getTracer, shutdownTracing } = await import('../src/telemetry.js');
    initTracing(`api_key=${secret}`);
    const span = getTracer().startSpan('capture');
    span.setAttribute('api_key', secret);
    span.setAttribute('nested', JSON.stringify({ password: secret }));
    span.addEvent('event', { token: secret });
    span.recordException(new Error(`password=${secret}`));
    span.end();
    await shutdownTracing();
    expect(exported).toHaveLength(1);
    const payload = exported.map(item => ({
      name: item.name, attributes: item.attributes, events: item.events,
      links: item.links, resource: item.resource.attributes, status: item.status,
    }));
    expect(JSON.stringify(payload)).not.toContain(secret);
    trace.disable();
  });
});
