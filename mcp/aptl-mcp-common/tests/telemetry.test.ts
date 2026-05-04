/**
 * Tests for the OpenTelemetry telemetry module.
 *
 * Verifies lifecycle, trace context loading, and tool call tracing
 * using mock/spy patterns since we can't easily intercept OTel spans
 * without a full in-memory exporter setup in the test harness.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { trace } from '@opentelemetry/api';
import {
  InMemorySpanExporter,
  NodeTracerProvider,
  SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-node';

// We need to test the module under controlled conditions
describe('telemetry', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aptl-telemetry-test-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('loadParentContext', () => {
    it('returns undefined when trace-context.json does not exist', async () => {
      vi.stubEnv('APTL_STATE_DIR', join(tmpDir, 'nonexistent'));

      const { loadParentContext } = await import('../src/telemetry.js');
      const ctx = loadParentContext();
      expect(ctx).toBeUndefined();

      vi.unstubAllEnvs();
    });

    it('returns a context when valid trace-context.json exists', async () => {
      const traceCtx = {
        trace_id: 'a'.repeat(32),
        span_id: 'b'.repeat(16),
        trace_flags: '01',
      };
      writeFileSync(join(tmpDir, 'trace-context.json'), JSON.stringify(traceCtx));
      vi.stubEnv('APTL_STATE_DIR', tmpDir);

      // Dynamic import to pick up env change
      const mod = await import('../src/telemetry.js');
      const ctx = mod.loadParentContext();
      expect(ctx).toBeDefined();

      vi.unstubAllEnvs();
    });

    it('returns undefined for invalid JSON', async () => {
      writeFileSync(join(tmpDir, 'trace-context.json'), 'not json');
      vi.stubEnv('APTL_STATE_DIR', tmpDir);

      const { loadParentContext } = await import('../src/telemetry.js');
      const ctx = loadParentContext();
      expect(ctx).toBeUndefined();

      vi.unstubAllEnvs();
    });

    it('returns undefined for invalid trace ID dimensions', async () => {
      const traceCtx = {
        trace_id: 'abc',  // too short
        span_id: 'def',   // too short
        trace_flags: '01',
      };
      writeFileSync(join(tmpDir, 'trace-context.json'), JSON.stringify(traceCtx));
      vi.stubEnv('APTL_STATE_DIR', tmpDir);

      const { loadParentContext } = await import('../src/telemetry.js');
      const ctx = loadParentContext();
      expect(ctx).toBeUndefined();

      vi.unstubAllEnvs();
    });
  });

  describe('traceToolCall', () => {
    it('returns the handler result on success', async () => {
      const { initTracing, traceToolCall, shutdownTracing } = await import('../src/telemetry.js');

      initTracing('test-server');

      const result = await traceToolCall(
        'test_tool',
        'test-server',
        { arg1: 'value1' },
        async () => ({ text: 'Hello' }),
      );

      expect(result).toEqual({ text: 'Hello' });

      await shutdownTracing();
    });

    it('re-throws handler errors', async () => {
      const { initTracing, traceToolCall, shutdownTracing } = await import('../src/telemetry.js');

      initTracing('test-server');

      await expect(
        traceToolCall(
          'failing_tool',
          'test-server',
          {},
          async () => { throw new Error('boom'); },
        ),
      ).rejects.toThrow('boom');

      await shutdownTracing();
    });
  });

  describe('traceToolCall - secret redaction', () => {
    let exporter: InMemorySpanExporter;
    let provider: NodeTracerProvider;

    beforeEach(() => {
      // Fresh provider per test; SimpleSpanProcessor exports synchronously
      // so spans are inspectable as soon as `span.end()` returns.
      // `trace.disable()` clears any global provider that earlier tests in
      // this file installed via `initTracing()` so `provider.register()` is
      // the one that wins (the OTel API silently no-ops if a global is
      // already set).
      trace.disable();
      exporter = new InMemorySpanExporter();
      provider = new NodeTracerProvider({
        spanProcessors: [new SimpleSpanProcessor(exporter)],
      });
      provider.register();
    });

    afterEach(async () => {
      trace.disable();
      await provider.shutdown();
      exporter.reset();
    });

    it('redacts secret-shaped argument values in span attributes', async () => {
      const { traceToolCall } = await import('../src/telemetry.js');

      await traceToolCall(
        'kali_run_command',
        'aptl-red',
        {
          host: 'labadmin@victim',
          password: 'SECRET_PLACEHOLDER_PASSWORD',
          token: 'SECRET_PLACEHOLDER_JWT',
        },
        async () => ({ stdout: 'ok' }),
      );

      const spans = exporter.getFinishedSpans();
      expect(spans).toHaveLength(1);
      const argsAttr = String(spans[0].attributes['aptl.tool.arguments']);
      expect(argsAttr).not.toContain('SECRET_PLACEHOLDER_PASSWORD');
      expect(argsAttr).not.toContain('SECRET_PLACEHOLDER_JWT');
      expect(argsAttr).toContain('[REDACTED]');
      // Non-secret diagnostic structure preserved.
      expect(argsAttr).toContain('labadmin@victim');
    });

    it('redacts secret-shaped values in tool response attribute', async () => {
      const { traceToolCall } = await import('../src/telemetry.js');

      await traceToolCall(
        'wazuh_get_session',
        'aptl-wazuh',
        {},
        async () => ({
          session_id: 'PLACEHOLDER_SESSION_ID',
          api_key: 'PLACEHOLDER_API_KEY',
          status: 'ok',
        }),
      );

      const spans = exporter.getFinishedSpans();
      const respAttr = String(spans[0].attributes['aptl.tool.response']);
      // Secrets and replayable session identifiers gone.
      expect(respAttr).not.toContain('PLACEHOLDER_API_KEY');
      expect(respAttr).not.toContain('PLACEHOLDER_SESSION_ID');
      expect(respAttr).toContain('[REDACTED]');
      // Non-sensitive diagnostic preserved.
      expect(respAttr).toContain('"status":"ok"');
    });

    it('reaches into MCP content[].text envelope to redact wrapped JSON', async () => {
      const { traceToolCall } = await import('../src/telemetry.js');

      await traceToolCall(
        'kali_run_command',
        'aptl-red',
        {
          command:
            "curl -H 'Authorization: Bearer SECRET_PLACEHOLDER_TOKEN' https://x",
        },
        async () => ({
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                data: { api_key: 'SECRET_PLACEHOLDER_API_KEY', ok: true },
              }),
            },
          ],
        }),
      );

      const spans = exporter.getFinishedSpans();
      const argsAttr = String(spans[0].attributes['aptl.tool.arguments']);
      const respAttr = String(spans[0].attributes['aptl.tool.response']);
      // Inline credentials inside the command string are masked.
      expect(argsAttr).not.toContain('SECRET_PLACEHOLDER_TOKEN');
      expect(argsAttr).toContain('[REDACTED]');
      // JSON-string envelope is parsed, redacted, and re-stringified.
      expect(respAttr).not.toContain('SECRET_PLACEHOLDER_API_KEY');
      expect(respAttr).toContain('[REDACTED]');
    });

    it('does not mutate the args passed in', async () => {
      const { traceToolCall } = await import('../src/telemetry.js');
      const args = { password: 'p', host: 'h' };

      await traceToolCall('t', 's', args, async () => ({ ok: true }));

      // Caller still sees real values; redaction only affects the span.
      expect(args).toEqual({ password: 'p', host: 'h' });
    });

    it('returns the unmodified handler result to the caller', async () => {
      const { traceToolCall } = await import('../src/telemetry.js');

      const result = await traceToolCall(
        't',
        's',
        {},
        async () => ({ token: 'real-token-needed-by-caller' }),
      );

      // Redaction is a tracing concern — callers see the real value.
      expect(result).toEqual({ token: 'real-token-needed-by-caller' });
    });
  });

  describe('initTracing / shutdownTracing', () => {
    it('initializes and shuts down without error', async () => {
      const { initTracing, getTracer, shutdownTracing } = await import(
        '../src/telemetry.js'
      );

      expect(() => initTracing('test-service')).not.toThrow();
      // After init, getTracer must return a usable Tracer.
      const tracer = getTracer('test-service');
      expect(tracer).toBeDefined();
      expect(typeof tracer.startSpan).toBe('function');

      await expect(shutdownTracing()).resolves.toBeUndefined();
    });

    it('shutdown without init is safe', async () => {
      const { shutdownTracing } = await import('../src/telemetry.js');
      await expect(shutdownTracing()).resolves.toBeUndefined();
    });
  });
});
