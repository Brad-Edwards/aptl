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

  describe('initTracing / shutdownTracing', () => {
    it('initializes and shuts down without error', async () => {
      const { initTracing, shutdownTracing } = await import('../src/telemetry.js');

      // Should not throw
      initTracing('test-service');
      await shutdownTracing();
    });

    it('shutdown without init is safe', async () => {
      const { shutdownTracing } = await import('../src/telemetry.js');
      await shutdownTracing(); // should not throw
    });
  });
});
