import { describe, it, expect } from 'vitest';
import type { PostToolHookInfo } from 'aptl-mcp-common';
import { isEffectiveRawCall, isOutcomeKnown } from '../src/effective-mode.js';

function baseInfo(overrides: Partial<PostToolHookInfo> = {}): PostToolHookInfo {
  return {
    toolName: 'kali_session_command',
    args: {},
    result: undefined,
    error: undefined,
    durationMs: 1,
    ...overrides,
  } as PostToolHookInfo;
}

describe('#282: isEffectiveRawCall', () => {
  it("returns true when the wrapped MCP result envelope has session_mode='raw'", () => {
    // The shape postToolHook actually receives — MCP SDK wraps the handler
    // output in { content: [{ type: 'text', text: <json> }] }.
    const info = baseInfo({
      args: { session_id: 's1', command: 'msfconsole' }, // no `raw` arg — inherited-raw case
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id: 's1',
              command: 'msfconsole',
              output: 'msf6 >',
              stderr: '',
              exit_code: 0,
              session_mode: 'raw',
            }),
          },
        ],
      },
    });
    expect(isEffectiveRawCall(info)).toBe(true);
  });

  it("returns false when the wrapped envelope has session_mode='normal'", () => {
    const info = baseInfo({
      args: { session_id: 's1', command: 'ls' },
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id: 's1',
              command: 'ls',
              output: 'file',
              stderr: '',
              exit_code: 0,
              session_mode: 'normal',
            }),
          },
        ],
      },
    });
    expect(isEffectiveRawCall(info)).toBe(false);
  });

  it("falls back to args.raw === true when the result envelope has no session_mode (mixed-version dev tree)", () => {
    const info = baseInfo({
      args: { session_id: 's1', command: 'x', raw: true },
      // Pre-#282 envelope shape: no session_mode field.
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id: 's1',
              command: 'x',
              output: '',
              stderr: '',
              exit_code: 0,
            }),
          },
        ],
      },
    });
    expect(isEffectiveRawCall(info)).toBe(true);
  });

  it("returns false when args.raw is omitted AND the envelope has no session_mode (the pre-#282 inherited-raw bug — preserved as the documented fallback gap)", () => {
    const info = baseInfo({
      args: { session_id: 's1', command: 'msfconsole' },
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id: 's1',
              command: 'msfconsole',
              output: 'msf6 >',
              exit_code: 0,
            }),
          },
        ],
      },
    });
    // This is the exact bug #282 fixes when both peers are upgraded. The
    // helper documents this as a transitional gap, not a correctness path —
    // mixed-version trees regress to the pre-#282 behavior, which is the
    // best we can do without the envelope signal.
    expect(isEffectiveRawCall(info)).toBe(false);
  });

  it("returns true on a directly-shaped envelope (test convenience path)", () => {
    const info = baseInfo({
      args: { session_id: 's1', command: 'x' },
      // Direct envelope, no MCP content wrapping — exercises the second
      // resolution branch in isEffectiveRawCall.
      result: { session_mode: 'raw' } as unknown,
    });
    expect(isEffectiveRawCall(info)).toBe(true);
  });

  it("treats malformed result content (non-JSON) as missing — falls back to args.raw", () => {
    const info = baseInfo({
      args: { session_id: 's1', command: 'x', raw: true },
      result: {
        content: [{ type: 'text', text: 'not-json{{' }],
      },
    });
    expect(isEffectiveRawCall(info)).toBe(true);
  });
});

describe('Codex review cycle 2 D-001: isOutcomeKnown preserves known failures in raw mode', () => {
  it("returns true (known) when the handler threw (info.error set) even in raw mode", () => {
    // Raw transport's exit_code: 0 artifact is irrelevant when the handler
    // itself threw — the failure is dispositive.
    expect(isOutcomeKnown(true, false, true)).toBe(true);
  });

  it("returns true (known) when the envelope reports success:false even in raw mode", () => {
    // Missing session, validation rejection, SSH layer throw all surface
    // as `{success: false, error: ...}` in the text envelope, which
    // deriveCommandOutcome parses to outcome.success === false.
    expect(isOutcomeKnown(false, false, true)).toBe(true);
  });

  it("returns false (Unknown) when raw mode and no real failure signal", () => {
    // Raw transport always returns success-ish, so without a real failure
    // signal we must report Unknown.
    expect(isOutcomeKnown(false, true, true)).toBe(false);
    expect(isOutcomeKnown(false, null, true)).toBe(false);
  });

  it("returns true (known) on normal-mode success", () => {
    expect(isOutcomeKnown(false, true, false)).toBe(true);
  });

  it("returns true (known) on normal-mode failure", () => {
    expect(isOutcomeKnown(false, false, false)).toBe(true);
  });

  it("returns false (Unknown) when normal mode and envelope has nothing decisive", () => {
    expect(isOutcomeKnown(false, null, false)).toBe(false);
  });
});
