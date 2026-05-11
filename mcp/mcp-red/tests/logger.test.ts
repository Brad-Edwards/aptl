import { describe, it, expect, vi } from 'vitest';

vi.mock('aptl-mcp-common', async () => {
  const actual = await vi.importActual<typeof import('../../aptl-mcp-common/src/redaction.js')>(
    '../../aptl-mcp-common/src/redaction.js',
  );
  return { redact: actual.redact };
});

import {
  deriveCommandSuccess,
  logRedTeamCommand,
  type OcsfRedTeamRecord,
  type SiemSink,
  stderrJsonlSink,
  PRODUCT_NAME,
  PRODUCT_VENDOR,
} from '../src/logger.js';
import { SeverityId } from '../src/classifier.js';

const ctx = (overrides: Record<string, unknown> = {}) => ({
  tool_name: 'kali_run_command',
  agent_name: 'aptl-kali-red',
  ...overrides,
});

describe('logRedTeamCommand — OCSF base fields', () => {
  it('emits a record with all OCSF base fields populated', () => {
    const captured: OcsfRedTeamRecord[] = [];
    const sink: SiemSink = (r) => captured.push(r);
    const rec = logRedTeamCommand('nmap -p 22 192.168.1.5', ctx(), sink);

    expect(rec).not.toBeNull();
    expect(captured).toHaveLength(1);
    const r = captured[0];
    expect(typeof r.time).toBe('number');
    expect(r.severity_id).toBeGreaterThanOrEqual(0);
    expect(r.severity_id).toBeLessThanOrEqual(6);
    expect(r.class_uid).toBe(4001);
    expect(r.activity_id).toBe(1);
    expect(r.type_uid).toBe(r.class_uid * 100 + r.activity_id);
    expect(r.metadata.product.name).toBe(PRODUCT_NAME);
    expect(r.metadata.product.vendor_name).toBe(PRODUCT_VENDOR);
    // dst_endpoint comes from the extractor
    expect(r.dst_endpoint?.ip).toBe('192.168.1.5');
    expect(r.dst_endpoint?.ports).toEqual([22]);
  });

  it('attaches MITRE attack info when classification has a technique', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap 10.0.0.1', ctx(), (r) => captured.push(r));
    expect(captured[0].attacks?.[0].technique?.uid).toBe('T1046');
    expect(captured[0].attacks?.[0].tactic?.name).toBe('Discovery');
  });

  it('omits attacks[] when the classification has no technique (generic fallback)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('echo hello', ctx(), (r) => captured.push(r));
    expect(captured[0].attacks).toBeUndefined();
  });
});

describe('logRedTeamCommand — redaction', () => {
  it('redacts inline credential-shaped values in process.cmd_line', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'curl -H "Authorization: Bearer secrettoken123" https://t.example/x',
      ctx(),
      (r) => captured.push(r),
    );
    const cmd = captured[0].process?.cmd_line ?? '';
    expect(cmd).not.toContain('secrettoken123');
    expect(cmd).toContain('[REDACTED]');
  });

  it('redacts --password style flags', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('mytool --password hunter2 host', ctx(), (r) => captured.push(r));
    expect(captured[0].process?.cmd_line ?? '').not.toContain('hunter2');
  });
});

describe('logRedTeamCommand — best-effort guarantee', () => {
  it('catches sink errors and returns the record without throwing', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const sink: SiemSink = () => {
      throw new Error('sink exploded');
    };
    expect(() => logRedTeamCommand('nmap 10.0.0.1', ctx(), sink)).not.toThrow();
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('returns null when the command is empty rather than throwing', () => {
    const captured: OcsfRedTeamRecord[] = [];
    const result = logRedTeamCommand('', ctx(), (r) => captured.push(r));
    expect(result).toBeNull();
    expect(captured).toHaveLength(0);
  });

  it('does not throw on non-string command input (defensive)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    // Force the type to exercise the runtime guard.
    const badCommand = undefined as unknown as string;
    const result = logRedTeamCommand(badCommand, ctx(), (r) => captured.push(r));
    expect(result).toBeNull();
  });
});

describe('logRedTeamCommand — severity', () => {
  it('uses the per-class default severity for a successful command', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap 10.0.0.1', ctx({ success: true }), (r) => captured.push(r));
    expect(captured[0].severity_id).toBe(SeverityId.LOW);
  });

  it('bumps severity to MEDIUM when success is false and class is below MEDIUM', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap 10.0.0.1', ctx({ success: false, exit_code: 1 }), (r) =>
      captured.push(r),
    );
    expect(captured[0].severity_id).toBe(SeverityId.MEDIUM);
    // OCSF normalised outcome lives in status / status_id; status_code
    // is reserved for source-specific values like the numeric exit code.
    expect(captured[0].status).toBe('Failure');
    expect(captured[0].status_id).toBe(2);
    expect(captured[0].status_code).toBe('1');
  });

  it('does not downgrade severity for HIGH-default tools on failure', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'hydra -l u -P p 10.0.0.1 ssh',
      ctx({ success: false }),
      (r) => captured.push(r),
    );
    expect(captured[0].severity_id).toBe(SeverityId.HIGH);
  });

  it('records OCSF normalized status when context.success is true', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap 10.0.0.1', ctx({ success: true, exit_code: 0 }), (r) =>
      captured.push(r),
    );
    expect(captured[0].status).toBe('Success');
    expect(captured[0].status_id).toBe(1);
    expect(captured[0].status_code).toBe('0');
  });
});

describe('stderrJsonlSink', () => {
  it('writes a single JSONL line with the [OCSF] sentinel prefix to stderr', () => {
    const writeSpy = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      const record: OcsfRedTeamRecord = {
        time: 1,
        severity_id: 1,
        class_uid: 1007,
        class_name: 'Process Activity',
        activity_id: 1,
        type_uid: 100701,
        metadata: { product: { name: PRODUCT_NAME, vendor_name: PRODUCT_VENDOR } },
        process: { cmd_line: 'echo hi' },
      };
      stderrJsonlSink(record);
      expect(writeSpy).toHaveBeenCalledTimes(1);
      const line = writeSpy.mock.calls[0][0] as string;
      expect(line.startsWith('[OCSF] ')).toBe(true);
      expect(line.endsWith('\n')).toBe(true);
      const parsed = JSON.parse(line.slice('[OCSF] '.length).trimEnd());
      expect(parsed.class_uid).toBe(1007);
      expect(parsed.process.cmd_line).toBe('echo hi');
    } finally {
      writeSpy.mockRestore();
    }
  });
});

describe('logRedTeamCommand — extracted-field promotion (review-finding regression)', () => {
  it('promotes extracted url / protocol / file.path into the OCSF record', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'sqlmap -u "https://target.example/login"',
      ctx(),
      (r) => captured.push(r),
    );
    expect(captured[0].http_request?.url).toBe('https://target.example/login');
    expect(captured[0].connection_info?.protocol_name).toBe('https');
  });

  it('promotes the wordlist file.path for credential-tool runs', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'hydra -l u -P /usr/share/wordlists/rockyou.txt 10.0.0.1 ssh',
      ctx(),
      (r) => captured.push(r),
    );
    expect(captured[0].file?.path).toBe('/usr/share/wordlists/rockyou.txt');
  });

  it('redacts URL userinfo end-to-end in the record', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'curl https://alice:hunter2@target.example/path',
      ctx(),
      (r) => captured.push(r),
    );
    const json = JSON.stringify(captured[0]);
    expect(json).not.toContain('hunter2');
  });

  it('redacts URL query-string secrets in http_request.url (security-finding regression)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'sqlmap -u "https://target.example/login?token=secrettoken123"',
      ctx(),
      (r) => captured.push(r),
    );
    const url = captured[0].http_request?.url ?? '';
    // The token value must be masked in the structured URL field.
    expect(url).not.toContain('secrettoken123');
    // The scheme/host/path portion stays intact for SIEM correlation.
    expect(url).toContain('target.example/login');
    expect(url).toContain('[REDACTED]');
  });

  it('redacts hydra short -p password from process.cmd_line (review-finding regression)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'hydra -l admin -p hunter2 192.168.1.5 ssh',
      ctx(),
      (r) => captured.push(r),
    );
    expect(captured[0].process?.cmd_line ?? '').not.toContain('hunter2');
  });

  it('redacts a quoted multi-word hydra short -p password (cycle-3 security regression)', () => {
    // `-p "secret phrase"` — the inner whitespace must not leave the second
    // word un-redacted. The pre-redactor must consume the entire quoted
    // shell token, not just the first \\S+.
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'hydra -l admin -p "secret phrase" 192.168.1.5 ssh',
      ctx(),
      (r) => captured.push(r),
    );
    const cmd = captured[0].process?.cmd_line ?? '';
    expect(cmd).not.toContain('secret');
    expect(cmd).not.toContain('phrase');
  });

  it('redacts a single-quoted hydra short -p password too', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      "hydra -l admin -p 'secret phrase' 192.168.1.5 ssh",
      ctx(),
      (r) => captured.push(r),
    );
    const cmd = captured[0].process?.cmd_line ?? '';
    expect(cmd).not.toContain('secret');
    expect(cmd).not.toContain('phrase');
  });

  it('redacts -p in wrapper-tool pipelines (cycle-6 security regression)', () => {
    // `proxychains4 hydra -p hunter2 …` — leading executable is
    // proxychains4, not hydra, so prior classifier-gated redaction would
    // have skipped this. Pre-redaction must apply regardless of the
    // leading-tool classification when the value is non-numeric.
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'proxychains4 hydra -l admin -p hunter2 192.168.1.5 ssh',
      ctx(),
      (r) => captured.push(r),
    );
    expect(captured[0].process?.cmd_line ?? '').not.toContain('hunter2');
  });

  it('redacts sshpass -p (cycle-6 security regression)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'sshpass -p secretpw ssh user@target',
      ctx(),
      (r) => captured.push(r),
    );
    expect(captured[0].process?.cmd_line ?? '').not.toContain('secretpw');
  });

  it('does NOT redact numeric -p values (port numbers must stay visible)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap -p 22 10.0.0.1', ctx(), (r) => captured.push(r));
    expect(captured[0].process?.cmd_line ?? '').toContain('-p 22');
  });
});

describe('deriveCommandSuccess — exit-code precedence (review-finding regression)', () => {
  function envelope(json: Record<string, unknown>) {
    return { content: [{ type: 'text', text: JSON.stringify(json) }] };
  }

  it('treats a session_command result with non-zero exit_code as failure', () => {
    // The common session_command handler returns transport-success
    // (`success: true`) even when the executed command failed, surfacing
    // the real result via `exit_code`. The hook must derive *command*
    // success from `exit_code === 0`, not the transport flag.
    const r = envelope({ success: true, exit_code: 1, output: 'no such file' });
    expect(deriveCommandSuccess(r, undefined)).toBe(false);
  });

  it('treats a kali_run_command result with nested output.code !== 0 as failure (cycle-4 review)', () => {
    // The common run_command handler returns `{ success: true, output: { stdout, stderr, code, signal } }`
    // for any SSH transport-success — the actual command exit is nested
    // under `output.code`. The hook must check the nested code too.
    const r = envelope({
      target: '10.0.0.1',
      command: 'false',
      username: 'kali',
      success: true,
      output: { stdout: '', stderr: '', code: 1, signal: null },
    });
    expect(deriveCommandSuccess(r, undefined)).toBe(false);
  });

  it('treats a kali_run_command result with nested output.code === 0 as success', () => {
    const r = envelope({
      success: true,
      output: { stdout: 'ok\n', stderr: '', code: 0, signal: null },
    });
    expect(deriveCommandSuccess(r, undefined)).toBe(true);
  });

  it('treats exit_code === 0 as command success', () => {
    const r = envelope({ success: true, exit_code: 0 });
    expect(deriveCommandSuccess(r, undefined)).toBe(true);
  });

  it('falls back to the transport-level success flag when exit_code is absent (run_command shape)', () => {
    // `run_command` returns `{ success: true, output }` without an
    // `exit_code`. Without an exit_code we trust the success field.
    expect(deriveCommandSuccess(envelope({ success: true }), undefined)).toBe(true);
    expect(deriveCommandSuccess(envelope({ success: false }), undefined)).toBe(false);
  });

  it('treats a thrown error as failure regardless of result', () => {
    expect(deriveCommandSuccess(envelope({ success: true }), new Error('boom'))).toBe(false);
  });

  it('defaults to false (Unknown) on malformed result envelopes — cycle-13 review', () => {
    // Cycle-13 changed the contract: malformed envelopes return
    // `success: null` from deriveCommandOutcome (so the OCSF logger can
    // emit Unknown), and the boolean wrapper degrades that to `false`
    // rather than fabricating a Success.
    expect(deriveCommandSuccess({}, undefined)).toBe(false);
    expect(deriveCommandSuccess(undefined, undefined)).toBe(false);
    expect(deriveCommandSuccess({ content: [{ type: 'text', text: 'not json' }] }, undefined)).toBe(
      false,
    );
  });
});

describe('deriveCommandOutcome — explicit unknown for malformed envelopes (cycle-13 review)', () => {
  function envelope(json: Record<string, unknown> | null) {
    return json === null ? {} : { content: [{ type: 'text', text: JSON.stringify(json) }] };
  }

  it('returns success: null when the result envelope has no content', () => {
    const o = deriveCommandOutcomeForTest({});
    expect(o.success).toBeNull();
  });

  it('returns success: null when content[0].text is not JSON', () => {
    const o = deriveCommandOutcomeForTest({ content: [{ type: 'text', text: 'not json' }] });
    expect(o.success).toBeNull();
  });

  it('returns success: null when JSON has neither exit_code nor success', () => {
    const o = deriveCommandOutcomeForTest(envelope({ session_id: 'x' }));
    expect(o.success).toBeNull();
  });

  it('still returns success: true for a real exit_code: 0 envelope', () => {
    const o = deriveCommandOutcomeForTest(envelope({ success: true, exit_code: 0 }));
    expect(o.success).toBe(true);
  });
});

describe('logRedTeamCommand — explicit Unknown status for raw mode (cycle-11 review)', () => {
  it('emits status_id=0 / status="Unknown" when outcome_unknown is set', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand(
      'whoami',
      ctx({ outcome_unknown: true }),
      (r) => captured.push(r),
    );
    expect(captured[0].status_id).toBe(0);
    expect(captured[0].status).toBe('Unknown');
  });

  it('still omits status fields when neither success nor outcome_unknown is provided', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('whoami', ctx(), (r) => captured.push(r));
    expect(captured[0].status_id).toBeUndefined();
    expect(captured[0].status).toBeUndefined();
  });
});

describe('logRedTeamCommand — OCSF correctness fixes (cycle-6 review)', () => {
  it('emits time as milliseconds since the Unix epoch (OCSF timestamp_t)', () => {
    const captured: OcsfRedTeamRecord[] = [];
    const before = Date.now();
    logRedTeamCommand('nmap 10.0.0.1', ctx(), (r) => captured.push(r));
    const after = Date.now();
    expect(captured[0].time).toBeGreaterThanOrEqual(before);
    expect(captured[0].time).toBeLessThanOrEqual(after);
  });

  it('emits category_uid and category_name on the record', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap 10.0.0.1', ctx(), (r) => captured.push(r));
    expect(captured[0].category_uid).toBe(4);
    expect(captured[0].category_name).toBe('Network Activity');
  });
});

describe('deriveCommandOutcome — signal handling (cycle-6 review)', () => {
  function envelope(json: Record<string, unknown>) {
    return { content: [{ type: 'text', text: JSON.stringify(json) }] };
  }

  it('treats a signal-terminated kali_run_command as failure', () => {
    // ssh2 may return code: null with signal: 'SIGTERM' for killed
    // commands; previously the outcome derivation fell through to the
    // transport success flag. Now it must surface as failure with the
    // signal name preserved.
    const r = envelope({
      success: true,
      output: { stdout: '', stderr: '', code: null, signal: 'SIGTERM' },
    });
    const outcome = deriveCommandOutcomeForTest(r);
    expect(outcome.success).toBe(false);
    expect(outcome.signal).toBe('SIGTERM');
  });
});

// Helper to import deriveCommandOutcome lazily (the import lives at the
// top of the file via deriveCommandSuccess; pull the new symbol here).
import { deriveCommandOutcome as _doc } from '../src/logger.js';
function deriveCommandOutcomeForTest(r: unknown) {
  return _doc(r, undefined);
}

describe('logRedTeamCommand — diagnostic envelope', () => {
  it('attaches the activity_type and tool to an aptl envelope on the record', () => {
    const captured: OcsfRedTeamRecord[] = [];
    logRedTeamCommand('nmap 10.0.0.1', ctx(), (r) => captured.push(r));
    expect(captured[0].aptl?.activity_type).toBe('port_scan');
    expect(captured[0].aptl?.tool).toBe('nmap');
  });
});
