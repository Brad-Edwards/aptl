import { describe, it, expect, vi } from 'vitest';
import {
  isCompositeTool,
  extractCompositeSteps,
  ocsfTasksForCompositeSteps,
} from '../src/composite-ocsf.js';
import type { SiemSink } from '../src/logger.js';

function envelope(payload: unknown) {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
}

describe('isCompositeTool', () => {
  it('recognizes the composite tool by suffix', () => {
    expect(isCompositeTool('kali_full_port_scan')).toBe(true);
  });
  it('does not match plain command tools', () => {
    expect(isCompositeTool('kali_run_command')).toBe(false);
    expect(isCompositeTool('kali_session_command')).toBe(false);
  });
});

describe('extractCompositeSteps', () => {
  it('pulls the steps[] array out of the composite result envelope', () => {
    const steps = extractCompositeSteps(
      envelope({ success: true, steps: [{ command: 'nmap -oX - 172.20.4.40', success: true, exit_code: 0 }] }),
    );
    expect(steps).toHaveLength(1);
    expect(steps[0].command).toContain('nmap');
  });

  it('drops step entries without a command string', () => {
    const steps = extractCompositeSteps(envelope({ steps: [{ exit_code: 0 }, { command: 'nmap x' }] }));
    expect(steps).toEqual([{ command: 'nmap x' }]);
  });

  it('returns [] for a malformed or non-composite result', () => {
    expect(extractCompositeSteps(undefined)).toEqual([]);
    expect(extractCompositeSteps({ content: [{ type: 'text', text: 'not json' }] })).toEqual([]);
    expect(extractCompositeSteps(envelope({ success: true }))).toEqual([]);
  });
});

describe('ocsfTasksForCompositeSteps', () => {
  it('emits one Success-classified OCSF record per step through the sink', async () => {
    const sink: SiemSink = vi.fn();
    const tasks = ocsfTasksForCompositeSteps(
      'kali_full_port_scan',
      'aptl-kali-red',
      [
        { command: 'nmap -oX - -T4 --open -p- 172.20.4.40', success: true, exit_code: 0, session_id: 'exec-1', duration_ms: 12 },
      ],
      sink,
    );
    expect(tasks).toHaveLength(1);
    await Promise.all(tasks);
    expect(sink).toHaveBeenCalledTimes(1);
    const record = (sink as any).mock.calls[0][0];
    expect(record.status_id).toBe(1);
    expect(record.status).toBe('Success');
    expect(record.status_code).toBe('0');
    expect(record.aptl).toMatchObject({ tool_name: 'kali_full_port_scan', session_id: 'exec-1' });
    expect(record.duration).toBe(12);
  });

  it('marks the OCSF outcome unknown when a step has no success flag', async () => {
    const sink: SiemSink = vi.fn();
    await Promise.all(
      ocsfTasksForCompositeSteps('kali_full_port_scan', 'aptl-kali-red', [{ command: 'nmap x' }], sink),
    );
    expect(sink).toHaveBeenCalledTimes(1);
    const record = (sink as any).mock.calls[0][0];
    expect(record.status_id).toBe(0);
    expect(record.status).toBe('Unknown');
  });

  it('emits a Failure-classified record for a failed step (success:false)', async () => {
    const records: any[] = [];
    const sink: SiemSink = (r) => { records.push(r); };
    await Promise.all(
      ocsfTasksForCompositeSteps('kali_full_port_scan', 'aptl-kali-red', [
        { command: 'nmap x', success: false, exit_code: 127 },
      ], sink),
    );
    expect(records).toHaveLength(1);
    expect(records[0].status_id).toBe(2);
    expect(records[0].status).toBe('Failure');
    expect(records[0].status_code).toBe('127');
  });
});
