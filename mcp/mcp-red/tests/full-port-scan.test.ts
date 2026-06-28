import { describe, it, expect, vi, beforeEach } from 'vitest';

// Stub the best-effort capture harvest so the handler test stays hermetic
// (no docker exec). Everything else from common stays real.
vi.mock('aptl-mcp-common', async (importOriginal) => {
  const actual = await importOriginal<typeof import('aptl-mcp-common')>();
  return { ...actual, harvestSession: vi.fn().mockResolvedValue(true) };
});

import {
  fullPortScanComposite,
  validatePortSpec,
  assertTargetInLabNetwork,
  buildScanCommand,
  parseNmapXml,
} from '../src/full-port-scan.js';

const SAMPLE_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - -T4 --open -p- 172.20.4.40">
  <host>
    <status state="up"/>
    <address addr="172.20.4.40" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>`;

const labConfig = {
  version: '1.0.0',
  server: {
    name: 'kali-red-team',
    version: '1.0.0',
    description: 'test',
    toolPrefix: 'kali',
    targetName: 'Kali Linux',
    configKey: 'kali',
  },
  lab: { name: 'aptl-local', network_subnet: '172.20.0.0/16' },
  containers: {
    kali: {
      container_name: 'aptl-kali',
      container_ip: '172.20.4.30',
      ssh_key: '/home/u/.ssh/aptl_lab_key',
      ssh_user: 'kali',
      ssh_port: 22,
      enabled: true,
    },
  },
} as any;

function makeContext(executeCommand: any) {
  return { labConfig, sshManager: { executeCommand } };
}

async function runScan(args: any, executeCommand: any) {
  const ctx = makeContext(executeCommand);
  const result = await fullPortScanComposite.handler(args, ctx as any);
  return JSON.parse(result.content[0].text);
}

describe('fullPortScanComposite metadata', () => {
  it('declares an ssh composite named full_port_scan that requires a target', () => {
    expect(fullPortScanComposite.name).toBe('full_port_scan');
    expect(fullPortScanComposite.contextKind).toBe('ssh');
    expect(fullPortScanComposite.inputSchema.required).toContain('target');
  });
});

describe('validatePortSpec', () => {
  it("maps 'all' (and the default) to the all-ports flag", () => {
    expect(validatePortSpec('all')).toBe('-p-');
    expect(validatePortSpec(undefined)).toBe('-p-');
  });

  it('accepts ranges and comma lists', () => {
    expect(validatePortSpec('1-1024')).toBe('-p 1-1024');
    expect(validatePortSpec('22,80,443')).toBe('-p 22,80,443');
  });

  it('rejects non-numeric / shell-bearing port specs', () => {
    expect(() => validatePortSpec('abc')).toThrow();
    expect(() => validatePortSpec('22; rm -rf /')).toThrow();
    expect(() => validatePortSpec('70000')).toThrow();
  });

  it('rejects a present-but-wrong-type spec instead of widening to all ports', () => {
    // A non-string value must NOT collapse to the all-ports default; only a
    // truly absent (undefined) spec means "all".
    expect(() => validatePortSpec(80 as unknown as string)).toThrow(/expected string/i);
    expect(() => validatePortSpec(['80'] as unknown as string)).toThrow(/expected string/i);
    expect(() => validatePortSpec(null as unknown as string)).toThrow(/expected string/i);
    expect(() => validatePortSpec({} as unknown as string)).toThrow(/expected string/i);
  });
});

describe('assertTargetInLabNetwork', () => {
  it('accepts a single host inside the lab subnet', () => {
    expect(() => assertTargetInLabNetwork('172.20.4.40', '172.20.0.0/16')).not.toThrow();
  });

  it('accepts a bounded CIDR (>= /24) inside the lab subnet', () => {
    expect(() => assertTargetInLabNetwork('172.20.4.0/24', '172.20.0.0/16')).not.toThrow();
  });

  it('rejects a host outside the lab subnet', () => {
    expect(() => assertTargetInLabNetwork('8.8.8.8', '172.20.0.0/16')).toThrow(/lab network/i);
  });

  it('rejects a CIDR wider than the fan-out cap', () => {
    expect(() => assertTargetInLabNetwork('172.20.0.0/16', '172.20.0.0/16')).toThrow(/fan-out|\/24/i);
  });

  it('rejects malformed targets', () => {
    expect(() => assertTargetInLabNetwork('not-an-ip', '172.20.0.0/16')).toThrow();
    expect(() => assertTargetInLabNetwork('172.20.4.999', '172.20.0.0/16')).toThrow();
    expect(() => assertTargetInLabNetwork('a.b.c.d', '172.20.0.0/16')).toThrow();
  });

  it('rejects a CIDR with a malformed prefix', () => {
    expect(() => assertTargetInLabNetwork('172.20.4.0/33', '172.20.0.0/16')).toThrow();
    expect(() => assertTargetInLabNetwork('172.20.4.0/xx', '172.20.0.0/16')).toThrow();
  });

  it('rejects a bounded CIDR that sits outside the lab subnet', () => {
    expect(() => assertTargetInLabNetwork('10.0.0.0/24', '172.20.0.0/16')).toThrow(/lab network/i);
  });

  it('returns the canonical host/CIDR string from a valid target', () => {
    expect(assertTargetInLabNetwork('172.20.4.40', '172.20.0.0/16')).toBe('172.20.4.40');
    expect(assertTargetInLabNetwork('172.20.4.0/24', '172.20.0.0/16')).toBe('172.20.4.0/24');
  });

  it('normalizes a CIDR whose address has host bits set to its network base', () => {
    expect(assertTargetInLabNetwork('172.20.4.55/24', '172.20.0.0/16')).toBe('172.20.4.0/24');
  });

  it('rejects a CIDR target carrying a command-injection suffix (extra slash)', () => {
    // `parseCidr` must not split-and-drop trailing slash data; the suffix after
    // the second slash would otherwise survive into the assembled command.
    expect(() => assertTargetInLabNetwork('172.20.4.0/24/; id', '172.20.0.0/16')).toThrow();
    expect(() => assertTargetInLabNetwork('172.20.4.0/24/', '172.20.0.0/16')).toThrow();
  });

  it('rejects a CIDR wider than the lab subnet even when it shares the lab base', () => {
    // Whole-range containment: lab /25 must reject a target /24 sharing the base,
    // since half the requested range falls outside the configured lab network.
    expect(() => assertTargetInLabNetwork('172.20.4.0/24', '172.20.4.0/25')).toThrow(/lab network/i);
  });
});

describe('buildScanCommand', () => {
  it('assembles an XML-output nmap command from validated primitives', () => {
    const cmd = buildScanCommand('172.20.4.40', '-p-');
    expect(cmd).toMatch(/^nmap /);
    expect(cmd).toContain('-oX -');
    expect(cmd).toContain('--open');
    expect(cmd).toContain('-p-');
    expect(cmd.endsWith('172.20.4.40')).toBe(true);
  });
});

describe('parseNmapXml', () => {
  it('extracts hosts, open ports, and services into a compact report', () => {
    const report = parseNmapXml(SAMPLE_XML);
    expect(report.open_port_count).toBe(2);
    expect(report.hosts).toHaveLength(1);
    expect(report.hosts[0].ip).toBe('172.20.4.40');
    const ports = report.hosts[0].ports;
    expect(ports).toEqual([
      { port: 22, protocol: 'tcp', state: 'open', service: 'ssh' },
      { port: 80, protocol: 'tcp', state: 'open', service: 'http' },
    ]);
  });

  it('returns an empty report for a scan with no hosts', () => {
    const report = parseNmapXml('<?xml version="1.0"?><nmaprun></nmaprun>');
    expect(report.hosts).toEqual([]);
    expect(report.open_port_count).toBe(0);
  });
});

describe('fullPortScanComposite.handler', () => {
  let exec: any;
  beforeEach(() => {
    exec = vi.fn().mockResolvedValue({
      stdout: SAMPLE_XML,
      stderr: '',
      code: 0,
      signal: null,
      sessionId: 'exec-abc',
      mode: 'normal',
    });
  });

  it('connects to the Kali container and scans the requested target', async () => {
    const out = await runScan({ target: '172.20.4.40' }, exec);
    expect(out.success).toBe(true);
    // Connects to the kali container IP, not the scan target.
    expect(exec.mock.calls[0][0]).toBe('172.20.4.30');
    expect(exec.mock.calls[0][1]).toBe('kali');
    // The executed command scans the requested target with all ports.
    const command = exec.mock.calls[0][3];
    expect(command).toContain('-p-');
    expect(command).toContain('172.20.4.40');
    expect(out.report.open_port_count).toBe(2);
  });

  it('threads a custom port spec into the nmap command', async () => {
    await runScan({ target: '172.20.4.40', ports: '22,80' }, exec);
    expect(exec.mock.calls[0][3]).toContain('-p 22,80');
  });

  it('surfaces the executed command and outcome as a step record', async () => {
    const out = await runScan({ target: '172.20.4.40' }, exec);
    expect(out.steps).toHaveLength(1);
    expect(out.steps[0].command).toContain('nmap');
    expect(out.steps[0].success).toBe(true);
    expect(out.steps[0].exit_code).toBe(0);
    expect(out.steps[0].session_id).toBe('exec-abc');
  });

  it('rejects an out-of-lab target before executing anything', async () => {
    const out = await runScan({ target: '8.8.8.8' }, exec);
    expect(out.success).toBe(false);
    expect(out.error).toMatch(/lab network/i);
    expect(exec).not.toHaveBeenCalled();
  });

  it('rejects a wide CIDR before executing anything', async () => {
    const out = await runScan({ target: '172.20.0.0/16' }, exec);
    expect(out.success).toBe(false);
    expect(exec).not.toHaveBeenCalled();
  });

  it('rejects an invalid port spec before executing anything', async () => {
    const out = await runScan({ target: '172.20.4.40', ports: 'bad;rm' }, exec);
    expect(out.success).toBe(false);
    expect(exec).not.toHaveBeenCalled();
  });

  it('rejects a present-but-wrong-type port spec instead of silently scanning all ports', async () => {
    // `{ ports: 80 }` (number) must fail validation, not collapse to the
    // all-ports (`-p-`) default — the input schema is not a runtime guard.
    const out = await runScan({ target: '172.20.4.40', ports: 80 }, exec);
    expect(out.success).toBe(false);
    expect(out.error).toMatch(/expected string/i);
    expect(exec).not.toHaveBeenCalled();
  });

  it('rejects a CIDR target with a command-injection suffix before executing anything', async () => {
    const out = await runScan({ target: '172.20.4.0/24/; id' }, exec);
    expect(out.success).toBe(false);
    expect(exec).not.toHaveBeenCalled();
  });

  it('scans the canonicalized network base, never the raw caller input', async () => {
    const out = await runScan({ target: '172.20.4.55/24' }, exec);
    expect(out.success).toBe(true);
    const command = exec.mock.calls[0][3];
    expect(command).toContain('172.20.4.0/24');
    expect(command).not.toContain('172.20.4.55');
    expect(out.target).toBe('172.20.4.0/24');
  });

  it('reports a failed nmap run as success:false with the failed step', async () => {
    const failExec = vi.fn().mockResolvedValue({
      stdout: '',
      stderr: 'nmap: command not found',
      code: 127,
      signal: null,
      sessionId: 'exec-fail',
      mode: 'normal',
    });
    const out = await runScan({ target: '172.20.4.40' }, failExec);
    expect(out.success).toBe(false);
    expect(out.steps[0].exit_code).toBe(127);
    expect(out.steps[0].success).toBe(false);
  });

  it('reports an SSH execution error as success:false with a step record', async () => {
    const throwExec = vi.fn().mockRejectedValue(new Error('ssh connection refused'));
    const out = await runScan({ target: '172.20.4.40' }, throwExec);
    expect(out.success).toBe(false);
    expect(out.error).toMatch(/ssh connection refused/);
    expect(out.steps[0].success).toBe(false);
    expect(out.steps[0].command).toContain('nmap');
  });

  it('returns the failure envelope with the step when nmap XML cannot be parsed', async () => {
    // nmap succeeded (exit 0) but emitted malformed/truncated XML. The handler
    // must keep the composite envelope (success:false, steps:[step]) so the red
    // OCSF/capture path still receives per-step attribution (ADR-045), rather
    // than throwing and rejecting the MCP call.
    const badXmlExec = vi.fn().mockResolvedValue({
      stdout: '<nmaprun><host><ports><port', // truncated, unparseable
      stderr: '',
      code: 0,
      signal: null,
      sessionId: 'exec-badxml',
      mode: 'normal',
    });
    const out = await runScan({ target: '172.20.4.40' }, badXmlExec);
    expect(out.success).toBe(false);
    expect(out.error).toMatch(/parse nmap xml/i);
    expect(out.steps).toHaveLength(1);
    expect(out.steps[0].success).toBe(true);
    expect(out.steps[0].exit_code).toBe(0);
    expect(out.steps[0].session_id).toBe('exec-badxml');
    expect(out.steps[0].command).toContain('nmap');
  });

  it('clamps an out-of-range timeout and passes it to executeCommand', async () => {
    await runScan({ target: '172.20.4.40', timeout_ms: 10_000_000 }, exec);
    expect(exec.mock.calls[0][5]).toBe(1_800_000);
  });

  it('honors an in-range custom timeout', async () => {
    await runScan({ target: '172.20.4.40', timeout_ms: 5000 }, exec);
    expect(exec.mock.calls[0][5]).toBe(5000);
  });

  it('fails when no sshManager is present in the context', async () => {
    const result = await fullPortScanComposite.handler(
      { target: '172.20.4.40' },
      { labConfig } as any,
    );
    const out = JSON.parse(result.content[0].text);
    expect(out.success).toBe(false);
    expect(exec).not.toHaveBeenCalled();
  });

  it('fails on a missing/blank target', async () => {
    const out = await runScan({}, exec);
    expect(out.success).toBe(false);
    expect(out.error).toMatch(/target is required/i);
    expect(exec).not.toHaveBeenCalled();
  });
});

describe('parseNmapXml multi-host', () => {
  const MULTI = `<?xml version="1.0"?>
<nmaprun>
  <host><address addr="172.20.4.40" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    <port protocol="tcp" portid="23"><state state="closed"/></port>
  </ports></host>
  <host><address addr="172.20.4.41" addrtype="ipv4"/></host>
</nmaprun>`;

  it('handles multiple hosts and skips non-open ports', () => {
    const report = parseNmapXml(MULTI);
    expect(report.hosts).toHaveLength(2);
    expect(report.open_port_count).toBe(1);
    expect(report.hosts[0].ports).toEqual([{ port: 22, protocol: 'tcp', state: 'open', service: 'ssh' }]);
    expect(report.hosts[1].ports).toEqual([]);
  });
});
