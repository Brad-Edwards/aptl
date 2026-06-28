/**
 * `kali_full_port_scan` composite MCP tool (ORC-003 / ADR-045).
 *
 * A single MCP tool call that runs an nmap full TCP scan against a lab target,
 * parses the structured XML output, and returns a compact open-ports report.
 * It is the first consumer of the composite registration seam in
 * `aptl-mcp-common` and the canonical example from ORC-003.
 *
 * Per ADR-045 this is a tool-boundary orchestrator over existing primitives,
 * not a new command runner:
 *  - execution stays inside the lab via `SSHConnectionManager` (no local
 *    nmap/child_process on the MCP host);
 *  - scan targets are validated to single hosts or bounded CIDRs inside the
 *    configured lab network before any command is assembled;
 *  - the executed nmap command and its outcome are surfaced as a
 *    `CompositeStepRecord` so they stay visible to the red OCSF / capture path
 *    (wired in `index.ts`);
 *  - the command is built from validated, allowlisted primitives — no
 *    free-form `extra_args` or raw shell concatenation;
 *  - structured nmap XML is parsed instead of scraping human-formatted text.
 */

import { XMLParser } from 'fast-xml-parser';
import {
  getTargetCredentials,
  harvestSession,
  redact,
  resolveCaptureContainer,
  type CompositeContext,
  type CompositeStepRecord,
  type CompositeTool,
  type LabConfig,
} from 'aptl-mcp-common';

/** Smallest CIDR prefix accepted — caps scan fan-out at 256 addresses (/24). */
const MIN_CIDR_PREFIX = 24;
const MAX_PORT = 65535;
const DEFAULT_TIMEOUT_MS = 600_000; // full TCP scans are slow
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 1_800_000;

const PORT_SPEC_RE = /^\d+(-\d+)?(,\d+(-\d+)?)*$/;

interface ReportPort {
  port: number;
  protocol: string;
  state: string;
  service?: string;
}

interface ReportHost {
  ip: string;
  ports: ReportPort[];
}

export interface PortScanReport {
  hosts: ReportHost[];
  open_port_count: number;
}

interface FullPortScanArgs {
  target?: unknown;
  ports?: unknown;
  timeout_ms?: unknown;
}

function ipv4ToInt(ip: string): number {
  const octets = ip.split('.');
  if (octets.length !== 4) {
    throw new Error(`invalid IPv4 address: ${JSON.stringify(ip)}`);
  }
  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) {
      throw new Error(`invalid IPv4 address: ${JSON.stringify(ip)}`);
    }
    const n = Number(octet);
    if (n > 255) {
      throw new Error(`invalid IPv4 address: ${JSON.stringify(ip)}`);
    }
    value = value * 256 + n;
  }
  return value >>> 0;
}

function intToIpv4(value: number): string {
  const n = value >>> 0;
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

interface Cidr {
  base: number;
  prefix: number;
}

function maskForPrefix(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

function parseCidr(value: string): Cidr {
  // Exactly one '/' separator. Splitting and ignoring extra slash-delimited
  // data would silently drop a command-injection suffix (e.g.
  // `172.20.4.0/24/; id`), so reject anything that is not strictly addr/prefix.
  const parts = value.split('/');
  if (parts.length !== 2) {
    throw new Error(`not a CIDR: ${JSON.stringify(value)}`);
  }
  const [addr, prefixPart] = parts;
  if (!/^\d{1,2}$/.test(prefixPart)) {
    throw new Error(`invalid CIDR prefix: ${JSON.stringify(value)}`);
  }
  const prefix = Number(prefixPart);
  if (prefix > 32) {
    throw new Error(`invalid CIDR prefix: ${JSON.stringify(value)}`);
  }
  const base = (ipv4ToInt(addr) & maskForPrefix(prefix)) >>> 0;
  return { base, prefix };
}

/**
 * Validate that `target` is a single IPv4 host or a bounded IPv4 CIDR that
 * lies entirely within the configured lab subnet, and return the canonical
 * command-safe target string to use when assembling the nmap command. Throws
 * on anything outside the lab network or wider than the fan-out cap. ADR-045
 * requires scan targets to default to the lab network with no hidden non-lab
 * allowance.
 *
 * The returned string is rebuilt from the validated numeric address (and, for
 * CIDRs, the normalized network base), so any trailing shell metacharacters in
 * the caller-supplied input cannot survive into the assembled command. Callers
 * MUST build the command from this return value, not the raw target.
 */
export function assertTargetInLabNetwork(
  target: string,
  labSubnet: string,
  minCidrPrefix: number = MIN_CIDR_PREFIX,
): string {
  const lab = parseCidr(labSubnet);
  const labMask = maskForPrefix(lab.prefix);

  if (target.includes('/')) {
    const cidr = parseCidr(target);
    if (cidr.prefix < minCidrPrefix) {
      throw new Error(
        `CIDR /${cidr.prefix} exceeds the scan fan-out cap (minimum /${minCidrPrefix})`,
      );
    }
    // Whole-range containment: a target range only fits inside the lab range if
    // it is no wider than the lab (prefix >= lab prefix) AND its network base,
    // masked to the lab prefix, equals the lab base. Checking the base alone
    // would accept a wider CIDR that merely shares the lab base (e.g. lab
    // 172.20.4.0/25 vs target 172.20.4.0/24).
    if (cidr.prefix < lab.prefix || ((cidr.base & labMask) >>> 0) !== lab.base) {
      throw new Error(`target ${target} is outside the lab network ${labSubnet}`);
    }
    return `${intToIpv4(cidr.base)}/${cidr.prefix}`;
  }

  const host = ipv4ToInt(target);
  if (((host & labMask) >>> 0) !== lab.base) {
    throw new Error(`target ${target} is outside the lab network ${labSubnet}`);
  }
  return intToIpv4(host);
}

/**
 * Validate the optional port spec and return the nmap `-p` flag. `all` (or a
 * truly absent spec — `undefined`) scans every TCP port. A present-but-wrong-type
 * value is rejected rather than silently widening the scan to all ports, since
 * the MCP input schema is not a runtime guard. Otherwise only digit/comma/dash
 * specs are accepted — never shell fragments.
 */
export function validatePortSpec(ports: unknown): string {
  if (ports === undefined || ports === 'all') {
    return '-p-';
  }
  if (typeof ports !== 'string') {
    throw new TypeError(`invalid port spec (expected string): ${JSON.stringify(ports)}`);
  }
  if (!PORT_SPEC_RE.test(ports)) {
    throw new Error(`invalid port spec: ${JSON.stringify(ports)}`);
  }
  for (const part of ports.split(',')) {
    for (const bound of part.split('-')) {
      if (Number(bound) > MAX_PORT) {
        throw new Error(`port out of range (1-${MAX_PORT}): ${bound}`);
      }
    }
  }
  return `-p ${ports}`;
}

/** Assemble the nmap command from already-validated primitives. */
export function buildScanCommand(target: string, portArg: string): string {
  return `nmap -oX - -T4 --open ${portArg} ${target}`;
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

// Minimal typed view of the nmap XML attribute shape fast-xml-parser produces
// with `attributeNamePrefix: '@_'`. Only the fields this report reads are
// modelled; the single cast at the parser boundary keeps the rest of the
// parse `any`-free.
interface NmapAddress {
  '@_addr'?: string;
  '@_addrtype'?: string;
}
interface NmapPort {
  '@_protocol'?: string;
  '@_portid'?: string;
  state?: { '@_state'?: string };
  service?: { '@_name'?: string };
}
interface NmapHost {
  address?: NmapAddress | NmapAddress[];
  ports?: { port?: NmapPort | NmapPort[] };
}
interface NmapDoc {
  nmaprun?: { host?: NmapHost | NmapHost[] };
}

/** Parse nmap XML (`-oX -`) into a compact open-ports report. */
export function parseNmapXml(xml: string): PortScanReport {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const parsed = parser.parse(xml) as NmapDoc;
  const hosts: ReportHost[] = [];
  let openPortCount = 0;

  for (const host of toArray<NmapHost>(parsed?.nmaprun?.host)) {
    const addresses = toArray<NmapAddress>(host.address);
    const ipv4 = addresses.find((a) => a['@_addrtype'] === 'ipv4') ?? addresses[0];
    const ip = ipv4?.['@_addr'] ?? 'unknown';
    const ports: ReportPort[] = [];
    for (const port of toArray<NmapPort>(host.ports?.port)) {
      const state = port.state?.['@_state'] ?? 'unknown';
      if (state !== 'open') continue;
      openPortCount += 1;
      ports.push({
        port: Number(port['@_portid']),
        protocol: port['@_protocol'] ?? 'tcp',
        state,
        service: port.service?.['@_name'],
      });
    }
    hosts.push({ ip, ports });
  }

  return { hosts, open_port_count: openPortCount };
}

function failure(error: string, steps: CompositeStepRecord[] = []): { content: { type: string; text: string }[] } {
  return {
    content: [{ type: 'text', text: JSON.stringify({ tool: 'full_port_scan', success: false, error, steps }, null, 2) }],
  };
}

async function bestEffortHarvest(labConfig: LabConfig, sessionId: string): Promise<void> {
  const containerName = resolveCaptureContainer(labConfig);
  if (!containerName) return;
  try {
    await harvestSession({ containerName }, sessionId);
  } catch (err) {
    console.error('[full_port_scan] capture harvest failed:', err);
  }
}

async function fullPortScanHandler(
  args: FullPortScanArgs,
  context: CompositeContext,
): Promise<{ content: { type: string; text: string }[] }> {
  const { labConfig, sshManager } = context;
  if (!sshManager) {
    return failure('SSH manager not configured for full_port_scan');
  }

  const target = typeof args.target === 'string' ? args.target.trim() : '';
  if (!target) {
    return failure('target is required and must be a non-empty string');
  }

  let canonicalTarget: string;
  let portArg: string;
  let timeoutMs: number;
  try {
    canonicalTarget = assertTargetInLabNetwork(target, labConfig.lab.network_subnet);
    portArg = validatePortSpec(args.ports);
    timeoutMs = DEFAULT_TIMEOUT_MS;
    if (typeof args.timeout_ms === 'number' && Number.isFinite(args.timeout_ms)) {
      timeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.floor(args.timeout_ms)));
    }
  } catch (err) {
    return failure(err instanceof Error ? err.message : 'invalid scan parameters');
  }

  // Build the command and report from the canonicalized target only — never the
  // raw caller input — so no unvalidated bytes reach the remote shell.
  const command = buildScanCommand(canonicalTarget, portArg);
  const credentials = getTargetCredentials(labConfig);

  const startedAt = Date.now();
  let result;
  try {
    result = await sshManager.executeCommand(
      credentials.target,
      credentials.username,
      credentials.sshKey,
      command,
      credentials.port,
      timeoutMs,
    );
  } catch (err) {
    const step: CompositeStepRecord = {
      command: String(redact(command)),
      success: false,
      duration_ms: Date.now() - startedAt,
    };
    return failure(err instanceof Error ? err.message : 'nmap execution failed', [step]);
  }

  await bestEffortHarvest(labConfig, result.sessionId);

  const succeeded = result.code === 0;
  const step: CompositeStepRecord = {
    command: String(redact(command)),
    exit_code: result.code ?? undefined,
    signal: result.signal ?? undefined,
    success: succeeded,
    session_id: result.sessionId,
    duration_ms: Date.now() - startedAt,
  };

  if (!succeeded) {
    return failure(`nmap exited with code ${result.code}: ${String(redact(result.stderr.trim()))}`, [step]);
  }

  // Parse failures must stay inside the composite envelope: nmap succeeded, so
  // the step record is real evidence the red OCSF/capture path needs. Returning
  // the failure envelope (success:false, steps:[step]) keeps per-step attribution
  // (ADR-045) instead of rejecting the MCP call and dropping the step.
  let report: PortScanReport;
  try {
    report = parseNmapXml(result.stdout);
  } catch (err) {
    return failure(
      `failed to parse nmap XML output: ${err instanceof Error ? err.message : String(err)}`,
      [step],
    );
  }

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          { tool: 'full_port_scan', success: true, target: canonicalTarget, ports: portArg, report, steps: [step] },
          null,
          2,
        ),
      },
    ],
  };
}

export const fullPortScanComposite: CompositeTool = {
  name: 'full_port_scan',
  description:
    'Run a full TCP port scan (nmap) against a single lab host or bounded CIDR, parse the XML output, and return a compact open-ports report. Scans are confined to the configured lab network.',
  contextKind: 'ssh',
  inputSchema: {
    type: 'object',
    properties: {
      target: {
        type: 'string',
        description: 'Single IPv4 host or IPv4 CIDR (no wider than /24) inside the lab network to scan.',
      },
      ports: {
        type: 'string',
        description: "Port spec: 'all' (default — all 65535 TCP ports), a range like '1-1024', or a list like '22,80,443'.",
        default: 'all',
      },
      timeout_ms: {
        type: 'number',
        description: 'Scan timeout in milliseconds (default 600000, clamped to 1000–1800000).',
        default: DEFAULT_TIMEOUT_MS,
      },
    },
    required: ['target'],
  },
  handler: fullPortScanHandler as CompositeTool['handler'],
};
