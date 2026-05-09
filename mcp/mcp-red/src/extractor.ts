/**
 * Red-team command metadata extractor.
 *
 * Pulls OCSF object fields (`src_endpoint`, `dst_endpoint`, `actor.user`,
 * `file.path`, `url`, `protocol`) out of an arbitrary command string. The
 * implementation is deliberately conservative — it does NOT try to be a
 * shell parser. It tokenises with quote-awareness, then runs targeted
 * regexes scoped to the unquoted portions only, so commands like
 * `echo "the host is 192.168.1.5"` do not surface the IP as a target.
 *
 * Per ADR-027, this module never raises; the logger's best-effort guarantee
 * relies on the extractor returning a plausibly-empty record rather than
 * throwing on malformed input.
 */

import { extractionSurface } from './classifier.js';
import type { ActivityClassification } from './classifier.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface OcsfEndpoint {
  ip?: string;
  hostname?: string;
  port?: number;
  ports?: number[];
  port_range?: string; // preserved spec when expansion would be too large
  cidr?: string;
}

export interface ExtractedFields {
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  dst_endpoints?: OcsfEndpoint[];
  actor?: { user?: { name?: string } };
  target_user?: string;
  file?: { path?: string };
  url?: string;
  protocol?: string;
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

// IPv4 with octet validation handled in code, not regex (cleaner than a
// hand-rolled `25[0-5]|2[0-4]\d|...` alternation).
const IPV4_RE = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?\b/g;

// IPv6 — split into two simpler patterns (full 8-group form and the
// `::`-shorthand form). Single combined pattern was over Sonar's
// regex-complexity threshold (S5843).
const IPV6_FULL_RE = /\b(?:[\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}\b/g;
const IPV6_COMPRESSED_RE = /(?:[\da-fA-F]{0,4}:){1,7}:[\da-fA-F]{0,4}|::[\da-fA-F:]{0,38}/g;

// Capture authority + optional path + optional query/fragment so that
// URLs without a path component (`https://target?x=1`) still preserve
// their query string for SIEM correlation. The authority may be a
// bracketed IPv6 literal (`http://[::1]:8080/x`); we accept `[…]`
// as a single authority unit.
// Authority match is intentionally permissive — `[`, `]`, `:` are
// allowed so bracketed IPv6 (`[::1]:8080`) is captured as one
// authority token. The TS-side `splitUrlAuthority` then peels apart
// brackets, port, and userinfo. Keeping the regex simple satisfies
// Sonar S5843 (regex complexity).
const URL_RE = /\b(https?):\/\/([^\s/?#'"]+)([/?#][^\s'"]*)?/i;

const TCP_PORT_MAX = 65535;

// Port-range expansion cap. Above this we keep the compact `port_range`
// spec and skip materialising every integer — common scanner syntax like
// `nmap -p 1-65535` would otherwise produce 65k-entry log lines.
const PORT_EXPANSION_CAP = 1024;

// ---------------------------------------------------------------------------
// Tokeniser (quote-aware)
// ---------------------------------------------------------------------------

interface Token {
  text: string;
  quoted: boolean; // was the entire token sourced from a quoted run?
}

// Short flags that take a value when in attached form (`-pVALUE`,
// `-uVALUE`). Listed explicitly so we don't accidentally split option
// clusters like `-sV` (nmap) or `-sn` (nmap) which mean different
// things together. These are the only short flags whose attached form
// the extractor needs to understand.
const ATTACHED_VALUE_SHORT_FLAGS = new Set([
  'p',
  'u',
  'U',
  'l',
  'L',
  'P',
  'H',
  'w',
  'd',
  'i',
  'J',
  'A',
]);

/**
 * Normalize equals (`--flag=value`) and attached (`-fVALUE`) flag
 * forms into separate `flag` + `value` tokens so per-tool semantics
 * apply uniformly. Quoted tokens are passed through unchanged because
 * their internal `=` is part of the literal value.
 */
function normalizeFlagForms(tokens: Token[]): Token[] {
  const out: Token[] = [];
  for (const t of tokens) {
    if (t.quoted) {
      out.push(t);
      continue;
    }
    const longEq = /^(--[a-zA-Z][\w-]*)=(.*)$/.exec(t.text);
    const shortEq = longEq ? null : /^(-[a-zA-Z])=(.*)$/.exec(t.text);
    const attachedShort = longEq || shortEq ? null : /^-([a-zA-Z])([^-=].*)$/.exec(t.text);
    const attachedSplittable =
      attachedShort &&
      ATTACHED_VALUE_SHORT_FLAGS.has(attachedShort[1]) &&
      !/^[A-Z]$/.test(attachedShort[2]);
    if (longEq) {
      out.push({ text: longEq[1], quoted: false }, { text: longEq[2], quoted: false });
    } else if (shortEq) {
      out.push({ text: shortEq[1], quoted: false }, { text: shortEq[2], quoted: false });
    } else if (attachedSplittable && attachedShort) {
      out.push(
        { text: `-${attachedShort[1]}`, quoted: false },
        { text: attachedShort[2], quoted: false },
      );
    } else {
      out.push(t);
    }
  }
  return out;
}

function tokenize(command: string): Token[] {
  const tokens: Token[] = [];
  let current = '';
  let quoted = false;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  const finish = () => {
    if (current.length > 0) {
      tokens.push({ text: current, quoted });
      current = '';
      quoted = false;
    }
  };
  for (const ch of command) {
    if (escaped) {
      current += ch;
      escaped = false;
    } else if (ch === '\\') {
      escaped = true;
    } else if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      quoted = true;
    } else if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      quoted = true;
    } else if (inSingle || inDouble) {
      current += ch;
    } else if (/\s/.test(ch)) {
      finish();
    } else {
      current += ch;
    }
  }
  finish();
  return tokens;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isOctetValid(part: string): boolean {
  const n = Number(part);
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

function tryParseIpv4(token: string): { ip: string; cidr?: string } | null {
  if (containsShellMeta(token)) return null;
  IPV4_RE.lastIndex = 0;
  const m = IPV4_RE.exec(token);
  if (!m) return null;
  const [, a, b, c, d, prefix] = m;
  if (![a, b, c, d].every(isOctetValid)) return null;
  const ip = `${a}.${b}.${c}.${d}`;
  if (prefix !== undefined) {
    const p = Number(prefix);
    if (Number.isInteger(p) && p >= 0 && p <= 32) {
      return { ip, cidr: `${ip}/${p}` };
    }
    return { ip }; // suffix invalid, but the IP is real
  }
  return { ip };
}

function tryParseIpv6(token: string): string | null {
  IPV6_FULL_RE.lastIndex = 0;
  const full = IPV6_FULL_RE.exec(token);
  if (full) return full[0];
  IPV6_COMPRESSED_RE.lastIndex = 0;
  const compressed = IPV6_COMPRESSED_RE.exec(token);
  if (compressed?.[0].includes(':')) return compressed[0];
  return null;
}

function tryParsePort(value: string): number | null {
  if (!/^\d+$/.test(value)) return null;
  const n = Number(value);
  if (n < 1 || n > TCP_PORT_MAX) return null;
  return n;
}

interface ExpandedPortSpec {
  ports?: number[];
  port_range?: string;
}

interface PortPart {
  lo: number;
  hi: number; // inclusive; equals lo for single-port parts
  count: number;
}

function parsePortPart(part: string): PortPart | null {
  if (part.includes('-')) {
    const [lo, hi] = part.split('-', 2);
    const lon = Number(lo);
    const hin = Number(hi);
    if (
      !Number.isInteger(lon) ||
      !Number.isInteger(hin) ||
      lon < 1 ||
      hin > TCP_PORT_MAX ||
      hin < lon
    ) {
      return null;
    }
    return { lo: lon, hi: hin, count: hin - lon + 1 };
  }
  const p = tryParsePort(part);
  if (p === null) return null;
  return { lo: p, hi: p, count: 1 };
}

function expandPortSpec(spec: string): ExpandedPortSpec | null {
  const parts = spec.split(',').map(parsePortPart);
  if (parts.includes(null)) return null;
  const validParts = parts as PortPart[];
  const totalCount = validParts.reduce((acc, p) => acc + p.count, 0);
  if (totalCount === 0) return null;
  // Above the cap, preserve the original spec verbatim and skip array
  // materialisation. SIEM consumers that need the ports can re-expand.
  if (totalCount > PORT_EXPANSION_CAP) {
    return { port_range: spec };
  }
  const ports: number[] = [];
  for (const part of validParts) {
    for (let p = part.lo; p <= part.hi; p++) ports.push(p);
  }
  return { ports };
}

// ---------------------------------------------------------------------------
// Per-tool flag semantics
// ---------------------------------------------------------------------------

/**
 * Per-tool truth table for the `-l` / `--user` / `--username` short
 * flags.
 *
 * - `ssh` / `plink` / `hydra` / `medusa` / `patator` / `crowbar` /
 *   `crackmapexec` / `cme` / `nxc` / `smbclient` use `-l` as a username.
 * - `ldapsearch` uses `-l <seconds>` as a time limit.
 * - `enum4linux` / `nbtscan` / `rpcclient` don't have a `-l` flag with
 *   a clear "target user" meaning.
 *
 * For ambiguous tools, we conservatively skip extraction rather than
 * fabricate an actor.
 */
const TOOLS_USING_DASH_L_AS_USER: ReadonlySet<string> = new Set([
  'ssh',
  'plink',
  'hydra',
  'medusa',
  'patator',
  'crowbar',
  'crackmapexec',
  'cme',
  'nxc',
  'smbclient',
]);

const TOOLS_USING_LONG_USER_AS_TARGET: ReadonlySet<string> = new Set([
  ...TOOLS_USING_DASH_L_AS_USER,
  'ssh',
  'rpcclient',
  // Conservative: curl / wget intentionally NOT in this set — their
  // `--user` is a Basic-auth credential pair which would leak the
  // password into actor.user.name.
]);

/**
 * Tools where short `-u` is a target user (NOT a URL). Distinct from
 * the long-form `--user` set because curl/sqlmap use `-u` as URL.
 */
const TOOLS_USING_DASH_U_AS_USER: ReadonlySet<string> = new Set([
  'crackmapexec',
  'cme',
  'nxc',
  'smbclient',
  'rpcclient',
  'evil-winrm',
  'kerbrute',
  'bloodhound-python',
  'bloodhound.py',
]);

const TOOLS_USING_DASH_BIG_U_AS_USER: ReadonlySet<string> = new Set([
  'smbclient',
  'rpcclient',
  'enum4linux',
]);

function isUserFlagForTool(flag: string, tool: string | undefined): boolean {
  if (!tool) return false;
  if (flag === '-l') return TOOLS_USING_DASH_L_AS_USER.has(tool);
  if (flag === '-u') return TOOLS_USING_DASH_U_AS_USER.has(tool);
  if (flag === '-U') return TOOLS_USING_DASH_BIG_U_AS_USER.has(tool);
  return TOOLS_USING_LONG_USER_AS_TARGET.has(tool);
}

/**
 * Tools whose `-o <path>` means "write output to file". Other tools
 * use `-o` for unrelated semantics (notably `ssh -o KEY=VALUE`).
 */
const TOOLS_USING_DASH_O_AS_OUTPUT: ReadonlySet<string> = new Set([
  'nmap',
  'masscan',
  'rustscan',
  'unicornscan',
  'gobuster',
  'dirb',
  'dirbuster',
  'wfuzz',
  'ffuf',
  'feroxbuster',
  'sqlmap',
  'nikto',
  'wpscan',
  'hydra',
  'medusa',
  'patator',
  'crowbar',
]);

function isOutputFlagForTool(tool: string | undefined): boolean {
  if (!tool) return false;
  return TOOLS_USING_DASH_O_AS_OUTPUT.has(tool);
}

/**
 * Tools where `-p <value>` is a password, NOT a port. Includes the
 * obvious credential brute-force tools and the host-discovery wrappers
 * (`crackmapexec`, `cme`, `nxc`) whose `-p` is a password — these
 * classify under `host_discovery` for activity but still take a
 * password short-flag.
 */
// Source of truth for tools whose short `-p` is a password (extractor +
// redactor share this). Mirrors `CREDENTIAL_SHORT_P_TOOLS` in
// `aptl-mcp-common/src/redaction.ts`; both sets must stay aligned —
// extractor uses it to consume the token (so the value never lands in
// `dst_endpoint.hostname`), redactor uses it for cmd_line masking.
const TOOLS_USING_DASH_P_AS_PASSWORD: ReadonlySet<string> = new Set([
  // credential_brute_force
  'hydra',
  'medusa',
  'patator',
  'crowbar',
  'sshpass',
  'kerbrute',
  // host_discovery tools that also take passwords
  'crackmapexec',
  'cme',
  'nxc',
  'bloodhound-python',
  'bloodhound.py',
  // remote_execution
  'evil-winrm',
  'impacket-psexec',
  'impacket-smbexec',
  'impacket-wmiexec',
  'impacket-secretsdump',
  'psexec.py',
  'smbexec.py',
  'wmiexec.py',
  'secretsdump.py',
  'getuserspns.py',
  'getnpusers.py',
  'ntlmrelayx.py',
  // database CLIs
  'mysql',
  'mysqladmin',
  'mariadb',
  'redis-cli',
]);

function isPasswordFlagForTool(tool: string | undefined): boolean {
  if (!tool) return false;
  return TOOLS_USING_DASH_P_AS_PASSWORD.has(tool);
}

/**
 * Apply a URL_RE match to `result.url` / `result.protocol` and to
 * `dst` (hostname / ip / port). Strips userinfo, splits bracketed IPv6
 * authorities, and routes IP literals to `dst.ip` rather than
 * `hostname`. Returns true on success.
 */
function splitUrlAuthority(hostport: string, dst: OcsfEndpoint): string {
  if (hostport.startsWith('[')) {
    const closeBracket = hostport.indexOf(']');
    if (closeBracket !== -1) {
      const after = hostport.slice(closeBracket + 1);
      if (after.startsWith(':')) {
        const port = tryParsePort(after.slice(1));
        if (port !== null) dst.port = port;
      }
      return hostport.slice(0, closeBracket + 1);
    }
    return hostport;
  }
  const lastColon = hostport.lastIndexOf(':');
  if (lastColon !== -1 && /^\d+$/.test(hostport.slice(lastColon + 1))) {
    const port = tryParsePort(hostport.slice(lastColon + 1));
    if (port !== null) dst.port = port;
    return hostport.slice(0, lastColon);
  }
  return hostport;
}

function assignUrlFromMatch(
  _tokenText: string,
  m: RegExpExecArray,
  result: ExtractedFields,
  dst: OcsfEndpoint,
): boolean {
  const scheme = m[1];
  const hostportRaw = m[2];
  const path = m[3] ?? '';
  const atIdx = hostportRaw.lastIndexOf('@');
  const hostport = atIdx >= 0 ? hostportRaw.slice(atIdx + 1) : hostportRaw;
  result.url = `${scheme}://${hostport}${path}`;
  result.protocol = scheme.toLowerCase();
  const host = splitUrlAuthority(hostport, dst);
  const unbracketed = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  const v4 = tryParseIpv4(unbracketed);
  if (v4) {
    dst.ip = v4.ip;
  } else if (tryParseIpv6(unbracketed)) {
    dst.ip = unbracketed;
  } else {
    dst.hostname = host;
  }
  return true;
}

function looksLikeHostname(token: string): boolean {
  // Hostnames must contain a `.` so a bare command name like `echo` or
  // `nmap` is not surfaced as a target. Bare-label hosts like `kali` are
  // intentionally not picked up — the lab targets containers by IP and
  // real targets are FQDN-shaped.
  if (token.startsWith('-')) return false;
  if (containsShellMeta(token)) return false;
  if (!/^[a-zA-Z][a-zA-Z0-9.-]*$/.test(token)) return false;
  return token.includes('.');
}

/**
 * Tokens containing shell-meta — parameter expansion (`${VAR}`, `$VAR`),
 * command substitution (`$(cmd)`, backtick `…`), or process substitution
 * (`<(cmd)`, `>(cmd)`) — must NOT be treated as concrete values. Their
 * runtime value is unknown to a static parser; promoting them as
 * destinations or files would be fabrication.
 */
function containsShellMeta(token: string): boolean {
  if (token.includes('$(') || token.includes('${') || token.includes('`')) return true;
  if (token.startsWith('<(') || token.startsWith('>(')) return true;
  // Bare $VAR (followed by a name char) — but NOT `$5` (positional) or
  // `$$` (PID); both rare in command-line args we'd extract.
  if (/\$[A-Za-z_]/.test(token)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Flag handlers — extracted from the dispatch loop so each handler stays
// small and the main loop's cognitive complexity stays bounded.
// ---------------------------------------------------------------------------

interface FlagCtx {
  i: number;
  next: string;
  classification: ActivityClassification;
  result: ExtractedFields;
  dst: OcsfEndpoint;
  consumedNext: Set<number>;
}

const WORDLIST_FAMILIES = new Set(['web_discovery', 'credential_brute_force']);

function consumeIfNotFlag(ctx: FlagCtx): boolean {
  if (ctx.next.startsWith('-')) return false;
  ctx.consumedNext.add(ctx.i + 1);
  return true;
}

function handleUserAgent(ctx: FlagCtx): void {
  consumeIfNotFlag(ctx);
}

function handleDashA(ctx: FlagCtx): void {
  const tool = ctx.classification.tool ?? '';
  if (tool === 'curl' || tool === 'wget') consumeIfNotFlag(ctx);
}

function handleSshJump(ctx: FlagCtx): void {
  if (ctx.classification.tool === 'ssh') consumeIfNotFlag(ctx);
}

function handleRemoteI(ctx: FlagCtx): void {
  if (ctx.classification.activity_type !== 'remote_execution') return;
  if (ctx.next.startsWith('-')) return;
  const v4 = tryParseIpv4(ctx.next);
  if (v4) {
    ctx.dst.ip = v4.ip;
    if (v4.cidr) ctx.dst.cidr = v4.cidr;
  } else if (looksLikeHostname(ctx.next)) {
    ctx.dst.hostname = ctx.next;
  }
  ctx.consumedNext.add(ctx.i + 1);
}

function handleNtlmHash(ctx: FlagCtx): void {
  if (isPasswordFlagForTool(ctx.classification.tool)) consumeIfNotFlag(ctx);
}

function handleDomainFlag(ctx: FlagCtx): void {
  if (
    isPasswordFlagForTool(ctx.classification.tool) ||
    ctx.classification.activity_type === 'remote_execution'
  ) {
    consumeIfNotFlag(ctx);
  }
}

function handleUserFlag(text: string, ctx: FlagCtx): void {
  if (!isUserFlagForTool(text, ctx.classification.tool)) return;
  if (ctx.next.startsWith('-')) return;
  const pct = ctx.next.indexOf('%');
  const cleaned = pct === -1 ? ctx.next : ctx.next.slice(0, pct);
  if (!cleaned.includes(':') && !/^https?:\/\//i.test(cleaned)) {
    ctx.result.target_user = cleaned;
  }
  ctx.consumedNext.add(ctx.i + 1);
}

function applyExpandedPorts(spec: string, dst: OcsfEndpoint): void {
  if (!/^[\d,-]+$/.test(spec)) return;
  const expanded = expandPortSpec(spec);
  if (!expanded) return;
  if (expanded.ports) dst.ports = expanded.ports;
  if (expanded.port_range) dst.port_range = expanded.port_range;
}

function handlePortOrPassword(ctx: FlagCtx): void {
  // `-p` is a password for credential tools — consume and don't surface.
  if (isPasswordFlagForTool(ctx.classification.tool)) {
    ctx.consumedNext.add(ctx.i + 1);
    return;
  }
  const tool = ctx.classification.tool;
  if (tool === 'ssh' || tool === 'plink') {
    const port = tryParsePort(ctx.next);
    if (port !== null) ctx.dst.port = port;
    return;
  }
  if (ctx.classification.activity_type === 'network_connection') {
    // `nc -p N` is a local source port — don't surface as destination.
    return;
  }
  applyExpandedPorts(ctx.next, ctx.dst);
}

function handlePortsList(ctx: FlagCtx): void {
  // `-P` is hydra's password list (file) OR nmap-style ports.
  if (ctx.classification.activity_type === 'credential_brute_force') {
    if (!ctx.next.startsWith('-')) {
      ctx.result.file = { path: ctx.next };
      ctx.consumedNext.add(ctx.i + 1);
    }
    return;
  }
  applyExpandedPorts(ctx.next, ctx.dst);
}

function handleOutputFile(ctx: FlagCtx): void {
  if (!isOutputFlagForTool(ctx.classification.tool)) return;
  if (ctx.next.startsWith('-')) return;
  ctx.result.file = { path: ctx.next };
  ctx.consumedNext.add(ctx.i + 1);
}

function setFileIfTool(
  ctx: FlagCtx,
  predicate: (cls: ActivityClassification) => boolean,
  preserveExisting = false,
): void {
  if (!predicate(ctx.classification)) return;
  if (ctx.next.startsWith('-')) return;
  if (!preserveExisting || !ctx.result.file) {
    ctx.result.file = { path: ctx.next };
  }
  ctx.consumedNext.add(ctx.i + 1);
}

function handleNmapOutputForm(ctx: FlagCtx): void {
  setFileIfTool(ctx, (c) => c.activity_type === 'port_scan');
}

function handleWordlist(ctx: FlagCtx): void {
  setFileIfTool(ctx, (c) => WORDLIST_FAMILIES.has(c.activity_type));
}

function handleHydraUserList(ctx: FlagCtx): void {
  setFileIfTool(ctx, (c) => c.activity_type === 'credential_brute_force', true);
}

function handleNmapInputList(ctx: FlagCtx): void {
  setFileIfTool(ctx, (c) => c.activity_type === 'port_scan');
}

const FLAG_HANDLERS: Record<string, (ctx: FlagCtx) => void> = {
  '--user-agent': handleUserAgent,
  '-A': handleDashA,
  '-J': handleSshJump,
  '-i': handleRemoteI,
  '-H': handleNtlmHash,
  '-d': handleDomainFlag,
  '-p': handlePortOrPassword,
  '--port': handlePortOrPassword,
  '--ports': handlePortsList,
  '--port-range': handlePortsList,
  '-P': handlePortsList,
  '-o': handleOutputFile,
  '--output': handleOutputFile,
  '-oN': handleNmapOutputForm,
  '-oX': handleNmapOutputForm,
  '-oG': handleNmapOutputForm,
  '-oA': handleNmapOutputForm,
  '-oS': handleNmapOutputForm,
  '-w': handleWordlist,
  '--wordlist': handleWordlist,
  '-L': handleHydraUserList,
  '-iL': handleNmapInputList,
};

const USER_FLAG_NAMES = new Set(['-l', '--user', '--username', '-u', '-U']);

function applyFlagHandlers(
  all: Token[],
  classification: ActivityClassification,
  result: ExtractedFields,
  dst: OcsfEndpoint,
  consumedNext: Set<number>,
): void {
  for (let i = 0; i < all.length; i++) {
    const text = all[i].text;
    const next = all[i + 1]?.text;
    if (next === undefined) continue;
    const ctx: FlagCtx = { i, next, classification, result, dst, consumedNext };
    if (USER_FLAG_NAMES.has(text)) {
      handleUserFlag(text, ctx);
      continue;
    }
    const handler = FLAG_HANDLERS[text];
    if (handler) handler(ctx);
  }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

export function extractMetadata(
  command: string,
  classification: ActivityClassification,
): ExtractedFields {
  if (!command || !command.trim()) return {};
  // Extract from the SAME unwrapped surface the classifier classified.
  // `extractionSurface` strips compound-command tails, sudo / env /
  // transparent-wrapper preamble, and `bash -c '<inner>'` quoting so
  // both passes see the same tokens. Without this, `bash -c 'nmap …'`
  // would classify as port_scan but extract zero targets.
  const head = extractionSurface(command);
  const tokens = normalizeFlagForms(tokenize(head));
  // Bare positional-host detection (loop 3) must NOT pick up IPs from
  // multi-word commentary like `echo "the host is 192.168.1.5"`. Targeted
  // extraction (URL detection, flag-pair processing) intentionally runs
  // against ALL tokens because shell users routinely quote URLs to escape
  // `&` / `?` and quote `-l "alice"` etc.
  const unquoted = tokens.filter((t) => !t.quoted);
  const all = tokens;
  const result: ExtractedFields = {};
  const dst: OcsfEndpoint = {};

  // 1. URL — for tools whose target is a URL, parse first so the dst
  // hostname/port come from the URL even when the URL also contains an IP-
  // shaped path. Userinfo (`user:password@host`) is stripped before
  // anything is recorded — even though `process.cmd_line` is later
  // redacted, structured fields must not echo credentials.
  //
  // Acceptance rules (cycle-9 review):
  //   (a) the token immediately follows a `-u` / `--url` / `-target` /
  //       `--target` flag — the explicit target-URL flag — OR
  //   (b) the URL is the entire token text and is unquoted — a
  //       standalone URL argument such as `curl https://target/x`.
  // Headers, payloads, decoy URLs in `-H 'Referer: …'`, or URLs inside
  // multi-word quoted commentary (`echo "visit https://target"`) are
  // intentionally NOT promoted, because they mislead SIEM correlation.
  const URL_TARGET_FLAGS = new Set(['-u', '--url', '--target', '-target', '-T']);
  // Flags whose URL value is NOT the target (proxies, headers, referer
  // overrides, upload sources). When a URL token follows one of these,
  // skip it and keep looking for the real target. Without this guard
  // `sqlmap --proxy http://127.0.0.1:8080 -u https://target/x` records
  // the proxy as the destination.
  const NON_TARGET_URL_FLAGS = new Set([
    '--proxy',
    '-x',
    '--socks5',
    '--socks4',
    '--socks5-hostname',
    '--referer',
    '-e',
    '--upload-file',
    '-T',
    '--header',
    '-H',
  ]);
  extractUrlTwoPass(all, URL_TARGET_FLAGS, NON_TARGET_URL_FLAGS, result, dst);

  // 2. Flag-driven extraction. Runs on all tokens (quoted values are valid
  // inputs — `hydra -l "alice" …`, `-w "/path/with spaces"`).
  // `consumedNext` tracks indices whose value was claimed by a file/output
  // flag so the positional-host loop below does not promote them to
  // hostnames (e.g. `nmap -o scan.txt 10.0.0.1` should not produce
  // `dst.hostname = scan.txt`).
  const consumedNext = new Set<number>();
  applyFlagHandlers(all, classification, result, dst, consumedNext);

  // 3. SSH-style `user@host[:port]` and positional host / IP / hostname.
  const positionalHostFound = extractPositionalHosts(all, consumedNext, classification, result, dst);

  // 4. `host port` positional pair (e.g. `nc 10.0.0.1 8080`).
  if (positionalHostFound && dst.port === undefined && dst.ports === undefined) {
    extractPositionalHostPort(all, consumedNext, dst);
  }

  // 5. Trailing protocol token for credential brute-force tools.
  extractTrailingProtocol(unquoted, classification, result);

  if (Object.keys(dst).length > 0) result.dst_endpoint = dst;
  return result;
}

const NETWORK_TARGETING_ACTIVITY_TYPES = new Set([
  'port_scan',
  'network_connection',
  'ssh_login_attempt',
  'credential_brute_force',
  'web_attack',
  'web_discovery',
  'host_discovery',
  'remote_execution',
  'network_poisoning',
]);

const KNOWN_BRUTEFORCE_PROTOCOLS = new Set([
  'ssh',
  'ftp',
  'http',
  'https',
  'mysql',
  'mssql',
  'postgres',
  'rdp',
  'smb',
  'telnet',
  'vnc',
  'imap',
  'pop3',
  'snmp',
]);

function tryUserAtHost(
  text: string,
  result: ExtractedFields,
  dst: OcsfEndpoint,
): boolean {
  const at = text.indexOf('@');
  if (at === -1) return false;
  const left = text.slice(0, at);
  const right = text.slice(at + 1);
  if (!/^[A-Za-z_][\w.-]*$/.test(left)) return false;
  result.target_user ??= left;
  const colon = right.lastIndexOf(':');
  let host = right;
  if (colon !== -1 && /^\d+$/.test(right.slice(colon + 1))) {
    const port = tryParsePort(right.slice(colon + 1));
    if (port !== null) dst.port = port;
    host = right.slice(0, colon);
  }
  const v4 = tryParseIpv4(host);
  if (v4) {
    dst.ip = v4.ip;
    if (v4.cidr) dst.cidr = v4.cidr;
  } else if (looksLikeHostname(host)) {
    dst.hostname = host;
  }
  return true;
}

function tryPositionalIpOrHostname(text: string, dst: OcsfEndpoint): boolean {
  const v4 = tryParseIpv4(text);
  if (v4) {
    if (!dst.ip) dst.ip = v4.ip;
    if (v4.cidr && !dst.cidr) dst.cidr = v4.cidr;
    return true;
  }
  const v6 = tryParseIpv6(text);
  if (v6 && !dst.ip) {
    dst.ip = v6;
    return true;
  }
  if (!dst.ip && !dst.hostname && looksLikeHostname(text)) {
    dst.hostname = text;
    return true;
  }
  return false;
}

function tryAssignUrl(
  ti: number,
  all: Token[],
  result: ExtractedFields,
  dst: OcsfEndpoint,
  predicate: (m: RegExpExecArray, t: Token, prevText: string) => boolean,
): boolean {
  const t = all[ti];
  const m = URL_RE.exec(t.text);
  if (!m) return false;
  const prevText = ti > 0 ? all[ti - 1].text : '';
  if (!predicate(m, t, prevText)) return false;
  return assignUrlFromMatch(t.text, m, result, dst);
}

function extractUrlTwoPass(
  all: Token[],
  targetFlags: Set<string>,
  nonTargetFlags: Set<string>,
  result: ExtractedFields,
  dst: OcsfEndpoint,
): void {
  // PASS 1: explicit target-URL flags take priority.
  for (let ti = 1; ti < all.length; ti++) {
    if (
      tryAssignUrl(ti, all, result, dst, (_m, _t, prev) => targetFlags.has(prev))
    ) {
      return;
    }
  }
  // PASS 2: standalone URL tokens; skip URLs that are values of known
  // non-target flags (proxies, headers, referer overrides, etc.).
  for (let ti = 0; ti < all.length; ti++) {
    if (
      tryAssignUrl(ti, all, result, dst, (m, t, prev) => {
        if (nonTargetFlags.has(prev)) return false;
        return m[0].length === t.text.trim().length;
      })
    ) {
      return;
    }
  }
}

function extractPositionalHosts(
  all: Token[],
  consumedNext: Set<number>,
  classification: ActivityClassification,
  result: ExtractedFields,
  dst: OcsfEndpoint,
): boolean {
  if (!NETWORK_TARGETING_ACTIVITY_TYPES.has(classification.activity_type)) return false;
  let found = false;
  for (let i = 0; i < all.length; i++) {
    const t = all[i];
    if (t.quoted || consumedNext.has(i)) continue;
    const text = t.text;
    if (text.startsWith('-')) continue;
    if (tryUserAtHost(text, result, dst)) {
      found = true;
      continue;
    }
    if (tryPositionalIpOrHostname(text, dst)) found = true;
  }
  return found;
}

function extractPositionalHostPort(
  all: Token[],
  consumedNext: Set<number>,
  dst: OcsfEndpoint,
): void {
  for (let i = 0; i < all.length - 1; i++) {
    const a = all[i];
    const b = all[i + 1];
    if (a.quoted || b.quoted) continue;
    if (consumedNext.has(i) || consumedNext.has(i + 1)) continue;
    const at = a.text;
    const bt = b.text;
    if (at.startsWith('-')) continue;
    const v4 = tryParseIpv4(at);
    const isIpv6 = !v4 && tryParseIpv6(at) !== null;
    const isHostname = !v4 && !isIpv6 && looksLikeHostname(at);
    if (!v4 && !isIpv6 && !isHostname) continue;
    const port = tryParsePort(bt);
    if (port !== null) {
      dst.port = port;
      return;
    }
  }
}

function extractTrailingProtocol(
  unquoted: Token[],
  classification: ActivityClassification,
  result: ExtractedFields,
): void {
  if (classification.activity_type !== 'credential_brute_force' || unquoted.length === 0) return;
  const last = unquoted.at(-1)?.text ?? '';
  if (last.startsWith('-')) return;
  if (!/^[a-z][\w-]*$/i.test(last)) return;
  if (KNOWN_BRUTEFORCE_PROTOCOLS.has(last.toLowerCase())) {
    result.protocol = last.toLowerCase();
  }
}
