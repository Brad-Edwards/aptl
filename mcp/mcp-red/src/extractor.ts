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

// IPv6 — must contain at least one `::` or two `:` so identifiers like
// `abc::` aren't accidentally matched while `2001:db8::1` and `::1` are.
// We keep the form deliberately conservative: token-bounded patterns
// covering the four canonical shapes (full 8-group, leading-zeros-elided,
// `::`-shorthand at end, `::`-shorthand in middle, `::loopback`). Order
// matters — longest forms must come first.
const IPV6_RE = new RegExp(
  '(?:' +
    // Full 8 groups, e.g. fe80:0:0:0:0:0:0:1
    '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' +
    // 1-7 groups followed by `::` and 1-7 groups (e.g. 2001:db8::1)
    '|(?:[0-9a-fA-F]{1,4}:){1,7}(?::[0-9a-fA-F]{1,4}){1,7}' +
    // 1-7 groups trailing `::` (e.g. fe80::)
    '|(?:[0-9a-fA-F]{1,4}:){1,7}:' +
    // `::` followed by 1-7 groups (e.g. ::1)
    '|::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}' +
    // bare `::`
    '|::' +
    ')',
  'g',
);

// Capture authority + optional path + optional query/fragment so that
// URLs without a path component (`https://target?x=1`) still preserve
// their query string for SIEM correlation. The authority may be a
// bracketed IPv6 literal (`http://[::1]:8080/x`); we accept `[…]`
// as a single authority unit.
const URL_RE = /\b(https?):\/\/(\[[0-9a-fA-F:]+\][^\s/?#'"]*|[^\s/?#'"]+)([/?#][^\s'"]*)?/i;

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
    // `--flag=value` (long form). The flag part has at least one `=`.
    const longEq = t.text.match(/^(--[a-zA-Z][\w-]*)=(.*)$/);
    if (longEq) {
      out.push({ text: longEq[1], quoted: false });
      out.push({ text: longEq[2], quoted: false });
      continue;
    }
    // `-flag=value` (short with equals — e.g., `-l=alice`).
    const shortEq = t.text.match(/^(-[a-zA-Z])=(.*)$/);
    if (shortEq) {
      out.push({ text: shortEq[1], quoted: false });
      out.push({ text: shortEq[2], quoted: false });
      continue;
    }
    // `-fVALUE` attached short form, only for the known value-taking
    // single-letter flags. `-iL` (nmap input list) handled separately
    // because L is a flag suffix, not a value.
    const attachedShort = t.text.match(/^-([a-zA-Z])([^-=].*)$/);
    if (
      attachedShort &&
      ATTACHED_VALUE_SHORT_FLAGS.has(attachedShort[1]) &&
      // Don't split `-iL`, `-iR`, `-oN`, `-oX`, `-oG`, `-oA` — those
      // are flag-with-suffix forms, not attached values.
      !/^[A-Z]$/.test(attachedShort[2])
    ) {
      out.push({ text: `-${attachedShort[1]}`, quoted: false });
      out.push({ text: attachedShort[2], quoted: false });
      continue;
    }
    out.push(t);
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
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      quoted = true;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      quoted = true;
      continue;
    }
    if (!inSingle && !inDouble && /\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push({ text: current, quoted });
        current = '';
        quoted = false;
      }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) tokens.push({ text: current, quoted });
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
  IPV6_RE.lastIndex = 0;
  const m = IPV6_RE.exec(token);
  if (!m) return null;
  const candidate = m[0];
  // Reject obvious junk: must contain at least one ':' and at most two
  // adjacent ':' tokens (the `::` shorthand).
  if (!candidate.includes(':')) return null;
  return candidate;
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

function expandPortSpec(spec: string): ExpandedPortSpec | null {
  const parts = spec.split(',');
  const ports: number[] = [];
  let totalCount = 0;
  for (const part of parts) {
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
      totalCount += hin - lon + 1;
    } else {
      const p = tryParsePort(part);
      if (p === null) return null;
      totalCount += 1;
    }
  }
  // Above the cap, preserve the original spec verbatim and skip array
  // materialisation. SIEM consumers that need the ports can re-expand.
  if (totalCount > PORT_EXPANSION_CAP) {
    return { port_range: spec };
  }
  for (const part of parts) {
    if (part.includes('-')) {
      const [lo, hi] = part.split('-', 2);
      const lon = Number(lo);
      const hin = Number(hi);
      for (let p = lon; p <= hin; p++) ports.push(p);
    } else {
      const p = tryParsePort(part);
      if (p === null) return null;
      ports.push(p);
    }
  }
  return ports.length > 0 ? { ports } : null;
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
function assignUrlFromMatch(
  tokenText: string,
  m: RegExpExecArray,
  result: ExtractedFields,
  dst: OcsfEndpoint,
): boolean {
  void tokenText; // referenced via captures
  const scheme = m[1];
  const hostportRaw = m[2];
  const path = m[3] ?? '';
  const atIdx = hostportRaw.lastIndexOf('@');
  const hostport = atIdx !== -1 ? hostportRaw.slice(atIdx + 1) : hostportRaw;
  result.url = `${scheme}://${hostport}${path}`;
  result.protocol = scheme.toLowerCase();
  let host = hostport;
  if (hostport.startsWith('[')) {
    const closeBracket = hostport.indexOf(']');
    if (closeBracket !== -1) {
      const bracketed = hostport.slice(0, closeBracket + 1);
      const after = hostport.slice(closeBracket + 1);
      host = bracketed;
      if (after.startsWith(':')) {
        const port = tryParsePort(after.slice(1));
        if (port !== null) dst.port = port;
      }
    }
  } else {
    const lastColon = hostport.lastIndexOf(':');
    if (lastColon !== -1 && /^\d+$/.test(hostport.slice(lastColon + 1))) {
      const port = tryParsePort(hostport.slice(lastColon + 1));
      if (port !== null) dst.port = port;
      host = hostport.slice(0, lastColon);
    }
  }
  const unbracketed = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  const v4 = tryParseIpv4(unbracketed);
  if (v4) {
    dst.ip = v4.ip;
  } else if (tryParseIpv6(unbracketed) !== null) {
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
  // PASS 1: explicit target-URL flags take priority. If the user wrote
  // \`-u <url>\`, that's the target regardless of any earlier URL
  // tokens.
  let urlAssigned = false;
  for (let ti = 1; ti < all.length && !urlAssigned; ti++) {
    const prevText = all[ti - 1].text;
    if (!URL_TARGET_FLAGS.has(prevText)) continue;
    const t = all[ti];
    const m = URL_RE.exec(t.text);
    if (!m) continue;
    if (assignUrlFromMatch(t.text, m, result, dst)) urlAssigned = true;
  }
  // PASS 2: standalone URL tokens elsewhere on the line, skipping any
  // URL that is the value of a known non-target flag.
  for (let ti = 0; ti < all.length && !urlAssigned; ti++) {
    const t = all[ti];
    const m = URL_RE.exec(t.text);
    if (!m) continue;
    const prevText = ti > 0 ? all[ti - 1].text : '';
    if (NON_TARGET_URL_FLAGS.has(prevText)) continue;
    const isWholeToken = m[0].length === t.text.trim().length;
    if (!isWholeToken) continue;
    if (assignUrlFromMatch(t.text, m, result, dst)) urlAssigned = true;
  }
  // (legacy single-loop URL extraction removed — replaced by the two-pass
  // approach above that prioritises explicit target-URL flags and
  // skips known non-target URL flags like `--proxy`, `-x`, `--referer`.)

  // 2. Flag-driven extraction. Runs on all tokens (quoted values are valid
  // inputs — `hydra -l "alice" …`, `-w "/path/with spaces"`).
  // `consumedNext` tracks indices whose value was claimed by a file/output
  // flag so the positional-host loop below does not promote them to
  // hostnames (e.g. `nmap -o scan.txt 10.0.0.1` should not produce
  // `dst.hostname = scan.txt`).
  const consumedNext = new Set<number>();
  for (let i = 0; i < all.length; i++) {
    const text = all[i].text;
    const next = all[i + 1]?.text;
    if (next === undefined) continue;

    // User flag handling — per-tool, not per-family. Different tools in
    // the same activity family use the same short flag for different
    // things (e.g. `ldapsearch -l 5` is a time limit, not a username),
    // so a per-family rule produces wrong actor.user.name values.
    // `--user-agent` is the HTTP User-Agent header for curl/wget — NOT
    // a target user. Always skip without consuming an arg.
    if (text === '--user-agent') {
      if (!next.startsWith('-')) consumedNext.add(i + 1);
      continue;
    }
    // `-A` is per-tool: curl/wget treat it as User-Agent (consumes next
    // token); nmap treats it as "aggressive scan" (NO value); other
    // tools may differ. Default behaviour: only consume the next token
    // when the tool is curl/wget.
    if (text === '-A') {
      const tool = classification.tool ?? '';
      if ((tool === 'curl' || tool === 'wget') && !next.startsWith('-')) {
        consumedNext.add(i + 1);
      }
      // For nmap and others, do NOT consume; positional target
      // extraction will pick up `10.0.0.1` correctly.
      continue;
    }
    // SSH `-J <jumphost>` is a proxy, not the target. Consume so the
    // jump host doesn't get promoted to dst_endpoint.
    if (text === '-J' && classification.tool === 'ssh') {
      if (!next.startsWith('-')) consumedNext.add(i + 1);
      continue;
    }
    // evil-winrm / impacket family `-i <host>` is the destination IP.
    if (text === '-i' && classification.activity_type === 'remote_execution') {
      if (!next.startsWith('-')) {
        const v4 = tryParseIpv4(next);
        if (v4) {
          dst.ip = v4.ip;
          if (v4.cidr) dst.cidr = v4.cidr;
        } else if (looksLikeHostname(next)) {
          dst.hostname = next;
        }
        consumedNext.add(i + 1);
      }
      continue;
    }
    // crackmapexec / cme / nxc `-H <hash>` — NTLM/password-equivalent
    // hash. Treat exactly like a password: never surface, mark consumed.
    if (text === '-H' && isPasswordFlagForTool(classification.tool)) {
      if (!next.startsWith('-')) consumedNext.add(i + 1);
      continue;
    }
    // crackmapexec / cme / nxc / impacket `-d <domain>` — Windows
    // domain. Surface as protocol context but don't promote to host.
    if (
      text === '-d' &&
      (isPasswordFlagForTool(classification.tool) ||
        classification.activity_type === 'remote_execution')
    ) {
      if (!next.startsWith('-')) consumedNext.add(i + 1);
      continue;
    }
    if (
      text === '-l' ||
      text === '--user' ||
      text === '--username' ||
      text === '-u' ||
      text === '-U'
    ) {
      if (isUserFlagForTool(text, classification.tool) && !next.startsWith('-')) {
        // Samba tools accept `username%password`; strip after `%` so the
        // password never lands in `actor.user.name`. The full original
        // value is still in the redacted `process.cmd_line`.
        const pct = next.indexOf('%');
        const cleaned = pct === -1 ? next : next.slice(0, pct);
        // Defence in depth: if the value also contains `:` (Basic-auth
        // pair shape), drop the value entirely rather than promote
        // `user:pass` even when its tool was on the allowlist. URLs
        // (e.g. `sqlmap -u https://target`) also get filtered — the
        // URL extractor handles those.
        if (!cleaned.includes(':') && !/^https?:\/\//i.test(cleaned)) {
          result.target_user = cleaned;
        }
        consumedNext.add(i + 1);
      }
      continue;
    }
    // -p PORT (numeric) → port
    // For hydra, -p is the password; the classifier tells us which family.
    if (text === '-p' || text === '--port') {
      // Tools whose `-p` is a password (credential_brute_force AND the
      // host_discovery wrappers like nxc/cme/crackmapexec). For these,
      // we mark the value consumed so the positional-host loop cannot
      // promote a dot-shaped password into `dst_endpoint.hostname` and
      // never surface it as a port.
      if (isPasswordFlagForTool(classification.tool)) {
        consumedNext.add(i + 1);
        continue;
      }
      // For SSH-style tools, `-p` is the *connection* port (single number).
      // For scanners like nmap/masscan, `-p` is a list spec (`22,80,443`
      // / `1-1024`). For nc/ncat/socat, `-p` is the LOCAL source port,
      // not a destination port — skip it so the positional `host port`
      // pair extracts the real destination.
      const sshLike = classification.tool === 'ssh' || classification.tool === 'plink';
      if (sshLike) {
        const port = tryParsePort(next);
        if (port !== null) dst.port = port;
        continue;
      }
      const networkConnectionTool = classification.activity_type === 'network_connection';
      if (networkConnectionTool) {
        // Skip — local source port for nc/ncat/socat. Don't surface as
        // `dst.port` or `dst.ports`. (We also don't currently model a
        // separate `src_endpoint.port` field — the value is preserved in
        // the redacted `process.cmd_line`.)
        continue;
      }
      if (/^[\d,-]+$/.test(next)) {
        const expanded = expandPortSpec(next);
        if (expanded) {
          if (expanded.ports) dst.ports = expanded.ports;
          if (expanded.port_range) dst.port_range = expanded.port_range;
        }
      }
      continue;
    }
    // --ports / --port-range → always ports
    if (text === '--ports' || text === '--port-range' || text === '-P') {
      // -P is hydra password list (file) OR nmap "ports". Disambiguate by
      // tool family — for credential brute-force tools, -P is a wordlist
      // file, recorded as file.path.
      if (classification.activity_type === 'credential_brute_force') {
        if (!next.startsWith('-')) {
          result.file = { path: next };
          // Mark as consumed so the positional-host loop does not pick up
          // a relative wordlist path (`passwords.txt`) as a hostname.
          consumedNext.add(i + 1);
        }
      } else if (/^[\d,-]+$/.test(next)) {
        const expanded = expandPortSpec(next);
        if (expanded) {
          if (expanded.ports) dst.ports = expanded.ports;
          if (expanded.port_range) dst.port_range = expanded.port_range;
        }
      }
      continue;
    }
    // -o / --output → output file path, BUT only for tools whose `-o`
    // really means an output file. `ssh -o StrictHostKeyChecking=no`
    // would otherwise be recorded as a fabricated file.path.
    // nmap also has the `-oN`, `-oX`, `-oG`, `-oA` forms (plain /
    // XML / grepable / all). Each takes a basename argument.
    if (text === '-o' || text === '--output') {
      if (isOutputFlagForTool(classification.tool) && !next.startsWith('-')) {
        result.file = { path: next };
        consumedNext.add(i + 1);
      }
      continue;
    }
    if (
      (text === '-oN' || text === '-oX' || text === '-oG' || text === '-oA' || text === '-oS') &&
      classification.activity_type === 'port_scan'
    ) {
      if (!next.startsWith('-')) {
        result.file = { path: next };
        consumedNext.add(i + 1);
      }
      continue;
    }
    // -w / --wordlist → wordlist path. ONLY for tool families that
    // actually take a wordlist (web_discovery, credential_brute_force).
    // For network_connection tools (`nc -w 5 host port`), `-w` is a
    // timeout in seconds — it's a number we should NOT log as a file
    // path. Other families (host_discovery, port_scan) don't use `-w`.
    if (text === '-w' || text === '--wordlist') {
      const wordlistFamilies = new Set(['web_discovery', 'credential_brute_force']);
      if (wordlistFamilies.has(classification.activity_type) && !next.startsWith('-')) {
        result.file = { path: next };
        consumedNext.add(i + 1);
      }
      continue;
    }
    // Hydra-style `-L users.txt` (user list file). Consume so it does
    // not get promoted to dst_endpoint.hostname later.
    if (text === '-L' && classification.activity_type === 'credential_brute_force') {
      if (!next.startsWith('-')) {
        // Don't overwrite a -P-set wordlist; the user list is a
        // separate concept but only one `file.path` is supported per
        // record. Prefer the password list; otherwise record the user
        // list.
        if (!result.file) result.file = { path: next };
        consumedNext.add(i + 1);
      }
      continue;
    }
    // `-iL targets.txt` — input list of targets, used by nmap and
    // masscan (port_scan family).
    if (text === '-iL' && classification.activity_type === 'port_scan') {
      if (!next.startsWith('-')) {
        result.file = { path: next };
        consumedNext.add(i + 1);
      }
      continue;
    }
  }

  // 3. SSH-style `user@host[:port]` and positional host / IP / hostname.
  // Only run the bare-hostname / bare-IP fishing for activity types whose
  // semantics include a network destination. Non-networking families like
  // `password_cracking` (`hashcat hashes.txt`) and the generic
  // `process_execution` fallback would otherwise promote arbitrary
  // filenames into `dst_endpoint.hostname`.
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
  const allowPositionalHostFishing = NETWORK_TARGETING_ACTIVITY_TYPES.has(
    classification.activity_type,
  );
  let positionalHostFound = false;
  if (allowPositionalHostFishing) {
    for (let i = 0; i < all.length; i++) {
      const t = all[i];
      if (t.quoted) continue;
      if (consumedNext.has(i)) continue;
      const text = t.text;
      if (text.startsWith('-')) continue;

      // user@host[:port]
      const at = text.indexOf('@');
      if (at !== -1) {
        const left = text.slice(0, at);
        const right = text.slice(at + 1);
        if (/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(left)) {
          result.target_user = result.target_user ?? left;
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
          positionalHostFound = true;
          continue;
        }
      }

      // Bare IPv4 or CIDR.
      const v4 = tryParseIpv4(text);
      if (v4) {
        if (!dst.ip) dst.ip = v4.ip;
        if (v4.cidr && !dst.cidr) dst.cidr = v4.cidr;
        positionalHostFound = true;
        continue;
      }
      // Bare IPv6.
      const v6 = tryParseIpv6(text);
      if (v6 && !dst.ip) {
        dst.ip = v6;
        positionalHostFound = true;
        continue;
      }
      // Bare hostname.
      if (!dst.ip && !dst.hostname && looksLikeHostname(text)) {
        dst.hostname = text;
        positionalHostFound = true;
      }
    }
  }

  // 4. `host port` positional pair (e.g. `nc 10.0.0.1 8080`,
  // `nc target.example 4444`). Iterates over `all` so we can apply the
  // same consumed-flag and quoted-token rules as the positional-host
  // loop, and accepts hostname-shaped first tokens too.
  if (positionalHostFound && dst.port === undefined && dst.ports === undefined) {
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
        break;
      }
    }
  }

  // 5. Trailing protocol token for credential brute-force tools — `hydra
  // ... 192.168.1.5 ssh` records the service token as `protocol`.
  if (classification.activity_type === 'credential_brute_force' && unquoted.length > 0) {
    const last = unquoted[unquoted.length - 1].text;
    if (/^[a-z][a-z0-9_-]*$/i.test(last) && !last.startsWith('-')) {
      const known = ['ssh', 'ftp', 'http', 'https', 'mysql', 'mssql', 'postgres', 'rdp', 'smb', 'telnet', 'vnc', 'imap', 'pop3', 'snmp'];
      if (known.includes(last.toLowerCase())) result.protocol = last.toLowerCase();
    }
  }

  if (Object.keys(dst).length > 0) result.dst_endpoint = dst;
  return result;
}
