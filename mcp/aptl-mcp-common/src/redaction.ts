/**
 * Shared redaction helper for serialization boundaries in MCP servers.
 *
 * Run analysis artifacts (OTel span attributes, exported run archives,
 * tool call traces) are not credential stores. Redact secret-shaped
 * values at the serialization boundary so file permissions and archive
 * locations remain defense in depth, not the only line of protection.
 * See ADR-012 § Security Guardrail.
 *
 * Mirrors `src/aptl/utils/redaction.py` so artifacts emitted from
 * either language match shape.
 */

export const REDACTED = '[REDACTED]';

// Defense-in-depth bounds for the redactor itself (issue #386, ARCH-386-01).
// These cap worst-case work at the secret boundary so a hostile or
// pathological artifact cannot turn redaction into a denial-of-service or a
// fail-open crash. Both bounds fail CLOSED (over-redact, never leak), matching
// the ADR-012 guardrail. Mirror any change in `redaction.py`.
//
// MAX_SCAN_LEN bounds the polynomial-backtracking command-flag passes (the
// `--<word>*<sensitive>` flag matcher and the per-segment shell scanners).
// Strings longer than this skip those passes (the linear key/value/header/
// PEM/bearer/URL passes still run), keeping CPU bounded.
const MAX_SCAN_LEN = 64 * 1024;
// MAX_DEPTH bounds recursion through nested objects/arrays/JSON-in-strings so
// a deeply nested artifact collapses to a bounded marker instead of
// overflowing the call stack. Matches the Python bound.
const MAX_DEPTH = 100;

// OBS-003 experimenter opt-out. The toggle is NOT consulted by the
// shared `redact()` primitive — that would disable redaction at
// every serialization boundary in the project (OTel/Tempo spans
// in `traceToolCall`, stderr OCSF lines, snapshot DTOs, CLI/API
// JSON), giving any lab/observability user with Tempo/Grafana
// access the ability to read raw control-plane secrets the moment
// an experimenter flips the env var (codex pre-push cycle 3
// finding-9). Instead, the toggle is consulted ONLY by the local
// per-run capture sink wrappers (`mcp-red/src/capture.ts`
// `captureToolCall`, `mcp-red/src/logger.ts` `localOcsfJsonlSink`,
// and any future experimental sink that explicitly opts in via
// the documented `experimentNoRedactActive()` helper). See ADR-033's
// "Secret-handling" Security Layers entry for the boundary contract.
const EXPERIMENT_NO_REDACT_ENV = 'APTL_EXPERIMENT_NO_REDACT';
const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

/**
 * Public accessor for the OBS-003 experimenter opt-out env var.
 * Returns true only when `APTL_EXPERIMENT_NO_REDACT` is set to a
 * truthy value (`1`/`true`/`yes`/`on`, case-insensitive). Any other
 * value (including `0`, `false`, empty, or unset) returns false
 * (redaction-on default). This is the only sanctioned consumer of
 * the toggle — call it from a local per-run capture sink BEFORE
 * invoking `redact()`, and skip the redact call when it returns
 * true. Do NOT add a guard inside `redact()` itself.
 */
export function experimentNoRedactActive(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[EXPERIMENT_NO_REDACT_ENV];
  if (raw === undefined) return false;
  return TRUTHY.has(raw.trim().toLowerCase());
}

// `pass` subsumes password/passwd/passphrase; `session` covers replayable
// session identifiers (Wazuh session_id, etc.). False-positive matches on
// unrelated tokens like `passport` are an acceptable cost — the ADR-012
// guardrail prefers over-redaction over leak.
const SENSITIVE_TOKENS: readonly string[] = [
  'pass',
  'secret',
  'token',
  'credential', // also matches "credentials"
  'authorization',
  'cookie',
  'jwt',
  'bearer',
  'api_key',
  'apikey',
  'key', // broad; carved out by SAFE_KEY_NAMES below
  'session',
];

// Tightened to names that are unambiguously paths/files: bare `ssh_key`
// could mean the private key material itself, so it is intentionally NOT
// in the allowlist.
const SAFE_KEY_NAMES: ReadonlySet<string> = new Set([
  'key_path',
  'key_file',
  'keypath',
  'keyfile',
  'ssh_key_path',
  'ssh_keyfile',
  'ssh_key_file',
  'public_key',
  'publickey',
]);

function isSensitiveKey(name: string): boolean {
  const lower = name.toLowerCase();
  if (SAFE_KEY_NAMES.has(lower)) return false;
  return SENSITIVE_TOKENS.some((token) => lower.includes(token));
}

// Inline-secret patterns for plain-text strings (command lines, HTTP
// headers, query strings, etc.). MCP tool args/responses regularly carry
// these — a key-only redactor cannot reach inside string values like
// `command: "curl -H 'Authorization: Bearer abc' ..."` or
// `body: "password=hunter2&user=alice"`. Patterns are intentionally
// conservative: they preserve the labelling token (`Bearer`, `password=`)
// so log readers know what was redacted, but mask the secret payload.
const SENSITIVE_KEY_PATTERN =
  '(?:pass(?:word|wd|phrase)?|secret|token|credential|api[_-]?key|apikey|jwt|bearer|session(?:_id)?|cookie)';
// `\S+` would greedily consume trailing quotes/punctuation around the
// secret value (e.g. eat the closing `'` of a curl `-H 'Authorization: ...'`
// header, corrupting downstream diagnostic structure). Stop at quotes
// and whitespace instead.
const VALUE_PATTERN = String.raw`[^\s'"]+`;
// Authorization header: keep optional scheme (`Basic`, `Bearer`) labelled
// for log-readability, mask the token. Single combined pattern so the
// optional-scheme branch and the value-only branch are mutually exclusive
// (avoids a double-redaction artifact on the same input).
// `i` flag handles both cases — listing `A-Z` alongside `a-z` is
// redundant under case-insensitive matching (Sonar S5869).
const AUTHORIZATION_PATTERN = new RegExp(
  String.raw`(authorization\s*[:=]\s*)(?:([a-z][\w-]*)\s+)?${VALUE_PATTERN}`,
  'gi',
);
// `\b` word-boundaries break on compound names because `_` is a word
// character — `access_token=...` matches neither `\btoken\b` nor
// `\baccess_token\b`. Use alphanumeric-only boundaries so `_`, `-`, and
// punctuation all count as separators.
const KEY_LB = String.raw`(?<![a-zA-Z0-9])`;
const KEY_RB = String.raw`(?![a-zA-Z0-9])`;
// `key=value` or `key: value` for any sensitive token. Stops at common
// delimiters so URL query strings and shell key/value pairs mask only
// the value, not the surrounding context. Capture leading and trailing
// quotes as separate groups so the replacement preserves them
// (otherwise wrapping `'<value>'` / `"<value>"` loses the closing
// quote, corrupting downstream diagnostic structure).
const SENSITIVE_KV_PATTERN = new RegExp(
  String.raw`(${KEY_LB}${SENSITIVE_KEY_PATTERN}${KEY_RB}\s*[=:]\s*['"]?)([^'"&\s,;|]+)(['"]?)`,
  'gi',
);
// Bare `Bearer <token>` (no Authorization: prefix).
const BARE_BEARER_PATTERN = new RegExp(
  String.raw`(${KEY_LB}bearer\s+)${VALUE_PATTERN}`,
  'gi',
);
// `--password value` / `--client-secret value` / `--access-token value`
// style (long CLI flags). The `[\w-]*` prefix allows compound flag
// names; regex backtracking finds the embedded sensitive token.
const CLI_FLAG_PATTERN = new RegExp(
  String.raw`(--[\w-]*${SENSITIVE_KEY_PATTERN}${KEY_RB}\s+)${VALUE_PATTERN}`,
  'gi',
);
// Cookie / Set-Cookie header: redact the entire body so multi-segment
// cookies like `Cookie: lang=en; connect.sid=SECRET` are masked in one
// pass instead of leaving later segments intact. Capture the leading
// and trailing quotes (when present) as separate groups so the
// replacement can put them back — otherwise a wrapping `'...'` loses
// its closing quote.
const COOKIE_HEADER_PATTERN =
  /((?:set-cookie|cookie)\s*[:=]\s*['"]?)([^'"\r\n]+)(['"]?)/gi;
// URL userinfo: `scheme://user:password@host/path`. Preserve user (often
// useful for diagnostics) and mask the password segment.
const URL_USERINFO_PATTERN = /(:\/\/[^/:@\s]+:)[^@\s]+(@)/gi;
// PEM key/cert blocks (`-----BEGIN PRIVATE KEY----- … -----END PRIVATE KEY-----`).
// Multi-line with `[\s\S]` since `.` does not match newline by default;
// non-greedy so adjacent blocks are masked separately.
const PEM_BLOCK_PATTERN =
  /(-----BEGIN[^-]*-----)[\s\S]*?(-----END[^-]*-----)/g;
// Recognizes `--<sensitive>` (or compound `--client-secret`,
// `--access-token`) as a standalone token used by array-pair detection
// so adjacent positional values get redacted.
const CLI_FLAG_TOKEN_PATTERN = new RegExp(
  String.raw`^--[\w-]*${SENSITIVE_KEY_PATTERN}${KEY_RB}$`,
  'i',
);

// `-p` / `-p=value` / `-p<value>` short-flag handling for credential
// tools. The leading token of the command line determines whether `-p`
// could carry a password (hydra, medusa, sshpass, crackmapexec, nxc, …)
// — but wrappers like `proxychains4 hydra …` or `sudo hydra …` shift
// that token. Detect both: if the command line contains any known
// credential-taking-`-p` tool token before the `-p`, redact the value
// even if numeric (numeric passwords are common). For unknown leading
// tools, only redact non-numeric `-p` values so port numbers
// (`nmap -p 22`) stay visible.
//
// Known tools whose short `-p` is a password value:
const CREDENTIAL_SHORT_P_TOOLS: ReadonlySet<string> = new Set([
  'hydra',
  'medusa',
  'patator',
  'crowbar',
  'sshpass',
  'crackmapexec',
  'cme',
  'nxc',
  'wfuzz',
  'mysql',
  'mysqladmin',
  'mariadb',
  'redis-cli',
  'evil-winrm',
  'bloodhound-python',
  'bloodhound.py',
  'kerbrute',
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
]);

// Tools whose `-w <value>` is a password (LDAP simple-bind). Distinct
// from wordlist-`-w` for hydra/wfuzz; per-segment detection picks the
// right meaning.
const LDAP_PASSWORD_TOOLS: ReadonlySet<string> = new Set([
  'ldapsearch',
  'ldapmodify',
  'ldapadd',
  'ldapdelete',
  'ldappasswd',
  'ldapwhoami',
  'ldapcompare',
]);

// `&&` / `||` / `&` / `;` / `|` boundaries split a command line into
// independent shell segments (used for per-segment credential-tool
// detection so `-p 22` in an unrelated nmap segment doesn't get masked
// just because a hydra invocation appears after `&&`).
// independent shell segments. Per-flag credential-tool detection scans
// the segment containing the flag, so `nmap -p 22 ... && hydra -p X`
// keeps nmap's port visible while masking hydra's password.
interface SegmentScanState {
  inSingle: boolean;
  inDouble: boolean;
  escaped: boolean;
}

/**
 * Update quote/escape state for one character. Returns true if the
 * caller should skip emitting a separator at this position (because we
 * are inside a quoted run, in an escape, or just toggled a quote).
 */
function advanceQuoteState(state: SegmentScanState, ch: string): boolean {
  if (state.escaped) {
    state.escaped = false;
    return true;
  }
  if (ch === '\\') {
    state.escaped = true;
    return true;
  }
  if (!state.inDouble && ch === "'") {
    state.inSingle = !state.inSingle;
    return true;
  }
  if (!state.inSingle && ch === '"') {
    state.inDouble = !state.inDouble;
    return true;
  }
  return state.inSingle || state.inDouble;
}

function ampersandStep(command: string, i: number): number {
  const prev = command[i - 1];
  const next = command[i + 1];
  if (prev === '>' || prev === '<' || next === '>') return 0; // not a separator
  return next === '&' ? 2 : 1;
}

function splitTopLevelSegments(command: string): { start: number; end: number }[] {
  // Multi-character separators (`&&`, `||`) are consumed atomically —
  // the loop skips past the second character so the splitter never
  // emits a zero-width range. The earlier `for` loop revisited the
  // second `&`, which the new segment-reconstructor in
  // `unquoteOptionsInCredentialSegments` would emit as a stray `&`
  // between segments.
  const segments: { start: number; end: number }[] = [];
  let start = 0;
  const state: SegmentScanState = { inSingle: false, inDouble: false, escaped: false };
  let i = 0;
  const n = command.length;
  while (i < n) {
    const ch = command[i];
    if (advanceQuoteState(state, ch)) {
      i++;
      continue;
    }
    if (ch === '|' || ch === ';') {
      segments.push({ start, end: i });
      start = i + 1;
      i++;
      continue;
    }
    if (ch === '&') {
      const advance = ampersandStep(command, i);
      if (advance > 0) {
        segments.push({ start, end: i });
        start = i + advance;
        i += advance;
        continue;
      }
    }
    i++;
  }
  segments.push({ start, end: command.length });
  return segments;
}

// Per-segment tool detection. Originally a single big alternation
// regex; Sonar S5843 flagged the long tool list as over the
// regex-complexity threshold (~34). Split into smaller batches; a
// segment matches if ANY batch hits. Each batch stays well under the
// 20 limit and `.some()` short-circuits once a batch matches.
const CREDENTIAL_TOOL_REGEXES: readonly RegExp[] = [
  /(^|[\s|;&])(?:[\w./-]+\/)?(hydra|medusa|patator|crowbar|sshpass|wfuzz|kerbrute)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(crackmapexec|cme|nxc|evil-winrm)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(bloodhound-python|bloodhound\.py)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(mysql|mariadb|mysqladmin|redis-cli)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(impacket-psexec|impacket-smbexec|impacket-wmiexec|impacket-secretsdump)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)/i,
];

function segmentHasCredentialTool(segment: string): boolean {
  return CREDENTIAL_TOOL_REGEXES.some((re) => re.test(segment));
}

// Tools where the short flags `-u` / `-U` carry a username (often paired
// with an embedded password — Basic-auth `user:pass` for HTTP clients,
// Samba `user%pass` for the SMB family). The short forms are scoped to
// this list so a generic `date -u +%Y:%m` (where `-u` is the UTC flag
// and `+%Y:%m` is just an unrelated value) is not mis-classified as
// Basic auth. The long `--user` form stays content-based — that
// spelling is overwhelmingly auth-bearing.
const BASIC_AUTH_SHORT_TOOL_REGEXES: readonly RegExp[] = [
  /(^|[\s|;&])(?:[\w./-]+\/)?(curl|wget|smbclient|smbget|hydra|medusa|kerbrute)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(crackmapexec|cme|nxc|evil-winrm)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(mysql|mysqladmin|mariadb|redis-cli|psql|ldapsearch|bloodhound-python|bloodhound\.py)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(impacket-[\w-]+|psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)/i,
];

function segmentHasBasicAuthShortTool(segment: string): boolean {
  return BASIC_AUTH_SHORT_TOOL_REGEXES.some((re) => re.test(segment));
}

// True when the segment names ANY credential-bearing tool family —
// used by the segment-scoped quote-strip below so an option-shaped
// token like `'-p'` is only normalized to bare `-p` when the segment
// is plausibly running a credential-using tool. References to
// per-family tool detectors below are hoisted via function
// declarations; the regex tables they use are initialized at module
// load before any consumer can call this.
function segmentHasAnyCredentialTool(segment: string): boolean {
  return (
    segmentHasCredentialTool(segment) ||
    segmentHasHashTool(segment) ||
    segmentHasLdapTool(segment) ||
    segmentHasImpacketTool(segment) ||
    segmentHasBasicAuthShortTool(segment)
  );
}

const QUOTED_OPTION_TOKEN_RE = /(['"])(-[A-Za-z][\w-]*)\1/g;

/**
 * Strip surrounding quotes from `'-X'` / `"-X"` option tokens — but
 * only inside segments that name a credential-bearing tool. The
 * earlier implementation ran this pre-pass globally, which mutated
 * arbitrary data (`echo '-p' hunter2` became `echo -p hunter2`, then
 * `redactShortPasswordFlag` redacted the trailing word as if it were
 * a password). Scoping the strip to credential-bearing segments
 * keeps the original `hydra '-p' hunter2` parity (hydra's segment
 * unquotes, the per-flag matcher fires) while leaving non-credential
 * text intact.
 */
export function unquoteOptionsInCredentialSegments(command: string): string {
  if (!command.includes("'") && !command.includes('"')) return command;
  const segments = splitTopLevelSegments(command);
  const parts: string[] = [];
  let lastEnd = 0;
  for (const { start, end } of segments) {
    if (start > lastEnd) parts.push(command.slice(lastEnd, start));
    let seg = command.slice(start, end);
    if (segmentHasAnyCredentialTool(seg)) {
      seg = seg.replace(QUOTED_OPTION_TOKEN_RE, '$2');
    }
    parts.push(seg);
    lastEnd = end;
  }
  if (lastEnd < command.length) parts.push(command.slice(lastEnd));
  return parts.join('');
}

// Quote- and form-aware short `-p` matcher. Originally a single regex
// with three value-form alternatives, but Sonar S5843 flagged the
// composed pattern as over the regex-complexity threshold (≥20). We
// now run three smaller regexes per flag — double-quoted, single-quoted,
// unquoted-with-escape — applied in that order so the quoted forms are
// consumed before the unquoted matcher could eat the surrounding quotes.
//
// The escape-aware unquoted alternative `(?:\\.|[^\s'"\\])+` consumes
// `\<anything>` plus ordinary non-whitespace non-quote characters so
// `hydra -p correct\ horse` is treated as a single shell token (the
// space after `correct\` is escaped).
const SHORT_P_DQUOTE = /(^|\s|\|)-p(\s+|=)("(?:[^"\\]|\\.)*")/g;
const SHORT_P_SQUOTE = /(^|\s|\|)-p(\s+|=)('(?:[^'\\]|\\.)*')/g;
const SHORT_P_UNQUOTED = /(^|\s|\|)-p(\s+|=)((?:\\.|[^\s'"\\])+)/g;
const SHORT_P_ATTACHED_DQUOTE = /(^|\s|\|)-p("(?:[^"\\]|\\.)*")/g;
const SHORT_P_ATTACHED_SQUOTE = /(^|\s|\|)-p('(?:[^'\\]|\\.)*')/g;
const SHORT_P_ATTACHED_UNQUOTED = /(^|\s|\|)-p([^\s='"](?:\\.|[^\s'"\\])*)/g;

function isPortLikeValue(stripped: string): boolean {
  // Comma- or hyphen-separated digits (with each segment ≤ 5 digits).
  return /^\d{1,5}(?:[,-]\d{1,5})*$/.test(stripped);
}

function stripQuotes(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

/**
 * Build an offset-to-bool predicate from the *current* command string.
 *
 * The earlier implementation computed segments once on the input and
 * reused those offsets across six sequential `.replace()` passes that
 * mutated the string between calls — once a quoted credential of a
 * length other than `[REDACTED]` was replaced, later offsets shifted
 * and could mis-classify matches into the wrong segment (e.g. a long
 * hydra password before `&& nmap -p 22` would shift the port match
 * leftwards into the hydra segment and mask `22`). Recompute per pass
 * via `segmentAwareReplace` instead.
 */
function buildSegmentPredicate(
  command: string,
  hasTool: (segment: string) => boolean,
): (offset: number) => boolean {
  const segments = splitTopLevelSegments(command);
  const flags = segments.map((s) => hasTool(command.slice(s.start, s.end)));
  return (offset: number): boolean => {
    for (let idx = 0; idx < segments.length; idx++) {
      if (offset >= segments[idx].start && offset < segments[idx].end) return flags[idx];
    }
    return false;
  };
}

/**
 * Run a sequence of segment-aware regex replacements safely.
 *
 * Each pass recomputes the segment predicate against the *current*
 * string before invoking `.replace()` — `.replace()`'s own match
 * offsets are consistent within a single call, so this is sufficient
 * to keep classification stable across replacements.
 *
 * `replacerFactory(inSeg)` returns the actual `String.replace` callback;
 * the factory closes over the freshly-computed predicate for that pass.
 */
function segmentAwareReplace(
  command: string,
  hasTool: (segment: string) => boolean,
  passes: ReadonlyArray<[RegExp, (inSeg: (offset: number) => boolean) => (...args: unknown[]) => string]>,
): string {
  let out = command;
  for (const [pattern, factory] of passes) {
    const inSeg = buildSegmentPredicate(out, hasTool);
    out = out.replace(pattern, factory(inSeg) as Parameters<typeof out.replace>[1]);
  }
  return out;
}

/**
 * Mask short `-p <value>` credential flags inline in `command`.
 *
 * Behaviour:
 *  - When the command's leading tokens include a known credential tool
 *    (hydra, sshpass, medusa, etc., or a wrapper pipeline that contains
 *    one), redact the value regardless of shape — numeric passwords are
 *    common.
 *  - Otherwise, only redact non-numeric `-p` values so `nmap -p 22`,
 *    `nmap -p 22,80,443`, and `nmap -p 1-1024` (port specs) stay visible.
 *
 * Recognises spaced (`-p value`), equals (`-p=value`), and attached
 * (`-p<value>`) shell forms; preserves leading whitespace/pipe so the
 * surrounding context isn't broken.
 */
export function redactShortPasswordFlag(command: string): string {
  const makeReplaceSpaced = (inCred: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const lead = args[1] as string;
      const sep = args[2] as string;
      const value = args[3] as string;
      const offset = args[4] as number;
      const stripped = stripQuotes(value);
      if (!inCred(offset) && isPortLikeValue(stripped)) {
        return `${lead}-p${sep}${value}`;
      }
      return `${lead}-p${sep}${REDACTED}`;
    };
  const makeReplaceAttached = (inCred: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const lead = args[1] as string;
      const value = args[2] as string;
      const offset = args[3] as number;
      const stripped = stripQuotes(value);
      if (!inCred(offset) && isPortLikeValue(stripped)) {
        return `${lead}-p${value}`;
      }
      return `${lead}-p ${REDACTED}`;
    };
  return segmentAwareReplace(command, segmentHasCredentialTool, [
    [SHORT_P_DQUOTE, makeReplaceSpaced],
    [SHORT_P_SQUOTE, makeReplaceSpaced],
    [SHORT_P_UNQUOTED, makeReplaceSpaced],
    [SHORT_P_ATTACHED_DQUOTE, makeReplaceAttached],
    [SHORT_P_ATTACHED_SQUOTE, makeReplaceAttached],
    [SHORT_P_ATTACHED_UNQUOTED, makeReplaceAttached],
  ]);
}

// `-H <hash>` / `-H=hash` / `-H<hash>` for credential-using tools
// (crackmapexec / cme / nxc / impacket *.py). The same flag means HTTP
// header to curl/wget — we only redact when the segment contains a
// credential tool that uses `-H` as a hash flag.
const NTLM_HASH_DQUOTE = /(^|\s|\|)-H(\s+|=)("(?:[^"\\]|\\.)*")/g;
const NTLM_HASH_SQUOTE = /(^|\s|\|)-H(\s+|=)('(?:[^'\\]|\\.)*')/g;
const NTLM_HASH_UNQUOTED = /(^|\s|\|)-H(\s+|=)((?:\\.|[^\s'"\\])+)/g;
const NTLM_HASH_ATTACHED_DQUOTE = /(^|\s|\|)-H("(?:[^"\\]|\\.)*")/g;
const NTLM_HASH_ATTACHED_SQUOTE = /(^|\s|\|)-H('(?:[^'\\]|\\.)*')/g;
const NTLM_HASH_ATTACHED_UNQUOTED = /(^|\s|\|)-H([^\s='"](?:\\.|[^\s'"\\])*)/g;

// Impacket's documented short form is `-hashes [<LM>]:<NT>` (single
// dash, full word; long form `--hashes` is also valid). Without
// these patterns a command like
// `psexec.py alice@dc -hashes :8846f7eaee8fb117` leaked the NT hash
// through redaction. Scoped to impacket tool segments only via
// HASH_TOOLS_RE to avoid over-redacting unrelated `--hashes` flags.
// Test-quality review cycle 1 finding-1 surfaced the missing
// assertion that exposed this pre-existing bug.
const NTLM_HASHES_DQUOTE = /(^|\s|\|)(--?hashes)(\s+|=)("(?:[^"\\]|\\.)*")/g;
const NTLM_HASHES_SQUOTE = /(^|\s|\|)(--?hashes)(\s+|=)('(?:[^'\\]|\\.)*')/g;
const NTLM_HASHES_UNQUOTED = /(^|\s|\|)(--?hashes)(\s+|=)((?:\\.|[^\s'"\\])+)/g;

const HASH_TOOLS_RE = /(^|[\s|;&])(?:[\w./-]+\/)?(crackmapexec|cme|nxc|psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|impacket-[\w-]+|evil-winrm)(?:\s|$)/i;

function segmentHasHashTool(segment: string): boolean {
  return HASH_TOOLS_RE.test(segment);
}

export function redactNtlmHashFlag(command: string): string {
  const makeReplaceSpaced = (inSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const sep = args[2] as string;
      const offset = args[4] as number;
      return inSeg(offset) ? `${lead}-H${sep}${REDACTED}` : match;
    };
  const makeReplaceAttached = (inSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const offset = args[3] as number;
      return inSeg(offset) ? `${lead}-H ${REDACTED}` : match;
    };
  // `-hashes`/`--hashes` (full-word impacket form). Preserves the
  // flag literal (`m[2]` is `-hashes` or `--hashes`) and only masks
  // the value (m[4]).
  const makeReplaceHashes = (inSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const flag = args[2] as string;
      const sep = args[3] as string;
      const offset = args[5] as number;
      return inSeg(offset) ? `${lead}${flag}${sep}${REDACTED}` : match;
    };
  return segmentAwareReplace(command, segmentHasHashTool, [
    [NTLM_HASH_DQUOTE, makeReplaceSpaced],
    [NTLM_HASH_SQUOTE, makeReplaceSpaced],
    [NTLM_HASH_UNQUOTED, makeReplaceSpaced],
    [NTLM_HASH_ATTACHED_DQUOTE, makeReplaceAttached],
    [NTLM_HASH_ATTACHED_SQUOTE, makeReplaceAttached],
    [NTLM_HASH_ATTACHED_UNQUOTED, makeReplaceAttached],
    [NTLM_HASHES_DQUOTE, makeReplaceHashes],
    [NTLM_HASHES_SQUOTE, makeReplaceHashes],
    [NTLM_HASHES_UNQUOTED, makeReplaceHashes],
  ]);
}

// `--user`, `-u`, `-U` for tools where the value can be a credential.
// Mask when:
//   - the value contains `:` AND it is NOT a URL (URL `-u` for sqlmap /
//     gobuster has `https:` in it but is not a credential) — Basic-auth
//     pair shape.
//   - the value contains `%` — Samba `username%password` shape.
// Bare `--user alice` (no colon, no `%`) is left alone.
const BASIC_AUTH_USER_DQUOTE = /(^|\s|\|)(--user|-u|-U)(\s+|=)("(?:[^"\\]|\\.)*")/g;
const BASIC_AUTH_USER_SQUOTE = /(^|\s|\|)(--user|-u|-U)(\s+|=)('(?:[^'\\]|\\.)*')/g;
const BASIC_AUTH_USER_UNQUOTED = /(^|\s|\|)(--user|-u|-U)(\s+|=)((?:\\.|[^\s'"\\])+)/g;
const BASIC_AUTH_USER_ATTACHED_DQUOTE = /(^|\s|\|)(-u|-U)("(?:[^"\\]|\\.)*")/g;
const BASIC_AUTH_USER_ATTACHED_SQUOTE = /(^|\s|\|)(-u|-U)('(?:[^'\\]|\\.)*')/g;
const BASIC_AUTH_USER_ATTACHED_UNQUOTED = /(^|\s|\|)(-u|-U)([^\s='"](?:\\.|[^\s'"\\])*)/g;

// LDAP simple-bind password: `ldapsearch -w <password>` and friends.
// Per-segment detected: `-w` for hydra/wfuzz is a wordlist (file path),
// not a password.
const LDAP_W_DQUOTE = /(^|\s|\|)-w(\s+|=)("(?:[^"\\]|\\.)*")/g;
const LDAP_W_SQUOTE = /(^|\s|\|)-w(\s+|=)('(?:[^'\\]|\\.)*')/g;
const LDAP_W_UNQUOTED = /(^|\s|\|)-w(\s+|=)((?:\\.|[^\s'"\\])+)/g;
const LDAP_W_ATTACHED_DQUOTE = /(^|\s|\|)-w("(?:[^"\\]|\\.)*")/g;
const LDAP_W_ATTACHED_SQUOTE = /(^|\s|\|)-w('(?:[^'\\]|\\.)*')/g;
const LDAP_W_ATTACHED_UNQUOTED = /(^|\s|\|)-w([^\s='"](?:\\.|[^\s'"\\])*)/g;
const LDAP_TOOL_RE = /(^|[\s|;&])(?:[\w./-]+\/)?(ldapadd|ldapcompare|ldapdelete|ldapmodify|ldappasswd|ldapsearch|ldapwhoami)(?:\s|$)/i;
function segmentHasLdapTool(segment: string): boolean {
  return LDAP_TOOL_RE.test(segment);
}
export function redactLdapPasswordFlag(command: string): string {
  const makeReplaceSpaced = (inSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const sep = args[2] as string;
      const offset = args[4] as number;
      return inSeg(offset) ? `${lead}-w${sep}${REDACTED}` : match;
    };
  const makeReplaceAttached = (inSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const offset = args[3] as number;
      return inSeg(offset) ? `${lead}-w ${REDACTED}` : match;
    };
  return segmentAwareReplace(command, segmentHasLdapTool, [
    [LDAP_W_DQUOTE, makeReplaceSpaced],
    [LDAP_W_SQUOTE, makeReplaceSpaced],
    [LDAP_W_UNQUOTED, makeReplaceSpaced],
    [LDAP_W_ATTACHED_DQUOTE, makeReplaceAttached],
    [LDAP_W_ATTACHED_SQUOTE, makeReplaceAttached],
    [LDAP_W_ATTACHED_UNQUOTED, makeReplaceAttached],
  ]);
}

const URL_PREFIX_RE = /^(?:https?|ftp|ldap|ldaps|smb|smbs):\/\//i;

function basicAuthValueIsCredential(value: string): boolean {
  const stripped = stripQuotes(value);
  if (URL_PREFIX_RE.test(stripped)) return false;
  return stripped.includes('%') || stripped.includes(':');
}

export function redactBasicAuthUser(command: string): string {
  // Long `--user` is content-only — overwhelmingly auth-bearing across
  // tools. Short `-u`/`-U` are tool-scoped to avoid `date -u +%Y:%m`,
  // `grep -u alice:other file`, etc., where those flags don't carry
  // auth values.
  const makeReplaceSpaced = (inShortSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const flag = args[2] as string;
      const sep = args[3] as string;
      const value = args[4] as string;
      const offset = args[5] as number;
      if (!basicAuthValueIsCredential(value)) return match;
      if ((flag === '-u' || flag === '-U') && !inShortSeg(offset)) return match;
      return `${lead}${flag}${sep}${REDACTED}`;
    };
  const makeReplaceAttached = (inShortSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const lead = args[1] as string;
      const flag = args[2] as string;
      const value = args[3] as string;
      const offset = args[4] as number;
      if (!basicAuthValueIsCredential(value)) return match;
      // Attached forms only fire on `-u`/`-U` by construction, so the
      // tool-segment gate always applies.
      if (!inShortSeg(offset)) return match;
      return `${lead}${flag} ${REDACTED}`;
    };
  return segmentAwareReplace(command, segmentHasBasicAuthShortTool, [
    [BASIC_AUTH_USER_DQUOTE, makeReplaceSpaced],
    [BASIC_AUTH_USER_SQUOTE, makeReplaceSpaced],
    [BASIC_AUTH_USER_UNQUOTED, makeReplaceSpaced],
    [BASIC_AUTH_USER_ATTACHED_DQUOTE, makeReplaceAttached],
    [BASIC_AUTH_USER_ATTACHED_SQUOTE, makeReplaceAttached],
    [BASIC_AUTH_USER_ATTACHED_UNQUOTED, makeReplaceAttached],
  ]);
}

function redactAuthorizationHeader(
  _match: string,
  prefix: string,
  scheme: string | undefined,
): string {
  return scheme ? `${prefix}${scheme} ${REDACTED}` : `${prefix}${REDACTED}`;
}

// Patterns applied sequentially via a static replace-table so the
// caller's cyclomatic / cognitive complexity stays bounded. Each entry
// is `[pattern, replacement]` where replacement is either a string or
// a replace callback.
type ReplaceEntry = [RegExp, string | ((...args: unknown[]) => string)];
// The quote-strip pre-pass that USED to live here was a global rewrite
// and corrupted non-option text (e.g. `echo '-p' hunter2` → `echo -p
// hunter2`, which then triggered `redactShortPasswordFlag`); it now
// lives inside `redactString` behind a segment-scoped tool gate. See
// `unquoteOptionsInCredentialSegments`.
// Linear, single-quantifier passes — ReDoS-safe at any input length and so
// run unconditionally. The polynomial-backtracking passes (CLI_FLAG_PATTERN
// and the per-segment command-flag chain) are length-gated in `redactString`.
const LINEAR_REDACTION_TABLE: ReplaceEntry[] = [
  // PEM blocks first so the surrounding markers stay verbatim.
  [PEM_BLOCK_PATTERN, `$1${REDACTED}$2`],
  // Authorization next so it wins over the more general patterns.
  [AUTHORIZATION_PATTERN, redactAuthorizationHeader as (...args: unknown[]) => string],
  [COOKIE_HEADER_PATTERN, `$1${REDACTED}$3`],
  [SENSITIVE_KV_PATTERN, `$1${REDACTED}$3`],
  [BARE_BEARER_PATTERN, `$1${REDACTED}`],
  [URL_USERINFO_PATTERN, `$1${REDACTED}$2`],
];

function tryRedactJsonString(value: string, depth: number): string | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed !== null && typeof parsed === 'object') {
      return JSON.stringify(redactInner(parsed, depth + 1));
    }
  } catch {
    // Fall through to inline-pattern scanning.
  }
  return null;
}

function redactString(value: string, depth: number): string {
  const jsonRedacted = tryRedactJsonString(value, depth);
  if (jsonRedacted !== null) return jsonRedacted;
  let out = value;
  for (const [pattern, replacement] of LINEAR_REDACTION_TABLE) {
    out = out.replaceAll(
      pattern,
      replacement as Parameters<typeof out.replaceAll>[1],
    );
  }
  // Polynomial-backtracking passes are length-gated to cap worst-case CPU at
  // the secret boundary (ARCH-386-01). Oversized strings skip them; the
  // linear passes above already masked the key/value/header/PEM/bearer/URL
  // secret shapes. Tool-context-aware short flags run last so the simpler
  // kv/flag patterns have first claim on overlapping shapes. The
  // segment-scoped quote-strip unquotes `'-X'`/`"-X"` option tokens *only*
  // within credential-bearing segments so `hydra '-p' hunter2` triggers the
  // per-flag matcher while `echo '-p' hunter2` is preserved verbatim.
  if (out.length <= MAX_SCAN_LEN) {
    out = out.replaceAll(CLI_FLAG_PATTERN, `$1${REDACTED}`);
    out = unquoteOptionsInCredentialSegments(out);
    out = redactShortPasswordFlag(out);
    out = redactNtlmHashFlag(out);
    out = redactLdapPasswordFlag(out);
    out = redactBasicAuthUser(out);
    out = redactImpacketPositionalAuth(out);
  }
  return out;
}

// Impacket family accepts a positional `user:password@host` (or
// `domain/user:password@host`) shape. The shared key/value redactors
// don't catch it because it's not a flag. Mask the password segment
// while preserving user@host context for SIEM correlation. Only fire
// when the segment contains an impacket-family tool token.
//
// Real Windows / domain passwords commonly contain `:`, `@`, and
// whitespace. Match three forms:
//   - bare:    `user:VALUE@host`            — VALUE is non-`@`,
//              non-whitespace chars (with backslash-escapes); aligns
//              with impacket's own `parse_target`, which uses `[^@]*`
//              for the password and therefore can't accept literal
//              `@` in unquoted form either. Users with `@` or
//              whitespace in passwords MUST quote.
//   - dquot:   `user:"VALUE"@host`          — quoted value (any char).
//   - squot:   `user:'VALUE'@host`          — single-quoted.
// Split into per-value-form patterns to keep each regex under Sonar's
// regex-complexity threshold (S5843). The combined form was ~28; each
// split form is ~15-18.
//
// DQUOTE / SQUOTE use the unrolled-loop quoted-string form
// (`[^Q\\]*(?:\\.[^Q\\]*)*`) instead of the alternation form
// (`(?:[^Q\\]|\\.)*`). Both match the same language, but the unrolled
// form has no inner alternation so the regex engine cannot pick
// between two alternatives that could match the same character —
// eliminating the ReDoS risk at the engine level (Sonar S5852).
//
// BARE uses exclusive alternatives `\\.|[^\\@\s]` instead of `\\.|\S`.
// `\S` overlaps with `\\.` (both can match the leading backslash of an
// escape), creating ambiguous backtracking; `[^\\@\s]` excludes the
// backslash so the alternatives are mutually exclusive. `@` is also
// excluded so the pattern stops at the host separator without needing
// laziness, which removes another backtracking source.
// A leading token-boundary lookbehind `(?<![\w\\/.:@-])` eliminates the
// O(n^2) ReDoS these patterns exhibited (ARCH-386-01 / redact-01): without
// it the engine re-tried the match at every offset inside a long flag-like
// token (`hydra --aaaa…` or `aaaa:bbbb` with no `@`), each attempt scanning
// the rest of the token. The lookbehind forbids starting a match in the
// middle of a target token, collapsing attempts from O(n) offsets to
// O(tokens), while still allowing a match to begin after whitespace,
// `;`/`|`/`&`, `=`, or a quote — exactly where an impacket positional target
// legitimately starts. Zero-width and non-capturing, so groups 1/2/3 stay
// user/value/host. Mirrors `redaction.py`; parity is verified by the shared
// golden corpus.
const IMPACKET_POSITIONAL_DQUOTE = /(?<![\w\\/.:@-])([\w\\/.-]+):"([^"\\]*(?:\\.[^"\\]*)*)"@([\w.-]+)(?=\s|$|[;|&])/g;
const IMPACKET_POSITIONAL_SQUOTE = /(?<![\w\\/.:@-])([\w\\/.-]+):'([^'\\]*(?:\\.[^'\\]*)*)'@([\w.-]+)(?=\s|$|[;|&])/g;
const IMPACKET_POSITIONAL_BARE = /(?<![\w\\/.:@-])([\w\\/.-]+):((?:\\.|[^\\@\s])+)@([\w.-]+)(?=\s|$|[;|&])/g;

const IMPACKET_TOOL_REGEXES: readonly RegExp[] = [
  /(^|[\s|;&])(?:[\w./-]+\/)?(impacket-[\w-]+)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(psexec\.py|smbexec\.py|wmiexec\.py|dcomexec\.py|atexec\.py)(?:\s|$)/i,
  /(^|[\s|;&])(?:[\w./-]+\/)?(secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)/i,
];
function segmentHasImpacketTool(segment: string): boolean {
  return IMPACKET_TOOL_REGEXES.some((re) => re.test(segment));
}

export function redactImpacketPositionalAuth(command: string): string {
  const makeReplace = (inSeg: (offset: number) => boolean) =>
    (...args: unknown[]): string => {
      const match = args[0] as string;
      const user = args[1] as string;
      const host = args[3] as string;
      const offset = args[4] as number;
      return inSeg(offset) ? `${user}:${REDACTED}@${host}` : match;
    };
  return segmentAwareReplace(command, segmentHasImpacketTool, [
    [IMPACKET_POSITIONAL_DQUOTE, makeReplace],
    [IMPACKET_POSITIONAL_SQUOTE, makeReplace],
    [IMPACKET_POSITIONAL_BARE, makeReplace],
  ]);
}

interface ArgvCredentialModes {
  cred: boolean;
  hash: boolean;
  ldap: boolean;
  basic: boolean;
}

function argvCredentialModes(leading: string): ArgvCredentialModes {
  if (!leading) return { cred: false, hash: false, ldap: false, basic: false };
  return {
    cred: segmentHasCredentialTool(leading),
    hash: segmentHasHashTool(leading),
    ldap: segmentHasLdapTool(leading),
    basic: segmentHasBasicAuthShortTool(leading),
  };
}

// Mode → set of short flags it owns → does the value need a content
// gate? Keeping this as data instead of an if/else chain keeps
// `argvShortFlagSkipIndices` under the cognitive-complexity ceiling.
interface ArgvShortFlagRule {
  mode: keyof ArgvCredentialModes;
  flags: ReadonlySet<string>;
  contentGated: boolean;
}
const ARGV_SHORT_FLAG_RULES: readonly ArgvShortFlagRule[] = [
  { mode: 'cred', flags: new Set(['-p']), contentGated: false },
  { mode: 'hash', flags: new Set(['-H']), contentGated: false },
  { mode: 'ldap', flags: new Set(['-w']), contentGated: false },
  // Basic-auth `-u`/`-U` keeps the same content gate as the string-mode
  // redactor: bare usernames stay visible, only credential pairs mask.
  { mode: 'basic', flags: new Set(['-u', '-U']), contentGated: true },
];

function isArgvShortFlagTarget(
  flag: string,
  value: string,
  modes: ArgvCredentialModes,
): boolean {
  for (const { mode, flags, contentGated } of ARGV_SHORT_FLAG_RULES) {
    if (!modes[mode] || !flags.has(flag)) continue;
    return contentGated ? basicAuthValueIsCredential(value) : true;
  }
  return false;
}

function argvShortFlagSkipIndices(
  items: ReadonlyArray<unknown>,
  modes: ArgvCredentialModes,
): Set<number> {
  const skip = new Set<number>();
  if (!modes.cred && !modes.hash && !modes.ldap && !modes.basic) return skip;
  for (let i = 0; i + 1 < items.length; i++) {
    const flag = items[i];
    const value = items[i + 1];
    if (typeof flag !== 'string' || typeof value !== 'string') continue;
    if (isArgvShortFlagTarget(flag, value, modes)) skip.add(i + 1);
  }
  return skip;
}

function redactArray(items: unknown[], depth: number): unknown[] {
  // Argv-shape detection: when the leading token is a credential-family
  // tool, mark indices whose values should be redacted as short-flag
  // credentials (-p/-H/-w/-u/-U). Without this, a structured
  // `args = ["hydra", "-p", "hunter2", ...]` payload bypasses the
  // short-flag redactors that only run on scalar command strings
  // (ADR-029 / codex review cycle 3, finding 2).
  const first = items[0];
  const leading = typeof first === 'string' ? first : '';
  const modes = argvCredentialModes(leading);
  const shortFlagSkip = argvShortFlagSkipIndices(items, modes);
  const out: unknown[] = [];
  let skipNext = false;
  for (let i = 0; i < items.length; i++) {
    if (skipNext) {
      out.push(REDACTED);
      skipNext = false;
      continue;
    }
    if (shortFlagSkip.has(i)) {
      out.push(REDACTED);
      continue;
    }
    out.push(redactInner(items[i], depth + 1));
    // Pair-form CLI args: ["--password", "hunter2"]. If this string is a
    // long-flag whose name is sensitive AND the next element is a string,
    // redact the next element as the value-of-flag.
    const item = items[i];
    if (
      typeof item === 'string' &&
      CLI_FLAG_TOKEN_PATTERN.test(item) &&
      i + 1 < items.length &&
      typeof items[i + 1] === 'string'
    ) {
      skipNext = true;
    }
  }
  return out;
}

/**
 * Return a JSON-serialization-safe copy of `value`.
 *
 * Recurses through plain objects and arrays. Replaces values whose
 * containing key is sensitive with the marker `[REDACTED]`. String values
 * are scanned for embedded credentials: JSON-encoded payloads are parsed
 * and recursively redacted; plain-text payloads are scanned for inline
 * `Authorization:`, `Bearer`, and `<sensitive_key>=value` patterns.
 *
 * Pure: never mutates the input.
 */
export function redact(value: unknown): unknown {
  // Does NOT consult `APTL_EXPERIMENT_NO_REDACT` (codex pre-push
  // cycle 3 finding-9). The experiment toggle is scoped to the
  // local per-run capture sinks only; callers that want
  // experimental-record semantics check `experimentNoRedactActive()`
  // themselves before invoking `redact`. This keeps OTel/Tempo,
  // runstore, snapshot, and stderr boundaries redacted at all
  // times regardless of the toggle.
  //
  // Recursion is depth-bounded and fails CLOSED — a structure deeper than
  // MAX_DEPTH collapses to `[REDACTED]` rather than overflowing the stack
  // (ARCH-386-01).
  return redactInner(value, 0);
}

function redactInner(value: unknown, depth: number): unknown {
  if (depth >= MAX_DEPTH) return REDACTED;
  if (Array.isArray(value)) {
    return redactArray(value, depth);
  }
  // Binary payloads (Buffer / typed arrays) are not JSON-serializable and may
  // carry secret material; decode and scan as a string so embedded
  // credentials are masked and the result is JSON-safe (mirrors the Python
  // bytes handling, ARCH-386-01 / redact-03). Checked before the generic
  // object branch, which would otherwise spread the bytes into an index map.
  if (value instanceof Uint8Array) {
    return redactString(Buffer.from(value).toString('utf-8'), depth);
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? REDACTED : redactInner(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') {
    return redactString(value, depth);
  }
  return value;
}
