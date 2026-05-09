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
function splitTopLevelSegments(command: string): { start: number; end: number }[] {
  const segments: { start: number; end: number }[] = [];
  let start = 0;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (inSingle || inDouble) continue;
    if (ch === '|' || ch === ';') {
      segments.push({ start, end: i });
      start = i + 1;
      continue;
    }
    if (ch === '&') {
      const prev = command[i - 1];
      const next = command[i + 1];
      if (prev === '>' || prev === '<' || next === '>') continue;
      segments.push({ start, end: i });
      // For `&&`, advance past the second `&` too.
      start = next === '&' ? i + 2 : i + 1;
    }
  }
  segments.push({ start, end: command.length });
  return segments;
}

// Regex literals for the per-segment tool detection. Kept in sync with
// the Set above by grouping the same tools alphabetically; a unit test
// pins both sources to the same list. Sonar S6325 prefers literal
// regexes over `new RegExp(string)` constructions.
const CREDENTIAL_TOOL_RE = /(^|[\s|;&])(?:[\w./-]+\/)?(bloodhound-python|bloodhound\.py|cme|crackmapexec|crowbar|evil-winrm|getnpusers\.py|getuserspns\.py|hydra|impacket-psexec|impacket-secretsdump|impacket-smbexec|impacket-wmiexec|kerbrute|mariadb|medusa|mysql|mysqladmin|ntlmrelayx\.py|nxc|patator|psexec\.py|redis-cli|secretsdump\.py|smbexec\.py|sshpass|wfuzz|wmiexec\.py)(?:\s|$)/i;

function segmentHasCredentialTool(segment: string): boolean {
  return CREDENTIAL_TOOL_RE.test(segment);
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
  const segments = splitTopLevelSegments(command);
  const segmentHasCred = segments.map((s) => segmentHasCredentialTool(command.slice(s.start, s.end)));
  const inCredentialSegment = (offset: number): boolean => {
    for (let idx = 0; idx < segments.length; idx++) {
      if (offset >= segments[idx].start && offset < segments[idx].end) return segmentHasCred[idx];
    }
    return false;
  };
  const replaceSpaced = (
    _match: string,
    lead: string,
    sep: string,
    value: string,
    offset: number,
  ): string => {
    const stripped = stripQuotes(value);
    if (!inCredentialSegment(offset) && isPortLikeValue(stripped)) {
      return `${lead}-p${sep}${value}`;
    }
    return `${lead}-p${sep}${REDACTED}`;
  };
  const replaceAttached = (
    _match: string,
    lead: string,
    value: string,
    offset: number,
  ): string => {
    const stripped = stripQuotes(value);
    if (!inCredentialSegment(offset) && isPortLikeValue(stripped)) {
      return `${lead}-p${value}`;
    }
    return `${lead}-p ${REDACTED}`;
  };
  // Quoted forms first (so the unquoted matcher can't eat the surrounding
  // quotes), then unquoted. Same ordering for the attached forms.
  let out = command.replace(SHORT_P_DQUOTE, replaceSpaced);
  out = out.replace(SHORT_P_SQUOTE, replaceSpaced);
  out = out.replace(SHORT_P_UNQUOTED, replaceSpaced);
  out = out.replace(SHORT_P_ATTACHED_DQUOTE, replaceAttached);
  out = out.replace(SHORT_P_ATTACHED_SQUOTE, replaceAttached);
  out = out.replace(SHORT_P_ATTACHED_UNQUOTED, replaceAttached);
  return out;
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

const HASH_TOOLS_RE = /(^|[\s|;&])(?:[\w./-]+\/)?(crackmapexec|cme|nxc|psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|impacket-[\w-]+|evil-winrm)(?:\s|$)/i;

function segmentHasHashTool(segment: string): boolean {
  return HASH_TOOLS_RE.test(segment);
}

export function redactNtlmHashFlag(command: string): string {
  const segments = splitTopLevelSegments(command);
  const inSegment = (offset: number): boolean => {
    for (const s of segments) {
      if (offset >= s.start && offset < s.end) {
        return segmentHasHashTool(command.slice(s.start, s.end));
      }
    }
    return false;
  };
  const replaceSpaced = (
    match: string,
    lead: string,
    sep: string,
    _value: string,
    offset: number,
  ): string => (inSegment(offset) ? `${lead}-H${sep}${REDACTED}` : match);
  const replaceAttached = (
    match: string,
    lead: string,
    _value: string,
    offset: number,
  ): string => (inSegment(offset) ? `${lead}-H ${REDACTED}` : match);
  let out = command.replace(NTLM_HASH_DQUOTE, replaceSpaced);
  out = out.replace(NTLM_HASH_SQUOTE, replaceSpaced);
  out = out.replace(NTLM_HASH_UNQUOTED, replaceSpaced);
  out = out.replace(NTLM_HASH_ATTACHED_DQUOTE, replaceAttached);
  out = out.replace(NTLM_HASH_ATTACHED_SQUOTE, replaceAttached);
  out = out.replace(NTLM_HASH_ATTACHED_UNQUOTED, replaceAttached);
  return out;
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
  const segments = splitTopLevelSegments(command);
  const inSegment = (offset: number): boolean => {
    for (const s of segments) {
      if (offset >= s.start && offset < s.end) {
        return segmentHasLdapTool(command.slice(s.start, s.end));
      }
    }
    return false;
  };
  const replaceSpaced = (
    match: string,
    lead: string,
    sep: string,
    _value: string,
    offset: number,
  ): string => (inSegment(offset) ? `${lead}-w${sep}${REDACTED}` : match);
  const replaceAttached = (
    match: string,
    lead: string,
    _value: string,
    offset: number,
  ): string => (inSegment(offset) ? `${lead}-w ${REDACTED}` : match);
  let out = command.replace(LDAP_W_DQUOTE, replaceSpaced);
  out = out.replace(LDAP_W_SQUOTE, replaceSpaced);
  out = out.replace(LDAP_W_UNQUOTED, replaceSpaced);
  out = out.replace(LDAP_W_ATTACHED_DQUOTE, replaceAttached);
  out = out.replace(LDAP_W_ATTACHED_SQUOTE, replaceAttached);
  out = out.replace(LDAP_W_ATTACHED_UNQUOTED, replaceAttached);
  return out;
}

const URL_PREFIX_RE = /^(?:https?|ftp|ldap|ldaps|smb|smbs):\/\//i;

export function redactBasicAuthUser(command: string): string {
  const replaceSpaced = (match: string, lead: string, flag: string, sep: string, value: string): string => {
    const stripped = stripQuotes(value);
    if (URL_PREFIX_RE.test(stripped)) return match;
    if (!stripped.includes('%') && !stripped.includes(':')) return match;
    return `${lead}${flag}${sep}${REDACTED}`;
  };
  const replaceAttached = (match: string, lead: string, flag: string, value: string): string => {
    const stripped = stripQuotes(value);
    if (URL_PREFIX_RE.test(stripped)) return match;
    if (!stripped.includes('%') && !stripped.includes(':')) return match;
    return `${lead}${flag} ${REDACTED}`;
  };
  let out = command.replace(BASIC_AUTH_USER_DQUOTE, replaceSpaced);
  out = out.replace(BASIC_AUTH_USER_SQUOTE, replaceSpaced);
  out = out.replace(BASIC_AUTH_USER_UNQUOTED, replaceSpaced);
  out = out.replace(BASIC_AUTH_USER_ATTACHED_DQUOTE, replaceAttached);
  out = out.replace(BASIC_AUTH_USER_ATTACHED_SQUOTE, replaceAttached);
  out = out.replace(BASIC_AUTH_USER_ATTACHED_UNQUOTED, replaceAttached);
  return out;
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
const STATIC_REDACTION_TABLE: ReplaceEntry[] = [
  // Quote-stripped standalone option tokens — `'-p'` → `-p`.
  [/(['"])(-[A-Za-z][\w-]*)\1/g, '$2'],
  // PEM blocks first so the surrounding markers stay verbatim.
  [PEM_BLOCK_PATTERN, `$1${REDACTED}$2`],
  // Authorization next so it wins over the more general patterns.
  [AUTHORIZATION_PATTERN, redactAuthorizationHeader as (...args: unknown[]) => string],
  [COOKIE_HEADER_PATTERN, `$1${REDACTED}$3`],
  [SENSITIVE_KV_PATTERN, `$1${REDACTED}$3`],
  [BARE_BEARER_PATTERN, `$1${REDACTED}`],
  [CLI_FLAG_PATTERN, `$1${REDACTED}`],
  [URL_USERINFO_PATTERN, `$1${REDACTED}$2`],
];

function tryRedactJsonString(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed !== null && typeof parsed === 'object') {
      return JSON.stringify(redact(parsed));
    }
  } catch {
    // Fall through to inline-pattern scanning.
  }
  return null;
}

function redactString(value: string): string {
  const jsonRedacted = tryRedactJsonString(value);
  if (jsonRedacted !== null) return jsonRedacted;
  let out = value;
  for (const [pattern, replacement] of STATIC_REDACTION_TABLE) {
    out = out.replaceAll(
      pattern,
      replacement as Parameters<typeof out.replaceAll>[1],
    );
  }
  // Tool-context-aware short flags run last so the simpler kv/flag
  // patterns above have first claim on overlapping shapes.
  out = redactShortPasswordFlag(out);
  out = redactNtlmHashFlag(out);
  out = redactLdapPasswordFlag(out);
  out = redactBasicAuthUser(out);
  out = redactImpacketPositionalAuth(out);
  return out;
}

// Impacket family accepts a positional `user:password@host` (or
// `domain/user:password@host`) shape. The shared key/value redactors
// don't catch it because it's not a flag. Mask the password segment
// while preserving user@host context for SIEM correlation. Only fire
// when the segment contains an impacket-family tool token.
//
// Real Windows / domain passwords commonly contain `:`, `@`, and
// whitespace, so a strict `[^\s:@]+` for the password segment misses
// real attacks. Match three forms:
//   - bare:    `user:VALUE@host`            — VALUE is everything from
//              the FIRST `:` to the LAST `@` before whitespace.
//   - dquot:   `user:"VALUE"@host`          — quoted value (any char).
//   - squot:   `user:'VALUE'@host`          — single-quoted.
// Use the LAST unescaped `@` (not the first) as the host separator so
// passwords containing `@` are masked correctly.
const IMPACKET_POSITIONAL_PATTERN = /([\w\\/.-]+):(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|((?:\\.|\S)+?))@([\w.-]+)(?=\s|$|[;|&])/g;

const IMPACKET_TOOL_RE = /(^|[\s|;&])(?:[\w./-]+\/)?(impacket-[\w-]+|psexec\.py|smbexec\.py|wmiexec\.py|dcomexec\.py|atexec\.py|secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)/i;
function segmentHasImpacketTool(segment: string): boolean {
  return IMPACKET_TOOL_RE.test(segment);
}

export function redactImpacketPositionalAuth(command: string): string {
  const segments = splitTopLevelSegments(command);
  return command.replace(
    IMPACKET_POSITIONAL_PATTERN,
    (
      match,
      user: string,
      _passDQ: string | undefined,
      _passSQ: string | undefined,
      _passBare: string | undefined,
      host: string,
      offset: number,
    ) => {
      let inImpacket = false;
      for (const s of segments) {
        if (offset >= s.start && offset < s.end) {
          inImpacket = segmentHasImpacketTool(command.slice(s.start, s.end));
          break;
        }
      }
      if (!inImpacket) return match;
      return `${user}:${REDACTED}@${host}`;
    },
  );
}

function redactArray(items: unknown[]): unknown[] {
  const out: unknown[] = [];
  let skipNext = false;
  for (let i = 0; i < items.length; i++) {
    if (skipNext) {
      out.push(REDACTED);
      skipNext = false;
      continue;
    }
    out.push(redact(items[i]));
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
  if (Array.isArray(value)) {
    return redactArray(value);
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? REDACTED : redact(v);
    }
    return out;
  }
  if (typeof value === 'string') {
    return redactString(value);
  }
  return value;
}
