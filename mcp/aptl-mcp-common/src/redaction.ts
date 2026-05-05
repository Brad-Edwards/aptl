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

function redactAuthorizationHeader(
  _match: string,
  prefix: string,
  scheme: string | undefined,
): string {
  return scheme ? `${prefix}${scheme} ${REDACTED}` : `${prefix}${REDACTED}`;
}

function redactString(value: string): string {
  // Try JSON.parse first — payloads like `'{"password":"x"}'` and the MCP
  // `content[].text` envelope (which wraps the real result in a JSON
  // string) need to be parsed, recursively redacted, and re-serialized.
  const trimmed = value.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(value);
      if (parsed !== null && typeof parsed === 'object') {
        return JSON.stringify(redact(parsed));
      }
    } catch {
      // Fall through to inline-pattern scanning.
    }
  }
  // PEM blocks first so the surrounding markers stay verbatim (the
  // inner key bytes contain `=`/`/` characters that other patterns
  // would otherwise see as `key=value`).
  let out = value.replaceAll(PEM_BLOCK_PATTERN, `$1${REDACTED}$2`);
  // Authorization next (its match overlaps with both sensitive-kv and bare
  // Bearer; running it before the others keeps a single `[REDACTED]` token
  // in the output).
  out = out.replaceAll(AUTHORIZATION_PATTERN, redactAuthorizationHeader);
  // Cookie before SENSITIVE_KV so the full header body is masked in one
  // pass (otherwise SENSITIVE_KV stops at `;` and leaves later segments).
  out = out.replaceAll(COOKIE_HEADER_PATTERN, `$1${REDACTED}$3`);
  out = out.replaceAll(SENSITIVE_KV_PATTERN, `$1${REDACTED}$3`);
  out = out.replaceAll(BARE_BEARER_PATTERN, `$1${REDACTED}`);
  out = out.replaceAll(CLI_FLAG_PATTERN, `$1${REDACTED}`);
  out = out.replaceAll(URL_USERINFO_PATTERN, `$1${REDACTED}$2`);
  return out;
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
