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
  '(?:pass(?:word|wd|phrase)?|secret|token|credential|api[_-]?key|apikey|jwt|bearer|session(?:_id)?)';
// Authorization header: keep optional scheme (`Basic`, `Bearer`) labelled
// for log-readability, mask the token. Single combined pattern so the
// optional-scheme branch and the value-only branch are mutually exclusive
// (avoids a double-redaction artifact on the same input).
const AUTHORIZATION_PATTERN =
  /(authorization\s*[:=]\s*)(?:([A-Za-z][\w-]*)\s+)?(\S+)/gi;
// `key=value` or `key: value` for any sensitive token. Stops at common
// delimiters so URL query strings and shell key/value pairs mask only
// the value, not the surrounding context.
const SENSITIVE_KV_PATTERN = new RegExp(
  String.raw`(\b${SENSITIVE_KEY_PATTERN}\b\s*[=:]\s*)['"]?[^'"&\s,;|]+['"]?`,
  'gi',
);
// Bare `Bearer <token>` (no Authorization: prefix).
const BARE_BEARER_PATTERN = /(\bbearer\s+)\S+/gi;
// `--password value` / `--token value` — long CLI flag with a separate
// space-separated value (the `key=value` form is already covered by
// SENSITIVE_KV_PATTERN).
const CLI_FLAG_PATTERN = new RegExp(
  String.raw`(--${SENSITIVE_KEY_PATTERN}\s+)\S+`,
  'gi',
);
// Recognizes `--<sensitive>` as a standalone token (used by array-pair
// detection so adjacent positional values get redacted).
const CLI_FLAG_TOKEN_PATTERN = new RegExp(
  `^--${SENSITIVE_KEY_PATTERN}$`,
  'i',
);

function redactAuthorizationHeader(
  _match: string,
  prefix: string,
  scheme: string | undefined,
  _value: string,
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
  // Authorization first (its match overlaps with both sensitive-kv and bare
  // Bearer; running it before the others keeps a single `[REDACTED]` token
  // in the output).
  let out = value.replaceAll(AUTHORIZATION_PATTERN, redactAuthorizationHeader);
  out = out.replaceAll(SENSITIVE_KV_PATTERN, `$1${REDACTED}`);
  out = out.replaceAll(BARE_BEARER_PATTERN, `$1${REDACTED}`);
  out = out.replaceAll(CLI_FLAG_PATTERN, `$1${REDACTED}`);
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
