/**
 * #282: detect whether a Kali tool call ran in effective raw mode so the
 * OCSF emitter can flag the result as Unknown rather than trusting
 * raw-mode `exit_code: 0`.
 *
 * The authoritative signal is `session_mode` in the `session_command`
 * result envelope (added in aptl-mcp-common after #282). When that field
 * is present, this helper consumes it; when it is missing (older common
 * peer in a mixed-version dev tree), it falls back to `args.raw === true`.
 * The fallback misses inherited-raw — the whole reason for #282 — so it is
 * strictly a transitional shim, not a correctness substitute.
 *
 * Extracted from `index.ts` so the helper is unit-testable without
 * spinning up the MCP server side effects index.ts performs at module
 * load.
 */

import type { PostToolHookInfo } from 'aptl-mcp-common';

/**
 * Raw-mode override semantics: raw transport's `exit_code: 0` artifact is
 * meaningless because the raw read times out, so the OCSF emitter must
 * surface it as Unknown rather than Success. But the override applies ONLY
 * to the transport "success-by-default" artifact, NOT to handler-level
 * KNOWN failures: an MCP handler that returns `{success: false, error: ...}`
 * (e.g., missing session, validation rejection, SSH layer throw) is a
 * known failure even when the call ran in raw mode. The post-tool hook
 * must record it as Failure, not Unknown.
 *
 * Codex pre-push review cycle 2 (post-#282 finding D-001).
 *
 * @param hasError true when PostToolHookInfo.error is set (handler threw).
 * @param outcomeSuccess parsed envelope success — `false` is a known
 *   failure; `null` means the envelope had nothing decisive.
 * @param isRawSessionCommand whether the call ran in effective raw mode.
 */
export function isOutcomeKnown(
  hasError: boolean,
  outcomeSuccess: boolean | null,
  isRawSessionCommand: boolean,
): boolean {
  const isKnownFailure = hasError || outcomeSuccess === false;
  // Known failures stay known regardless of raw mode. Otherwise, raw
  // mode suppresses the transport's exit_code: 0 success artifact.
  return isKnownFailure || (!isRawSessionCommand && outcomeSuccess !== null);
}

export function isEffectiveRawCall(info: PostToolHookInfo): boolean {
  const result = info.result as
    | { session_mode?: string; content?: Array<{ text?: string }> }
    | undefined;

  // MCP tool results are wrapped as `{ content: [{ type: 'text', text: '<json>' }] }`
  // by the SDK before they reach the post-tool hook. Parse the inner JSON
  // to read session_mode out of the envelope our handler produced.
  if (
    result?.content &&
    Array.isArray(result.content) &&
    result.content[0]?.text
  ) {
    try {
      const parsed = JSON.parse(result.content[0].text);
      if (parsed && typeof parsed.session_mode === 'string') {
        return parsed.session_mode === 'raw';
      }
    } catch {
      // fall through to args fallback
    }
  }
  // Direct envelope (test paths surface the parsed result directly).
  if (result && typeof result.session_mode === 'string') {
    return result.session_mode === 'raw';
  }
  return (info.args as { raw?: boolean }).raw === true;
}
