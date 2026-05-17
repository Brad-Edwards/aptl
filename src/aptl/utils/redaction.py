"""Shared redaction helper for serialization boundaries.

Run analysis artifacts (``snapshot.json``, OTel span attributes, exported
run archives, the local run store under ``LocalRunStore``) are not
credential stores. Redact secret-shaped values at the serialization
boundary so file permissions and archive locations remain defense in
depth, not the only line of protection. See ADR-012 § Security Guardrail
and ADR-029 (control-plane secret handling).

This module mirrors ``mcp/aptl-mcp-common/src/redaction.ts`` so artifacts
emitted from either language match shape — including the command-line
credential forms (short ``-p`` passwords, ``-H`` NTLM hashes, ``-w`` LDAP
bind passwords, ``--user``/``-u``/``-U`` Basic-auth and Samba
``user%pass``, and impacket positional ``user:pass@host``). When you
change a pattern here, mirror it there and keep ``tests/test_redaction.py``
and ``mcp/aptl-mcp-common/tests/redaction.test.ts`` in parity.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

REDACTED = "[REDACTED]"

# OBS-003 experimenter opt-out. The toggle is NOT consulted by the
# shared :func:`redact` primitive — that would disable redaction at
# every serialization boundary in the project (OTel/Tempo spans,
# `LocalRunStore` JSON/JSONL writes, snapshot DTOs, stderr OCSF
# lines, CLI/API JSON), giving any lab/observability user with
# Tempo/Grafana access the ability to read raw control-plane
# secrets the moment an experimenter flips the env var (codex
# pre-push cycle 3 finding-9 — class category: "Global redact()
# identity bypass affecting every serialization boundary that
# imports the shared redactor"). Instead, the toggle is consulted
# ONLY by the local per-run capture sink wrappers
# (`mcp-red/src/capture.ts` `captureToolCall`,
# `mcp-red/src/logger.ts` `localOcsfJsonlSink`) and any future
# experimental sink that explicitly opts in via the documented
# `experiment_no_redact_active()` helper. See ADR-033's
# "Secret-handling" Security Layers entry for the boundary contract.
_EXPERIMENT_NO_REDACT_ENV = "APTL_EXPERIMENT_NO_REDACT"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def experiment_no_redact_active() -> bool:
    """Public accessor for the OBS-003 experimenter opt-out env var.

    Returns ``True`` only when ``APTL_EXPERIMENT_NO_REDACT`` is set
    to a truthy value (``1``, ``true``, ``yes``, ``on`` — case-
    insensitive). Any other value (including ``0``, ``false``,
    empty, or unset) returns ``False`` (redaction-on default).

    This is the **only** sanctioned consumer of the toggle. Call
    this from a local per-run capture sink BEFORE invoking
    :func:`redact`, and skip the redact call when it returns ``True``.
    Do NOT add a guard inside :func:`redact` itself — that would
    disable redaction for every serialization boundary in the
    project, not just the experimental record.
    """
    return os.environ.get(_EXPERIMENT_NO_REDACT_ENV, "").strip().lower() in _TRUTHY

# Substring tokens that mark a key as carrying credential material. Match
# is case-insensitive substring against the *full key name* so a field like
# ``ssl_authorization_header`` is also caught. ``pass`` subsumes
# ``password``/``passwd``/``passphrase``; ``session`` covers replayable
# session identifiers (Wazuh session_id, etc.). False-positive matches on
# unrelated tokens like ``passport`` are an acceptable cost — the ADR-012
# guardrail prefers over-redaction over leak.
_SENSITIVE_TOKENS: tuple[str, ...] = (
    "pass",
    "secret",
    "token",
    "credential",  # also matches "credentials"
    "authorization",
    "cookie",
    "jwt",
    "bearer",
    "api_key",
    "apikey",
    "key",  # broad — see allowlist below
    "session",
)

# Field names that look sensitive (contain "key") but legitimately hold a
# path or other public reference, not key material. Tightened to names
# that are unambiguously paths/files: bare ``ssh_key`` could mean the
# private key material itself, so it is intentionally NOT in the
# allowlist.
_SAFE_KEY_NAMES: frozenset[str] = frozenset(
    {
        "key_path",
        "key_file",
        "keypath",
        "keyfile",
        "ssh_key_path",
        "ssh_keyfile",
        "ssh_key_file",
        "public_key",
        "publickey",
    }
)


def _is_sensitive_key(name: str) -> bool:
    lower = name.lower()
    if lower in _SAFE_KEY_NAMES:
        return False
    return any(token in lower for token in _SENSITIVE_TOKENS)


# Inline-secret patterns for plain-text strings (command lines, headers,
# query strings, etc.). Mirrors the TypeScript helper so artifacts emitted
# from either language match shape.
_SENSITIVE_KEY_PATTERN = (
    r"(?:pass(?:word|wd|phrase)?|secret|token|credential|"
    r"api[_-]?key|apikey|jwt|bearer|session(?:_id)?|cookie)"
)
# `\S+` would greedily consume trailing quotes/punctuation around the
# secret value (e.g. eat the closing `'` of a curl `-H 'Authorization: ...'`
# header, corrupting downstream diagnostic structure). Stop at quotes
# and whitespace instead.
_VALUE_PATTERN = r"[^\s'\"]+"
_AUTHORIZATION_RE = re.compile(
    # `re.IGNORECASE` handles both cases — listing `A-Z` alongside `a-z`
    # is redundant under case-insensitive matching (Sonar S5869).
    rf"(authorization\s*[:=]\s*)(?:([a-z][\w-]*)\s+)?{_VALUE_PATTERN}",
    re.IGNORECASE,
)
# `\b` word-boundaries break on compound names because `_` is a word
# character — `access_token=...` matches neither `\btoken\b` nor
# `\baccess_token\b`. Use alphanumeric-only boundaries so `_`, `-`, and
# punctuation all count as separators.
_KEY_LB = r"(?<![a-zA-Z0-9])"  # left boundary
_KEY_RB = r"(?![a-zA-Z0-9])"  # right boundary
# Capture leading and trailing quotes as separate groups so the
# replacement preserves them (otherwise wrapping `'<value>'` /
# `"<value>"` loses the closing quote, corrupting downstream
# diagnostic structure).
_SENSITIVE_KV_RE = re.compile(
    rf"({_KEY_LB}{_SENSITIVE_KEY_PATTERN}{_KEY_RB}\s*[=:]\s*['\"]?)([^'\"&\s,;|]+)(['\"]?)",
    re.IGNORECASE,
)
_BARE_BEARER_RE = re.compile(
    rf"({_KEY_LB}bearer\s+){_VALUE_PATTERN}", re.IGNORECASE
)
# `--password value` / `--client-secret value` / `--access-token value`
# style (long CLI flags). The `[\w-]*` prefixes allow compound flag
# names like `--client-secret`; regex backtracking finds the embedded
# sensitive token.
_CLI_FLAG_RE = re.compile(
    rf"(--[\w-]*{_SENSITIVE_KEY_PATTERN}{_KEY_RB}\s+){_VALUE_PATTERN}",
    re.IGNORECASE,
)
# Cookie / Set-Cookie header: redact the entire body so multi-segment
# cookies like `Cookie: lang=en; connect.sid=SECRET` are masked in one
# pass instead of leaving later segments intact. Capture the leading and
# trailing quotes (when present) as separate groups so the replacement
# can put them back — otherwise a wrapping `'...'` loses its closing
# quote.
_COOKIE_HEADER_RE = re.compile(
    r"((?:set-cookie|cookie)\s*[:=]\s*['\"]?)([^'\"\r\n]+)(['\"]?)",
    re.IGNORECASE,
)
# URL userinfo: `scheme://user:password@host/path`. Preserve user (often
# useful for diagnostics) and mask the password segment.
_URL_USERINFO_RE = re.compile(r"(://[^/:@\s]+:)[^@\s]+(@)")
# PEM key/cert blocks. `re.DOTALL` lets `.` span newlines; non-greedy so
# adjacent blocks are masked separately.
_PEM_BLOCK_RE = re.compile(
    r"(-----BEGIN[^-]*-----).*?(-----END[^-]*-----)",
    re.DOTALL,
)
# Recognizes `--<sensitive>` (or compound `--client-secret`,
# `--access-token`) as a standalone token used by array-pair detection
# so adjacent positional values get redacted.
_CLI_FLAG_TOKEN_RE = re.compile(
    rf"^--[\w-]*{_SENSITIVE_KEY_PATTERN}{_KEY_RB}$",
    re.IGNORECASE,
)
# Quote-stripped standalone option tokens — `'-p'` → `-p`, `"-U"` → `-U`.
# Runs before the flag matchers so a quoted option token still triggers
# the per-flag credential redaction below.
_QUOTED_OPTION_TOKEN_RE = re.compile(r"""(['"])(-[A-Za-z][\w-]*)\1""")


def _redact_authorization(match: "re.Match[str]") -> str:
    prefix, scheme = match.group(1), match.group(2)
    if scheme:
        return f"{prefix}{scheme} {REDACTED}"
    return f"{prefix}{REDACTED}"


# --------------------------------------------------------------------------
# Command-line credential forms (mirrors redaction.ts).
#
# Some credential shapes can't be matched by a key/value pattern alone
# because the same flag means different things to different tools — `-p`
# is a port to nmap but a password to hydra; `-H` is an HTTP header to
# curl but an NTLM hash to crackmapexec; `-w` is a wordlist to hydra but
# an LDAP bind password to ldapsearch. So these are scoped per shell
# segment: split the command on top-level `&&`/`||`/`;`/`|`/`&`, then
# redact a flag's value only when the segment containing it names a tool
# for which the flag carries a secret.
# --------------------------------------------------------------------------


def _advance_quote_state(state: dict[str, bool], ch: str) -> bool:
    """Update single/double-quote and escape state for one character.

    Returns ``True`` when the caller should treat this position as inside
    a quoted run / escape and therefore not a segment separator.
    """
    if state["escaped"]:
        state["escaped"] = False
        return True
    if ch == "\\":
        state["escaped"] = True
        return True
    if not state["in_double"] and ch == "'":
        state["in_single"] = not state["in_single"]
        return True
    if not state["in_single"] and ch == '"':
        state["in_double"] = not state["in_double"]
        return True
    return state["in_single"] or state["in_double"]


def _ampersand_step(command: str, i: int) -> int:
    """How far past an ``&`` to advance the segment start (0 = not a separator).

    ``2>&1``, ``&>file``, ``<&3`` are redirections, not separators.
    ``&&`` advances by 2, a lone ``&`` (background) by 1.
    """
    prev = command[i - 1] if i > 0 else ""
    nxt = command[i + 1] if i + 1 < len(command) else ""
    if prev in (">", "<") or nxt == ">":
        return 0
    return 2 if nxt == "&" else 1


def _split_top_level_segments(command: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` half-open ranges for each top-level shell segment.

    Quote- and escape-aware. Multi-character separators (``&&``, ``||``)
    are consumed atomically — the loop skips past the second character
    so the splitter never emits a zero-width range. Any subsequent
    reconstruction (``_unquote_options_in_credential_segments``) can
    re-join the slices with the original separator characters intact;
    the previous ``for ... enumerate`` loop revisited the second ``&``,
    which the reconstructor would emit as a stray ``&`` between segments.
    """
    segments: list[tuple[int, int]] = []
    start = 0
    state: dict[str, bool] = {"in_single": False, "in_double": False, "escaped": False}
    n = len(command)
    i = 0
    while i < n:
        ch = command[i]
        if _advance_quote_state(state, ch):
            i += 1
            continue
        if ch in ("|", ";"):
            segments.append((start, i))
            start = i + 1
            i += 1
            continue
        if ch == "&":
            advance = _ampersand_step(command, i)
            if advance > 0:
                segments.append((start, i))
                start = i + advance
                i += advance
                continue
        i += 1
    segments.append((start, n))
    return segments


def _segment_predicate(command: str, segment_test: "re.Pattern[str] | tuple"):
    """Build an ``offset -> bool`` predicate over precomputed segments.

    ``segment_test`` is either a compiled regex (the segment matches if
    the regex searches successfully) or a tuple of regexes (matches if
    *any* hits — split this way to keep each regex under Sonar's
    regex-complexity threshold).
    """
    segments = _split_top_level_segments(command)
    tests = segment_test if isinstance(segment_test, tuple) else (segment_test,)

    def hit(text: str) -> bool:
        return any(t.search(text) for t in tests)

    flags = [hit(command[s:e]) for (s, e) in segments]

    def in_flagged_segment(offset: int) -> bool:
        for idx, (s, e) in enumerate(segments):
            if s <= offset < e:
                return flags[idx]
        return False

    return in_flagged_segment


# Per-segment tool-family detectors. Split into small batches so each
# regex stays well under the regex-complexity threshold (Sonar S5843);
# a segment matches if ANY batch hits and `.search()` short-circuits.
_CREDENTIAL_TOOL_REGEXES: tuple["re.Pattern[str]", ...] = (
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(hydra|medusa|patator|crowbar|sshpass|wfuzz|kerbrute)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(crackmapexec|cme|nxc|evil-winrm)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(bloodhound-python|bloodhound\.py)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(mysql|mariadb|mysqladmin|redis-cli)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?"
        r"(impacket-psexec|impacket-smbexec|impacket-wmiexec|impacket-secretsdump)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?"
        r"(psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)",
        re.IGNORECASE,
    ),
)
_HASH_TOOLS_RE = re.compile(
    r"(^|[\s|;&])(?:[\w./-]+/)?"
    r"(crackmapexec|cme|nxc|psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|impacket-[\w-]+|evil-winrm)(?:\s|$)",
    re.IGNORECASE,
)
_LDAP_TOOL_RE = re.compile(
    r"(^|[\s|;&])(?:[\w./-]+/)?"
    r"(ldapadd|ldapcompare|ldapdelete|ldapmodify|ldappasswd|ldapsearch|ldapwhoami)(?:\s|$)",
    re.IGNORECASE,
)
_IMPACKET_TOOL_REGEXES: tuple["re.Pattern[str]", ...] = (
    re.compile(r"(^|[\s|;&])(?:[\w./-]+/)?(impacket-[\w-]+)(?:\s|$)", re.IGNORECASE),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(psexec\.py|smbexec\.py|wmiexec\.py|dcomexec\.py|atexec\.py)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)",
        re.IGNORECASE,
    ),
)
# Tools where the short flags ``-u`` / ``-U`` carry a username (often
# paired with an embedded password — Basic-auth ``user:pass`` for HTTP
# clients, Samba ``user%pass`` for the SMB family). The short forms are
# scoped to this list so a generic ``date -u +%Y:%m`` (where ``-u`` is a
# UTC flag and ``+%Y:%m`` is just an unrelated value) is not mis-classified
# as Basic auth. The long ``--user`` form stays content-based — that
# spelling is overwhelmingly auth-bearing.
_BASIC_AUTH_SHORT_TOOLS_REGEXES: tuple["re.Pattern[str]", ...] = (
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(curl|wget|smbclient|smbget|hydra|medusa|kerbrute)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(crackmapexec|cme|nxc|evil-winrm)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?(mysql|mysqladmin|mariadb|redis-cli|psql|ldapsearch|bloodhound-python|bloodhound\.py)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[\s|;&])(?:[\w./-]+/)?"
        r"(impacket-[\w-]+|psexec\.py|smbexec\.py|wmiexec\.py|secretsdump\.py|getuserspns\.py|getnpusers\.py|ntlmrelayx\.py)(?:\s|$)",
        re.IGNORECASE,
    ),
)
# Union of every credential-bearing tool family. Used by the
# segment-scoped quote-strip so an option-shaped token like ``'-p'`` is
# only normalized to bare ``-p`` when its segment is plausibly running a
# credential-using tool. Outside such segments (``echo '-p' hunter2``,
# ``grep '-u' alice file``) the quotes are left in place so the per-flag
# matchers cannot fire on innocent data.
_ANY_CREDENTIAL_TOOL_REGEXES: tuple["re.Pattern[str]", ...] = (
    *_CREDENTIAL_TOOL_REGEXES,
    _HASH_TOOLS_RE,
    _LDAP_TOOL_RE,
    *_IMPACKET_TOOL_REGEXES,
    *_BASIC_AUTH_SHORT_TOOLS_REGEXES,
)

# Quoted-value forms use the unrolled-loop pattern `"[^"\\]*(?:\\.[^"\\]*)*"`
# (not the alternation form `(?:[^"\\]|\\.)*`) so the regex engine has no
# ambiguous backtracking path — eliminates the ReDoS class at the engine
# level (Sonar S5852). The unquoted/attached forms are escape-aware:
# `(?:\\.|[^\s'"\\])+` consumes `\<anything>` plus ordinary tokens so
# `hydra -p correct\ horse` is one shell token.
_DQ_VALUE = r'"[^"\\]*(?:\\.[^"\\]*)*"'
_SQ_VALUE = r"'[^'\\]*(?:\\.[^'\\]*)*'"
_BARE_VALUE = r"(?:\\.|[^\s'\"\\])+"

_SHORT_P_DQUOTE = re.compile(rf"(^|\s|\|)-p(\s+|=)({_DQ_VALUE})")
_SHORT_P_SQUOTE = re.compile(rf"(^|\s|\|)-p(\s+|=)({_SQ_VALUE})")
_SHORT_P_UNQUOTED = re.compile(rf"(^|\s|\|)-p(\s+|=)({_BARE_VALUE})")
_SHORT_P_ATTACHED_DQUOTE = re.compile(rf"(^|\s|\|)-p({_DQ_VALUE})")
_SHORT_P_ATTACHED_SQUOTE = re.compile(rf"(^|\s|\|)-p({_SQ_VALUE})")
_SHORT_P_ATTACHED_UNQUOTED = re.compile(r"(^|\s|\|)-p([^\s='\"](?:\\.|[^\s'\"\\])*)")

_NTLM_HASH_DQUOTE = re.compile(rf"(^|\s|\|)-H(\s+|=)({_DQ_VALUE})")
_NTLM_HASH_SQUOTE = re.compile(rf"(^|\s|\|)-H(\s+|=)({_SQ_VALUE})")
_NTLM_HASH_UNQUOTED = re.compile(rf"(^|\s|\|)-H(\s+|=)({_BARE_VALUE})")
_NTLM_HASH_ATTACHED_DQUOTE = re.compile(rf"(^|\s|\|)-H({_DQ_VALUE})")
_NTLM_HASH_ATTACHED_SQUOTE = re.compile(rf"(^|\s|\|)-H({_SQ_VALUE})")
_NTLM_HASH_ATTACHED_UNQUOTED = re.compile(r"(^|\s|\|)-H([^\s='\"](?:\\.|[^\s'\"\\])*)")

# Impacket's documented short form is `-hashes [<LM>]:<NT>` (single
# dash, full word). The `-H` patterns above only catch the
# crackmapexec/nxc shape. Without these, a command like
# `psexec.py alice@dc -hashes :8846f7eaee8fb117` leaked the NT hash
# through redaction (test-quality review cycle 1 finding-1 surfaced
# the missing assertion that exposed this pre-existing bug).
_NTLM_HASHES_DQUOTE = re.compile(rf"(^|\s|\|)(--?hashes)(\s+|=)({_DQ_VALUE})")
_NTLM_HASHES_SQUOTE = re.compile(rf"(^|\s|\|)(--?hashes)(\s+|=)({_SQ_VALUE})")
_NTLM_HASHES_UNQUOTED = re.compile(rf"(^|\s|\|)(--?hashes)(\s+|=)({_BARE_VALUE})")

_LDAP_W_DQUOTE = re.compile(rf"(^|\s|\|)-w(\s+|=)({_DQ_VALUE})")
_LDAP_W_SQUOTE = re.compile(rf"(^|\s|\|)-w(\s+|=)({_SQ_VALUE})")
_LDAP_W_UNQUOTED = re.compile(rf"(^|\s|\|)-w(\s+|=)({_BARE_VALUE})")
_LDAP_W_ATTACHED_DQUOTE = re.compile(rf"(^|\s|\|)-w({_DQ_VALUE})")
_LDAP_W_ATTACHED_SQUOTE = re.compile(rf"(^|\s|\|)-w({_SQ_VALUE})")
_LDAP_W_ATTACHED_UNQUOTED = re.compile(r"(^|\s|\|)-w([^\s='\"](?:\\.|[^\s'\"\\])*)")

_BASIC_AUTH_USER_DQUOTE = re.compile(rf"(^|\s|\|)(--user|-u|-U)(\s+|=)({_DQ_VALUE})")
_BASIC_AUTH_USER_SQUOTE = re.compile(rf"(^|\s|\|)(--user|-u|-U)(\s+|=)({_SQ_VALUE})")
_BASIC_AUTH_USER_UNQUOTED = re.compile(rf"(^|\s|\|)(--user|-u|-U)(\s+|=)({_BARE_VALUE})")
_BASIC_AUTH_USER_ATTACHED_DQUOTE = re.compile(rf"(^|\s|\|)(-u|-U)({_DQ_VALUE})")
_BASIC_AUTH_USER_ATTACHED_SQUOTE = re.compile(rf"(^|\s|\|)(-u|-U)({_SQ_VALUE})")
_BASIC_AUTH_USER_ATTACHED_UNQUOTED = re.compile(
    r"(^|\s|\|)(-u|-U)([^\s='\"](?:\\.|[^\s'\"\\])*)"
)

# Impacket positional `user:password@host` / `domain/user:password@host`.
# Mirrors impacket's own `parse_target` (`[^@]*` for the password), so the
# bare form can't contain a literal `@`; users with `@`/whitespace in the
# password MUST quote. `(?=\s|$|[;|&])` requires a token boundary after the
# host so we don't eat into the rest of the command line.
_IMPACKET_POSITIONAL_DQUOTE = re.compile(
    r'([\w\\/.-]+):"([^"\\]*(?:\\.[^"\\]*)*)"@([\w.-]+)(?=\s|$|[;|&])'
)
_IMPACKET_POSITIONAL_SQUOTE = re.compile(
    r"([\w\\/.-]+):'([^'\\]*(?:\\.[^'\\]*)*)'@([\w.-]+)(?=\s|$|[;|&])"
)
_IMPACKET_POSITIONAL_BARE = re.compile(
    r"([\w\\/.-]+):((?:\\.|[^\\@\s])+)@([\w.-]+)(?=\s|$|[;|&])"
)

_URL_PREFIX_RE = re.compile(r"^(?:https?|ftp|ldap|ldaps|smb|smbs)://", re.IGNORECASE)
_PORT_LIKE_RE = re.compile(r"^\d{1,5}(?:[,-]\d{1,5})*$")


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _is_port_like(stripped: str) -> bool:
    """Comma- or hyphen-separated digit groups (each ≤ 5 digits) — a port spec."""
    return bool(_PORT_LIKE_RE.fullmatch(stripped))


def _unquote_options_in_credential_segments(command: str) -> str:
    """Strip surrounding quotes from ``'-X'`` / ``"-X"`` option tokens —
    but only inside segments that name a credential-bearing tool.

    The earlier implementation ran this pre-pass globally, which mutated
    arbitrary data (``echo '-p' hunter2`` became ``echo -p hunter2``,
    then `_redact_short_password_flag` redacted the trailing word as if
    it were a password). Scoping the strip to credential-bearing
    segments keeps the original `hydra '-p' hunter2` parity (hydra's
    segment unquotes, the per-flag matcher fires) while leaving
    non-credential text intact.
    """
    if "'" not in command and '"' not in command:
        return command  # cheap fast path; most commands have no quotes
    segments = _split_top_level_segments(command)
    out_parts: list[str] = []
    last_end = 0
    for s, e in segments:
        if s > last_end:
            # Preserve the separator characters (``&&``/``||``/``;``/``|``/``&``).
            out_parts.append(command[last_end:s])
        seg = command[s:e]
        if any(t.search(seg) for t in _ANY_CREDENTIAL_TOOL_REGEXES):
            seg = _QUOTED_OPTION_TOKEN_RE.sub(r"\2", seg)
        out_parts.append(seg)
        last_end = e
    if last_end < len(command):
        out_parts.append(command[last_end:])
    return "".join(out_parts)


def _segment_aware_sub_chain(
    command: str,
    segment_test: "re.Pattern[str] | tuple",
    passes: list,
) -> str:
    """Run a sequence of segment-aware substitutions safely.

    Each pass recomputes the segment predicate against the *current*
    string before invoking ``re.sub`` — the prior approach (compute
    segments once on the input, then run six sequential ``.sub()`` calls
    on a mutating string) reused stale offsets after replacements
    shifted character positions, which could mis-classify later matches
    into the wrong segment and over-redact things like ``nmap -p 22``
    after a long quoted hydra password contracted the string. Recompute
    per pass; ``re.sub``'s own callback offsets are consistent within a
    single ``.sub()`` call, so this is sufficient.

    ``passes`` is a list of ``(pattern, replacer_factory)`` where
    ``replacer_factory(in_seg)`` returns the ``re.sub`` callback.
    """
    out = command
    for pattern, factory in passes:
        in_seg = _segment_predicate(out, segment_test)
        out = pattern.sub(factory(in_seg), out)
    return out


def _redact_short_password_flag(command: str) -> str:
    """Mask short ``-p <value>`` credential flags.

    Numeric values stay visible (so ``nmap -p 22``, ``nmap -p 22,80``,
    ``nmap -p 1-1024`` survive) unless the segment names a credential tool
    (``hydra``, ``sshpass``, ``medusa``, …), in which case the value is
    masked even when numeric — numeric passwords are common. Handles
    spaced (``-p value``), equals (``-p=value``), and attached
    (``-p<value>``) shell forms.
    """

    def make_repl_spaced(in_cred):
        def repl(m: "re.Match[str]") -> str:
            lead, sep, value = m.group(1), m.group(2), m.group(3)
            if not in_cred(m.start()) and _is_port_like(_strip_quotes(value)):
                return f"{lead}-p{sep}{value}"
            return f"{lead}-p{sep}{REDACTED}"

        return repl

    def make_repl_attached(in_cred):
        def repl(m: "re.Match[str]") -> str:
            lead, value = m.group(1), m.group(2)
            if not in_cred(m.start()) and _is_port_like(_strip_quotes(value)):
                return f"{lead}-p{value}"
            return f"{lead}-p {REDACTED}"

        return repl

    return _segment_aware_sub_chain(
        command,
        _CREDENTIAL_TOOL_REGEXES,
        [
            (_SHORT_P_DQUOTE, make_repl_spaced),
            (_SHORT_P_SQUOTE, make_repl_spaced),
            (_SHORT_P_UNQUOTED, make_repl_spaced),
            (_SHORT_P_ATTACHED_DQUOTE, make_repl_attached),
            (_SHORT_P_ATTACHED_SQUOTE, make_repl_attached),
            (_SHORT_P_ATTACHED_UNQUOTED, make_repl_attached),
        ],
    )


def _redact_ntlm_hash_flag(command: str) -> str:
    """Mask ``-H <hash>`` only inside a segment that names a hash-using tool
    (crackmapexec / cme / nxc / impacket *.py / evil-winrm). ``curl -H
    'X-Foo: bar'`` is left alone."""

    def make_repl_spaced(in_seg):
        def repl(m: "re.Match[str]") -> str:
            if not in_seg(m.start()):
                return m.group(0)
            return f"{m.group(1)}-H{m.group(2)}{REDACTED}"

        return repl

    def make_repl_attached(in_seg):
        def repl(m: "re.Match[str]") -> str:
            if not in_seg(m.start()):
                return m.group(0)
            return f"{m.group(1)}-H {REDACTED}"

        return repl

    out = _segment_aware_sub_chain(
        command,
        _HASH_TOOLS_RE,
        [
            (_NTLM_HASH_DQUOTE, make_repl_spaced),
            (_NTLM_HASH_SQUOTE, make_repl_spaced),
            (_NTLM_HASH_UNQUOTED, make_repl_spaced),
            (_NTLM_HASH_ATTACHED_DQUOTE, make_repl_attached),
            (_NTLM_HASH_ATTACHED_SQUOTE, make_repl_attached),
            (_NTLM_HASH_ATTACHED_UNQUOTED, make_repl_attached),
        ],
    )

    # Impacket-specific `-hashes :HASH` / `--hashes <LM>:<NT>` form.
    # Scoped to segments where an impacket *.py tool appears so we
    # don't over-redact unrelated `--hashes` flags. Preserves the
    # flag literal (`m.group(2)` is `-hashes` or `--hashes`) and
    # only masks the value (group 4).
    def make_repl_hashes(in_seg):
        def repl(m: "re.Match[str]") -> str:
            if not in_seg(m.start()):
                return m.group(0)
            return f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}"
        return repl

    impacket_pred_re = re.compile(
        "|".join(p.pattern for p in _IMPACKET_TOOL_REGEXES),
        re.IGNORECASE,
    )
    out = _segment_aware_sub_chain(
        out,
        impacket_pred_re,
        [
            (_NTLM_HASHES_DQUOTE, make_repl_hashes),
            (_NTLM_HASHES_SQUOTE, make_repl_hashes),
            (_NTLM_HASHES_UNQUOTED, make_repl_hashes),
        ],
    )
    return out


def _redact_ldap_password_flag(command: str) -> str:
    """Mask ``-w <password>`` (LDAP simple bind) only inside a segment that
    names an ``ldap*`` tool. ``hydra -w wordlist.txt`` (wordlist, not a
    password) is left alone."""

    def make_repl_spaced(in_seg):
        def repl(m: "re.Match[str]") -> str:
            if not in_seg(m.start()):
                return m.group(0)
            return f"{m.group(1)}-w{m.group(2)}{REDACTED}"

        return repl

    def make_repl_attached(in_seg):
        def repl(m: "re.Match[str]") -> str:
            if not in_seg(m.start()):
                return m.group(0)
            return f"{m.group(1)}-w {REDACTED}"

        return repl

    return _segment_aware_sub_chain(
        command,
        _LDAP_TOOL_RE,
        [
            (_LDAP_W_DQUOTE, make_repl_spaced),
            (_LDAP_W_SQUOTE, make_repl_spaced),
            (_LDAP_W_UNQUOTED, make_repl_spaced),
            (_LDAP_W_ATTACHED_DQUOTE, make_repl_attached),
            (_LDAP_W_ATTACHED_SQUOTE, make_repl_attached),
            (_LDAP_W_ATTACHED_UNQUOTED, make_repl_attached),
        ],
    )


def _basic_auth_value_is_credential(value: str) -> bool:
    stripped = _strip_quotes(value)
    if _URL_PREFIX_RE.match(stripped):  # `sqlmap -u https://target/...`
        return False
    return "%" in stripped or ":" in stripped  # Samba user%pass / Basic user:pass


def _redact_basic_auth_user(command: str) -> str:
    """Mask ``--user``/``-u``/``-U`` when the value is a credential pair.

    The long ``--user`` form is content-based — overwhelmingly auth
    bearing across tools, so a value with ``:`` or ``%`` (and not a
    URL) is masked. The short ``-u``/``-U`` forms ALSO require the
    segment to name a tool that actually uses those short flags for
    auth (curl/wget/smbclient/nxc/crackmapexec/impacket family/…).
    Without that gate, ``date -u +%Y:%m`` (where ``-u`` is the UTC
    flag and ``+%Y:%m`` is just an unrelated value) would be misread
    as Basic auth.
    """

    def make_repl_spaced(in_short_seg):
        def repl(m: "re.Match[str]") -> str:
            lead, flag, sep, value = m.group(1), m.group(2), m.group(3), m.group(4)
            if not _basic_auth_value_is_credential(value):
                return m.group(0)
            if flag in ("-u", "-U") and not in_short_seg(m.start()):
                return m.group(0)
            return f"{lead}{flag}{sep}{REDACTED}"

        return repl

    def make_repl_attached(in_short_seg):
        def repl(m: "re.Match[str]") -> str:
            lead, flag, value = m.group(1), m.group(2), m.group(3)
            if not _basic_auth_value_is_credential(value):
                return m.group(0)
            # Attached forms only fire on the short flags (``-u``/``-U``)
            # by construction, so the tool-segment gate always applies.
            if not in_short_seg(m.start()):
                return m.group(0)
            return f"{lead}{flag} {REDACTED}"

        return repl

    return _segment_aware_sub_chain(
        command,
        _BASIC_AUTH_SHORT_TOOLS_REGEXES,
        [
            (_BASIC_AUTH_USER_DQUOTE, make_repl_spaced),
            (_BASIC_AUTH_USER_SQUOTE, make_repl_spaced),
            (_BASIC_AUTH_USER_UNQUOTED, make_repl_spaced),
            (_BASIC_AUTH_USER_ATTACHED_DQUOTE, make_repl_attached),
            (_BASIC_AUTH_USER_ATTACHED_SQUOTE, make_repl_attached),
            (_BASIC_AUTH_USER_ATTACHED_UNQUOTED, make_repl_attached),
        ],
    )


def _redact_impacket_positional_auth(command: str) -> str:
    """Mask the password in an impacket positional ``user:password@host``
    target (``psexec.py corp/alice:pw@dc``) — only inside a segment that
    names an impacket-family tool, so a ``user:token@host`` elsewhere is
    untouched. Preserves ``user`` and ``@host`` for SIEM correlation."""

    def make_repl(in_seg):
        def repl(m: "re.Match[str]") -> str:
            if not in_seg(m.start()):
                return m.group(0)
            return f"{m.group(1)}:{REDACTED}@{m.group(3)}"

        return repl

    return _segment_aware_sub_chain(
        command,
        _IMPACKET_TOOL_REGEXES,
        [
            (_IMPACKET_POSITIONAL_DQUOTE, make_repl),
            (_IMPACKET_POSITIONAL_SQUOTE, make_repl),
            (_IMPACKET_POSITIONAL_BARE, make_repl),
        ],
    )


def _redact_command_flags(value: str) -> str:
    """Apply the tool-context-aware command-line redactors in order.

    Runs after the simple key/value patterns so the cheaper shapes have
    first claim on overlapping inputs (matches ``redaction.ts``'s order).
    The leading segment-scoped quote-strip unquotes ``'-X'``/``"-X"``
    option tokens *only* within credential-bearing segments so
    ``hydra '-p' hunter2`` still triggers the per-flag matcher while
    ``echo '-p' hunter2`` is preserved verbatim.
    """
    out = _unquote_options_in_credential_segments(value)
    out = _redact_short_password_flag(out)
    out = _redact_ntlm_hash_flag(out)
    out = _redact_ldap_password_flag(out)
    out = _redact_basic_auth_user(out)
    out = _redact_impacket_positional_auth(out)
    return out


def _redact_string(value: str) -> str:
    # Try JSON.parse first — payloads like '{"password":"x"}' and the MCP
    # `content[].text` envelope (which wraps the real result in a JSON
    # string) need to be parsed, recursively redacted, and re-serialized.
    stripped = value.lstrip()
    if stripped and stripped[0] in "{[":
        try:
            parsed = json.loads(value)
        except ValueError:  # JSONDecodeError is a ValueError subclass
            parsed = None
        if isinstance(parsed, (dict, list)):
            return json.dumps(redact(parsed), separators=(",", ":"))
    # PEM blocks first so the markers stay verbatim (the inner key bytes
    # contain `=`/`/` characters that other patterns would otherwise see
    # as `key=value`). The quote-strip pre-pass that USED to live here
    # was a global rewrite and corrupted non-option text like
    # ``echo '-p' hunter2``; it now lives inside ``_redact_command_flags``
    # behind a segment-scoped tool gate.
    out = _PEM_BLOCK_RE.sub(rf"\1{REDACTED}\2", value)
    out = _AUTHORIZATION_RE.sub(_redact_authorization, out)
    # Cookie before SENSITIVE_KV so the full header body is masked in one
    # pass (otherwise SENSITIVE_KV stops at `;` and leaves later segments).
    out = _COOKIE_HEADER_RE.sub(rf"\1{REDACTED}\3", out)
    out = _SENSITIVE_KV_RE.sub(rf"\1{REDACTED}\3", out)
    out = _BARE_BEARER_RE.sub(rf"\1{REDACTED}", out)
    out = _CLI_FLAG_RE.sub(rf"\1{REDACTED}", out)
    out = _URL_USERINFO_RE.sub(rf"\1{REDACTED}\2", out)
    # Tool-context-aware short flags last so the simpler kv/flag patterns
    # above have first claim on overlapping shapes.
    return _redact_command_flags(out)


def _argv_credential_modes(leading: str) -> dict[str, bool]:
    """Classify an argv leading token by which credential-flag families
    apply. Empty / unknown returns all-False (the array is not treated
    as an argv for short-flag purposes)."""
    return {
        "cred": any(t.search(leading) for t in _CREDENTIAL_TOOL_REGEXES),
        "hash": bool(_HASH_TOOLS_RE.search(leading)),
        "ldap": bool(_LDAP_TOOL_RE.search(leading)),
        "basic": any(t.search(leading) for t in _BASIC_AUTH_SHORT_TOOLS_REGEXES),
    }


# Mode → (set of short flags it owns) → does the value need a content gate?
# Keeping this as data instead of an if/elif chain keeps
# ``_argv_short_flag_skip_indices`` under the cognitive-complexity ceiling.
_ARGV_SHORT_FLAG_RULES: tuple[tuple[str, frozenset[str], bool], ...] = (
    ("cred", frozenset({"-p"}), False),
    ("hash", frozenset({"-H"}), False),
    ("ldap", frozenset({"-w"}), False),
    # Basic-auth `-u`/`-U` keeps the same content gate as the string-mode
    # redactor: bare usernames stay visible, only credential pairs mask.
    ("basic", frozenset({"-u", "-U"}), True),
)


def _is_argv_short_flag_target(
    flag: str, value: str, modes: dict[str, bool]
) -> bool:
    """Decide whether ``value`` (the element following ``flag``) should be
    redacted as a short-flag credential value, per ``modes``."""
    for mode, flags, content_gated in _ARGV_SHORT_FLAG_RULES:
        if not modes[mode] or flag not in flags:
            continue
        if content_gated:
            return _basic_auth_value_is_credential(value)
        return True
    return False


def _argv_short_flag_skip_indices(items: list, modes: dict[str, bool]) -> set[int]:
    """Indices in ``items`` whose value should be redacted as a short-flag
    credential, given the modes derived from the argv leading token.

    Mirrors the per-segment string-mode short-flag rules — ``-p`` for
    credential tools, ``-H`` for hash tools, ``-w`` for LDAP tools,
    ``-u``/``-U`` for basic-auth tools (with the bare-username carve-out).
    """
    skip: set[int] = set()
    if not any(modes.values()):
        return skip
    for i in range(len(items) - 1):
        flag = items[i]
        value = items[i + 1]
        if not isinstance(flag, str) or not isinstance(value, str):
            continue
        if _is_argv_short_flag_target(flag, value, modes):
            skip.add(i + 1)
    return skip


def _redact_list(items: list | tuple) -> list:
    out: list = []
    skip_next = False
    # Argv-shape detection: when the leading token is a credential-family
    # tool, mark indices whose values should be redacted as short-flag
    # credentials (`-p`/`-H`/`-w`/`-u`/`-U`). Without this, a structured
    # ``args = ["hydra", "-p", "hunter2", ...]`` payload bypasses the
    # short-flag redactors that only run on scalar command strings
    # (ADR-029 / codex review cycle 3, finding 2).
    items_list = list(items)
    leading = items_list[0] if items_list and isinstance(items_list[0], str) else ""
    modes = _argv_credential_modes(leading) if leading else {
        "cred": False, "hash": False, "ldap": False, "basic": False,
    }
    short_flag_skip = _argv_short_flag_skip_indices(items_list, modes)
    for idx, item in enumerate(items_list):
        if skip_next:
            out.append(REDACTED)
            skip_next = False
            continue
        if idx in short_flag_skip:
            out.append(REDACTED)
            continue
        out.append(redact(item))
        # Pair-form CLI args: ["--password", "hunter2"]. If this string is
        # a long-flag whose name is sensitive AND the next element is a
        # plain string, redact the next element as the value-of-flag.
        if (
            isinstance(item, str)
            and _CLI_FLAG_TOKEN_RE.match(item)
            and idx + 1 < len(items_list)
            and isinstance(items_list[idx + 1], str)
        ):
            skip_next = True
    return out


def redact(value: Any) -> Any:
    """Return a JSON-serialization-safe copy of ``value``.

    Recurses through dicts, lists, and tuples (tuples normalize to lists
    so the result is JSON-compatible). Replaces values whose containing
    key is sensitive with the marker ``[REDACTED]``. String values are
    scanned for embedded credentials: JSON-encoded payloads are parsed
    and recursively redacted; plain-text payloads are scanned for inline
    ``Authorization:``, ``Bearer``, ``<sensitive_key>=value``,
    ``--<sensitive_key> value``, and the command-line credential forms
    (short ``-p`` passwords, ``-H`` NTLM hashes, ``-w`` LDAP bind
    passwords, ``--user``/``-u``/``-U`` Basic-auth and Samba
    ``user%pass``, impacket positional ``user:pass@host``). List
    traversal also catches ``["--password", "hunter2"]`` pair-form CLI
    args.

    Pure: never mutates the input.

    Does NOT consult ``APTL_EXPERIMENT_NO_REDACT`` (codex pre-push
    cycle 3 finding-9). The experiment toggle is scoped to the local
    per-run capture sinks only; callers that want experimental-record
    semantics check :func:`experiment_no_redact_active` themselves
    before invoking ``redact``. This keeps OTel/Tempo, runstore,
    snapshot, and stderr boundaries redacted at all times regardless
    of the toggle.
    """
    if isinstance(value, dict):
        return {
            k: REDACTED if _is_sensitive_key(str(k)) else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return _redact_list(value)
    if isinstance(value, str):
        return _redact_string(value)
    return value
