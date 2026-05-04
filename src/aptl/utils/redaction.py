"""Shared redaction helper for serialization boundaries.

Run analysis artifacts (`snapshot.json`, OTel span attributes, exported
run archives) are not credential stores. Redact secret-shaped values at
the serialization boundary so file permissions and archive locations
remain defense in depth, not the only line of protection. See ADR-012,
Security Guardrail.
"""

from __future__ import annotations

import json
import re
from typing import Any

REDACTED = "[REDACTED]"

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
    r"api[_-]?key|apikey|jwt|bearer|session(?:_id)?)"
)
_AUTHORIZATION_RE = re.compile(
    r"(authorization\s*[:=]\s*)(?:([A-Za-z][A-Za-z0-9_-]*)\s+)?(\S+)",
    re.IGNORECASE,
)
_SENSITIVE_KV_RE = re.compile(
    rf"(\b{_SENSITIVE_KEY_PATTERN}\b\s*[=:]\s*)['\"]?[^'\"&\s,;|]+['\"]?",
    re.IGNORECASE,
)
_BARE_BEARER_RE = re.compile(r"(\bbearer\s+)\S+", re.IGNORECASE)
# `--password value` / `--token value` style (long CLI flags).
_CLI_FLAG_RE = re.compile(
    rf"(--{_SENSITIVE_KEY_PATTERN}\s+)\S+",
    re.IGNORECASE,
)
# Recognizes `--<sensitive>` as a standalone token (used by array-pair
# detection so adjacent positional values get redacted).
_CLI_FLAG_TOKEN_RE = re.compile(rf"^--{_SENSITIVE_KEY_PATTERN}$", re.IGNORECASE)


def _redact_authorization(match: "re.Match[str]") -> str:
    prefix, scheme, _value = match.group(1), match.group(2), match.group(3)
    if scheme:
        return f"{prefix}{scheme} {REDACTED}"
    return f"{prefix}{REDACTED}"


def _redact_string(value: str) -> str:
    # Try JSON.parse first — payloads like '{"password":"x"}' and the MCP
    # `content[].text` envelope (which wraps the real result in a JSON
    # string) need to be parsed, recursively redacted, and re-serialized.
    stripped = value.lstrip()
    if stripped and stripped[0] in "{[":
        try:
            parsed = json.loads(value)
        except (ValueError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return json.dumps(redact(parsed), separators=(",", ":"))
    out = _AUTHORIZATION_RE.sub(_redact_authorization, value)
    out = _SENSITIVE_KV_RE.sub(rf"\1{REDACTED}", out)
    out = _BARE_BEARER_RE.sub(rf"\1{REDACTED}", out)
    out = _CLI_FLAG_RE.sub(rf"\1{REDACTED}", out)
    return out


def _redact_list(items: list | tuple) -> list:
    out: list = []
    skip_next = False
    for idx, item in enumerate(items):
        if skip_next:
            out.append(REDACTED)
            skip_next = False
            continue
        out.append(redact(item))
        # Pair-form CLI args: ["--password", "hunter2"]. If this string is
        # a long-flag whose name is sensitive AND the next element is a
        # plain string, redact the next element as the value-of-flag.
        if (
            isinstance(item, str)
            and _CLI_FLAG_TOKEN_RE.match(item)
            and idx + 1 < len(items)
            and isinstance(items[idx + 1], str)
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
    ``Authorization:``, ``Bearer``, ``<sensitive_key>=value``, and
    ``--<sensitive_key> value`` patterns. List traversal also catches
    ``["--password", "hunter2"]`` pair-form CLI args.

    Pure: never mutates the input.
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
