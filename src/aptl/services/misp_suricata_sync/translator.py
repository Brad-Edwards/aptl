"""Translate MISP attributes into Suricata-compatible alert rules.

Pure module: no I/O, no MISP polling, no Suricata reload — just deterministic
rendering. ADR-019 invariant: action is always ``alert``.
"""

from __future__ import annotations

import zlib
from typing import Iterable

from aptl.services.misp_suricata_sync.models import (
    MispAttribute,
    RenderedRule,
    TranslationResult,
)
from aptl.utils.logging import get_logger

log = get_logger("misp_suricata_sync")

# Bytes safe to splice into a Suricata ``content:"..."`` directive without
# escaping. Anything outside this set becomes ``|XX|`` hex.
_CONTENT_SAFE = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/?=&"
)
_SID_OFFSET_MASK = 0x7FFFFFF

# Suricata file-hash keyword per MISP attribute type.
_HASH_KEYWORDS: dict[str, str] = {
    "md5": "filemd5",
    "sha1": "filesha1",
    "sha256": "filesha256",
}


def _crc32_sid_offset(type_: str, value: str) -> int:
    return zlib.crc32(f"{type_}|{value}".encode()) & _SID_OFFSET_MASK


def _escape_content(value: str) -> str:
    out: list[str] = []
    for byte in value.encode("utf-8", "replace"):
        if byte in _CONTENT_SAFE:
            out.append(chr(byte))
        else:
            out.append(f"|{byte:02X}|")
    return "".join(out)


def _split_url(url: str) -> tuple[str, str]:
    """Return ``(host, path)`` for a URL. Path is empty if URL has no path."""
    rest = url.split("://", 1)[-1]
    slash = rest.find("/")
    if slash == -1:
        return rest, ""
    return rest[:slash], rest[slash:]


def _hash_list_path(rules_out_dir: str, hash_type: str) -> str:
    return f"{rules_out_dir.rstrip('/')}/misp-{hash_type}.list"


class IocTranslator:
    """Render MISP attributes as Suricata rule strings."""

    def __init__(self, sid_base: int, rules_out_dir: str) -> None:
        self._sid_base = sid_base
        self._rules_out_dir = rules_out_dir

    def translate(self, attrs: Iterable[MispAttribute]) -> TranslationResult:
        # Stable order: sort by (type, value) so output is deterministic
        # regardless of MISP response ordering.
        ordered = sorted(attrs, key=lambda a: (a.type, a.value))

        seen_sids: set[int] = set()
        inline_rules: list[RenderedRule] = []
        hash_lists: dict[str, list[str]] = {ht: [] for ht in _HASH_KEYWORDS}

        for attr in ordered:
            if attr.type in _HASH_KEYWORDS:
                # Aggregated rule emitted later; just collect the digest.
                hash_lists[attr.type].append(attr.value)
                continue

            sid = self._sid_base + _crc32_sid_offset(attr.type, attr.value)
            if sid in seen_sids:
                log.warning(
                    "SID collision at %d for %s=%s; dropping duplicate",
                    sid, attr.type, attr.value,
                )
                continue
            text = self._render_inline(attr, sid)
            if text is None:
                continue
            seen_sids.add(sid)
            inline_rules.append(
                RenderedRule(
                    sid=sid,
                    attribute_type=attr.type,
                    attribute_value=attr.value,
                    text=text,
                )
            )

        # One rule per non-empty hash type, referencing its sidecar list.
        for hash_type, values in hash_lists.items():
            if not values:
                continue
            sid = self._sid_base + _crc32_sid_offset(
                "_hash_list", hash_type
            )
            if sid in seen_sids:
                log.warning(
                    "SID collision at %d for hash list %s; skipping rule",
                    sid, hash_type,
                )
                continue
            seen_sids.add(sid)
            keyword = _HASH_KEYWORDS[hash_type]
            list_path = _hash_list_path(self._rules_out_dir, hash_type)
            msg = _escape_content(f"APTL MISP IOC {hash_type} (list)")
            text = (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; flow:established; file.data; '
                f'{keyword}:{list_path}; sid:{sid}; rev:1;)'
            )
            inline_rules.append(
                RenderedRule(
                    sid=sid,
                    attribute_type=hash_type,
                    attribute_value=list_path,
                    text=text,
                )
            )

        # Strip empty hash-type entries so callers only iterate the ones
        # they need to write.
        hash_lists = {ht: sorted(set(v)) for ht, v in hash_lists.items() if v}

        return TranslationResult(rules=inline_rules, hash_lists=hash_lists)

    def _render_inline(self, attr: MispAttribute, sid: int) -> str | None:
        meta = (
            f"; metadata:misp_event_id {attr.event_id}"
            if attr.event_id and attr.event_id.strip()
            else ""
        )
        type_ = attr.type
        value = attr.value

        if type_ == "ip-src":
            msg = _escape_content(f"APTL MISP IOC ip-src: {value}")
            return (
                f'alert ip {value} any -> any any '
                f'(msg:"{msg}"; sid:{sid}; rev:1{meta};)'
            )

        if type_ == "ip-dst":
            msg = _escape_content(f"APTL MISP IOC ip-dst: {value}")
            return (
                f'alert ip any any -> {value} any '
                f'(msg:"{msg}"; sid:{sid}; rev:1{meta};)'
            )

        if type_ in ("domain", "hostname"):
            content = _escape_content(value)
            msg = _escape_content(f"APTL MISP IOC domain: {value}")
            return (
                f'alert dns any any -> any any '
                f'(msg:"{msg}"; dns.query; content:"{content}"; nocase; '
                f'sid:{sid}; rev:1{meta};)'
            )

        if type_ == "url":
            host, path = _split_url(value)
            if not host:
                log.warning("URL IOC %r has no host; skipping", value)
                return None
            host_content = _escape_content(host)
            parts = [
                f'alert http any any -> any any (msg:"',
                _escape_content(f"APTL MISP IOC url: {value}"),
                f'"; http.host; content:"{host_content}"; nocase',
            ]
            if path and path != "/":
                path_content = _escape_content(path)
                parts.append(
                    f'; http.uri; content:"{path_content}"; nocase'
                )
            parts.append(f"; sid:{sid}; rev:1{meta};)")
            return "".join(parts)

        log.warning("Unsupported MISP IOC type %r; skipping", type_)
        return None


def render_rules_file(
    rules: list[RenderedRule],
    *,
    misp_url: str,
    tag_filter: str,
    sid_base: int,
) -> str:
    """Render the full rule file (header comment + body).

    The header is intentionally timestamp-free so identical IOC sets
    produce byte-identical output across syncs (idempotency requirement
    for :class:`RuleFileWriter`).
    """
    header_lines = [
        "# APTL MISP-to-Suricata sync — generated, do not edit by hand.",
        "# All rules are 'alert' per ADR-019 (Suricata IDS-only).",
        f"# misp_url={misp_url}",
        f"# tag_filter={tag_filter}",
        f"# sid_base={sid_base}",
        f"# ioc_count={len(rules)}",
        "",
    ]
    body = [r.text for r in rules]
    return "\n".join(header_lines + body) + ("\n" if body else "")


def render_hash_list_file(hash_type: str, digests: list[str]) -> str:
    """Render the Suricata hash-list sidecar file content."""
    body_lines = [
        f"# APTL MISP-to-Suricata sync — {hash_type} hash list, generated.",
        "# One hash per line; loaded by Suricata via the corresponding "
        "file-hash rule in misp-iocs.rules.",
    ]
    body_lines.extend(sorted(set(digests)))
    return "\n".join(body_lines) + "\n"
