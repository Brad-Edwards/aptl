"""Translate MISP attributes into Suricata-compatible alert rules.

Pure module: no I/O, no MISP polling, no Suricata reload — just deterministic
rendering. ADR-019 invariant: action is always ``alert``.
"""

from __future__ import annotations

import zlib
from datetime import datetime, timezone
from typing import Iterable

from aptl.services.misp_suricata_sync.models import MispAttribute, RenderedRule
from aptl.utils.logging import get_logger

log = get_logger("misp_suricata_sync")

# Bytes safe to splice into a Suricata ``content:"..."`` directive without
# escaping. Anything outside this set becomes ``|XX|`` hex.
_CONTENT_SAFE = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/?=&"
)
_SID_OFFSET_MASK = 0x7FFFFFF


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


def _url_path(url: str) -> str:
    """Extract the path-and-query portion of a URL; default to ``/``."""
    rest = url.split("://", 1)[-1]
    slash = rest.find("/")
    if slash == -1:
        return "/"
    path = rest[slash:]
    return path or "/"


class IocTranslator:
    """Render MISP attributes as Suricata rule strings."""

    def __init__(self, sid_base: int) -> None:
        self._sid_base = sid_base

    def translate(self, attrs: Iterable[MispAttribute]) -> list[RenderedRule]:
        # Stable order: sort by (type, value) so output is deterministic
        # regardless of MISP response ordering.
        ordered = sorted(attrs, key=lambda a: (a.type, a.value))

        seen_sids: set[int] = set()
        rules: list[RenderedRule] = []
        for attr in ordered:
            sid = self._sid_base + _crc32_sid_offset(attr.type, attr.value)
            if sid in seen_sids:
                log.warning(
                    "SID collision at %d for %s=%s; dropping duplicate",
                    sid, attr.type, attr.value,
                )
                continue
            text = self._render(attr, sid)
            if text is None:
                continue
            seen_sids.add(sid)
            rules.append(
                RenderedRule(
                    sid=sid,
                    attribute_type=attr.type,
                    attribute_value=attr.value,
                    text=text,
                )
            )
        return rules

    def _render(self, attr: MispAttribute, sid: int) -> str | None:
        meta = (
            f"; metadata:misp_event_id {attr.event_id}"
            if attr.event_id and attr.event_id.strip()
            else ""
        )
        type_ = attr.type
        value = attr.value

        if type_ in ("ip-src", "ip-dst"):
            msg = _escape_content(f"APTL MISP IOC {type_}: {value}")
            return (
                f'alert ip {value} any -> any any '
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
            path = _url_path(value)
            content = _escape_content(path)
            msg = _escape_content(f"APTL MISP IOC url: {value}")
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; http.uri; content:"{content}"; nocase; '
                f'sid:{sid}; rev:1{meta};)'
            )

        if type_ in ("sha256", "sha1", "md5"):
            keyword = {
                "sha256": "filesha256",
                "sha1": "filesha1",
                "md5": "filemd5",
            }[type_]
            content = _escape_content(value)
            msg = _escape_content(f"APTL MISP IOC {type_}: {value}")
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; {keyword}; content:"{content}"; '
                f'sid:{sid}; rev:1{meta};)'
            )

        log.warning("Unsupported MISP IOC type %r; skipping", type_)
        return None


def render_rules_file(
    rules: list[RenderedRule],
    *,
    misp_url: str,
    tag_filter: str,
    sid_base: int,
    now: datetime | None = None,
) -> str:
    """Render the full rule file (header comment + body)."""
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    header_lines = [
        "# APTL MISP-to-Suricata sync — generated, do not edit by hand.",
        "# All rules are 'alert' per ADR-019 (Suricata IDS-only).",
        f"# generated_at={timestamp}",
        f"# misp_url={misp_url}",
        f"# tag_filter={tag_filter}",
        f"# sid_base={sid_base}",
        f"# ioc_count={len(rules)}",
        "",
    ]
    body = [r.text for r in rules]
    return "\n".join(header_lines + body) + ("\n" if body else "")
