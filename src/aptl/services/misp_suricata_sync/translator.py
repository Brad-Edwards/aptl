"""Translate MISP attributes into Suricata-compatible alert rules.

Pure module: no I/O, no MISP polling, no Suricata reload — just deterministic
rendering. ADR-019 invariant: action is always ``alert``.
"""

from __future__ import annotations

import ipaddress
import re
import zlib
from typing import Callable, Iterable
from urllib.parse import urlparse

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
# 24-bit mask gives ~16M slots so the birthday-paradox collision rate
# stays low for realistic IOC counts (≤ 1000 IOCs ⇒ < 0.003% per pair,
# ≤ 100k IOCs ⇒ ~30%). Combined with `SID_BASE = 99_000_000` (default)
# this lands the generated range entirely outside Suricata's bundled
# ET Open (2.x million range) and any sane operator-authored band.
_SID_OFFSET_MASK = 0xFFFFFF
_SID_OFFSET_RANGE = _SID_OFFSET_MASK + 1

# Suricata file-hash keyword per MISP attribute type, plus expected digest
# length in hex characters.
_HASH_KEYWORDS: dict[str, str] = {
    "md5": "filemd5",
    "sha1": "filesha1",
    "sha256": "filesha256",
}
# Public tuple consumers iterate over so they always touch every hash
# type (even when MISP currently has zero IOCs of that type) and don't
# leave a stale sidecar behind when the last IOC of a type is removed.
HASH_TYPES = tuple(_HASH_KEYWORDS)
_HASH_HEX_LENGTHS: dict[str, int] = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_NUMERIC_RE = re.compile(r"^[0-9]+$")


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


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _is_valid_hash(hash_type: str, value: str) -> bool:
    expected_len = _HASH_HEX_LENGTHS[hash_type]
    return len(value) == expected_len and bool(_HEX_RE.match(value))


def _split_url(url: str) -> tuple[str, str, str]:
    """Return ``(scheme, host, path-with-query)`` from a URL.

    Uses :mod:`urllib.parse` so credentials, ports, fragments, query-only
    URLs, and IPv6 hosts all parse correctly. Host is lowercased and
    stripped of any user-info / port. Path includes the query string when
    present so URL IOCs that vary only by query parameter still match.
    Schemeless inputs default to ``http`` so they continue to match
    plaintext HTTP traffic.
    """
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host, path


def _hash_list_rule_arg(hash_type: str) -> str:
    """Path embedded in a Suricata file-hash rule directive.

    Relative to Suricata's ``default-rule-path`` per the documented
    behavior of ``filemd5`` / ``filesha1`` / ``filesha256``. The lab's
    suricata.yaml mounts the misp directory at
    ``/var/lib/suricata/rules/misp`` (i.e. under default-rule-path), so
    a relative path resolves correctly. The on-disk write path is
    independent and lives in :class:`ServiceConfig.rules_out_path`.
    """
    return f"misp/misp-{hash_type}.list"


def _event_id_metadata(attr: MispAttribute) -> str:
    """Render the optional ``metadata:misp_event_id N`` directive.

    Splices a numeric ``event_id`` into rule metadata when present;
    drops malformed values with a warning so they cannot inject syntax
    into the rule file (which would break the next Suricata reload).
    """
    if not attr.event_id or not attr.event_id.strip():
        return ""
    ev = attr.event_id.strip()
    if _NUMERIC_RE.match(ev):
        return f"; metadata:misp_event_id {ev}"
    log.warning(
        "Ignoring non-numeric event_id %r on %s=%s",
        attr.event_id, attr.type, attr.value,
    )
    return ""


def _render_ip_src(value: str, sid: int, meta: str) -> str | None:
    if not _is_valid_ip(value):
        log.warning("Skipping malformed ip-src value %r", value)
        return None
    value = value.strip()
    msg = _escape_content(f"APTL MISP IOC ip-src: {value}")
    return (
        f'alert ip {value} any -> any any '
        f'(msg:"{msg}"; sid:{sid}; rev:1{meta};)'
    )


def _render_ip_dst(value: str, sid: int, meta: str) -> str | None:
    if not _is_valid_ip(value):
        log.warning("Skipping malformed ip-dst value %r", value)
        return None
    value = value.strip()
    msg = _escape_content(f"APTL MISP IOC ip-dst: {value}")
    return (
        f'alert ip any any -> {value} any '
        f'(msg:"{msg}"; sid:{sid}; rev:1{meta};)'
    )


def _render_domain(value: str, sid: int, meta: str) -> str | None:
    content = _escape_content(value)
    msg = _escape_content(f"APTL MISP IOC domain: {value}")
    # ``dotprefix`` anchors the left side (start of buffer or preceded
    # by a dot); ``endswith`` anchors the right side. Together they
    # cover exact + subdomain matches without false positives like
    # "bad.com.evil".
    return (
        f'alert dns any any -> any any '
        f'(msg:"{msg}"; dns.query; content:"{content}"; nocase; '
        f'dotprefix; endswith; sid:{sid}; rev:1{meta};)'
    )


def _render_url(value: str, sid: int, meta: str) -> str | None:
    scheme, host, path = _split_url(value)
    if not host:
        log.warning("URL IOC %r has no host; skipping", value)
        return None
    host_content = _escape_content(host)
    msg = _escape_content(f"APTL MISP IOC url: {value}")
    if scheme == "https":
        # HTTPS URI is encrypted; SNI is the only field a passive IDS
        # can see, so match that instead of emitting a dead http rule.
        return (
            f'alert tls any any -> any any '
            f'(msg:"{msg}"; tls.sni; content:"{host_content}"; '
            f'nocase; dotprefix; endswith; sid:{sid}; rev:1{meta};)'
        )
    parts = [
        'alert http any any -> any any (msg:"',
        msg,
        f'"; http.host; content:"{host_content}"; nocase; '
        f"dotprefix; endswith",
    ]
    if path and path != "/":
        parts.append(
            f'; http.uri; content:"{_escape_content(path)}"; nocase'
        )
    parts.append(f"; sid:{sid}; rev:1{meta};)")
    return "".join(parts)


# Per-type renderer signature: (value, sid, meta) -> rule text or None.
_Renderer = Callable[[str, int, str], "str | None"]

# Dispatch table for inline renderers, keyed by MISP attribute type.
# Hash types are aggregated separately and rendered in the translator's
# main loop, so they do not appear here.
_RENDERERS: dict[str, _Renderer] = {
    "ip-src": _render_ip_src,
    "ip-dst": _render_ip_dst,
    "domain": _render_domain,
    "hostname": _render_domain,
    "url": _render_url,
}


class IocTranslator:
    """Render MISP attributes as Suricata rule strings."""

    def __init__(self, sid_base: int) -> None:
        self._sid_base = sid_base

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
                if not _is_valid_hash(attr.type, attr.value):
                    log.warning(
                        "Skipping malformed %s digest %r (expected %d hex chars)",
                        attr.type,
                        attr.value,
                        _HASH_HEX_LENGTHS[attr.type],
                    )
                    continue
                hash_lists[attr.type].append(attr.value.lower())
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
            rule_arg = _hash_list_rule_arg(hash_type)
            msg = _escape_content(f"APTL MISP IOC {hash_type} (list)")
            text = (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; flow:established; file.data; '
                f'{keyword}:{rule_arg}; sid:{sid}; rev:1;)'
            )
            inline_rules.append(
                RenderedRule(
                    sid=sid,
                    attribute_type=hash_type,
                    attribute_value=rule_arg,
                    text=text,
                )
            )

        # Strip empty hash-type entries so callers only iterate the ones
        # they need to write.
        hash_lists = {ht: sorted(set(v)) for ht, v in hash_lists.items() if v}

        return TranslationResult(rules=inline_rules, hash_lists=hash_lists)

    def _render_inline(self, attr: MispAttribute, sid: int) -> str | None:
        meta = _event_id_metadata(attr)
        renderer = _RENDERERS.get(attr.type)
        if renderer is None:
            log.warning("Unsupported MISP IOC type %r; skipping", attr.type)
            return None
        return renderer(attr.value, sid, meta)


def render_rules_file(
    rules: list[RenderedRule],
    *,
    misp_url: str,
    tag_filter: str,
    sid_base: int,
) -> str:
    """Render the full rule file (header comment + body).

    The header is intentionally timestamp-free so identical IOC sets
    produce byte-identical output across syncs — that's the
    idempotency contract :func:`aptl.services.misp_suricata_sync.rule_writer.write_if_changed`
    relies on to skip writes (and therefore Suricata reloads) when
    nothing has changed.
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
