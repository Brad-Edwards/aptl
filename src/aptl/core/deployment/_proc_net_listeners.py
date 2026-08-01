"""Parse the kernel's per-netns socket tables into trusted listener facts.

The RAES realization observer reads a node's service listeners from OUTSIDE the
container's trust boundary (issue #876 security review): a sidecar that joins the
target's network namespace reads ``/proc/net/{tcp,tcp6,udp,udp6,unix}`` with its
own trusted binary, and this module turns that raw kernel output into
``(protocol, address, port)`` triples plus the set of bound pathname unix-socket
paths. The target's filesystem and binaries are never consulted, so a workload
that shadows ``ss``/``test`` cannot change the attested result.

The reader concatenates the five files behind ``@@<name>`` markers so one sidecar
run yields all of them; :func:`parse_proc_net_listeners` splits on those markers.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

# The sidecar labels each file with this marker so a single concatenated read can
# be split back into per-file sections.
SECTION_MARKER = "@@"
# One shell reader, portable to any base image with ``sh`` + ``cat``.
PROC_NET_READER = (
    'for f in tcp tcp6 udp udp6 unix; do '
    'echo "' + SECTION_MARKER + '$f"; cat /proc/net/$f 2>/dev/null; done'
)

# Kernel TCP_LISTEN state in /proc/net/tcp{,6}.
_TCP_LISTEN = "0A"


@dataclass(frozen=True)
class ContainerListeners:
    """Listener state observed from outside a container's trust boundary.

    ``sockets`` are ``(protocol, address, port)`` triples where ``protocol`` is
    ``"tcp"`` or ``"udp"`` and ``address`` is a canonical textual form (e.g.
    ``"0.0.0.0"``, ``"::"``, ``"127.0.0.1"``). ``unix_socket_paths`` are the bound
    pathname unix sockets present in the namespace.
    """

    sockets: tuple[tuple[str, str, int], ...] = ()
    unix_socket_paths: frozenset[str] = field(default_factory=frozenset)


def parse_proc_net_listeners(text: str) -> ContainerListeners:
    """Parse marked ``/proc/net/*`` output into trusted listener facts."""

    sections = _split_sections(text)
    sockets: list[tuple[str, str, int]] = []
    for name in ("tcp", "tcp6"):
        sockets.extend(_parse_inet(sections.get(name, ""), "tcp", listen_only=True))
    for name in ("udp", "udp6"):
        # A bound UDP socket has no LISTEN state; its mere presence is the
        # listener, so every parsed entry is kept.
        sockets.extend(_parse_inet(sections.get(name, ""), "udp", listen_only=False))
    unix_paths = _parse_unix(sections.get("unix", ""))
    return ContainerListeners(
        sockets=tuple(sockets), unix_socket_paths=frozenset(unix_paths)
    )


def _split_sections(text: str) -> dict[str, str]:
    """Split concatenated reader output into ``{file_name: body}``."""

    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith(SECTION_MARKER):
            current = line[len(SECTION_MARKER):].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def _parse_inet(
    text: str, protocol: str, *, listen_only: bool
) -> list[tuple[str, str, int]]:
    """Parse one ``/proc/net/{tcp,tcp6,udp,udp6}`` body into listener triples."""

    out: list[tuple[str, str, int]] = []
    for line in text.splitlines():
        fields = line.split()
        # Row shape: ``sl local_address rem_address st ...``; skip the header and
        # any short/malformed row.
        if len(fields) < 4 or fields[0] == "sl" or ":" not in fields[1]:
            continue
        if listen_only and fields[3].upper() != _TCP_LISTEN:
            continue
        addr_hex, _, port_hex = fields[1].rpartition(":")
        address = _decode_hex_address(addr_hex)
        if address is None:
            continue
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        out.append((protocol, address, port))
    return out


def _decode_hex_address(addr_hex: str) -> str | None:
    """Decode a ``/proc/net`` hex address into canonical textual form.

    IPv4 is a single little-endian 32-bit word; IPv6 is four little-endian 32-bit
    words. Bytes within each word are reversed before ``inet_ntop`` so a wildcard
    bind renders ``0.0.0.0`` / ``::`` and a loopback bind ``127.0.0.1`` / ``::1``.
    """

    try:
        if len(addr_hex) == 8:
            return socket.inet_ntop(socket.AF_INET, bytes.fromhex(addr_hex)[::-1])
        if len(addr_hex) == 32:
            words = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
            packed = b"".join(bytes.fromhex(word)[::-1] for word in words)
            return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, OSError):
        return None
    return None


def _parse_unix(text: str) -> set[str]:
    """Return the bound pathname unix-socket paths in ``/proc/net/unix``.

    Only pathname sockets carry a trailing path column; unnamed and abstract
    sockets are skipped, so the header row (whose last column is ``Path``) and
    short rows are excluded by the same path-shape test.
    """

    paths: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        path = fields[-1]
        if path.startswith("/"):
            paths.add(path)
    return paths
