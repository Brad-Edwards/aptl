"""Unit tests for the trusted ``/proc/net/*`` listener parser (issue #876).

The parser turns the kernel's per-netns socket tables -- read host-side by a
sidecar that never executes a container binary -- into the ``(protocol, address,
port)`` triples and bound unix-socket paths the realization observer corroborates
declared listeners against. These pin the hex decoding (wildcard vs concrete,
IPv4/IPv6, LISTEN-only for TCP) so a shadowed in-container ``ss`` can never be the
source of an attested value.
"""

from __future__ import annotations

from aptl.core.deployment._proc_net_listeners import (
    SECTION_MARKER,
    parse_proc_net_listeners,
)


def _section(name: str, *rows: str) -> str:
    return "\n".join([f"{SECTION_MARKER}{name}", *rows])


# Header rows exactly as the kernel prints them, so the parser's header skip is
# exercised against real column layouts.
_TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode"
)
_UNIX_HEADER = "Num       RefCount Protocol Flags    Type St Inode Path"


def test_ipv4_loopback_listen_socket_is_decoded():
    text = _section(
        "tcp",
        _TCP_HEADER,
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00 0 0 1 1",
    )
    result = parse_proc_net_listeners(text)
    assert ("tcp", "127.0.0.1", 8080) in result.sockets


def test_ipv4_wildcard_bind_decodes_to_all_interfaces():
    text = _section(
        "tcp",
        "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00 0 0 2 1",
    )
    result = parse_proc_net_listeners(text)
    assert ("tcp", "0.0.0.0", 80) in result.sockets


def test_non_listen_tcp_sockets_are_ignored():
    # State 01 == ESTABLISHED: not a listener, must not be reported.
    text = _section(
        "tcp",
        "   0: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00 0 0 3 1",
    )
    assert parse_proc_net_listeners(text).sockets == ()


def test_ipv6_wildcard_and_loopback_are_decoded():
    text = _section(
        "tcp6",
        "0: 00000000000000000000000000000000:1F90 "
        "00000000000000000000000000000000:0000 0A 0 0 0 1",
        "1: 00000000000000000000000001000000:0050 "
        "00000000000000000000000000000000:0000 0A 0 0 0 1",
    )
    sockets = parse_proc_net_listeners(text).sockets
    assert ("tcp", "::", 8080) in sockets
    assert ("tcp", "::1", 80) in sockets


def test_udp_socket_is_reported_regardless_of_state():
    # UDP has no LISTEN state; a bound socket (state 07) is the listener.
    text = _section(
        "udp",
        "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00 0 0 9 2",
    )
    assert ("udp", "0.0.0.0", 53) in parse_proc_net_listeners(text).sockets


def test_bound_pathname_unix_socket_path_is_collected():
    text = _section(
        "unix",
        _UNIX_HEADER,
        "0000000000000000: 00000002 00000000 00010000 0001 01 12345 /run/app.sock",
        # An unnamed socket carries no path column and must be skipped.
        "0000000000000000: 00000002 00000000 00010000 0001 01 12346",
    )
    result = parse_proc_net_listeners(text)
    assert result.unix_socket_paths == frozenset({"/run/app.sock"})


def test_unknown_sections_and_blank_input_are_empty():
    result = parse_proc_net_listeners("")
    assert result.sockets == ()
    assert result.unix_socket_paths == frozenset()
