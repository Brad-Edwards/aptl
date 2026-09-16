"""Unit tests for the trusted ``/proc/net/*`` listener parser (issue #876).

The parser turns the kernel's per-netns socket tables -- read host-side without
executing a container binary or adding an observer -- into the ``(protocol, address,
port)`` triples and bound unix-socket paths the realization observer corroborates
declared listeners against. These pin the hex decoding (wildcard vs concrete,
IPv4/IPv6, LISTEN-only for TCP) so a shadowed in-container ``ss`` can never be the
source of an attested value.
"""

from __future__ import annotations

import pytest

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


@pytest.fixture
def host_proc(tmp_path):
    container_id = "a1" * 32
    proc = tmp_path / "73"
    (proc / "net").mkdir(parents=True)
    # Fields after comm begin at field 3; field 22 binds process lifetime.
    (proc / "stat").write_text("73 (init) S " + "0 " * 18 + "456\n")
    (proc / "cgroup").write_text(f"0::/system.slice/docker-{container_id}.scope\n")
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (proc / "net" / name).write_text(_TCP_HEADER + "\n")
    (proc / "net" / "unix").write_text(_UNIX_HEADER + "\n")
    with (proc / "net" / "tcp").open("a") as stream:
        stream.write("0: 00000000:1F90 00000000:0000 0A 0 0 0 1\n")
    return tmp_path, {"Id": container_id, "State": {"Running": True, "Pid": 73}}


def test_native_host_readback_needs_no_added_observer(host_proc):
    from aptl.core.deployment._proc_net_listeners import read_container_listeners

    root, info = host_proc
    observed = read_container_listeners(info, proc_root=root)
    assert observed is not None
    assert ("tcp", "0.0.0.0", 8080) in observed.sockets


def test_pid_reuse_during_read_is_not_listener_evidence(host_proc, monkeypatch):
    from aptl.core.deployment import _proc_net_listeners as reader

    root, info = host_proc
    original = reader._bounded_read
    stat_reads = 0

    def read(path, limit):
        nonlocal stat_reads
        value = original(path, limit)
        if path.name == "stat":
            stat_reads += 1
            if stat_reads > 1:
                return value.replace("456", "789")
        return value

    monkeypatch.setattr(reader, "_bounded_read", read)
    assert reader.read_container_listeners(info, proc_root=root) is None


def test_missing_kernel_table_header_is_not_successful_empty_evidence(host_proc):
    from aptl.core.deployment._proc_net_listeners import read_container_listeners

    root, info = host_proc
    (root / "73/net/tcp").write_text("unavailable\n")
    assert read_container_listeners(info, proc_root=root) is None


def test_native_readback_bounds_total_bytes_across_tables(host_proc):
    from aptl.core.deployment._proc_net_listeners import read_container_listeners

    root, info = host_proc
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (root / "73/net" / name).write_text(_TCP_HEADER + "\n" + " " * (300 * 1024))
    assert read_container_listeners(info, proc_root=root) is None


@pytest.mark.parametrize(
    "defect", ["foreign-pid", "missing-table", "oversized", "stopped"]
)
def test_incomplete_or_wrong_host_namespace_is_not_listener_evidence(host_proc, defect):
    from aptl.core.deployment._proc_net_listeners import read_container_listeners

    root, info = host_proc
    if defect == "foreign-pid":
        (root / "73/cgroup").write_text("0::/system.slice/docker-foreign.scope\n")
    elif defect == "missing-table":
        (root / "73/net/tcp6").unlink()
    elif defect == "oversized":
        (root / "73/net/tcp").write_bytes(b"x" * (1024 * 1024 + 1))
    else:
        info["State"]["Running"] = False
    assert read_container_listeners(info, proc_root=root) is None


def test_backend_does_not_launch_a_sidecar_when_native_readback_is_unavailable(
    tmp_path, monkeypatch
):
    import subprocess
    from aptl.core.deployment.docker_compose import DockerComposeBackend

    backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl-test")
    commands = []
    monkeypatch.setattr(backend, "container_inspect", lambda name: {})

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(backend, "_run", run)
    assert backend.observe_container_listeners("aptl-target") is None
    assert commands == []
