"""Behavioral checks for the namespace-scoped appliance boundary probe."""

import importlib.util
import socket
import threading
from pathlib import Path


PROBE = (
    Path(__file__).parents[1] / "containers" / "network-boundary-helper" / "probe.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("network_boundary_probe", PROBE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_probe_listener_proves_a_real_tcp_connection() -> None:
    probe = _module()
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()
    result: list[int] = []
    listener = threading.Thread(
        target=lambda: result.append(probe._listen("127.0.0.1", port, 2.0))
    )
    listener.start()
    for _attempt in range(100):
        if probe._connect("127.0.0.1", port, 0.05) == 0:
            break
    listener.join(timeout=3)

    assert result == [0]


def test_probe_connect_fails_when_no_target_is_listening() -> None:
    probe = _module()
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()

    assert probe._connect("127.0.0.1", port, 0.05) == 1
