"""Rootless host-user separation for prompt-free desktop access."""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from aptl.appliance.seat.namespace import enter_private_network, private_desktop
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint


def test_only_single_new_desktop_publication_gets_private_network() -> None:
    desktop = BoundaryEndpoint(
        audience="participant", address="127.0.0.1", port=18080,
        protocol="tcp", guest_address="127.0.0.1", guest_port=8080,
    )
    assert private_desktop((desktop,))
    assert not private_desktop((desktop, desktop))
    assert not private_desktop((desktop.model_copy(update={"guest_port": 443}),))


def test_namespace_entry_requires_same_host_account() -> None:
    with (
        patch("aptl.appliance.seat.namespace.in_private_network", return_value=True),
        patch("aptl.appliance.seat.namespace.Path.stat", return_value=SimpleNamespace(st_uid=1000)),
        patch("aptl.appliance.seat.namespace.os.getuid", return_value=1000),
    ):
        assert enter_private_network(5151) == (
            "nsenter", "--target", "5151", "--user", "--net",
            "--preserve-credentials", "--",
        )

    with (
        patch("aptl.appliance.seat.namespace.in_private_network", return_value=True),
        patch("aptl.appliance.seat.namespace.Path.stat", return_value=SimpleNamespace(st_uid=2000)),
        patch("aptl.appliance.seat.namespace.os.getuid", return_value=1000),
        pytest.raises(ValueError, match="another host account"),
    ):
        enter_private_network(5151)


def test_prompt_free_desktop_port_is_unreachable_outside_user_namespace() -> None:
    if not shutil.which("bwrap") or not shutil.which("nsenter"):
        pytest.skip("rootless network namespace tools are unavailable")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(
        ["bwrap", "--unshare-net", "--dev-bind", "/", "/",
         sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        child = None
        for _ in range(40):
            children = subprocess.run(
                ["pgrep", "-P", str(process.pid)], capture_output=True, text=True,
            ).stdout.strip().splitlines()
            if children:
                child = int(children[0])
                break
            time.sleep(0.05)
        if child is None:
            pytest.skip("rootless network namespace is unavailable")
        prefix = enter_private_network(child)
        for _ in range(40):
            result = subprocess.run(
                [*prefix, sys.executable, "-c",
                 "import urllib.request,sys; assert urllib.request.urlopen(sys.argv[1],timeout=2).status == 200",
                 f"http://127.0.0.1:{port}/"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                break
            time.sleep(0.05)
        assert result.returncode == 0
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.5)
    finally:
        process.terminate()
        process.wait(timeout=5)
