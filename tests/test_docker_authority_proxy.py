"""Issue #912: the mediated Docker authority actually refuses what it must.

The proxy is the authorization boundary for a `host_root_equivalent` authority,
so these tests run the real script against a stub daemon and assert on what
reached that daemon. A policy that is only inspected, never exercised, is not
an authorization boundary.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

PROXY = (
    Path(__file__).resolve().parents[1]
    / "containers/docker-authority-proxy/proxy.py"
)
ADMITTED = "ghcr.io/shuffle/shuffle-worker@sha256:" + "f" * 64
OTHER = "ghcr.io/shuffle/shuffle-worker@sha256:" + "e" * 64


class _StubDaemon:
    """A unix-socket HTTP server recording everything that reached it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.received: list[bytes] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        with connection:
            try:
                data = connection.recv(65536)
            except OSError:
                return
            if data:
                self.received.append(data)
            body = b'{"Id":"stub"}'
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )

    def close(self) -> None:
        self._server.close()


class _Client:
    """Issue one request through the mediated socket."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def request(self, method: str, target: str, body: object = None):
        connection = http.client.HTTPConnection("localhost")
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(10)
        connection.sock.connect(str(self.path))
        payload = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"} if payload else {}
        connection.request(method, target, body=payload, headers=headers)
        response = connection.getresponse()
        text = response.read().decode()
        connection.close()
        return response.status, text


@pytest.fixture
def authority(tmp_path):
    """Run the real proxy in front of a stub daemon."""

    upstream = tmp_path / "upstream.sock"
    mediated = tmp_path / "mediated.sock"
    daemon = _StubDaemon(upstream)
    process = subprocess.Popen(
        [sys.executable, str(PROXY)],
        env={
            **os.environ,
            "APTL_DOCKER_AUTHORITY_SOCKET": str(mediated),
            "APTL_DOCKER_AUTHORITY_UPSTREAM": str(upstream),
            "APTL_DOCKER_AUTHORITY_IMAGES": ADMITTED,
        },
        stderr=subprocess.PIPE,
    )
    for _ in range(100):
        if mediated.exists():
            break
        time.sleep(0.05)
    assert mediated.exists(), "the mediated socket never appeared"
    try:
        yield _Client(mediated), daemon
    finally:
        process.terminate()
        process.wait(timeout=10)
        daemon.close()


def _create(image: str, host_config: dict | None = None) -> dict:
    payload: dict = {"Image": image, "Cmd": ["true"]}
    if host_config is not None:
        payload["HostConfig"] = host_config
    return payload


def test_an_admitted_image_with_safe_options_reaches_the_daemon(authority):
    client, daemon = authority

    status, _text = client.request(
        "POST", "/v1.44/containers/create?name=worker", _create(ADMITTED)
    )

    assert status == 200
    assert len(daemon.received) == 1


@pytest.mark.parametrize(
    ("label", "host_config"),
    [
        ("host filesystem bind", {"Binds": ["/:/host"]}),
        (
            "socket remount",
            {
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": "/var/run/docker.sock",
                        "Target": "/var/run/docker.sock",
                    }
                ]
            },
        ),
        ("privileged", {"Privileged": True}),
        ("added capability", {"CapAdd": ["SYS_ADMIN"]}),
        ("host devices", {"Devices": [{"PathOnHost": "/dev/sda"}]}),
        ("host network", {"NetworkMode": "host"}),
        ("joining another container", {"NetworkMode": "container:aptl-misp"}),
        ("host pid namespace", {"PidMode": "host"}),
        ("host ipc namespace", {"IpcMode": "host"}),
        ("relaxed seccomp", {"SecurityOpt": ["seccomp=unconfined"]}),
        ("host port publication", {"PublishAllPorts": True}),
    ],
)
def test_an_admitted_image_cannot_be_given_host_access(authority, label, host_config):
    """The digest is not the whole contract.

    Pre-pulling the declared image constrains nothing if that image can then be
    created with a host bind or `Privileged`, which is the gap post-hoc
    `ancestor=` observation cannot close either.
    """

    client, daemon = authority

    status, text = client.request(
        "POST", "/v1.44/containers/create", _create(ADMITTED, host_config)
    )

    assert status == 403, label
    assert "aptl docker authority" in text
    assert daemon.received == [], f"{label} reached the daemon"


@pytest.mark.parametrize("image", [OTHER, "alpine:latest", "", None, 42])
def test_an_image_outside_the_admitted_set_never_reaches_the_daemon(authority, image):
    client, daemon = authority
    payload = {"Cmd": ["true"]} if image is None else {"Image": image, "Cmd": ["true"]}

    status, _text = client.request("POST", "/v1.44/containers/create", payload)

    assert status == 403
    assert daemon.received == []


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("POST", "/v1.44/containers/abc/exec"),
        ("POST", "/v1.44/exec/abc/start"),
        ("POST", "/v1.44/images/create?fromImage=alpine"),
        ("POST", "/v1.44/commit"),
        ("POST", "/v1.44/build"),
        ("POST", "/v1.44/volumes/create"),
        ("POST", "/v1.44/networks/create"),
        ("DELETE", "/v1.44/networks/aptl-security"),
        ("POST", "/v1.44/swarm/init"),
        ("GET", "/v1.44/containers/abc/archive"),
        ("PUT", "/v1.44/containers/abc/archive"),
        ("POST", "/v1.44/containers/abc/update"),
    ],
)
def test_an_unrouted_endpoint_never_reaches_the_daemon(authority, method, target):
    """Deny by default: an orchestrator needs a small, named set of calls.

    `exec` and `archive` would let the workload run commands in, or write files
    into, containers it did not create; `build` and `commit` would let it mint
    an image outside the admitted set and then create from it.
    """

    client, daemon = authority

    status, _text = client.request(method, target)

    assert status == 403
    assert daemon.received == []


def test_the_routed_read_endpoints_still_work(authority):
    """A boundary that blocks the orchestrator's own reads is not usable."""

    client, daemon = authority

    for method, target in (
        ("GET", "/_ping"),
        ("GET", "/v1.44/version"),
        ("GET", "/v1.44/containers/json"),
        ("GET", "/v1.44/containers/abc/json"),
        ("POST", "/v1.44/containers/abc/start"),
        ("POST", "/v1.44/containers/abc/wait"),
        ("DELETE", "/v1.44/containers/abc"),
    ):
        status, _text = client.request(method, target)
        assert status == 200, f"{method} {target}"
    assert len(daemon.received) == 7


def test_a_body_the_boundary_cannot_evaluate_is_refused(authority):
    """Fail closed: an unparsed create is an unauthorized create."""

    client, daemon = authority
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    connection.connect(str(client.path))
    connection.sendall(
        b"POST /v1.44/containers/create HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
    )
    status_line = connection.recv(64)
    connection.close()

    assert b"403" in status_line
    assert daemon.received == []


def test_the_admitted_set_is_the_only_source_of_permitted_images(tmp_path):
    """An authority with no admitted images may create nothing at all."""

    upstream = tmp_path / "upstream.sock"
    mediated = tmp_path / "mediated.sock"
    daemon = _StubDaemon(upstream)
    process = subprocess.Popen(
        [sys.executable, str(PROXY)],
        env={
            **os.environ,
            "APTL_DOCKER_AUTHORITY_SOCKET": str(mediated),
            "APTL_DOCKER_AUTHORITY_UPSTREAM": str(upstream),
            "APTL_DOCKER_AUTHORITY_IMAGES": "",
        },
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if mediated.exists():
                break
            time.sleep(0.05)
        status, _text = _Client(mediated).request(
            "POST", "/v1.44/containers/create", _create(ADMITTED)
        )
    finally:
        process.terminate()
        process.wait(timeout=10)
        daemon.close()

    assert status == 403
    assert daemon.received == []
