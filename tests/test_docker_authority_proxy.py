"""Issue #912: the mediated Docker authority actually refuses what it must.

The proxy is the authorization boundary for a `host_root_equivalent` authority,
so these tests run the real script against a stub daemon and assert on what
reached that daemon. A policy that is only inspected, never exercised, is not
an authorization boundary.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

PROXY = (
    Path(__file__).resolve().parents[1] / "containers/docker-authority-proxy/proxy.py"
)
ADMITTED = "ghcr.io/shuffle/shuffle-worker@sha256:" + "f" * 64
OTHER = "ghcr.io/shuffle/shuffle-worker@sha256:" + "e" * 64
OWNER_LABEL = "org.aptl.docker-authority=managed"
ALLOWED_NETWORK = "aptl_aptl-security"


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
            request_line = data.split(b"\r\n", 1)[0] if data else b""
            if b"/containers/abc/json " in request_line:
                body = json.dumps(
                    {
                        "Id": "abc",
                        "Config": {"Labels": {"org.aptl.docker-authority": "managed"}},
                    }
                ).encode()
            elif b"/containers/host-container/json " in request_line:
                body = b'{"Id":"host-container","Config":{"Labels":{}}}'
            else:
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


@contextmanager
def _running_authority(
    images: str,
) -> Iterator[tuple[_Client, _StubDaemon]]:
    """Run the proxy with socket paths short enough for every supported OS."""

    # macOS limits AF_UNIX paths to 104 bytes. Pytest's per-test tmp_path can
    # exceed that before the socket filename is appended. Prefer the standard
    # short POSIX temp root when present and otherwise use the platform default.
    temporary_root = "/tmp" if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(
        prefix="aptl-da-", dir=temporary_root
    ) as temporary_directory:
        socket_directory = Path(temporary_directory)
        upstream = socket_directory / "upstream.sock"
        mediated = socket_directory / "mediated.sock"
        daemon = _StubDaemon(upstream)
        process = subprocess.Popen(
            [sys.executable, str(PROXY)],
            env={
                **os.environ,
                "APTL_DOCKER_AUTHORITY_SOCKET": str(mediated),
                "APTL_DOCKER_AUTHORITY_UPSTREAM": str(upstream),
                "APTL_DOCKER_AUTHORITY_IMAGES": images,
                "APTL_DOCKER_AUTHORITY_NETWORKS": ALLOWED_NETWORK,
            },
            stderr=subprocess.PIPE,
        )
        try:
            for _ in range(100):
                if mediated.exists():
                    break
                time.sleep(0.05)
            assert mediated.exists(), "the mediated socket never appeared"
            yield _Client(mediated), daemon
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            daemon.close()


@pytest.fixture
def authority():
    """Run the real proxy in front of a stub daemon."""

    with _running_authority(ADMITTED) as running:
        yield running


def _create(image: str, host_config: dict | None = None) -> dict:
    selected = {"NetworkMode": ALLOWED_NETWORK, **(host_config or {})}
    payload: dict = {"Image": image, "Cmd": ["true"], "HostConfig": selected}
    return payload


def test_an_admitted_image_with_safe_options_reaches_the_daemon(authority):
    client, daemon = authority

    status, _text = client.request(
        "POST", "/v1.44/containers/create?name=worker", _create(ADMITTED)
    )

    assert status == 200
    assert len(daemon.received) == 1


def test_create_injects_an_unforgeable_authority_ownership_label(authority):
    """Every later operation is scoped to containers this boundary created."""

    client, daemon = authority

    status, _text = client.request(
        "POST",
        "/v1.44/containers/create?name=worker",
        {**_create(ADMITTED), "Labels": {"scenario": "techvault"}},
    )

    assert status == 200
    request = daemon.received[-1]
    payload = json.loads(request.split(b"\r\n\r\n", 1)[1])
    assert payload["Labels"] == {
        "scenario": "techvault",
        "org.aptl.docker-authority": "managed",
    }


def test_caller_cannot_replace_the_authority_ownership_label(authority):
    client, daemon = authority

    status, _text = client.request(
        "POST",
        "/v1.44/containers/create",
        {
            **_create(ADMITTED),
            "Labels": {"org.aptl.docker-authority": "forged"},
        },
    )

    assert status == 200
    payload = json.loads(daemon.received[-1].split(b"\r\n\r\n", 1)[1])
    assert payload["Labels"]["org.aptl.docker-authority"] == "managed"


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
        ("an undeclared Docker network", {"NetworkMode": "other_project_default"}),
        ("host pid namespace", {"PidMode": "host"}),
        ("host ipc namespace", {"IpcMode": "host"}),
        ("relaxed seccomp", {"SecurityOpt": ["seccomp=unconfined"]}),
        ("host port publication", {"PublishAllPorts": True}),
        ("another container's volumes", {"VolumesFrom": ["sensitive:ro"]}),
        ("legacy link environment", {"Links": ["database:database"]}),
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


def test_create_cannot_attach_an_extra_undeclared_network(authority):
    client, daemon = authority
    payload = {
        **_create(ADMITTED),
        "NetworkingConfig": {
            "EndpointsConfig": {"other_project_default": {"Aliases": ["worker"]}}
        },
    }

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
    # Container-scoped calls are preceded by an ownership inspection.
    assert len(daemon.received) == 11


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("GET", "/v1.44/containers/host-container/json"),
        ("GET", "/v1.44/containers/host-container/logs"),
        ("POST", "/v1.44/containers/host-container/stop"),
        ("DELETE", "/v1.44/containers/host-container"),
    ],
)
def test_container_routes_cannot_target_unowned_host_containers(
    authority, method, target
):
    """The proxy must not become a read/delete API for every host container."""

    client, daemon = authority

    status, _text = client.request(method, target)

    assert status == 403
    # One read-only inspect is the authorization check. The requested action
    # itself must never be forwarded (for GET .../json they are the same URI,
    # so exactly that one inspection is expected).
    assert len(daemon.received) == 1
    if not target.endswith("/json"):
        forwarded_lines = [request.split(b"\r\n", 1)[0] for request in daemon.received]
        assert f"{method} {target} HTTP/1.1".encode() not in forwarded_lines


def test_container_listing_is_forcibly_scoped_to_owned_containers(authority):
    client, daemon = authority

    status, _text = client.request("GET", "/v1.44/containers/json?all=1")

    assert status == 200
    request_line = daemon.received[-1].split(b"\r\n", 1)[0]
    assert b"all=1" in request_line
    assert b"filters=" in request_line
    assert b"org.aptl.docker-authority" in request_line


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


def test_conflicting_content_lengths_are_refused_before_the_daemon(authority):
    client, daemon = authority
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    connection.connect(str(client.path))
    connection.sendall(
        b"GET /_ping HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 0\r\n"
        b"Content-Length: 128\r\n\r\n"
    )
    status_line = connection.recv(64)
    connection.close()

    assert b"403" in status_line
    assert daemon.received == []


def test_the_admitted_set_is_the_only_source_of_permitted_images():
    """An authority with no admitted images may create nothing at all."""

    with _running_authority("") as (client, daemon):
        status, _text = client.request(
            "POST", "/v1.44/containers/create", _create(ADMITTED)
        )

    assert status == 403
    assert daemon.received == []
