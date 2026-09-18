"""Mediating Docker authority for a declared orchestration workload.

A scenario may declare that a node orchestrates workloads -- TechVault's
Shuffle Orborus declares `host_root_equivalent` privilege over a Docker control
interface. Granting that by bind-mounting the host's own socket satisfies the
declaration and destroys the containment boundary at the same time: the Docker
API is a host-root API, so a compromise of the declaring workload can create a
container with a host filesystem bind, `Privileged`, added capabilities, or
another copy of the socket, and step straight out onto the host. Pre-pulling
the declared images does not prevent any of that, and observing containers
afterwards by `ancestor=<digest>` cannot see a container that was created from
something else.

*How* the declared authority is granted is a backend choice, so APTL grants it
through this proxy instead. The workload still sees a read-write Docker socket
at the declared path; every request through it is authorized first, before it
reaches the daemon.

The policy is deny-by-default in three ways that matter:

* only the endpoints an orchestrator needs are routed at all;
* `POST /containers/create` must name an image in the admitted digest set;
* that same request must carry none of the create options that would confer
  host access, whatever image it names.

Anything this proxy cannot fully parse and evaluate is refused rather than
forwarded, so a malformed or unfamiliar request fails closed. It handles no
credentials and makes no decisions of its own: the admitted digest set arrives
from the realization that declared it.
"""

from __future__ import annotations

import json
import os
import re
import socket
import socketserver
import sys
import threading

SOCKET_PATH = os.environ["APTL_DOCKER_AUTHORITY_SOCKET"]
UPSTREAM_PATH = os.getenv("APTL_DOCKER_AUTHORITY_UPSTREAM", "/var/run/docker.sock")
#: Newline-separated exact `repo@sha256:...` references the admitted plan
#: declared. An empty set means nothing may be created, which is the correct
#: posture for an authority whose declared closure is empty.
ALLOWED_IMAGES = frozenset(
    item.strip()
    for item in os.getenv("APTL_DOCKER_AUTHORITY_IMAGES", "").splitlines()
    if item.strip()
)

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 4 * 1024 * 1024
_VERSION_PREFIX = re.compile(r"^/v[0-9]+\.[0-9]+")
_CONTAINER_ID = r"[A-Za-z0-9][A-Za-z0-9_.-]*"

#: (method, exact-or-pattern) pairs an orchestrator legitimately needs. Read
#: endpoints are included because an orchestrator has to observe what it ran;
#: none of them can change host state.
_ROUTES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (method, re.compile(pattern))
    for method, pattern in (
        ("GET", r"^/_ping$"),
        ("HEAD", r"^/_ping$"),
        ("GET", r"^/version$"),
        ("GET", r"^/info$"),
        ("GET", r"^/containers/json$"),
        ("POST", r"^/containers/create$"),
        ("GET", rf"^/containers/{_CONTAINER_ID}/json$"),
        ("GET", rf"^/containers/{_CONTAINER_ID}/logs$"),
        ("GET", rf"^/containers/{_CONTAINER_ID}/stats$"),
        ("POST", rf"^/containers/{_CONTAINER_ID}/start$"),
        ("POST", rf"^/containers/{_CONTAINER_ID}/stop$"),
        ("POST", rf"^/containers/{_CONTAINER_ID}/kill$"),
        ("POST", rf"^/containers/{_CONTAINER_ID}/wait$"),
        ("DELETE", rf"^/containers/{_CONTAINER_ID}$"),
        ("GET", r"^/images/json$"),
        ("GET", r"^/images/.+/json$"),
        ("GET", r"^/networks$"),
        ("GET", r"^/networks/.+$"),
    )
)

#: Create options that hand out host access. Every one of these is refused
#: regardless of the image, because a declared image running with a host bind
#: or `Privileged` is a host compromise just the same.
_FORBIDDEN_HOST_CONFIG = (
    "Binds",
    "Mounts",
    "Privileged",
    "CapAdd",
    "Devices",
    "DeviceRequests",
    "DeviceCgroupRules",
    "CgroupParent",
    "SecurityOpt",
    "Sysctls",
    "UsernsMode",
    "PidMode",
    "IpcMode",
    "UTSMode",
    "CgroupnsMode",
    "Runtime",
    "PublishAllPorts",
    "PortBindings",
    "ExtraHosts",
)
#: Namespace modes that join the host or another container's namespace.
_FORBIDDEN_NETWORK_MODES = ("host", "none")


class _Denied(Exception):
    """One refused request, carrying the reason recorded for the operator."""


def _log(message: str) -> None:
    """Record one bounded decision. Request bodies are never logged."""

    print(f"[aptl-docker-authority] {message}", file=sys.stderr, flush=True)


def _normalize(target: str) -> str:
    """Strip the API version prefix and query string from a request target."""

    path = target.split("?", 1)[0]
    return _VERSION_PREFIX.sub("", path) or "/"


def _routed(method: str, path: str) -> bool:
    """Whether this exact method and path is one of the routed endpoints."""

    return any(
        method == allowed and pattern.match(path) for allowed, pattern in _ROUTES
    )


def _authorize_create(body: bytes) -> None:
    """Refuse a container create that names an undeclared image or host access."""

    try:
        payload = json.loads(body or b"{}")
    except ValueError as exc:
        raise _Denied("create body is not JSON") from exc
    if not isinstance(payload, dict):
        raise _Denied("create body is not an object")

    image = payload.get("Image")
    if not isinstance(image, str) or image not in ALLOWED_IMAGES:
        raise _Denied("create names an image outside the admitted digest set")

    host_config = payload.get("HostConfig") or {}
    if not isinstance(host_config, dict):
        raise _Denied("create carries an unreadable HostConfig")
    for option in _FORBIDDEN_HOST_CONFIG:
        if host_config.get(option):
            raise _Denied(f"create requests host access through {option}")
    network_mode = str(host_config.get("NetworkMode", "") or "")
    if network_mode in _FORBIDDEN_NETWORK_MODES or network_mode.startswith(
        "container:"
    ):
        raise _Denied("create requests a namespace it may not join")
    # A container may not be handed the daemon it was created through.
    if payload.get("Volumes"):
        raise _Denied("create requests anonymous volumes")


def _read_headers(stream) -> tuple[bytes, list[bytes]]:
    """Read the request line and headers, bounded."""

    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = stream.read(1)
        if not chunk:
            raise _Denied("connection closed before a complete request")
        raw += chunk
        if len(raw) > _MAX_HEADER_BYTES:
            raise _Denied("request headers exceed the admitted bound")
    head, _, _rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return lines[0], lines[1:]


def _header(headers: list[bytes], name: str) -> str:
    """Return one header value, case-insensitively."""

    prefix = name.lower().encode() + b":"
    for line in headers:
        if line.lower().startswith(prefix):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return ""


def _read_body(stream, headers: list[bytes]) -> bytes:
    """Read a bounded request body, refusing anything it cannot measure."""

    if _header(headers, "Transfer-Encoding").lower() == "chunked":
        raise _Denied("chunked request bodies are not evaluated")
    raw_length = _header(headers, "Content-Length")
    if not raw_length:
        return b""
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise _Denied("unreadable Content-Length") from exc
    if length < 0 or length > _MAX_BODY_BYTES:
        raise _Denied("request body exceeds the admitted bound")
    body = stream.read(length)
    if len(body) != length:
        raise _Denied("request body was truncated")
    return body


def _refuse(connection: socket.socket, reason: str) -> None:
    """Answer one refused request without reaching the daemon."""

    _log(f"denied: {reason}")
    payload = json.dumps({"message": f"aptl docker authority: {reason}"}).encode()
    connection.sendall(
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + payload
    )


def _relay(source: socket.socket, destination: socket.socket) -> None:
    """Copy bytes one way until the source closes."""

    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _Handler(socketserver.BaseRequestHandler):
    """Authorize one request, then relay its connection when it is allowed."""

    def handle(self) -> None:
        connection: socket.socket = self.request
        stream = connection.makefile("rb")
        try:
            request_line, headers = _read_headers(stream)
            parts = request_line.split(b" ")
            if len(parts) != 3:
                raise _Denied("malformed request line")
            method = parts[0].decode("latin-1")
            path = _normalize(parts[1].decode("latin-1"))
            body = _read_body(stream, headers)
            if not _routed(method, path):
                raise _Denied(f"{method} {path} is not a routed endpoint")
            if method == "POST" and path == "/containers/create":
                _authorize_create(body)
        except _Denied as denied:
            _refuse(connection, str(denied))
            return
        except OSError:
            return
        self._forward(connection, request_line, headers, body)

    def _forward(
        self,
        connection: socket.socket,
        request_line: bytes,
        headers: list[bytes],
        body: bytes,
    ) -> None:
        """Send the authorized request upstream and relay the daemon's answer."""

        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.connect(UPSTREAM_PATH)
        except OSError:
            _refuse(connection, "the Docker daemon is unreachable")
            return
        _log(f"allowed: {request_line.decode('latin-1')}")
        with upstream:
            upstream.sendall(
                request_line + b"\r\n" + b"\r\n".join(headers) + b"\r\n\r\n" + body
            )
            # The daemon may hijack the connection (attach, wait), so both
            # directions are relayed rather than one response being parsed.
            outbound = threading.Thread(
                target=_relay, args=(connection, upstream), daemon=True
            )
            outbound.start()
            _relay(upstream, connection)


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    """Serve the mediated socket until the container stops."""

    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    server = _Server(SOCKET_PATH, _Handler)
    # The declaring workload runs as its own user, so the socket has to be
    # reachable by it. Authorization is what constrains the caller, not file
    # permissions: anything that reaches this socket is still policed.
    os.chmod(SOCKET_PATH, 0o666)
    _log(
        f"serving {SOCKET_PATH} -> {UPSTREAM_PATH} "
        f"({len(ALLOWED_IMAGES)} admitted image(s))"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
