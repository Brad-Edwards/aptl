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
import http.client
import os
import re
import socket
import socketserver
import sys
import threading
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
ALLOWED_NETWORKS = frozenset(
    item.strip()
    for item in os.getenv("APTL_DOCKER_AUTHORITY_NETWORKS", "").splitlines()
    if item.strip()
)
OWNER_LABEL = os.getenv(
    "APTL_DOCKER_AUTHORITY_OWNER_LABEL",
    "org.aptl.docker-authority=managed",
)
OWNER_LABEL_KEY, _OWNER_SEPARATOR, OWNER_LABEL_VALUE = OWNER_LABEL.partition("=")
if (
    not _OWNER_SEPARATOR
    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-/]*", OWNER_LABEL_KEY)
    or not OWNER_LABEL_VALUE
    or any(character in OWNER_LABEL_VALUE for character in "\r\n")
):
    raise RuntimeError("invalid Docker authority ownership label")

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 4 * 1024 * 1024
_MAX_INSPECT_BYTES = 1024 * 1024
_VERSION_PREFIX = re.compile(r"^/v[0-9]+\.[0-9]+")
_CONTAINER_ID = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_CONTAINER_ROUTE = re.compile(
    rf"^/containers/(?P<identifier>{_CONTAINER_ID})(?:/(?:json|logs|stats|start|stop|kill|wait))?$"
)

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
    "VolumesFrom",
    "Links",
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


def _authorize_create(body: bytes) -> bytes:
    """Authorize and ownership-label one admitted container create."""

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
    if (
        network_mode in _FORBIDDEN_NETWORK_MODES
        or network_mode.startswith("container:")
        or network_mode not in ALLOWED_NETWORKS
    ):
        raise _Denied("create requests a network it may not join")
    networking = payload.get("NetworkingConfig") or {}
    if not isinstance(networking, dict):
        raise _Denied("create carries an unreadable NetworkingConfig")
    endpoints = networking.get("EndpointsConfig") or {}
    if not isinstance(endpoints, dict) or any(
        not isinstance(name, str) or name not in ALLOWED_NETWORKS
        for name in endpoints
    ):
        raise _Denied("create requests an additional network it may not join")
    # A container may not be handed the daemon it was created through.
    if payload.get("Volumes"):
        raise _Denied("create requests anonymous volumes")

    labels = payload.get("Labels") or {}
    if not isinstance(labels, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in labels.items()
    ):
        raise _Denied("create carries unreadable labels")
    # This label is the durable authorization receipt for every later
    # container-scoped operation. The caller may not forge or remove it.
    labels[OWNER_LABEL_KEY] = OWNER_LABEL_VALUE
    payload["Labels"] = labels
    return json.dumps(payload, separators=(",", ":")).encode()


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


def _header_values(headers: list[bytes], name: str) -> list[str]:
    """Return every value for a named header after strict syntax checks."""

    prefix = name.lower().encode() + b":"
    values: list[str] = []
    for line in headers:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise _Denied("request carries a malformed header")
        if line.lower().startswith(prefix):
            values.append(line.split(b":", 1)[1].strip().decode("latin-1"))
    return values


def _read_body(stream, headers: list[bytes]) -> bytes:
    """Read a bounded request body, refusing anything it cannot measure."""

    if _header_values(headers, "Transfer-Encoding"):
        raise _Denied("transferred request bodies are not evaluated")
    lengths = _header_values(headers, "Content-Length")
    if len(lengths) > 1:
        raise _Denied("request carries conflicting Content-Length headers")
    if not lengths:
        return b""
    raw_length = lengths[0]
    if not raw_length.isascii() or not raw_length.isdecimal():
        raise _Denied("unreadable Content-Length")
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


def _owned_container(identifier: str, target: str) -> bool:
    """Return whether Docker records the proxy's ownership receipt."""

    version = _VERSION_PREFIX.match(urlsplit(target).path)
    prefix = version.group(0) if version else ""
    inspect_target = f"{prefix}/containers/{identifier}/json"
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.settimeout(5)
        upstream.connect(UPSTREAM_PATH)
        with upstream:
            upstream.sendall(
                f"GET {inspect_target} HTTP/1.1\r\n"
                "Host: localhost\r\nConnection: close\r\n\r\n".encode()
            )
            response = http.client.HTTPResponse(upstream)
            response.begin()
            body = response.read(_MAX_INSPECT_BYTES + 1)
            if response.status != 200 or len(body) > _MAX_INSPECT_BYTES:
                return False
    except (OSError, http.client.HTTPException):
        return False
    try:
        payload = json.loads(body)
        labels = payload.get("Config", {}).get("Labels", {})
    except (AttributeError, TypeError, ValueError):
        return False
    return isinstance(labels, dict) and labels.get(OWNER_LABEL_KEY) == OWNER_LABEL_VALUE


def _authorize_container_target(path: str, target: str) -> None:
    """Refuse operations on containers not created through this authority."""

    if path in ("/containers/json", "/containers/create"):
        return
    matched = _CONTAINER_ROUTE.fullmatch(path)
    if matched and not _owned_container(matched.group("identifier"), target):
        raise _Denied("container is not owned by this Docker authority")


def _scoped_container_list(target: str) -> str:
    """Force the Docker list filter to this authority's owned containers."""

    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise _Denied("request target is not origin-form")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    raw_filters = [value for name, value in pairs if name == "filters"]
    if len(raw_filters) > 1:
        raise _Denied("container list carries conflicting filters")
    try:
        filters = json.loads(raw_filters[0]) if raw_filters else {}
    except ValueError as exc:
        raise _Denied("container list carries unreadable filters") from exc
    if not isinstance(filters, dict):
        raise _Denied("container list filters are not an object")
    labels = filters.get("label", [])
    if isinstance(labels, str):
        labels = [labels]
    if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
        raise _Denied("container list carries unreadable label filters")
    filters["label"] = [*labels, OWNER_LABEL]
    pairs = [(name, value) for name, value in pairs if name != "filters"]
    pairs.append(("filters", json.dumps(filters, separators=(",", ":"))))
    return urlunsplit(("", "", parsed.path, urlencode(pairs), ""))


def _forward_headers(headers: list[bytes], body: bytes) -> list[bytes]:
    """Return unambiguous framing headers for the body already evaluated."""

    kept = [
        line
        for line in headers
        if line.split(b":", 1)[0].strip().lower()
        not in (b"content-length", b"transfer-encoding")
    ]
    return [*kept, f"Content-Length: {len(body)}".encode()]


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
            target = parts[1].decode("latin-1")
            version = parts[2].decode("latin-1")
            path = _normalize(target)
            body = _read_body(stream, headers)
            if not _routed(method, path):
                raise _Denied(f"{method} {path} is not a routed endpoint")
            if method == "POST" and path == "/containers/create":
                body = _authorize_create(body)
            _authorize_container_target(path, target)
            if method == "GET" and path == "/containers/json":
                target = _scoped_container_list(target)
            request_line = f"{method} {target} {version}".encode("latin-1")
            headers = _forward_headers(headers, body)
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
