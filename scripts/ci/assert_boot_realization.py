"""Prove the installed-wheel boot actually realized what its scenario declares.

The clean-install gate used to observe one package, one account and one
directory. Every realization defect that reached a running lab in the meantime
lived somewhere else: content that never landed, a service unit that was never
enabled, a listener that bound the package default instead of the authored
port, a host publication that did not match the declaration, and a workflow
that was registered but never driven (issue #993).

This asserts one *causal* chain, so no check can pass vacuously: the scenario's
inline content moves the SSH daemon's port, the declared unit starts it, the
declared listener binds the moved port, and that port is published on the exact
loopback binding the scenario wrote. Break the content and the listener, the
port tuple and the connection probe all fail with it.

Like ``assert_project_teardown.py`` this runs against the *installed* package
and reuses its identities and query rules rather than restating them: the
workspace-owned Compose project plus the admitted ``aptl.node.address`` label
resolve the container, the backend's own listener reader observes sockets from
outside the container's trust boundary, and RAES's workflow contract model
parses the persisted run. A bare container name, an image, a filename or a
daemon-wide search is never the authority.

The decision is a pure function over observed facts
(``boot_realization_failures``) so the gate's own failure modes are unit
tested without Docker; only the gathering below touches the daemon. Output
carries safe identifiers and expected/observed non-secret state — never content
bodies, inspect payloads, environment or tracebacks.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from aptl.core.config import find_config, load_config
from aptl.core.deployment import get_backend
from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    WorkspaceOwnership,
)

_DOCKER_TIMEOUT = 60
_EXEC_TIMEOUT = 60
_CONNECT_TIMEOUT = 15
# A config file this gate reads is bounded scenario-authored text. A larger
# read would be a different kind of artifact and is a failure, not a truncation.
_CONTENT_READ_LIMIT = 64 * 1024
_TERMINAL_WORKFLOW_STATUS = "succeeded"
# A service greeting is one short line. Reading more would make the gate a
# consumer of remote output rather than an observer of one fact.
_BANNER_READ_LIMIT = 256


@dataclass(frozen=True)
class BootExpectation:
    """What the scenario declared, carried as safe identities.

    These are the fixture's own values, passed in rather than hardcoded, so the
    next small regression adds one field and one assertion instead of another
    job or script.
    """

    node_address: str
    content_path: str
    content_text: str
    unit_name: str
    container_port: int
    protocol: str
    host_ip: str
    host_port: int
    workflow_address: str
    # The greeting the declared service sends unprompted, or empty to require
    # only that the connection is accepted. It is a bounded identity, never a
    # credential or a protocol exchange.
    endpoint_banner_prefix: str = ""


@dataclass(frozen=True)
class BootObservation:
    """What the running lab was observed to be.

    ``content`` is ``None`` when the file is absent; ``workflow`` is ``None``
    when no result was persisted for the expected address. Both are distinct
    from an empty value, which is a realized-but-wrong effect.
    """

    container_names: tuple[str, ...]
    content: str | None
    unit: Mapping[str, str]
    listeners: frozenset[tuple[str, int]]
    # (host_ip, host_port, container_port, protocol). The container port is
    # carried because a host binding names a destination: publishing
    # 127.0.0.1:32022 to container port 22 is a different realization from
    # publishing it to 2022, and nothing else in this gate separates them.
    bindings: frozenset[tuple[str, int, int, str]]
    endpoint_reachable: bool
    endpoint_banner: str
    workflow: Mapping[str, object] | None
    workflow_history: tuple[Mapping[str, object], ...] = field(default=())


def _container_failures(
    expected: BootExpectation, observed: BootObservation
) -> list[str]:
    """Require exactly one project-owned container for the declared node."""

    count = len(observed.container_names)
    if count == 1:
        return []
    return [
        f"node {expected.node_address}: expected exactly one project-owned "
        f"container, observed {count}"
    ]


def _content_failures(expected: BootExpectation, observed: BootObservation) -> list[str]:
    """Require the declared content to be present with the authored bytes.

    The backend's own placement readback observes presence only, so the exact
    comparison happens here. Neither the expected nor the observed body is
    printed: a mismatch is reported by path and length.
    """

    if observed.content is None:
        return [f"content {expected.content_path}: not present on the node"]
    if observed.content != expected.content_text:
        return [
            f"content {expected.content_path}: placed bytes differ from the "
            f"authored content (expected {len(expected.content_text)} bytes, "
            f"observed {len(observed.content)})"
        ]
    return []


def _unit_failures(expected: BootExpectation, observed: BootObservation) -> list[str]:
    """Require the declared unit to be enabled, active and not failed.

    A unit that started and then exited non-zero is still ``enabled``, so the
    result is read too. An unreadable unit fails rather than passing on a
    missing key.
    """

    required = (
        ("UnitFileState", "enabled"),
        ("ActiveState", "active"),
        ("Result", "success"),
    )
    failures = []
    for name, wanted in required:
        actual = observed.unit.get(name)
        if actual != wanted:
            failures.append(
                f"unit {expected.unit_name}: {name} is "
                f"{actual or 'unreadable'!s}, expected {wanted}"
            )
    return failures


def _listener_failures(
    expected: BootExpectation, observed: BootObservation
) -> list[str]:
    """Require the authored listener to be bound, protocol included.

    The protocol is carried rather than reduced to a port: a bound udp/2022
    does not satisfy a declared tcp/2022.
    """

    wanted = (expected.protocol, expected.container_port)
    if wanted in observed.listeners:
        return []
    return [
        f"listener {expected.protocol}/{expected.container_port}: not bound "
        f"inside the node's network namespace"
    ]


def _binding_failures(expected: BootExpectation, observed: BootObservation) -> list[str]:
    """Require the exact declared host publication and no wider one.

    An extra binding is a failure even when the declared one is present: a
    correct loopback publication does not excuse a second one that exposes the
    port on every interface (ADR-034 Host Exposure Amendment).
    """

    wanted = (
        expected.host_ip,
        expected.host_port,
        expected.container_port,
        expected.protocol,
    )
    failures = []
    if wanted not in observed.bindings:
        failures.append(
            f"published port {expected.host_ip}:{expected.host_port}/"
            f"{expected.protocol}: not realized to container port "
            f"{expected.container_port} on the node's container"
        )
    for host_ip, host_port, container_port, protocol in sorted(
        observed.bindings - {wanted}
    ):
        failures.append(
            f"published port {host_ip}:{host_port}/{protocol} -> container "
            f"port {container_port}: realized but not declared by the scenario"
        )
    return failures


def _endpoint_failures(
    expected: BootExpectation, observed: BootObservation
) -> list[str]:
    """Require the declared service itself to answer on the published port.

    A bare connection is not enough. Docker publishes the host port whether or
    not anything is bound behind it, and with the userland proxy in front
    ``connect()`` succeeds against a closed container port — so a connection
    check alone passes on the publication that ``_binding_failures`` already
    covered. When the scenario names the greeting its service sends, that
    greeting is the effect. The observed greeting is never echoed: it is remote
    output.
    """

    if not observed.endpoint_reachable:
        return [
            f"published port {expected.host_ip}:{expected.host_port}/"
            f"{expected.protocol}: no connection could be established"
        ]
    if not expected.endpoint_banner_prefix:
        return []
    if not observed.endpoint_banner:
        return [
            f"published port {expected.host_ip}:{expected.host_port}/"
            f"{expected.protocol}: the connection was accepted but the service "
            f"sent no greeting"
        ]
    if not observed.endpoint_banner.startswith(expected.endpoint_banner_prefix):
        return [
            f"published port {expected.host_ip}:{expected.host_port}/"
            f"{expected.protocol}: the service answering is not the declared "
            f"one (expected a {expected.endpoint_banner_prefix!r} greeting)"
        ]
    return []


def _workflow_failures(
    expected: BootExpectation, observed: BootObservation
) -> list[str]:
    """Require a terminal, successfully driven workflow with real history.

    Parsed with the RAES contract model rather than read as loose JSON:
    ``PENDING`` is the truthful *registered* state, so accepting a persisted
    file, or its filename, would accept a workflow that never ran.
    """

    from raes_contracts.workflow import WorkflowExecutionState, WorkflowHistoryEvent

    if observed.workflow is None:
        return [
            f"workflow {expected.workflow_address}: no persisted result in the "
            f"run archive"
        ]
    try:
        state = WorkflowExecutionState.from_payload(observed.workflow)
    except (TypeError, ValueError) as exc:
        return [
            f"workflow {expected.workflow_address}: persisted result is not a "
            f"valid RAES execution state ({type(exc).__name__})"
        ]
    failures = []
    status = getattr(state.workflow_status, "value", state.workflow_status)
    if status != _TERMINAL_WORKFLOW_STATUS:
        failures.append(
            f"workflow {expected.workflow_address}: status is {status}, "
            f"expected {_TERMINAL_WORKFLOW_STATUS}"
        )
    if not observed.workflow_history:
        failures.append(
            f"workflow {expected.workflow_address}: terminal state carries no "
            f"history events"
        )
        return failures
    try:
        for event in observed.workflow_history:
            WorkflowHistoryEvent.from_payload(event)
    except (TypeError, ValueError) as exc:
        failures.append(
            f"workflow {expected.workflow_address}: history is not a valid "
            f"RAES event stream ({type(exc).__name__})"
        )
    return failures


def boot_realization_failures(
    expected: BootExpectation, observed: BootObservation
) -> list[str]:
    """Return every way the observed lab fails the declared realization.

    Every check runs: one boot surfaces every defect it has rather than only
    the first, so a repair cycle does not need a second boot to find the next.
    """

    failures: list[str] = []
    for check in (
        _container_failures,
        _content_failures,
        _unit_failures,
        _listener_failures,
        _binding_failures,
        _endpoint_failures,
        _workflow_failures,
    ):
        failures.extend(check(expected, observed))
    return failures


def _validate_address_component(workflow_address: str) -> str:
    """Return the archive directory name for a workflow address.

    The address is an identity the caller names, never a path it steers: the
    orchestrator persists under the address with ``/`` replaced, so anything
    that could traverse out of the run directory is rejected outright.
    """

    safe = workflow_address.replace("/", "_")
    if not safe or safe != Path(safe).name or safe in (".", ".."):
        raise ValueError(f"invalid workflow address: {workflow_address!r}")
    return safe


def read_workflow_run(
    runs_dir: Path, workflow_address: str
) -> tuple[dict[str, object] | None, tuple[dict[str, object], ...]]:
    """Read the one persisted workflow result and history from the run archive.

    The run directory is *discovered* — its id is a timestamp the lab mints —
    but the workflow is addressed, not guessed. More than one run directory is
    ambiguous rather than "use the newest": this gate boots exactly one lab, so
    a second run means something else wrote into the archive.
    """

    safe_address = _validate_address_component(workflow_address)
    if not runs_dir.is_dir():
        return None, ()
    # ``LocalRunStore`` stores each run under ``<base>/<run_id>/`` with a
    # ``manifest.json`` at its root, and keeps its own infrastructure — the
    # finalization ``locks/`` directory — beside them. The run record is the
    # marker; counting every child directory read ``locks`` as a second run and
    # refused a healthy boot as ambiguous.
    run_dirs = sorted(
        entry
        for entry in runs_dir.iterdir()
        if entry.is_dir() and (entry / "manifest.json").is_file()
    )
    if not run_dirs:
        return None, ()
    if len(run_dirs) > 1:
        raise ValueError(
            f"expected exactly one run directory under {runs_dir.name}, "
            f"found {len(run_dirs)}"
        )
    archive = run_dirs[0] / "orchestration" / safe_address
    result_path = archive / "result.json"
    if not result_path.is_file():
        return None, ()
    result = json.loads(result_path.read_text(encoding="utf-8"))
    history_path = archive / "history.jsonl"
    history: list[dict[str, object]] = []
    if history_path.is_file():
        history = [
            json.loads(line)
            for line in history_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    return result, tuple(history)


def _run(argv: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run one bounded Docker command with no shell."""

    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=timeout, check=False
    )


def _resolve_container_names(project_name: str, node_address: str) -> tuple[str, ...]:
    """Return the project-owned container names carrying the node's address label.

    Two independent authorities have to agree before anything is read: the
    Compose project label plus the admitted ``aptl.node.address`` label select
    the candidate here, and every read below goes back through the backend,
    which re-resolves that name against its own durable ownership receipts. A
    bare name, an image, or a daemon-wide search is never the authority.
    """

    result = _run(
        [
            "docker",
            "ps",
            "--format",
            "{{.Names}}",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--filter",
            f"label=aptl.node.address={node_address}",
        ],
        timeout=_DOCKER_TIMEOUT,
    )
    if result.returncode != 0:
        return ()
    return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())


def _observe_content(backend: object, container_name: str, path: str) -> str | None:
    """Return the file's exact bytes from the node, or ``None`` if absent.

    Read through the backend's bounded archive API rather than a guest command,
    so the result does not depend on a binary inside the target and the body
    never passes through any process's argv.
    """

    payload = backend.container_file_read(
        container_name, path, max_bytes=_CONTENT_READ_LIMIT
    )
    if payload is None:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _observe_unit(
    backend: object, container_name: str, unit_name: str
) -> dict[str, str]:
    """Return the service manager's own view of one unit."""

    result = backend.container_exec(
        container_name,
        [
            "systemctl",
            "show",
            unit_name,
            "-p",
            "UnitFileState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "Result",
        ],
        timeout=_EXEC_TIMEOUT,
    )
    if result.returncode != 0:
        return {}
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            properties[name.strip()] = value.strip()
    return properties


def _observe_listeners(
    backend: object, container_name: str
) -> frozenset[tuple[str, int]]:
    """Return ``(protocol, port)`` listeners read from outside the container.

    The backend reads the kernel's own per-namespace socket tables after
    binding them to the daemon-observed container identity, so a workload that
    shadows ``ss`` cannot change the answer.
    """

    listeners = backend.observe_container_listeners(container_name)
    if listeners is None:
        return frozenset()
    return frozenset(
        (protocol, port) for protocol, _address, port in listeners.sockets
    )


def published_bindings(ports: object) -> frozenset[tuple[str, int, int, str]]:
    """Parse a Docker port map into full host-to-container binding tuples.

    The backend's own ``owned_bindings`` helper answers a different question —
    whether this project already holds a host port — so it returns no container
    port at all. Proving an exact publication needs the destination, so the map
    is parsed here rather than widening a helper whose caller does not want the
    extra dimension.

    A container port with no host entries is exposed but unpublished: it has no
    host side to compare and contributes no binding.
    """

    if not isinstance(ports, dict):
        return frozenset()
    bindings: set[tuple[str, int, int, str]] = set()
    for key, entries in ports.items():
        container_port, _, protocol = str(key).partition("/")
        if not container_port.isdigit():
            continue
        for entry in entries or ():
            if not isinstance(entry, dict):
                continue
            host_port = str(entry.get("HostPort") or "")
            if not host_port.isdigit():
                continue
            bindings.add(
                (
                    str(entry.get("HostIp") or ""),
                    int(host_port),
                    int(container_port),
                    protocol or "tcp",
                )
            )
    return frozenset(bindings)


def _observe_bindings(
    backend: object, container_name: str
) -> frozenset[tuple[str, int, int, str]]:
    """Return the host bindings the daemon reports for the node's container."""

    inspected = backend.container_inspect(container_name)
    return published_bindings((inspected.get("NetworkSettings") or {}).get("Ports"))


def _probe_endpoint(host_ip: str, host_port: int, protocol: str) -> tuple[bool, str]:
    """Open one bounded TCP connection and read the unprompted greeting.

    Nothing is ever sent: the probe opens the socket, reads at most one short
    bounded chunk of whatever the service offers first, and closes. No
    credential, no protocol negotiation, no interactive session.
    """

    if protocol != "tcp":
        return True, ""
    try:
        with socket.create_connection(
            (host_ip, host_port), timeout=_CONNECT_TIMEOUT
        ) as connection:
            connection.settimeout(_CONNECT_TIMEOUT)
            try:
                greeting = connection.recv(_BANNER_READ_LIMIT)
            except OSError:
                return True, ""
        return True, greeting.decode("utf-8", errors="replace").strip()
    except OSError:
        return False, ""


def _observe(
    backend: object, project_name: str, project_dir: Path, expected: BootExpectation
) -> BootObservation:
    """Gather every observed fact the decision needs, failing closed on absence."""

    container_names = _resolve_container_names(project_name, expected.node_address)
    content: str | None = None
    unit: dict[str, str] = {}
    listeners: frozenset[tuple[str, int]] = frozenset()
    bindings: frozenset[tuple[str, int, int, str]] = frozenset()
    if len(container_names) == 1:
        container_name = container_names[0]
        content = _observe_content(backend, container_name, expected.content_path)
        unit = _observe_unit(backend, container_name, expected.unit_name)
        listeners = _observe_listeners(backend, container_name)
        bindings = _observe_bindings(backend, container_name)
    reachable, banner = _probe_endpoint(
        expected.host_ip, expected.host_port, expected.protocol
    )
    workflow, history = read_workflow_run(
        project_dir / "runs", expected.workflow_address
    )
    return BootObservation(
        container_names=container_names,
        content=content,
        unit=unit,
        listeners=listeners,
        bindings=bindings,
        endpoint_reachable=reachable,
        endpoint_banner=banner,
        workflow=workflow,
        workflow_history=history,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("--node-address", required=True)
    parser.add_argument("--content-path", required=True)
    parser.add_argument("--content-text", required=True)
    parser.add_argument("--unit-name", required=True)
    parser.add_argument("--container-port", required=True, type=int)
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument("--host-ip", required=True)
    parser.add_argument("--host-port", required=True, type=int)
    parser.add_argument("--workflow-address", required=True)
    parser.add_argument("--endpoint-banner-prefix", default="")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Return 0 only when every declared realization effect is observed."""

    args = _parse_args(argv[1:])
    project_dir = args.project_dir.resolve()
    config_path = find_config(project_dir)
    if config_path is None:
        print(f"No aptl.json found in {project_dir}", file=sys.stderr)
        return 2
    config = load_config(config_path)
    if config.deployment.provider != "docker-compose":
        print("Boot realization proof requires local Docker Compose", file=sys.stderr)
        return 2
    try:
        ownership = WorkspaceOwnership.load(project_dir, config.deployment.project_name)
    except OwnershipConflictError:
        print("Project ownership state could not be loaded", file=sys.stderr)
        return 2
    if ownership is None:
        print("Project ownership state is missing", file=sys.stderr)
        return 2

    expected = BootExpectation(
        node_address=args.node_address,
        content_path=args.content_path,
        content_text=args.content_text,
        unit_name=args.unit_name,
        container_port=args.container_port,
        protocol=args.protocol,
        host_ip=args.host_ip,
        host_port=args.host_port,
        workflow_address=args.workflow_address,
        endpoint_banner_prefix=args.endpoint_banner_prefix,
    )
    backend = get_backend(config, project_dir)
    try:
        observed = _observe(backend, ownership.project_name, project_dir, expected)
    except (ValueError, subprocess.TimeoutExpired) as exc:
        # These carry this gate's own bounded text about its own inputs — an
        # ambiguous run archive, a rejected workflow address, a command that
        # outran its timeout — so the operator gets the reason, not just a
        # type name they cannot act on.
        print(f"Boot realization could not be observed: {exc}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError) as exc:
        # These can carry daemon or filesystem detail, so only the class
        # travels.
        print(
            f"Boot realization could not be observed: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    failures = boot_realization_failures(expected, observed)
    if failures:
        for failure in failures:
            print(f"BOOT REALIZATION FAILURE: {failure}", file=sys.stderr)
        return 1
    print(
        f"Boot realization verified for {expected.node_address} "
        f"(project {ownership.project_name})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
