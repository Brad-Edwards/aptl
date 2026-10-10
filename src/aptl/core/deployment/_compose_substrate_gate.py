"""Target-daemon capability gate for the generic systemd substrate (issue #955).

The substrate runs systemd unprivileged by asking Docker for a writable version
of the container's OWN namespace-scoped cgroup2 mount, via ``--security-opt
writable-cgroups=true`` (Docker Engine 28.0, moby#48828). Two properties of that
option make this an ordered safety gate rather than a convenience check.

**Docker does not gate the option on cgroup version.** It clears the read-only
flag on whatever cgroup mount the container gets, v1 or v2. On cgroup v1 a
writable cgroupfs re-enables the classic ``release_agent`` host-code-execution
escape and exposes a writable device controller, so requesting it on a v1 daemon
is worse than the recipe it replaces. The upstream review of moby#48828 raised
exactly this and accepted it as a documentation problem (moby#49333), so neither
Docker nor runc will refuse it on our behalf. Hence: prove cgroup v2 FIRST, and
never reach the second probe otherwise.

**An unsupported daemon's refusal is not a capability signal.** Engine < 28.0
answers ``invalid --security-opt 2: "writable-cgroups=true"`` -- byte-identical
in shape to its reply for any unknown option, so it cannot distinguish an old
daemon from a bad value and must never be parsed as though it could. The gate
asks the daemon its version instead, and does so before any image build, network
creation, or container removal, so an unsupported host fails before mutation.

There is deliberately **no fallback** to the retired privileged recipe. A
fallback would make the realized security posture a silent function of the
operator's Docker version: the same scenario would yield either a private cgroup
namespace with zero added capabilities, or a host cgroup namespace with
``CAP_SYS_ADMIN`` and ``seccomp:unconfined``, with nothing in the range's own
evidence distinguishing them. It would also defeat the exact-readback contract,
which cannot describe two postures at once without reintroducing a conditional
exemption.

**Rootless and userns-remap daemons are refused by name.** Both reject an
explicit ``writable-cgroups`` request at container create (moby
``daemon/oci_linux.go``: "option WritableCgroups conflicts with user namespaces
and rootless mode"), and a userns-remap daemon forces writable cgroups on
regardless of what was asked. Neither is a qualified substrate runtime (ADR-060
makes the VM seat the alternative boundary), so the gate names the mode before
mutation instead of letting the create fail with an opaque start error.

**Lab start refuses a rootless daemon for every scenario** (#1053). LilRAE does
not support rootless Docker at all, not only for systemd nodes, so
:func:`require_rootful_daemon` asks the same security-options question before
any SSH key, credential render, volume, certificate, image pull or Compose
change, and before ``aptl lab start --clean`` tears anything down, whatever the
scenario selects. userns-remap stays refused only where the substrate posture
needs writable cgroups.

A future supported cgroup v1 path would be a separately qualified backend policy
with its own exact readback baseline -- never a boolean that re-enables host
authority through this gate.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from aptl.core.deployment.errors import BackendSeedError

# The `--security-opt` value that makes the container's own cgroup2 mount
# writable. Shared with the run-flag builder so the started container and the
# gate that authorized it can never name different options.
WRITABLE_CGROUPS_OPTION = "writable-cgroups=true"

# Docker Engine that introduced `writable-cgroups` (moby#48828, milestone
# 28.0.0). Compared numerically, never lexically: "5.0.0" sorts above "28.0.0"
# as text, which would admit an ancient daemon and reject a future one.
SUBSTRATE_MIN_DOCKER_ENGINE = (28, 0)

_PROBE_TIMEOUT_SECONDS = 30

_ROOTLESS_MODE = "rootless"

# Daemon modes, as named in ``docker info``'s SecurityOptions, that cannot run
# the substrate posture, with the wording an operator will recognize.
_UNQUALIFIED_DAEMON_MODES = (
    (_ROOTLESS_MODE, "rootless"),
    ("userns", "user-namespace remapping (userns-remap)"),
)

_SUBSTRATE_REQUIREMENT = (
    "the generic systemd substrate requires a cgroup v2 daemon at Docker Engine "
    f"{SUBSTRATE_MIN_DOCKER_ENGINE[0]}.{SUBSTRATE_MIN_DOCKER_ENGINE[1]} or newer"
)
_ROOTFUL_REQUIREMENT = "LilRAE requires a rootful Docker daemon"

# The only form of a cgroup version answer a refusal repeats. Anything else the
# daemon prints is not trusted text and is described instead.
_CGROUP_VERSION_ANSWER = re.compile(r"\d{1,2}", re.ASCII)


class UnqualifiedDaemonModeError(BackendSeedError):
    """The daemon runs in a mode the substrate cannot use (rootless, userns-remap).

    A distinct type, so a caller can name the fix for the mode itself rather
    than the cgroup and engine fix. Every existing ``BackendSeedError`` handler
    still catches it.
    """


def _probe(
    run: Callable[..., Any],
    argv: list[str],
    subject: str,
    requirement: str = _SUBSTRATE_REQUIREMENT,
) -> str:
    """Run one daemon probe and return its trimmed stdout.

    A probe that cannot be completed is a refusal, not a default: an
    unanswerable question is never a yes. Daemon stderr is deliberately not
    surfaced -- the caller gets a stable reason, not raw output that could carry
    a host path, a remote endpoint, or an operator's environment.
    """

    unanswered = (
        f"could not determine the target Docker daemon's {subject}; {requirement}"
    )
    try:
        result = run(argv, timeout=_PROBE_TIMEOUT_SECONDS)
    # Any runner failure -- a timeout, a missing binary, a transport error on a
    # remote endpoint -- is a refusal, never a pass.
    except Exception as exc:
        raise BackendSeedError(unanswered) from exc
    if getattr(result, "returncode", 1) != 0:
        raise BackendSeedError(unanswered)
    return str(getattr(result, "stdout", "") or "").strip()


def _require_cgroup_v2(run: Callable[..., Any]) -> None:
    """Refuse any daemon that is not on the unified (v2) hierarchy."""

    version = _probe(
        run,
        ["docker", "info", "--format", "{{.CgroupVersion}}"],
        "cgroup version",
    )
    if version != "2":
        raise BackendSeedError(
            "the generic systemd substrate requires a Docker daemon on cgroup "
            f"v2; this daemon reports {_reported_cgroup_version(version)}. It is "
            "not supported, and the writable-cgroups option the substrate "
            "depends on is unsafe on cgroup v1"
        )


def _reported_cgroup_version(answer: str) -> str:
    """Repeat the daemon's cgroup answer only when it is a version number."""

    if _CGROUP_VERSION_ANSWER.fullmatch(answer):
        return answer
    return "an unrecognized cgroup version" if answer else "no cgroup version"


def _engine_version(run: Callable[..., Any]) -> tuple[int, int]:
    """Return the target daemon's (major, minor) engine version."""

    raw = _probe(
        run,
        ["docker", "version", "--format", "{{.Server.Version}}"],
        "engine version",
    )
    parts = raw.split(".")
    try:
        return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except (IndexError, ValueError) as exc:
        raise BackendSeedError(
            "could not parse the target Docker daemon's engine version; the "
            "generic systemd substrate requires Docker Engine "
            f"{SUBSTRATE_MIN_DOCKER_ENGINE[0]}.{SUBSTRATE_MIN_DOCKER_ENGINE[1]}"
            " or newer"
        ) from exc


def _security_option_names(raw: str) -> frozenset[str]:
    """Return the ``name=`` values of a daemon's JSON SecurityOptions list."""

    try:
        options = json.loads(raw) if raw else None
    except ValueError as exc:
        raise BackendSeedError(
            "could not parse the target Docker daemon's security options"
        ) from exc
    options = [] if options is None else options
    if not isinstance(options, list) or not all(
        isinstance(option, str) for option in options
    ):
        raise BackendSeedError(
            "could not parse the target Docker daemon's security options"
        )
    return frozenset(
        part.removeprefix("name=")
        for option in options
        for part in option.split(",")
        if part.startswith("name=")
    )


def _daemon_security_option_names(
    run: Callable[..., Any], requirement: str = _SUBSTRATE_REQUIREMENT
) -> frozenset[str]:
    """Ask the target daemon for its SecurityOptions ``name=`` values."""

    return _security_option_names(
        _probe(
            run,
            ["docker", "info", "--format", "{{json .SecurityOptions}}"],
            "security options",
            requirement,
        )
    )


def require_rootful_daemon(run: Callable[..., Any]) -> None:
    """Refuse a rootless daemon with a named reason, for every scenario.

    Lab start calls this once the backend is bound and before any SSH key,
    credential render, volume, certificate, image pull or Compose change, and
    ``--clean`` calls it before its teardown (#1053). ``run`` is the selected
    backend's list-form runner, so an explicitly selected endpoint is the
    daemon that answers; nothing here redirects to another daemon.
    """

    if _ROOTLESS_MODE in _daemon_security_option_names(run, _ROOTFUL_REQUIREMENT):
        raise BackendSeedError(
            "LilRAE does not support a Docker daemon running in rootless mode. "
            "Use a rootful Docker daemon"
        )


def _require_qualified_daemon_mode(run: Callable[..., Any]) -> None:
    """Refuse rootless and userns-remap daemons with a named reason."""

    names = _daemon_security_option_names(run)
    for mode, label in _UNQUALIFIED_DAEMON_MODES:
        if mode in names:
            raise UnqualifiedDaemonModeError(
                "the generic systemd substrate does not support a Docker daemon "
                f"running in {label} mode: it refuses the writable-cgroups "
                "option systemd nodes depend on. Use a rootful daemon without "
                "userns-remap"
            )


def require_substrate_daemon_support(run: Callable[..., Any]) -> None:
    """Fail closed unless the target daemon can run the substrate's posture.

    ``run`` is the backend's own list-form runner, so an SSH backend
    interrogates *its* daemon with the remote ``DOCKER_HOST``, timeout, and
    error translation already configured. A local-host probe would inspect the
    wrong daemon entirely.

    Ordered: cgroup v2, then engine version, then daemon mode. cgroup v2 comes
    first because that order is the safety property.
    """

    _require_cgroup_v2(run)
    major, minor = _engine_version(run)
    if (major, minor) < SUBSTRATE_MIN_DOCKER_ENGINE:
        raise BackendSeedError(
            "the generic systemd substrate requires Docker Engine "
            f"{SUBSTRATE_MIN_DOCKER_ENGINE[0]}.{SUBSTRATE_MIN_DOCKER_ENGINE[1]}"
            f" or newer; this daemon reports {major}.{minor}. Older engines "
            "lack the writable-cgroups option systemd nodes depend on"
        )
    _require_qualified_daemon_mode(run)


def _selected(
    name: str,
    service: Mapping[str, Any],
    profiles: frozenset[str],
    exclude_services: frozenset[str],
    only_services: frozenset[str],
) -> bool:
    """Whether Compose would start this service for the given selection.

    A service named explicitly as an ``up`` target is started even when none of
    its profiles is enabled, so an explicit target is selected regardless of
    profile; otherwise the profile rules decide.
    """

    if name in exclude_services:
        return False
    if only_services:
        return name in only_services
    service_profiles = service.get("profiles") or ()
    return not service_profiles or bool(profiles.intersection(service_profiles))


def compose_services_requesting_writable_cgroups(
    compose_files: Iterable[Path],
    profiles: Iterable[str],
    *,
    exclude_services: Iterable[str] = (),
    only_services: Iterable[str] = (),
) -> tuple[str, ...]:
    """Return the selected Compose services that ask for writable cgroups.

    A Compose-managed systemd service (the ``reverse`` profile) takes the same
    posture as the generic substrate, so it depends on the same daemon support.
    Compose itself would surface an unsupported daemon only as Docker's opaque
    ``invalid --security-opt`` at create; knowing which selected services need
    the option lets the backend run this gate before ``up`` instead.

    Reads each file's authored model. An unreadable file names nothing here;
    Compose's own model validation owns reporting it.
    """

    selected_profiles = frozenset(profiles)
    excluded = frozenset(exclude_services)
    only = frozenset(only_services)
    requesting = (
        str(name)
        for compose_file in compose_files
        for name, service in _compose_services(Path(compose_file)).items()
        if isinstance(service, Mapping)
        and WRITABLE_CGROUPS_OPTION in (service.get("security_opt") or ())
        and _selected(str(name), service, selected_profiles, excluded, only)
    )
    return tuple(dict.fromkeys(requesting))


def _compose_services(compose_file: Path) -> Mapping[str, Any]:
    """Return one Compose file's authored ``services`` map, or none if unreadable."""

    try:
        model = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    services = model.get("services") if isinstance(model, Mapping) else None
    return services if isinstance(services, Mapping) else {}
