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

A future supported cgroup v1 path would be a separately qualified backend policy
with its own exact readback baseline -- never a boolean that re-enables host
authority through this gate.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

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


def _probe(run: Callable[..., Any], argv: list[str], subject: str) -> str:
    """Run one daemon probe and return its trimmed stdout.

    A probe that cannot be completed is a refusal, not a default: an
    unanswerable question is never a yes. Daemon stderr is deliberately not
    surfaced -- the caller gets a stable reason, not raw output that could carry
    a host path, a remote endpoint, or an operator's environment.
    """

    try:
        result = run(argv, timeout=_PROBE_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - any runner failure is a refusal
        raise BackendSeedError(
            f"could not determine the target Docker daemon's {subject}; "
            "the generic systemd substrate requires a cgroup v2 daemon at "
            f"Docker Engine {SUBSTRATE_MIN_DOCKER_ENGINE[0]}."
            f"{SUBSTRATE_MIN_DOCKER_ENGINE[1]} or newer"
        ) from exc
    if getattr(result, "returncode", 1) != 0:
        raise BackendSeedError(
            f"could not determine the target Docker daemon's {subject}; "
            "the generic systemd substrate requires a cgroup v2 daemon at "
            f"Docker Engine {SUBSTRATE_MIN_DOCKER_ENGINE[0]}."
            f"{SUBSTRATE_MIN_DOCKER_ENGINE[1]} or newer"
        )
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
            f"v2; this daemon reports {version or 'no cgroup version'}. It is "
            "not supported, and the writable-cgroups option the substrate "
            "depends on is unsafe on cgroup v1"
        )


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


def require_substrate_daemon_support(run: Callable[..., Any]) -> None:
    """Fail closed unless the target daemon can run the substrate's posture.

    ``run`` is the backend's own list-form runner, so an SSH backend
    interrogates *its* daemon with the remote ``DOCKER_HOST``, timeout, and
    error translation already configured. A local-host probe would inspect the
    wrong daemon entirely.

    Ordered: cgroup v2, then engine version. The order is the safety property.
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
