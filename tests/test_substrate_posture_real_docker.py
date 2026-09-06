"""The substrate posture, proved against a real Docker daemon (issue #955).

Every other test in this change asserts on argv or on a fixture shaped like a
`docker inspect` payload. Those catch regressions in APTL's own logic but cannot
answer the question this issue actually turns on: does systemd still come up,
and is the container really unprivileged?

So these tests drive `ComposeBaseSubstrateMixin.start_base_container` -- the same
code path `aptl lab start` uses -- against the real daemon, then read the posture
back off the running container with the daemon's own inspect output and out of
`/proc/1/status` inside it.

The measurement that motivated the change is worth restating, because it is the
opposite of what the flags suggested: the retired recipe (host cgroup namespace,
read-write host cgroupfs bind, `seccomp:unconfined`, and
SYS_ADMIN/SYS_NICE/SYS_RESOURCE) booted the Debian substrate `degraded` with six
failed units. Holding CAP_SYS_ADMIN made systemd *attempt* host operations that
then failed inside a container. Dropping every capability and using the daemon's
default seccomp profile boots it `running` with zero failed units.

Marked `integration` per-test (not module-level) so the default
`-k "not integration"` run does not zero this module's coverage, and skipped
when the daemon, the images, or the required engine version are unavailable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from aptl.backends.raes_base_substrate import BaseContainerSpec, InitRequirements
from aptl.core.deployment import DockerComposeBackend
from aptl.core.deployment._compose_substrate_gate import SUBSTRATE_MIN_DOCKER_ENGINE

_IMAGES = {
    "debian": "aptl/generic-systemd-base-debian:latest",
    "rocky": "aptl/generic-systemd-base:latest",
}


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )


def _daemon_supports_the_posture() -> bool:
    if shutil.which("docker") is None:
        return False
    info = _docker("info", "--format", "{{.CgroupVersion}}")
    version = _docker("version", "--format", "{{.Server.Version}}")
    if info.returncode != 0 or version.returncode != 0:
        return False
    if info.stdout.strip() != "2":
        return False
    parts = version.stdout.strip().split(".")
    try:
        return (int(parts[0]), int(parts[1])) >= SUBSTRATE_MIN_DOCKER_ENGINE
    except (IndexError, ValueError):
        return False


requires_daemon = pytest.mark.skipif(
    not _daemon_supports_the_posture(),
    reason="needs a cgroup v2 Docker daemon at Engine "
    f"{SUBSTRATE_MIN_DOCKER_ENGINE[0]}.{SUBSTRATE_MIN_DOCKER_ENGINE[1]}+",
)


@pytest.fixture
def started_node(tmp_path):
    """Start one generic systemd node through APTL's own backend, then clean up."""

    started: list[str] = []

    def start(image_key: str) -> tuple[str, dict]:
        image = _IMAGES[image_key]
        if _docker("image", "inspect", image).returncode != 0:
            pytest.skip(f"{image} is not built on this host")
        name = f"aptl-955-{image_key}-{int(time.time() * 1000)}"
        spec = BaseContainerSpec(
            node_address=f"provision.node.{image_key}",
            container_name=name,
            image_ref=image,
            runs_services=True,
            init=InitRequirements(),
        )
        backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl955")
        started.append(name)
        backend.start_base_container(spec)
        info = json.loads(_docker("inspect", name).stdout)[0]
        return name, info

    yield start

    for name in started:
        _docker("rm", "-f", name)


def _wait_for_systemd(name: str, timeout: int = 120) -> str:
    """Return systemd's settled state, or the last state seen before timeout."""

    deadline = time.time() + timeout
    state = ""
    while time.time() < deadline:
        result = _docker("exec", name, "systemctl", "is-system-running", timeout=30)
        state = result.stdout.strip()
        if state in {"running", "degraded"}:
            return state
        if _docker("inspect", "-f", "{{.State.Running}}", name).stdout.strip() != "true":
            return f"exited({_docker('inspect', '-f', '{{.State.ExitCode}}', name).stdout.strip()})"
        time.sleep(2)
    return state or "timeout"


@pytest.mark.integration
@requires_daemon
@pytest.mark.parametrize("image_key", ["debian", "rocky"])
def test_substrate_boots_systemd_cleanly_without_privilege(started_node, image_key):
    """systemd reaches `running` with zero failed units and no added privilege."""

    name, info = started_node(image_key)

    assert _wait_for_systemd(name) == "running", (
        "systemd must reach `running`; the retired privileged recipe reached only "
        "`degraded`"
    )
    failed = _docker(
        "exec", name, "systemctl", "--failed", "--no-legend", "--plain"
    ).stdout.strip()
    assert failed == "", f"unexpected failed units: {failed}"


@pytest.mark.integration
@requires_daemon
@pytest.mark.parametrize("image_key", ["debian", "rocky"])
def test_realized_container_carries_no_host_authority(started_node, image_key):
    """The daemon's own readback shows none of the retired privilege."""

    name, info = started_node(image_key)
    host = info["HostConfig"]

    assert host["CgroupnsMode"] == "private"
    assert not host.get("CapAdd")
    assert not host.get("Binds")
    assert "writable-cgroups=true" in (host.get("SecurityOpt") or [])
    assert not any(
        "unconfined" in str(option) for option in (host.get("SecurityOpt") or [])
    )
    assert all(
        mount.get("Destination") != "/sys/fs/cgroup" for mount in info.get("Mounts", [])
    )


@pytest.mark.integration
@requires_daemon
def test_pid1_is_seccomp_filtered_and_holds_no_extra_capability(started_node):
    """Inside the container: the filter is on, and SYS_ADMIN is not held.

    `Seccomp: 0` is what the retired `seccomp:unconfined` produced and is the
    value this issue exists to eliminate on the AI-driven boxes.
    """

    name, _info = started_node("debian")
    assert _wait_for_systemd(name) == "running"

    status = _docker("exec", name, "sh", "-c", "grep -E '^(Seccomp|CapEff):' /proc/1/status").stdout
    seccomp = next(line for line in status.splitlines() if line.startswith("Seccomp:"))
    assert seccomp.split()[1] != "0", "PID 1 must run under a seccomp filter"

    # CAP_SYS_ADMIN is bit 21; assert it is absent from PID 1's effective set
    # rather than comparing the whole mask, which varies with the daemon's
    # default capability set.
    cap_eff = int(
        next(line for line in status.splitlines() if line.startswith("CapEff:")).split()[1],
        16,
    )
    assert not cap_eff & (1 << 21), "PID 1 must not hold CAP_SYS_ADMIN"


@pytest.mark.integration
@requires_daemon
def test_the_container_cannot_see_the_host_cgroup_tree(started_node):
    """The private namespace is real: the host's docker scopes are not visible.

    Proved by contrast rather than assertion of absence alone -- the container's
    own systemd creates a `system.slice`, so merely finding that path proves
    nothing. The host's slice contains `docker-*.scope` entries; the
    container's contains only its own units.
    """

    name, _info = started_node("debian")
    assert _wait_for_systemd(name) == "running"

    visible = _docker(
        "exec", name, "sh", "-c",
        "ls /sys/fs/cgroup/system.slice 2>/dev/null | grep -c docker || true",
    ).stdout.strip()
    assert visible == "0", "the container must not see the host's container scopes"


@pytest.mark.integration
@requires_daemon
def test_a_retired_recipe_container_is_not_reused(started_node, tmp_path):
    """A warm lab's stale privileged container must be recreated, not adopted.

    This is the field case: on any machine carrying a lab from before this
    change, the container matches on name and image, so the old reuse check
    accepted it and the hardening silently never applied.
    """

    image = _IMAGES["debian"]
    if _docker("image", "inspect", image).returncode != 0:
        pytest.skip(f"{image} is not built on this host")

    name = f"aptl-955-stale-{int(time.time() * 1000)}"
    _docker(
        "run", "-d", "--name", name,
        "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        "--cap-add", "SYS_ADMIN", "--cap-add", "SYS_NICE", "--cap-add", "SYS_RESOURCE",
        "--security-opt", "seccomp:unconfined",
        "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp",
        "-e", "container=docker", image,
    )
    try:
        backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl955")
        spec = BaseContainerSpec(
            node_address="provision.node.debian",
            container_name=name,
            image_ref=image,
            runs_services=True,
            init=InitRequirements(),
        )
        assert not backend._base_container_already_realized(spec, image)
    finally:
        _docker("rm", "-f", name)
