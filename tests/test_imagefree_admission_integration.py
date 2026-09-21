"""Full-stack real-Docker test: admit an image-free SDL and realize it (ADR-048).

Exercises the entire path through the real RAES compiler:
parse -> plan -> interpret -> deployment_spec (image_free derived) ->
backend.realize -> generic materializer -> real container, verified by
read-after-write. Zero product code; proves an arbitrary image-free scenario
composes and boots on local Docker.

Marked `integration`; skipped without Docker.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from raes import parse_sdl_file
from raes_runtime.manager import RuntimeManager

from aptl.backends.raes import create_aptl_runtime_target
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.scenario_bundle import project_tree_bundle
from tests.helpers import realized_container_name, realized_project_name

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _bundle(root):
    return project_tree_bundle(root, root / "scenarios" / "demo.sdl.yaml")


_MATERIALIZATION_ENVELOPE = (
    _REPO_ROOT / "tests" / "fixtures" / "materialization-envelope.sdl.yaml"
)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, text=True).returncode
        == 0
    )


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_admit_and_realize_image_free_scenario_on_real_docker(tmp_path):
    sdl = tmp_path / "imagefree.sdl.yaml"
    shutil.copyfile(_MATERIALIZATION_ENVELOPE, sdl)
    # The shared fixture declares service units, so the node materializes onto
    # the init-capable generic substrate, which the backend builds from the
    # Dockerfile its own project dir ships (issue #1006). Stage that context
    # exactly as a real lab directory holds it.
    shutil.copytree(
        _REPO_ROOT / "containers" / "generic-systemd-base-debian",
        tmp_path / "containers" / "generic-systemd-base-debian",
    )
    container = "aptl-smoke-box"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)

    cfg = AptlConfig(lab={"name": "smoke"}, containers={})
    backend = DockerComposeBackend(
        project_dir=tmp_path, project_name="aptl-imagefree-admit"
    )

    # Admit through the real RAES compiler/planner/interpreter.
    scenario = parse_sdl_file(sdl)
    bundle = _bundle(tmp_path)
    target = create_aptl_runtime_target(
        project_dir=tmp_path, config=cfg, backend=backend, bundle=bundle
    )
    plan = RuntimeManager(target).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=plan.provisioning, config=cfg, bundle=bundle
    )
    assert [d.message for d in realization.diagnostics if d.is_error] == []

    spec = realization.deployment_spec([])
    # Fully image-free: every node is materialized, so nothing is left for the
    # Compose path (this replaces the removed whole-spec image_free flag).
    from aptl.core.deployment._compose_realization import _needs_compose

    assert _needs_compose(spec) is False

    try:
        result = backend.realize(spec, scenario_root=tmp_path)
        assert result.success, result.error
        assert (
            "curl"
            in backend.container_exec(
                container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
            ).stdout
        )
        assert (
            backend.container_exec(container, ["id", "-u", "analyst"]).returncode == 0
        )
        assert (
            backend.container_exec(
                container,
                ["stat", "-c", "%U:%G %a", "/var/lib/aptl-smoke"],
            ).stdout.strip()
            == "analyst:analysts 750"
        )
        # The #993 causal chain: the placed content is what moves the daemon
        # off its package default, so the unit and the listener below are
        # evidence that the placement really happened.
        assert (
            backend.container_exec(
                container, ["cat", "/etc/ssh/sshd_config.d/10-aptl-smoke.conf"]
            ).stdout
            == "Port 2022\n"
        )
        assert (
            backend.container_exec(
                container, ["systemctl", "is-active", "ssh.service"]
            ).stdout.strip()
            == "active"
        )
        listeners = backend.observe_container_listeners(container)
        assert listeners is not None
        assert 2022 in {port for _protocol, _address, port in listeners.sockets}
    finally:
        subprocess.run(
            ["docker", "rm", "-f", realized_container_name(backend, container)],
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "docker",
                "network",
                "rm",
                f"{realized_project_name(backend)}_aptl-smoke",
            ],
            capture_output=True,
            text=True,
        )


_SERVICE_SDL = """\
name: imagefree-service-smoke
description: Image-free scenario with a running service (ADR-048 systemd path).
nodes:
  svc-net:
    type: switch
    description: svc net
  svc-box:
    type: compute
    os: linux
    runtime:
      packages:
        - {manager: dnf, name: openssh-server, version: "*"}
      service_manager_units:
        - {unit_id: sshd, unit_name: sshd.service, enabled_state: enabled, active_state: active}
"""


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_admit_and_realize_service_node_boots_a_real_service(tmp_path):
    """The dnf/RHEL counterpart of the shared fixture's apt/Debian service path.

    Since issue #993 the shared `materialization-envelope.sdl.yaml` covers the
    apt service chain live, all the way through the installed-wheel boot gate.
    This case is kept for the one boundary that does not cover: a different
    package family selects a different generic systemd substrate
    (`generic-systemd-base`, not `generic-systemd-base-debian`) and a
    differently named unit. Its claim is narrowed accordingly — it proves the
    dnf substrate boots a declared unit, not the service path in general.
    """

    # A lab directory carries the container build contexts. The backend builds
    # the generic base from the Dockerfile its own project dir ships, on every
    # start, rather than trusting whatever `aptl/...:latest` happens to be local
    # (issue #1006) — so stage the context this scenario materializes onto,
    # exactly as a real lab directory holds it.
    shutil.copytree(
        _REPO_ROOT / "containers" / "generic-systemd-base",
        tmp_path / "containers" / "generic-systemd-base",
    )
    sdl = tmp_path / "svc.sdl.yaml"
    sdl.write_text(_SERVICE_SDL, encoding="utf-8")
    container = "aptl-svc-box"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)

    cfg = AptlConfig(lab={"name": "svc"}, containers={})
    backend = DockerComposeBackend(
        project_dir=tmp_path, project_name="aptl-imagefree-svc"
    )
    scenario = parse_sdl_file(sdl)
    bundle = _bundle(tmp_path)
    target = create_aptl_runtime_target(
        project_dir=tmp_path, config=cfg, backend=backend, bundle=bundle
    )
    plan = RuntimeManager(target).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=plan.provisioning, config=cfg, bundle=bundle
    )
    assert [d.message for d in realization.diagnostics if d.is_error] == []
    spec = realization.deployment_spec([])
    # Fully image-free: every node is materialized, so nothing is left for the
    # Compose path (this replaces the removed whole-spec image_free flag).
    from aptl.core.deployment._compose_realization import _needs_compose

    assert _needs_compose(spec) is False

    try:
        result = backend.realize(spec, scenario_root=tmp_path)
        assert result.success, result.error
        # The service the SDL declared is really running.
        active = backend.container_exec(
            container, ["systemctl", "is-active", "sshd.service"]
        )
        assert active.stdout.strip() == "active"
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], capture_output=True, text=True
        )
        subprocess.run(
            ["docker", "network", "rm", "aptl-imagefree-svc_aptl-svc"],
            capture_output=True,
            text=True,
        )
