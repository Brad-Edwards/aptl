"""Full-stack real-Docker test: admit an image-free SDL and realize it (ADR-047).

Exercises the entire path through the real ACES compiler:
parse -> plan -> interpret -> deployment_spec (image_free derived) ->
backend.realize -> generic materializer -> real container, verified by
read-after-write. Zero product code; proves an arbitrary image-free scenario
composes and boots on local Docker.

Marked `integration`; skipped without Docker.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from aces_sdl import parse_sdl_file
from aces_runtime.manager import RuntimeManager

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment.docker_compose import DockerComposeBackend

pytestmark = pytest.mark.integration

_SDL = """\
name: imagefree-admission-smoke
description: Minimal image-free scenario (ADR-047 full-stack validation).
nodes:
  smoke-net:
    type: switch
    description: smoke net
  smoke-box:
    type: vm
    os: linux
    runtime:
      packages:
        - {manager: apt, name: curl, version: "1.0"}
      local_identity:
        groups:
          - {name: analysts}
        users:
          - {username: analyst, supplemental_groups: [analysts]}
"""


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True).returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_admit_and_realize_image_free_scenario_on_real_docker(tmp_path):
    sdl = tmp_path / "imagefree.sdl.yaml"
    sdl.write_text(_SDL, encoding="utf-8")
    container = "aptl-smoke-box"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)

    cfg = AptlConfig(lab={"name": "smoke"}, containers={})
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl-imagefree-admit")

    # Admit through the real ACES compiler/planner/interpreter.
    scenario = parse_sdl_file(sdl)
    target = create_aptl_runtime_target(project_dir=tmp_path, config=cfg, backend=backend)
    plan = RuntimeManager(target).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=plan.provisioning, project_dir=tmp_path, config=cfg
    )
    assert [d.message for d in realization.diagnostics if d.is_error] == []

    spec = realization.deployment_spec([])
    assert spec.image_free is True

    try:
        result = backend.realize(spec)
        assert result.success, result.error
        assert "curl" in backend.container_exec(
            container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
        ).stdout
        assert backend.container_exec(container, ["id", "-u", "analyst"]).returncode == 0
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)


_SERVICE_SDL = """\
name: imagefree-service-smoke
description: Image-free scenario with a running service (ADR-047 systemd path).
nodes:
  svc-net:
    type: switch
    description: svc net
  svc-box:
    type: vm
    os: linux
    runtime:
      packages:
        - {manager: dnf, name: openssh-server, version: "*"}
      service_manager_units:
        - {unit_id: sshd, unit_name: sshd.service, enabled_state: enabled, active_state: active}
"""


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_admit_and_realize_service_node_boots_a_real_service(tmp_path):
    # Ensure the generic systemd base exists (built from the checked-in Dockerfile).
    subprocess.run(
        ["docker", "build", "-t", "aptl/generic-systemd-base:latest",
         "containers/generic-systemd-base"],
        capture_output=True, text=True, timeout=600,
    )
    sdl = tmp_path / "svc.sdl.yaml"
    sdl.write_text(_SERVICE_SDL, encoding="utf-8")
    container = "aptl-svc-box"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)

    cfg = AptlConfig(lab={"name": "svc"}, containers={})
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl-imagefree-svc")
    scenario = parse_sdl_file(sdl)
    target = create_aptl_runtime_target(project_dir=tmp_path, config=cfg, backend=backend)
    plan = RuntimeManager(target).plan(scenario)
    realization = interpret_provisioning_plan(plan=plan.provisioning, project_dir=tmp_path, config=cfg)
    assert [d.message for d in realization.diagnostics if d.is_error] == []
    spec = realization.deployment_spec([])
    assert spec.image_free is True

    try:
        result = backend.realize(spec)
        assert result.success, result.error
        # The service the SDL declared is really running.
        active = backend.container_exec(container, ["systemctl", "is-active", "sshd.service"])
        assert active.stdout.strip() == "active"
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
