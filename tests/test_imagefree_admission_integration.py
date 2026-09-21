"""Full-stack real-Docker test: admit an image-free SDL and realize it (ADR-048).

Exercises the entire path through the real RAES compiler:
parse -> plan -> interpret -> deployment_spec (image_free derived) ->
backend.realize -> generic materializer -> real container, verified by
read-after-write. Zero product code; proves an arbitrary image-free scenario
composes and boots on local Docker.

One scenario, the shared `materialization-envelope.sdl.yaml`. A second live
scenario used to boot the same service path on the dnf/RHEL substrate; issue
#993 retired it, because the shared fixture now proves that path live here and
again in the installed-wheel boot gate, while the family-aware substrate
selection the second scenario actually distinguished is a pure lookup already
pinned in `tests/test_raes_materializer.py` — which, unlike either live test,
runs in CI. What no longer has live coverage is Rocky's systemd booting under
APTL's init flags; no shipped scenario declares a dnf node, and
`docs/testing/boot-realization-coverage.md` records that as an explicit gap.

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
