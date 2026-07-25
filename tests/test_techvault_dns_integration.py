"""Real-Docker proof: a real TechVault node (dns) boots working image-free.

Authors the dns node from its real bind9 config + zones as declared ACES state
(admitted straight from `scenarios/techvault-operational.sdl.yaml`, not a
reauthored fixture), realizes it via the generic materializer, and asserts
named is active and resolves the real TechVault zone. Zero product code.
Marked `integration`; skipped without Docker.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from aces_sdl import parse_sdl_file
from aces_runtime.manager import RuntimeManager

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_materializer import PlaceFileOp, PlaceProjectContentOp
from aptl.backends.aces_node_materialization import realize_node
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment.docker_compose import DockerComposeBackend

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True).returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_dns_node_boots_image_free_and_resolves():
    repo = Path(__file__).resolve().parent.parent
    subprocess.run(
        ["docker", "build", "-t", "aptl/generic-systemd-base-debian:latest",
         str(repo / "containers/generic-systemd-base-debian")],
        capture_output=True, text=True, timeout=600,
    )
    subprocess.run(["docker", "rm", "-f", "aptl-dns"], capture_output=True, text=True)

    cfg = AptlConfig(lab={"name": "x"}, containers={})
    be = DockerComposeBackend(project_dir=repo, project_name="aptl")
    plan = RuntimeManager(
        create_aptl_runtime_target(project_dir=repo, config=cfg, backend=be)
    ).plan(parse_sdl_file(repo / "scenarios/techvault-operational.sdl.yaml"))
    real = interpret_provisioning_plan(plan=plan.provisioning, project_dir=repo, config=cfg)
    assert [x.message for x in real.diagnostics if x.is_error] == []
    spec = real.deployment_spec([])

    dns_node = next(n for n in spec.nodes if n.name == "dns")
    dns_content = [c for c in spec.content if c.target_address == dns_node.address]
    ops = []
    for c in dns_content:
        dest = "/" + c.dest_relpath.lstrip("/")
        if c.source_kind == "inline-text":
            ops.append(PlaceFileOp(path=dest, content=c.inline_text))
        elif c.source_kind in ("project-file", "project-directory"):
            ops.append(
                PlaceProjectContentOp(
                    dest_path=dest,
                    source_relpath=c.source_relpath,
                    is_directory=c.source_kind == "project-directory",
                )
            )

    try:
        result = realize_node(dns_node, be, tuple(ops))
        assert result is None, getattr(result, "error", None)
        assert be.container_exec(
            "aptl-dns", ["systemctl", "is-active", "named.service"]
        ).stdout.strip() == "active"
        # The real named.conf's custom log channels wrote into a directory
        # this materialization must create and chown to bind:bind (the user
        # named drops privileges to via `-u bind`); prove it actually did.
        assert be.container_exec(
            "aptl-dns", ["stat", "-c", "%U:%G", "/var/log/named"]
        ).stdout.strip() == "bind:bind"
        # named serves the real TechVault zone.
        dig = be.container_exec(
            "aptl-dns", ["dig", "+short", "@127.0.0.1", "webapp.techvault.local"]
        )
        assert "172.20.1.20" in dig.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", "aptl-dns"], capture_output=True, text=True)
