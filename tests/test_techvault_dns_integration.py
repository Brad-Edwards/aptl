"""Real-Docker proof: a real TechVault node (dns) boots working image-free.

Authors the dns node from its real bind9 config + zones as declared ACES state,
admits it through the real ACES compiler, realizes it via the generic
materializer, and asserts named is active and resolves the real TechVault zone.
Zero product code. Marked `integration`; skipped without Docker.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml
from aces_sdl import parse_sdl_file
from aces_runtime.manager import RuntimeManager

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment.docker_compose import DockerComposeBackend

pytestmark = pytest.mark.integration

_NAMED_CONF = """options {
    directory "/var/cache/bind";
    recursion yes;
    allow-recursion { 172.20.0.0/16; };
    listen-on { any; };
    forwarders { 8.8.8.8; };
    dnssec-validation no;
};
zone "techvault.local" { type master; file "/etc/bind/zones/techvault.local.zone"; };
zone "20.172.in-addr.arpa" { type master; file "/etc/bind/zones/172.20.rev"; };
"""


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
    zone_fwd = (repo / "containers/dns/zones/techvault.local.zone").read_text()
    zone_rev = (repo / "containers/dns/zones/172.20.rev").read_text()
    sdl = {
        "name": "techvault-dns",
        "nodes": {
            "net": {"type": "switch", "description": "n"},
            "dns": {"type": "vm", "os": "linux", "runtime": {
                "packages": [
                    {"manager": "apt", "name": "bind9", "version": "*"},
                    {"manager": "apt", "name": "dnsutils", "version": "*"},
                ],
                "service_manager_units": [
                    {"unit_id": "named", "unit_name": "named.service",
                     "enabled_state": "enabled", "active_state": "active"},
                ],
            }},
        },
        "content": {
            "named-conf": {"type": "file", "target": "dns",
                           "path": "/etc/bind/named.conf", "text": _NAMED_CONF},
            "zone-fwd": {"type": "file", "target": "dns",
                         "path": "/etc/bind/zones/techvault.local.zone", "text": zone_fwd},
            "zone-rev": {"type": "file", "target": "dns",
                         "path": "/etc/bind/zones/172.20.rev", "text": zone_rev},
        },
    }
    d = Path(tempfile.mkdtemp())
    (d / "dns.sdl.yaml").write_text(yaml.safe_dump(sdl))
    subprocess.run(["docker", "rm", "-f", "aptl-dns"], capture_output=True, text=True)

    cfg = AptlConfig(lab={"name": "x"}, containers={})
    be = DockerComposeBackend(project_dir=d, project_name="aptl-dns-test")
    plan = RuntimeManager(
        create_aptl_runtime_target(project_dir=d, config=cfg, backend=be)
    ).plan(parse_sdl_file(d / "dns.sdl.yaml"))
    real = interpret_provisioning_plan(plan=plan.provisioning, project_dir=d, config=cfg)
    assert [x.message for x in real.diagnostics if x.is_error] == []
    spec = real.deployment_spec([])
    assert spec.image_free is True

    try:
        res = be.realize(spec)
        assert res.success, res.error
        assert be.container_exec(
            "aptl-dns", ["systemctl", "is-active", "named.service"]
        ).stdout.strip() == "active"
        # named serves the real TechVault zone.
        dig = be.container_exec(
            "aptl-dns", ["dig", "+short", "@127.0.0.1", "webapp.techvault.local"]
        )
        assert "172.20.1.20" in dig.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", "aptl-dns"], capture_output=True, text=True)
