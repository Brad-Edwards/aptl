"""Why two Compose services keep CAP_SYS_ADMIN when the substrate gave it up (#955).

Issue #955 removed `CAP_SYS_ADMIN` from every node on the generic systemd
substrate. Two Compose-managed services keep their own grant, and this module
holds the measurements that justify them, so each is a documented, tested
necessity rather than an assumption nobody rechecked. Both were judged on their
own evidence: neither runs the substrate's systemd recipe, so neither could
inherit the substrate's proof, and the substrate's own three capabilities looked
equally load-bearing right up until they were measured and turned out not to be.

`ad` runs supervisord. `samba-tool domain provision` writes the sysvol's NT ACLs
into the `security.NTACL` extended attribute, and the kernel gates writes to the
whole `security.*` xattr namespace behind CAP_SYS_ADMIN. Without it, provisioning
fails at `setsysvolacl` -> `smbd.set_nt_acl` with NT_STATUS_ACCESS_DENIED and the
container exits 255 before the domain exists.

`reverse` runs systemd, and moves to the new cgroup v2 posture, but keeps one
capability. Its first-boot `reverse-tools-install.service` installs falco, whose
dpkg post-install runs `falcoctl driver install` (driver type kmod). A bisect on
a real boot isolated the cause instead of assuming it: default seccomp plus
CAP_SYS_ADMIN reaches `active`; `seccomp:unconfined` with no capability still
fails. So the capability is required and the unconfined profile, SYS_NICE, and
SYS_RESOURCE are not.

The behavioural test is marked `integration` (per-test, not module-level, so the
default `-k "not integration"` run does not zero this module's coverage) because
it needs a real Docker daemon and the built AD image. The Compose-contract tests
run everywhere and fail if a grant or its rationale is quietly dropped.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).parents[1]
_AD_IMAGE = "aptl-ad-probe:latest"


def _ad_service() -> dict:
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    return compose["services"]["ad"]


def test_ad_still_declares_the_measured_capability_grant():
    """The grant is intentional, and both capabilities are still distinct needs."""

    cap_add = _ad_service().get("cap_add") or []

    # SYS_ADMIN: security.NTACL xattr writes during domain provisioning.
    # NET_ADMIN: the in-process Wazuh agent's `firewall-drop` active response.
    assert set(cap_add) == {"SYS_ADMIN", "NET_ADMIN"}


def test_the_ad_capability_rationale_is_recorded_beside_the_grant():
    """A future reader must find WHY before deciding this is cargo cult.

    The substrate's own three capabilities looked equally load-bearing and were
    not; the difference here is a measurement, and a measurement that is not
    written down beside the grant is one nobody will repeat.
    """

    compose_text = (PROJECT_ROOT / "docker-compose.yml").read_text()

    assert "security.NTACL" in compose_text
    assert "955" in compose_text


def test_ad_does_not_use_the_retired_systemd_recipe():
    """`ad` runs supervisord; it must never acquire the substrate's old flags."""

    service = _ad_service()

    assert service.get("cgroup") != "host"
    assert "seccomp:unconfined" not in (service.get("security_opt") or [])
    assert not any(
        str(volume).startswith("/sys/fs/cgroup")
        for volume in (service.get("volumes") or [])
    )


def _run_ad(*cap_flags: str) -> subprocess.CompletedProcess:
    """Attempt an AD provision with the given capability set."""

    name = f"aptl-ad-captest-{'-'.join(cap_flags) or 'none'}".replace("--", "")
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    argv = [
        "docker", "run", "--rm", "--name", name, "--hostname", "ad",
        "-e", "SAMBA_DOMAIN=TECHVAULT",
        "-e", "SAMBA_REALM=TECHVAULT.LOCAL",
        "-e", "SAMBA_ADMIN_PASSWORD=Admin123!",
        "--entrypoint", "sh",
        *cap_flags,
        _AD_IMAGE,
        "-c",
        # Exercise the exact kernel permission the provision depends on, rather
        # than waiting out a full domain provision: writing any `security.*`
        # xattr is what Samba's setntacl ultimately performs.
        "mkdir -p /tmp/acl && setfattr -n security.NTACL -v 0sAQAA /tmp/acl",
    ]
    return subprocess.run(argv, capture_output=True, text=True, timeout=300)


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="needs a Docker daemon")
def test_security_xattr_write_requires_sys_admin_in_the_ad_image():
    """The measurement itself: drop SYS_ADMIN and the provisioning step fails.

    Goes red if someone removes the grant from docker-compose.yml believing it
    is unnecessary -- the failure mode this test exists to prevent.
    """

    if subprocess.run(
        ["docker", "image", "inspect", _AD_IMAGE], capture_output=True, check=False
    ).returncode != 0:
        pytest.skip(f"{_AD_IMAGE} is not built on this host")

    without = _run_ad("--cap-add", "NET_ADMIN")
    assert without.returncode != 0
    assert "Operation not permitted" in (without.stderr + without.stdout)

    with_sys_admin = _run_ad("--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN")
    assert with_sys_admin.returncode == 0, with_sys_admin.stderr


def _reverse_service() -> dict:
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    return compose["services"]["reverse"]


def test_reverse_moved_off_the_retired_systemd_recipe():
    """issue #955: the `reverse` profile's service uses the new cgroup v2 posture.

    It is not in the default range, but a shipped compatibility model still
    emitting the retired flags would make "the range is hardened" untrue.
    """

    service = _reverse_service()

    assert service.get("cgroup") == "private"
    assert "writable-cgroups=true" in (service.get("security_opt") or [])
    assert "seccomp:unconfined" not in (service.get("security_opt") or [])
    assert not any(
        str(volume).startswith("/sys/fs/cgroup")
        for volume in (service.get("volumes") or [])
    )


def test_reverse_keeps_only_the_capability_the_bisect_justified():
    """SYS_NICE and SYS_RESOURCE were unnecessary; SYS_ADMIN was not.

    Measured by bisect on a real boot: with the default seccomp profile and
    CAP_SYS_ADMIN, `reverse-tools-install.service` reaches active; with
    `seccomp:unconfined` and no capability it fails on falco's
    `falcoctl driver install` postinst. So exactly one capability survives, and
    the two that were carried alongside it do not.
    """

    assert set(_reverse_service().get("cap_add") or []) == {"SYS_ADMIN"}


def test_the_reverse_capability_rationale_is_recorded_beside_the_grant():
    compose_text = (PROJECT_ROOT / "docker-compose.yml").read_text()

    assert "falcoctl driver install" in compose_text
