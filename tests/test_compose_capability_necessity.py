"""Why two substrates keep CAP_SYS_ADMIN when the systemd substrate gave it up (#955).

Issue #955 removed `CAP_SYS_ADMIN` from every node on the generic systemd
substrate. Two realizations keep their own grant, and this module holds the
measurements that justify them, so each is a documented, tested necessity
rather than an assumption nobody rechecked. Both were judged on their own
evidence: the substrate's own three capabilities looked equally load-bearing
right up until they were measured and turned out not to be.

The Active Directory domain controller is realized on the backend-selected Samba
provider base (`_raes_backend_implementation_profiles._active_directory_base`),
which runs Samba directly, not systemd. `samba-tool domain provision` writes the
sysvol's NT ACLs into the `security.NTACL` extended attribute, and the kernel
gates writes to the whole `security.*` xattr namespace behind CAP_SYS_ADMIN.
Without it, provisioning fails at `setsysvolacl` -> `smbd.set_nt_acl` with
NT_STATUS_ACCESS_DENIED before the domain exists.

`reverse` runs systemd, and moves to the new cgroup v2 posture, but keeps one
capability. Its first-boot `reverse-tools-install.service` installs falco, whose
dpkg post-install runs `falcoctl driver install` (driver type kmod). A bisect on
a real boot isolated the cause instead of assuming it: default seccomp plus
CAP_SYS_ADMIN reaches `active`; `seccomp:unconfined` with no capability still
fails. So the capability is required and the unconfined profile, SYS_NICE, and
SYS_RESOURCE are not.

Issue #976 evaluates replacing both product choices so neither grant is needed.

The behavioural test is marked `integration` (per-test, not module-level, so the
default `-k "not integration"` run does not zero this module's coverage) because
it needs a real Docker daemon and the built Samba provider image. The contract
tests run everywhere and fail if a grant or its rationale is quietly dropped.
"""

from __future__ import annotations

import inspect
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from aptl.backends import _raes_backend_implementation_profiles as profiles
from aptl.backends._raes_backend_implementation_images import SAMBA_AD_BASE_IMAGE
from aptl.backends.raes_node_materialization import realize_node
from aptl.core.deployment.docker_compose import DockerComposeBackend

PROJECT_ROOT = Path(__file__).parents[1]


def test_the_samba_provider_selects_exactly_the_measured_capability():
    """The provider's own minimum is SYS_ADMIN and nothing else.

    NET_ADMIN (the in-process Wazuh agent's `firewall-drop` response) is an
    authored runtime grant, not part of the provider substrate's minimum.
    """

    source = inspect.getsource(profiles._active_directory_base)

    assert 'run_capabilities=("SYS_ADMIN",)' in source


def test_the_samba_capability_rationale_is_recorded_beside_the_grant():
    """A future reader must find WHY before deciding this is cargo cult.

    The substrate's own three capabilities looked equally load-bearing and were
    not; the difference here is a measurement, and a measurement that is not
    written down beside the grant is one nobody will repeat.
    """

    source = inspect.getsource(profiles._active_directory_base)

    assert "security.NTACL" in source
    assert "955" in source


class _StartRecorder:
    """A backend that records the base container the materializer starts.

    Raising from the start stops materialization there, so nothing else runs
    and no Docker daemon is needed.
    """

    def __init__(self) -> None:
        self.started = []
        self.copied = []

    def start_base_container(self, spec) -> None:
        self.started.append(spec)
        raise RuntimeError("recorded, not started")

    def copy_into_container(self, *args, **kwargs) -> None:
        self.copied.append((args, kwargs))


# `docker run` flags that would give the container more than its added capability.
_PRIVILEGE_FLAGS = frozenset(
    {"--privileged", "--security-opt", "--cgroupns", "--userns", "--pid", "--ipc"}
)


def test_the_realized_ad_node_carries_only_the_provider_capability(
    rendered_techvault, tmp_path
):
    """`ad` in Compose is a scale-to-zero stub; the grant lives on the provider.

    So the check drives the pinned pack's realized `ad` node through the
    materializer to the base container it starts, and renders that
    container's `docker run` command (#954). The Samba provider adds
    SYS_ADMIN and nothing else, the scenario authors no capability of its
    own, and no security option or namespace flag comes with it.
    """

    ad = next(node for node in rendered_techvault.nodes if node.name == "ad")
    backend = _StartRecorder()

    result = realize_node(ad, backend)

    assert len(backend.started) == 1, result
    assert not backend.copied, result
    (started,) = backend.started
    argv = DockerComposeBackend(tmp_path)._base_container_create_command(
        started, None, started.image_ref
    )
    # Docker reads both `--cap-add X` and `--cap-add=X`.
    added = [argv[index + 1] for index, flag in enumerate(argv) if flag == "--cap-add"]
    added += [flag.split("=", 1)[1] for flag in argv if flag.startswith("--cap-add=")]
    assert ad.runtime is None or ad.runtime.linux_capabilities is None
    assert added == ["SYS_ADMIN"]
    assert not {flag.split("=", 1)[0] for flag in argv} & _PRIVILEGE_FLAGS, argv


def _write_security_xattr(*cap_flags: str) -> subprocess.CompletedProcess:
    """Attempt the provision's `security.*` xattr write with the given grants."""

    argv = [
        "docker", "run", "--rm",
        "--entrypoint", "python3",
        *cap_flags,
        SAMBA_AD_BASE_IMAGE,
        "-c",
        # Exercise the exact kernel permission the provision depends on, rather
        # than waiting out a full domain provision: writing any `security.*`
        # xattr is what Samba's setntacl ultimately performs.
        "import os; os.makedirs('/tmp/acl', exist_ok=True); "
        "os.setxattr('/tmp/acl', 'security.NTACL', b'\\x01\\x00\\x00')",
    ]
    return subprocess.run(argv, capture_output=True, text=True, timeout=300)


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="needs a Docker daemon")
def test_security_xattr_write_requires_sys_admin_in_the_samba_provider_image():
    """The measurement itself: drop SYS_ADMIN and the provisioning write fails.

    Goes red if someone removes the grant believing it is unnecessary -- the
    failure mode this test exists to prevent.
    """

    if subprocess.run(
        ["docker", "image", "inspect", SAMBA_AD_BASE_IMAGE],
        capture_output=True,
        check=False,
    ).returncode != 0:
        pytest.skip(f"{SAMBA_AD_BASE_IMAGE} is not built on this host")

    without = _write_security_xattr()
    assert without.returncode != 0
    assert "Operation not permitted" in (without.stderr + without.stdout)

    with_sys_admin = _write_security_xattr("--cap-add", "SYS_ADMIN")
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
