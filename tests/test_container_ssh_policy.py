"""SSH policy lives in an APTL drop-in, not in edits to the vendor config.

Ubuntu 26.04 ships ``openssh-server`` with an ``Include
/etc/ssh/sshd_config.d/*.conf`` near the top of the distribution's own
``sshd_config``, and the package already owns ``/run/sshd``. The old layer
(``mkdir /var/run/sshd`` plus three ``sed`` rewrites of the vendor file) failed
the build on the ``mkdir`` and, had it survived, would have kept APTL's policy
in a file the distribution owns.

These are regression guards on the Dockerfile text, not proof of policy: what
the daemon actually enforces is established by running ``sshd -T`` in the built
image (issue #1006), because a file can say anything. They exist so the
``sed``-the-vendor-file pattern cannot come back unnoticed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.helpers import dockerfile_copies

REPO_ROOT = Path(__file__).resolve().parents[1]

# Both Ubuntu substrates duplicate the shared base layer, so both must carry it.
_UBUNTU_SUBSTRATES = (
    Path("containers/base/Dockerfile.ubuntu"),
    Path("containers/reverse/Dockerfile"),
)
_DROP_IN = Path("containers/base/sshd/00-aptl-hardening.conf")
_REQUIRED_DIRECTIVES = (
    "PermitRootLogin no",
    "PasswordAuthentication no",
    "PubkeyAuthentication yes",
)
_VENDOR_CONFIG_EDIT = re.compile(r"sed\b[^\n]*/etc/ssh/sshd_config\b(?!\.d)")
_RUN_SSHD_MKDIR = re.compile(r"mkdir\b[^\n]*/(var/)?run/sshd\b")


def test_drop_in_states_the_whole_policy() -> None:
    text = (REPO_ROOT / _DROP_IN).read_text(encoding="utf-8")
    missing = [d for d in _REQUIRED_DIRECTIVES if d not in text.splitlines()]
    assert not missing, f"{_DROP_IN} no longer states: {missing}"


def test_drop_in_sorts_ahead_of_distribution_drop_ins() -> None:
    """OpenSSH keeps the first value it sees, so precedence is lexical."""
    assert _DROP_IN.name.startswith("00-"), (
        f"{_DROP_IN.name} must sort before any distribution drop-in, "
        "or the distribution's value wins."
    )


@pytest.mark.parametrize("dockerfile", _UBUNTU_SUBSTRATES, ids=str)
def test_ubuntu_substrate_installs_the_drop_in(dockerfile: Path) -> None:
    """The drop-in must be COPYed into the directory sshd includes.

    Checked on the parsed COPY instruction, not on file text: a comment naming
    `/etc/ssh/sshd_config.d/` used to satisfy this while the real COPY could
    point anywhere.
    """
    copies = dockerfile_copies(REPO_ROOT / dockerfile)
    assert (f"base/sshd/{_DROP_IN.name}", "/etc/ssh/sshd_config.d/") in copies, (
        f"{dockerfile} does not COPY {_DROP_IN.name} into /etc/ssh/sshd_config.d/; "
        f"its COPY instructions are {copies}"
    )


@pytest.mark.parametrize("dockerfile", _UBUNTU_SUBSTRATES, ids=str)
def test_ubuntu_substrate_does_not_edit_the_vendor_config(dockerfile: Path) -> None:
    text = (REPO_ROOT / dockerfile).read_text(encoding="utf-8")
    assert not _VENDOR_CONFIG_EDIT.search(text), (
        f"{dockerfile} edits /etc/ssh/sshd_config in place. State the policy in "
        f"{_DROP_IN} instead; the vendor file's layout is not APTL's to depend on."
    )


@pytest.mark.parametrize("dockerfile", _UBUNTU_SUBSTRATES, ids=str)
def test_ubuntu_substrate_does_not_recreate_the_package_owned_rundir(
    dockerfile: Path,
) -> None:
    text = (REPO_ROOT / dockerfile).read_text(encoding="utf-8")
    assert not _RUN_SSHD_MKDIR.search(text), (
        f"{dockerfile} recreates /run/sshd, which openssh-server already owns; "
        "on Ubuntu 26.04 that fails the build."
    )


def test_copy_parser_ignores_comments_and_pairs_source_with_destination(tmp_path):
    """A commented destination or a split COPY must not look like the real one."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM scratch\n"
        "# COPY base/sshd/00-aptl-hardening.conf /etc/ssh/sshd_config.d/\n"
        "COPY --chmod=644 base/sshd/00-aptl-hardening.conf /tmp/\n"
        "COPY other.conf \\\n"
        "     /etc/ssh/sshd_config.d/\n",
        encoding="utf-8",
    )

    copies = dockerfile_copies(dockerfile)

    assert ("base/sshd/00-aptl-hardening.conf", "/etc/ssh/sshd_config.d/") not in copies
    assert ("base/sshd/00-aptl-hardening.conf", "/tmp/") in copies
    assert ("other.conf", "/etc/ssh/sshd_config.d/") in copies
