"""Content-source policy tests: forbidden paths + key-material allowlist (#816).

A retroactive Codex security review of PR #812 found that content-placement
source resolution only checked project-root containment, not *which*
in-repo file was selected — a scenario could name `.env` (real operator
credentials) as its source, targeting a participant-accessible node like
kali, and the file would be copied in. These tests pin the fix: universal
secret paths are always rejected regardless of project-root containment,
and the one legitimate exception (keys/ + config/lab-ssh/, which hold both
distributable public keys and the SEC #417 pivot private keys) is
restricted to the exact filenames src/aptl/core/ssh.py generates.
"""

from __future__ import annotations

import pytest
from aces_contracts.planning import PlannedResource, RuntimeDomain

from aptl.backends.aces_content_realization import (
    _forbidden_source_reason,
    resolve_content_placement,
    resolve_image_free_content_placement,
)

# --------------------------------------------------------------------------- #
# _forbidden_source_reason — pure policy function
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "source_name",
    [
        ".env",
        ".env.local",
        ".env.development.local",
        ".env.production.local",
        "config/soc_certs/ca.key",
        "config/wazuh_indexer_ssl_certs/indexer.pem",
        ".git/config",
        ".git",
        "keys/some_new_secret",
        "config/lab-ssh/other_key",
    ],
)
def test_forbidden_or_unlisted_sources_are_rejected(source_name):
    assert _forbidden_source_reason(source_name) is not None


@pytest.mark.parametrize(
    "source_name",
    [
        "keys/aptl_lab_key.pub",
        "keys/authorized_keys",
        "keys/target_authorized_keys",
        "keys/victim_authorized_keys",
        "config/lab-ssh/kali_pivot_key",
        "config/lab-ssh/kali_pivot_key.pub",
        "config/lab-ssh/workstation_pivot_key",
        "config/lab-ssh/workstation_pivot_key.pub",
        "src",
        "pyproject.toml",
        "README.md",
        "hatch_build.py",
        "containers/db/init/01-schema.sql",
        "containers/kali/scripts/aptl-wrap-shell.sh",
    ],
)
def test_legitimate_sources_are_not_forbidden(source_name):
    assert _forbidden_source_reason(source_name) is None


def test_leading_slash_does_not_bypass_the_check():
    assert _forbidden_source_reason("/.env") is not None
    assert _forbidden_source_reason("/config/soc_certs/ca.key") is not None


# --------------------------------------------------------------------------- #
# resolve_content_placement — legacy (Compose-managed) entry point
# --------------------------------------------------------------------------- #


def _resource(address: str = "provision.content-placement.attack") -> PlannedResource:
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={},
    )


def _file_payload(source_name: str, *, dest: str = "public/leak.txt") -> dict:
    return {
        "name": "attack",
        "content_name": "attack",
        "target_node": "fileshare",
        "target_address": "provision.node.fileshare",
        "spec": {
            "type": "file",
            "description": "",
            "target": "fileshare",
            "path": dest,
            "destination": "",
            "text": None,
            "source": {"name": source_name, "version": "*", "build": None},
            "format": "",
            "items": [],
            "sensitive": False,
            "tags": [],
        },
    }


def test_legacy_path_rejects_dotenv_as_a_content_source(tmp_path):
    (tmp_path / ".env").write_text("MISP_API_KEY=real-secret-value\n")
    payload = _file_payload(".env")

    content, diagnostics = resolve_content_placement(
        resource=_resource(),
        payload=payload,
        target_address="provision.node.fileshare",
        target_service="fileshare",
        project_dir=tmp_path,
    )

    assert content is None
    assert len(diagnostics) == 1
    assert diagnostics[0].is_error


def test_legacy_path_still_realizes_an_allowed_key_source(tmp_path):
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "victim_authorized_keys").write_text("ssh-ed25519 AAAA...\n")
    payload = _file_payload("keys/victim_authorized_keys")

    content, diagnostics = resolve_content_placement(
        resource=_resource(),
        payload=payload,
        target_address="provision.node.fileshare",
        target_service="fileshare",
        project_dir=tmp_path,
    )

    assert diagnostics == []
    assert content is not None
    assert content.source_relpath == "keys/victim_authorized_keys"


def test_legacy_path_rejects_an_unlisted_file_under_keys(tmp_path):
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "some_new_secret").write_text("shh\n")
    payload = _file_payload("keys/some_new_secret")

    content, diagnostics = resolve_content_placement(
        resource=_resource(),
        payload=payload,
        target_address="provision.node.fileshare",
        target_service="fileshare",
        project_dir=tmp_path,
    )

    assert content is None
    assert len(diagnostics) == 1
    assert diagnostics[0].is_error


# --------------------------------------------------------------------------- #
# resolve_image_free_content_placement — ADR-048 generic-materializer entry point
# --------------------------------------------------------------------------- #


def _image_free_payload(source_name: str, *, dest: str = "/home/kali/leak.txt") -> dict:
    return {
        "name": "attack",
        "content_name": "attack",
        "spec": {
            "type": "file",
            "description": "",
            "target": "kali",
            "path": dest,
            "destination": "",
            "text": None,
            "source": {"name": source_name, "version": "*", "build": None},
            "format": "",
            "items": [],
            "sensitive": False,
            "tags": [],
        },
    }


def test_image_free_path_rejects_dotenv_targeting_kali():
    payload = _image_free_payload(".env")

    content, diagnostics = resolve_image_free_content_placement(
        resource=_resource(),
        payload=payload,
        target_address="provision.node.kali",
    )

    assert content is None
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "aptl.provisioner.content-source-forbidden"
    assert diagnostics[0].is_error


def test_image_free_path_still_realizes_the_kali_pivot_key():
    payload = _image_free_payload(
        "config/lab-ssh/kali_pivot_key", dest="/home/kali/.ssh/kali_pivot_key"
    )

    content, diagnostics = resolve_image_free_content_placement(
        resource=_resource(),
        payload=payload,
        target_address="provision.node.kali",
    )

    assert diagnostics == []
    assert content is not None
    assert content.source_relpath == "config/lab-ssh/kali_pivot_key"


def test_image_free_path_rejects_an_unlisted_file_under_config_lab_ssh():
    payload = _image_free_payload(
        "config/lab-ssh/other_key", dest="/home/kali/.ssh/other_key"
    )

    content, diagnostics = resolve_image_free_content_placement(
        resource=_resource(),
        payload=payload,
        target_address="provision.node.kali",
    )

    assert content is None
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "aptl.provisioner.content-source-forbidden"
