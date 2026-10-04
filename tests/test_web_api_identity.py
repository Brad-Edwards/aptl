"""The split web API runs as the project's owner, never as root (issue #1193).

The API reads lab state the operator's ``aptl`` process wrote under the mounted
project, including owner-only (0600) records, and reaches the daemon through
the bind-mounted Docker socket. So the container runs as the project owner's
uid/gid with only the socket's group added. Both come from the operator's
``.env`` — the supported setup for the Compose ``web`` profile — and an unset
value must stop container creation rather than fall back to root or to an
identity that silently cannot read lab state.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _api_service() -> dict:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"]["aptl-web-api"]


def _fallback(value: str, variable: str) -> str:
    match = re.fullmatch(r"\$\{" + variable + r":-(?P<fallback>[^}]+)\}", value)
    assert match, f"{value!r} is not interpolated from {variable}"
    return match.group("fallback")


def test_api_runs_as_the_configured_project_owner() -> None:
    fallback = _fallback(_api_service()["user"], "APTL_WEB_API_USER")
    # A non-numeric name exists in no image, so Docker refuses to create the
    # container instead of running it as root or as the image's default user.
    assert not re.fullmatch(r"[0-9]+(:[0-9]+)?", fallback)


def test_api_joins_only_the_configured_socket_group() -> None:
    groups = _api_service()["group_add"]
    assert len(groups) == 1
    fallback = _fallback(groups[0], "APTL_DOCKER_SOCKET_GID")
    assert not fallback.isdigit()


def test_api_image_default_user_is_not_root() -> None:
    dockerfile = (REPO_ROOT / "web" / "Dockerfile.api").read_text(encoding="utf-8")
    users = re.findall(r"^USER\s+(\S+)", dockerfile, re.MULTILINE)
    assert users and users[-1].split(":")[0] not in {"0", "root"}


def test_env_example_documents_how_to_set_both_values() -> None:
    example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^APTL_WEB_API_USER=", example, re.MULTILINE)
    assert re.search(r"^APTL_DOCKER_SOCKET_GID=", example, re.MULTILINE)
    assert "id -u" in example and "id -g" in example
    assert "stat -c %g /var/run/docker.sock" in example


def test_web_reference_names_the_setup_values() -> None:
    reference = (REPO_ROOT / "docs" / "reference" / "web.md").read_text(encoding="utf-8")
    assert "APTL_WEB_API_USER" in reference
    assert "APTL_DOCKER_SOCKET_GID" in reference
