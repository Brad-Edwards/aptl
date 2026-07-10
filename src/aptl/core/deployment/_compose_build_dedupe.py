"""Runtime Compose override generation for duplicate local builds."""

from pathlib import Path
from typing import Any

import yaml

from aptl.utils.logging import get_logger

log = get_logger("deployment.compose_build_dedupe")

# Runtime-only Compose override used to avoid building the same local tag from
# identical service build recipes twice during one ``compose up --build``.
_BUILD_DEDUPE_OVERRIDE = Path(".aptl") / "compose-build-dedupe.yml"


class _ComposeReset:
    """Sentinel rendered as Compose's ``!reset null`` merge directive."""


class _ComposeDumper(yaml.SafeDumper):
    """YAML dumper with Docker Compose merge-tag support."""


def _represent_compose_reset(
    dumper: yaml.Dumper,
    value: _ComposeReset,
) -> yaml.nodes.ScalarNode:
    """Represent a Compose reset tag for removing overridden attributes."""
    return dumper.represent_scalar("!reset", "null")


_ComposeDumper.add_representer(_ComposeReset, _represent_compose_reset)
_COMPOSE_RESET = _ComposeReset()


def write_duplicate_build_override(project_dir: Path) -> Path | None:
    """Write an override disabling duplicate local image builds."""
    services = _load_compose_services(project_dir / "docker-compose.yml")
    duplicate_overrides = _duplicate_build_overrides(services)
    if not duplicate_overrides:
        return None

    override_path = project_dir / _BUILD_DEDUPE_OVERRIDE
    override_path.parent.mkdir(parents=True, exist_ok=True)
    override_text = yaml.dump(
        {"services": duplicate_overrides},
        Dumper=_ComposeDumper,
        sort_keys=True,
    )
    override_path.write_text(
        override_text.replace("!reset 'null'", "!reset null"),
        encoding="utf-8",
        newline="\n",
    )
    return override_path


def _load_compose_services(compose_path: Path) -> dict[str, Any]:
    """Load service definitions from the project Compose file."""
    try:
        compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        log.debug("Could not inspect compose build definitions: %s", exc)
        return {}
    if not isinstance(compose, dict):
        return {}
    services = compose.get("services")
    return services if isinstance(services, dict) else {}


def _duplicate_build_overrides(
    services: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return service overrides for repeated local image build recipes."""
    seen: dict[tuple[str, str], str] = {}
    overrides: dict[str, dict[str, Any]] = {}
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        identity = _build_identity(service)
        if identity is None:
            continue
        if identity in seen:
            overrides[name] = {"build": _COMPOSE_RESET, "pull_policy": "never"}
        else:
            seen[identity] = name
    return overrides


def _build_identity(service: dict[str, Any]) -> tuple[str, str] | None:
    """Return the local image/build identity for a buildable service."""
    image = service.get("image")
    build = service.get("build")
    if not isinstance(image, str) or build in (None, False):
        return None
    build_key = yaml.safe_dump(build, sort_keys=True)
    return image, build_key
