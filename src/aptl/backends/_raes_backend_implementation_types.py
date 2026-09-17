"""Value types and compact builders for backend implementation profiles."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SemanticRuntimeSelector:
    """One typed runtime record that identifies an implementation family."""

    collection: str
    field_name: str
    value: str
    version: str = ""


@dataclass(frozen=True)
class BackendImplementationProfile:
    """One immutable image and the minimum mechanics needed to run it."""

    profile_id: str
    selector: SemanticRuntimeSelector
    source_name: str
    source_version: str
    image_ref: str
    image_mode: str = "pull"
    dockerfile_relpath: str = ""
    context_relpath: str = ""
    runtime_selections: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class BackendBaseSelection:
    """A local substrate plus any semantic provider it must bootstrap."""

    image_ref: str
    use_image_command: bool = False
    run_capabilities: tuple[str, ...] = ()
    provider_kind: str = ""
    provider_parameters: tuple[tuple[str, str], ...] = ()


def environment(*variables: dict[str, str]) -> list[dict[str, str]]:
    """Build an authored-order runtime environment profile value."""

    return list(variables)


def variable(
    name: str,
    value: str = "",
    *,
    classification: str = "plain",
    provenance: str = "compose",
) -> dict[str, str]:
    """Build one classified runtime environment variable."""

    return {
        "name": name,
        "value": value,
        "value_classification": classification,
        "provenance": provenance,
    }


def published_port(
    container_port: int, host_port: int, protocol: str = "tcp"
) -> dict[str, object]:
    """Build one loopback-only published port selection."""

    return {
        "container_port": container_port,
        "protocol": protocol,
        "host_port": host_port,
        "host_ip": "127.0.0.1",
    }


__all__ = (
    "BackendBaseSelection",
    "BackendImplementationProfile",
    "SemanticRuntimeSelector",
    "environment",
    "published_port",
    "variable",
)
