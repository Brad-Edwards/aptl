"""Typed range-snapshot data model.

The dataclasses that make up a :class:`RangeSnapshot` live here, apart from the
capture logic in :mod:`aptl.core.snapshot`, so the model is a dependency-free
leaf: it imports nothing from the capture module and can be shared without a
cycle. ``aptl.core.snapshot`` re-exports every name below, so existing
``from aptl.core.snapshot import RangeSnapshot`` imports keep working.
"""

from dataclasses import asdict, dataclass, field
from typing import Any

from aptl.utils.redaction import redact


@dataclass
class SoftwareVersions(object):
    """Versions of key software components."""

    python_version: str = ""
    docker_version: str = ""
    compose_version: str = ""
    wazuh_manager_version: str = ""
    wazuh_indexer_version: str = ""
    aptl_version: str = ""
    raes_version: str = ""


@dataclass
class ContainerSnapshot(object):
    """State of a single Docker container."""

    name: str = ""
    image: str = ""
    image_id: str = ""
    status: str = ""
    health: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    networks: dict[str, str] = field(default_factory=dict)
    ports: list[str] = field(default_factory=list)
    image_digest: str = ""
    # Docker restart policy name ("no", "always", "unless-stopped", ...). This
    # distinguishes a run-to-completion container (restart "no", exits and stays
    # exited by design) from a long-running service (which must stay up). It is a
    # compose realization fact APTL itself authored, so recording it here is not
    # scenario knowledge.
    restart_policy: str = ""


@dataclass
class WazuhRulesSnapshot(object):
    """Summary of Wazuh rule configuration."""

    total_rules: int = 0
    custom_rules: int = 0
    custom_rule_files: list[str] = field(default_factory=list)
    total_decoders: int = 0
    custom_decoders: int = 0


@dataclass
class NetworkSnapshot(object):
    """State of a Docker network."""

    name: str = ""
    subnet: str = ""
    gateway: str = ""
    containers: list[str] = field(default_factory=list)


@dataclass
class ServiceEndpoint(object):
    """A host-accessible service endpoint."""

    name: str = ""
    url: str = ""
    host: str = "localhost"
    port: int = 0
    protocol: str = ""
    credentials: str = ""


@dataclass
class SSHEndpoint(object):
    """An SSH-accessible container."""

    name: str = ""
    host: str = "localhost"
    port: int = 0
    user: str = ""
    key_path: str = "~/.ssh/aptl_lab_key"
    command: str = ""


@dataclass
class RangeSnapshot(object):
    """Complete point-in-time snapshot of the lab range."""

    timestamp: str = ""
    software: SoftwareVersions = field(default_factory=SoftwareVersions)
    containers: list[ContainerSnapshot] = field(default_factory=list)
    wazuh_rules: WazuhRulesSnapshot = field(default_factory=WazuhRulesSnapshot)
    networks: list[NetworkSnapshot] = field(default_factory=list)
    config_hashes: dict[str, str] = field(default_factory=dict)
    services: list[ServiceEndpoint] = field(default_factory=list)
    ssh: list[SSHEndpoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary.

        Sensitive fields (service credentials, API tokens, etc.) are
        redacted at this boundary so every caller — `aptl lab status
        --json`, `--output`, future archive writers — gets the same safe
        shape. See ADR-012 § Security Guardrail.
        """
        return redact(asdict(self))


__all__ = [
    "ContainerSnapshot",
    "NetworkSnapshot",
    "RangeSnapshot",
    "SSHEndpoint",
    "ServiceEndpoint",
    "SoftwareVersions",
    "WazuhRulesSnapshot",
]
