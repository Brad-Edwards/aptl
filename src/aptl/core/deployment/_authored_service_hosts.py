"""Host names the scenario itself authors for its certificate-bearing services.

A lab CA only helps if the certificate covers the address the scenario tells
consumers to use. TechVault authors MISP's participant-visible identity as the
``misp-canonical-url`` platform-application setting and points the IOC sync
agent at that same host, so a certificate issued only for the short service
name would be rejected by every verifying consumer of the authored address.

The rule applied here is deliberately narrow and reads only authored state: a
platform application whose settings carry an ``https`` URL states that its node
is reached at that URL's host. Nothing is inferred from a node name, a network
alias, or a DNS zone, and a scenario that authors no such setting adds no SAN.
"""

from __future__ import annotations

from urllib.parse import urlparse

from aptl.core.deployment.realization import DeploymentRealizationSpec

_SECURE_SCHEME = "https"
_CANONICAL_URL_SUFFIX = "-canonical-url"


def authored_service_hosts(
    realization: DeploymentRealizationSpec,
) -> dict[str, tuple[str, ...]]:
    """Return each node's authored HTTPS host names, keyed by node name."""

    hosts: dict[str, set[str]] = {}
    for node in realization.nodes:
        for application in getattr(node.runtime, "platform_applications", ()) or ():
            for setting in getattr(application, "settings", ()) or ():
                if not str(getattr(setting, "setting_id", "")).endswith(
                    _CANONICAL_URL_SUFFIX
                ):
                    continue
                host = _secure_host(str(getattr(setting, "value", "")))
                if host is not None:
                    hosts.setdefault(node.name, set()).add(host)
    return {name: tuple(sorted(found)) for name, found in hosts.items()}


def _secure_host(value: str) -> str | None:
    """Return the host of an authored ``https`` URL, or ``None``."""

    if not value.startswith(f"{_SECURE_SCHEME}://"):
        return None
    parsed = urlparse(value)
    return parsed.hostname if parsed.scheme == _SECURE_SCHEME else None


__all__ = ("authored_service_hosts",)
