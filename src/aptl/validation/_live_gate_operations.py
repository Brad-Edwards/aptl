"""The scenario-neutral operations a verification plugin drives (#878/#879).

A plugin decides *what* to check for one scenario; core owns *how* to observe a
live range. This surface is that boundary. It exposes only capability-oriented,
scenario-neutral operations -- reach a host from another host, generate a
representative event and see whether the defensive stack recorded it -- backed by
the same framework the live gate already used (bounded windows, re-driving a
trigger while its window is open, preferring probe targets that actually expose
the service). None of that machinery is duplicated into the plugin.

The surface deliberately carries no run store, destination paths, raw config,
``.env`` mapping, process environment, or unrestricted backend handle. A plugin
names an origin node and asks a question; the framework answers it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.collectors import _resolve_lab_ca_path
from aptl.core.deployment import get_backend
from aptl.core.deployment._compose_runtime_orchestration import (
    bind_runtime_product_execution,
    docker_authority_admissions,
)
from aptl.core.env import find_placeholder_env_values, load_dotenv
from aptl.utils.curl_safe import curl_json
from aptl.utils.placeholders import contains_placeholder
from aptl.validation._live_gate_probes import (
    _find_container,
    _ping_from_kali,
    _shared_network_targets,
)
from aptl.validation._live_gate_telemetry import telemetry_diagnostics

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState


@dataclass(frozen=True)
class ReachabilityResult(object):
    """Whether an origin reached every host it shares a network with."""

    reached: bool
    tested: tuple[str, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class DetectionResult(object):
    """Whether a representative event traversed the defensive stack."""

    observed: bool
    diagnostics: tuple[str, ...]
    correlation_marker: str = ""


@dataclass(frozen=True)
class ProductApiEndpoint(object):
    """Names of local configuration fields for one authenticated product API.

    A verifier owns these non-secret locators. Core resolves their values from
    the project credential boundary and permits requests only to localhost.
    """

    credential_name: str
    port_name: str
    default_port: int


class LiveGateOperations(object):
    """Core-owned capabilities a scenario verifier drives against a live range.

    Constructed by the live gate after boot, from the run's project directory,
    config, options, and post-boot state. The plugin receives it as the context's
    ``operations`` and never sees the underlying config or backend.
    """

    def __init__(
        self,
        *,
        project_dir: Path,
        config: "AptlConfig",
        options: "LiveGateOptions",
        state: "LiveGateState",
    ) -> None:
        self._project_dir = project_dir
        self._config = config
        self._options = options
        self._state = state

    def reachability_from(self, origin: str) -> ReachabilityResult:
        """Return whether ``origin`` reaches every host on its shared networks.

        Targets are derived from live network co-membership, not a fixed list, so
        only the origin node is a scenario constant. The plugin supplies it.
        """

        containers = (self._state.snapshot or {}).get("containers", [])
        origin_container = _find_container(containers, origin)
        if origin_container is None:
            return ReachabilityResult(
                False, (), (f"origin {origin!r} not present in the booted range",)
            )
        networks = set((origin_container.get("networks") or {}).keys())
        targets = (
            _shared_network_targets(origin_container, containers, networks)
            if networks
            else []
        )
        if not targets:
            reason = (
                f"origin {origin!r} has no network attachments"
                if not networks
                else f"no host shares a network with {origin!r} to test"
            )
            return ReachabilityResult(False, (), (reason,))
        backend = get_backend(self._config, self._project_dir)
        diagnostics = [
            f"{origin} cannot reach {name} ({ip}) on shared network"
            for name, ip in targets
            if not _ping_from_kali(backend, ip)
        ]
        tested = tuple(name for name, _ in targets)
        self._state.evidence = {"reachability_targets": list(tested)}
        return ReachabilityResult(not diagnostics, tested, tuple(diagnostics))

    def detection_evidence(
        self, origin: str, sensor: str, deadline_seconds: int
    ) -> DetectionResult:
        """Generate one representative event from ``origin`` and grade traversal.

        Drives the existing bounded-window collection: the event is re-driven
        while the window is open rather than fired once, and probe targets that
        actually expose the service are preferred. Both are framework behaviour
        and stay here. The verdict on what the collected evidence means is the
        plugin's; this returns whether a correlated defensive-stack alert was
        observed at all.
        """

        # The collection window is framework-owned and taken from the run's
        # options; ``deadline_seconds`` is accepted for surface symmetry with a
        # plugin's own deadline, which is already that same window.
        del deadline_seconds
        containers = (self._state.snapshot or {}).get("containers", [])
        origin_container = _find_container(containers, origin)
        if origin_container is None:
            return DetectionResult(
                False,
                (f"origin {origin!r} not present; cannot generate an event",),
            )
        networks = set((origin_container.get("networks") or {}).keys())
        targets = _shared_network_targets(origin_container, containers, networks)
        if not targets:
            return DetectionResult(
                False, ("no reachable target to generate defensive-stack telemetry",)
            )
        sensor_targets = [target for target in targets if target[0] == sensor]
        if len(sensor_targets) != 1:
            return DetectionResult(
                False,
                (f"sensor {sensor!r} is missing or ambiguous on shared networks",),
            )
        # Put the verifier-selected sensor first. The bounded nmap trigger
        # addresses its first target, while the subsequent SSH probes retain
        # their scenario-neutral listener-based ordering.
        targets = sensor_targets + [target for target in targets if target[0] != sensor]
        diagnostics = telemetry_diagnostics(
            targets,
            self._config,
            self._project_dir,
            self._options,
            self._state,
        )
        marker = ""
        telemetry = (self._state.evidence or {}).get("telemetry")
        if isinstance(telemetry, Mapping):
            correlations = [
                value
                for key, value in telemetry.items()
                if str(key).endswith("_correlation") and isinstance(value, Mapping)
            ]
            if len(correlations) == 1:
                marker = str(correlations[0].get("correlation_id", ""))
        return DetectionResult(not diagnostics, tuple(diagnostics), marker)

    def product_json(
        self,
        endpoint: ProductApiEndpoint,
        path: str,
        *,
        method: str = "GET",
        body: object | None = None,
    ) -> object | None:
        """Call one authenticated localhost product endpoint without leaking keys.

        The plugin supplies only configuration field names and a relative API
        path. Core retains the project credential boundary, CA selection, port
        validation, and fixed-localhost destination.
        """

        if (
            not _configuration_name(endpoint.credential_name)
            or not _configuration_name(endpoint.port_name)
            or not path.startswith("/")
            or path.startswith("//")
            or len(path) > 1024
            or method not in {"GET", "POST"}
        ):
            return None
        try:
            raw = load_dotenv(self._project_dir / ".env")
            if find_placeholder_env_values(raw):
                return None
            api_key = raw.get(endpoint.credential_name, "")
            if not api_key or contains_placeholder(api_key):
                return None
            port = _validated_port(raw.get(endpoint.port_name, endpoint.default_port))
            ca_cert_path = _resolve_lab_ca_path(
                str(self._project_dir / "config" / "soc_certs" / "lab-ca.pem")
            )
        except (OSError, TypeError, ValueError):
            return None
        return curl_json(
            f"https://localhost:{port}{path}",
            auth_header=f"Bearer {api_key}",
            body=body,
            method=method,
            ca_cert_path=ca_cert_path,
        )

    def bind_runtime_execution(self, execution_id: str) -> None:
        """Narrow the one active authority to a product-accepted execution."""

        if not _bounded_identity(execution_id):
            raise ValueError("runtime execution identity is invalid")

        spec = self._state.deployment_spec
        admissions = docker_authority_admissions(spec)
        if len(admissions) != 1:
            raise ValueError("runtime execution authority is missing or ambiguous")
        self._state.deployment_spec = bind_runtime_product_execution(
            spec,
            authority_correlation_id=admissions[0].correlation_id,
            product_execution_id=execution_id,
        )


def _bounded_identity(value: object) -> bool:
    """Whether an opaque product identifier is safe to retain in evidence."""

    text = str(value or "")
    return bool(
        text and len(text) <= 128 and text.replace("-", "").replace("_", "").isalnum()
    )


def _configuration_name(value: object) -> bool:
    """Return whether a plugin supplied one bounded environment-field name."""

    text = str(value or "")
    return bool(
        text
        and len(text) <= 128
        and text == text.upper()
        and text.replace("_", "").isalnum()
    )


def _validated_port(value: object) -> int:
    """Return one valid host port or fail before making a request."""

    port = int(str(value))
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return port


__all__ = [
    "DetectionResult",
    "LiveGateOperations",
    "ProductApiEndpoint",
    "ReachabilityResult",
]
