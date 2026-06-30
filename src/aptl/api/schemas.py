"""API response models for the APTL web interface."""

from typing import Literal, Optional

from pydantic import BaseModel, Field

from aptl.core.lab_types import StartupDiagnostic

# Closed-set ADR-030 wire strings. Mirroring the enums as ``Literal``
# unions keeps the wire schema closed for FastAPI / OpenAPI clients
# without forcing them to import the Python core types.
StartupOutcomeLiteral = Literal[
    "ready", "degraded_usable", "degraded_unusable", "failed"
]
DiagnosticImpactLiteral = Literal[
    "cosmetic", "telemetry", "capability", "readiness"
]
DiagnosticSeverityLiteral = Literal["info", "warning", "error"]


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"


class StartupDiagnosticModel(BaseModel):
    """API projection of :class:`aptl.core.lab_types.StartupDiagnostic`.

    Mirrors the dataclass field-by-field. String values (``impact``,
    ``severity``) carry the stable wire strings from the core enums —
    keep ``web/src/lib/types.ts`` aligned (ADR-030 anti-pattern: never
    reclassify a core result in the API or web layer).
    """

    step: str
    impact: DiagnosticImpactLiteral
    severity: DiagnosticSeverityLiteral
    message: str
    component: str = ""
    operator_action: str = ""

    @classmethod
    def from_dataclass(cls, diag: StartupDiagnostic) -> "StartupDiagnosticModel":
        return cls(
            step=diag.step,
            impact=diag.impact.value,
            severity=diag.severity.value,
            message=diag.message,
            component=diag.component,
            operator_action=diag.operator_action,
        )


class ContainerInfo(BaseModel):
    """Container status information."""

    name: str = ""
    state: str = ""
    status: str = ""
    health: str = ""
    image: str = ""
    ports: list[str] = []

    @classmethod
    def from_compose_dict(cls, data: dict) -> "ContainerInfo":
        """Create from docker compose ps JSON output."""
        # docker compose ps --format json uses varying key names
        # across versions; handle common variants.
        name = data.get("Name", data.get("name", ""))
        state = data.get("State", data.get("state", ""))
        status = data.get("Status", data.get("status", ""))
        health = data.get("Health", data.get("health", ""))
        image = data.get("Image", data.get("image", ""))

        # Ports can be a string like "0.0.0.0:443->443/tcp" or a list
        raw_ports = data.get("Ports", data.get("ports", data.get("Publishers", [])))
        if isinstance(raw_ports, str):
            ports = [p.strip() for p in raw_ports.split(",") if p.strip()]
        elif isinstance(raw_ports, list):
            # Could be list of dicts (Publishers format) or list of strings
            ports = []
            for p in raw_ports:
                if isinstance(p, dict):
                    url = p.get("URL", "")
                    target = p.get("TargetPort", "")
                    published = p.get("PublishedPort", 0)
                    protocol = p.get("Protocol", "tcp")
                    if published:
                        ports.append(f"{url}:{published}->{target}/{protocol}")
                else:
                    ports.append(str(p))
        else:
            ports = []

        return cls(
            name=name,
            state=state,
            status=status,
            health=health,
            image=image,
            ports=ports,
        )


class LabStatusResponse(BaseModel):
    """Response for GET /api/lab/status."""

    running: bool
    containers: list[ContainerInfo] = []
    error: Optional[str] = None


class LabActionResponse(BaseModel):
    """Response for POST /api/lab/start and POST /api/lab/stop.

    ``outcome`` and ``diagnostics`` carry the ADR-030 structured
    classification. They are optional/default-empty so older clients
    that only consume ``{success, message, error}`` keep working.
    """

    success: bool
    message: str = ""
    error: Optional[str] = None
    outcome: Optional[StartupOutcomeLiteral] = None
    diagnostics: list[StartupDiagnosticModel] = Field(default_factory=list)


class KillActionResponse(BaseModel):
    """Response for POST /api/lab/kill."""

    success: bool
    mcp_processes_killed: int = 0
    containers_stopped: bool = False
    session_cleared: bool = False
    errors: list[str] = Field(default_factory=list)


class ScenarioSummaryResponse(BaseModel):
    """Card-summary projection of one curated scenario catalog entry.

    Narrow by design: only the facts the curated catalog
    (``scenarios/catalog.json`` / :class:`ScenarioCatalogEntry`) authoritatively
    owns. Richer card facts (mode, difficulty, tags, estimated time, required
    containers) are intentionally NOT modelled here — the ACES SDL does not own
    those fields and the legacy in-tree scenario model that did is deliberately
    not revived (see ``docs/specs/web-gui-design-preflight.md`` UI-008c). Those
    belong to the scenario-detail/workbench projection, which is out of scope
    for the Lab Home slice.
    """

    id: str
    name: str
    description: str = ""


class ConfigResponse(BaseModel):
    """Response for GET /api/config."""

    lab_name: str = ""
    network_subnet: str = ""
    containers: dict[str, bool] = {}
    run_storage_backend: str = "local"
