"""API response models for the APTL web interface."""

from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, Field

from aptl.core.lab_types import StartupDiagnostic

# Closed-set ADR-030 wire strings. Mirroring the enums as ``Literal``
# unions keeps the wire schema closed for FastAPI / OpenAPI clients
# without forcing them to import the Python core types.
StartupOutcomeLiteral = Literal[
    "ready", "degraded_usable", "degraded_unusable", "failed"
]
DiagnosticImpactLiteral = Literal["cosmetic", "telemetry", "capability", "readiness"]
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
    def from_compose_dict(cls, data: dict[str, Any]) -> "ContainerInfo":
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


ScenarioModeLiteral = Literal["red", "blue", "purple"]
ScenarioDifficultyLiteral = Literal["beginner", "intermediate", "advanced", "expert"]


class ScenarioValidationState(BaseModel):
    """Whether a catalog entry resolved and its ACES SDL projected cleanly.

    Distinct from lab readiness, container health, objective completion, and
    scoring (UI-008d guardrail): ``valid`` means only that the catalog entry
    and its ACES projection loaded/validated. ``detail`` carries a redacted,
    user-facing reason when ``valid`` is ``False`` — never a raw stack trace,
    parser exception, or filesystem path.
    """

    valid: bool
    detail: Optional[str] = None


class ScenarioSummaryResponse(BaseModel):
    """Card-summary projection of one curated scenario catalog entry (UI-008d).

    Exposes only card/list facts (design-preflight UI-008d guardrail): id,
    name, and description come from the curated catalog; mode, difficulty,
    estimated time, and tags come from the narrow validated catalog metadata
    extension (:class:`ScenarioCatalogMetadata`); required containers and the
    validation summary are projected from the ACES SDL. The catalog ``path``
    locator stays internal and is never modelled here. Workbench detail,
    scoring, SIEM query execution, and terminal session state belong to the
    scenario-detail projection, not the summary contract.
    """

    id: str
    name: str
    description: str = ""
    mode: Optional[ScenarioModeLiteral] = None
    difficulty: Optional[ScenarioDifficultyLiteral] = None
    estimated_minutes: Optional[int] = None
    tags: list[str] = Field(default_factory=list)
    required_containers: list[str] = Field(default_factory=list)
    validation: ScenarioValidationState


# --- Scenario-detail workbench projection (UI-008d) ---
#
# The detail route returns header facts plus an ordered ``WorkbenchBlock``
# discriminated union. The union — NOT the removed legacy in-tree
# ``ScenarioDefinition`` / web ``buildBlockSequence`` shape — is the contract;
# ``web/src/lib/types.ts`` mirrors these wire shapes. Each block family is
# projected from whatever the ACES SDL actually owns and is omitted when its
# source section is empty (no fabricated content). Blocks are display/action
# *descriptors*, not authorities: a terminal block only names a requested
# container (the WebSocket still enforces the ADR-039/040 gates) and a SIEM
# query block only carries curated display copy (execution is #421's surface).


class NarrativeBlock(BaseModel):
    """Authored/derived Markdown narrative rendered through the DOMPurify path."""

    type: Literal["narrative"] = "narrative"
    key: str
    content: str


class SectionDividerBlock(BaseModel):
    """A titled visual divider grouping the blocks that follow it."""

    type: Literal["section-divider"] = "section-divider"
    key: str
    title: str


class ContainerStatusBlock(BaseModel):
    """Required-container names for the scenario (ACES VM nodes).

    Live container state is read from the lab-status stream by the UI; this
    block only names the required containers so the workbench can render
    status pills that do not imply the lab is running.
    """

    type: Literal["container-status"] = "container-status"
    key: str
    containers: list[str] = Field(default_factory=list)


class ObjectiveBlock(BaseModel):
    """A declarative ACES experiment objective (name/description/success)."""

    type: Literal["objective"] = "objective"
    key: str
    name: str
    description: str = ""
    success: str = ""


class StepBlock(BaseModel):
    """One ordered step projected from an ACES workflow."""

    type: Literal["step"] = "step"
    key: str
    index: int
    name: str
    description: str = ""
    step_type: str = ""


class SiemQueryBlock(BaseModel):
    """A curated SIEM query descriptor (display-only in v1).

    Carries display copy and a curated query payload. Execution belongs to the
    SIEM API owner (#421) with backend validation, time-range/row caps, and
    redacted errors — this block never ships raw OpenSearch passthrough. Not
    emitted from the current scenario corpus (no ACES SIEM-query source yet);
    defined so the frontend block interface can coordinate with #421.
    """

    type: Literal["siem-query"] = "siem-query"
    key: str
    product_name: str = ""
    description: str = ""
    query: dict[str, Any] = Field(default_factory=dict)


class TerminalBlock(BaseModel):
    """A lazy terminal descriptor naming a requested container target."""

    type: Literal["terminal"] = "terminal"
    key: str
    container: str
    label: str = ""


WorkbenchBlock = Annotated[
    Union[
        NarrativeBlock,
        SectionDividerBlock,
        ContainerStatusBlock,
        ObjectiveBlock,
        StepBlock,
        SiemQueryBlock,
        TerminalBlock,
    ],
    Field(discriminator="type"),
]


class ScenarioDetailResponse(BaseModel):
    """Backend-owned scenario-detail projection for ``GET /api/scenarios/{id}``.

    Header facts (id/name/description/mode/difficulty/estimated_minutes/tags/
    required_containers/validation) plus an ordered ``WorkbenchBlock`` union.
    Never exposes the catalog ``path`` locator, raw parser exceptions, or
    archived SDL locations.
    """

    id: str
    name: str
    description: str = ""
    mode: Optional[ScenarioModeLiteral] = None
    difficulty: Optional[ScenarioDifficultyLiteral] = None
    estimated_minutes: Optional[int] = None
    tags: list[str] = Field(default_factory=list)
    required_containers: list[str] = Field(default_factory=list)
    validation: ScenarioValidationState
    blocks: list[WorkbenchBlock] = Field(default_factory=list)


class ConfigResponse(BaseModel):
    """Response for GET /api/config."""

    lab_name: str = ""
    network_subnet: str = ""
    containers: dict[str, bool] = {}
    run_storage_backend: str = "local"
