"""API response models for the APTL web interface."""

from typing import Optional

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"


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
    """Response for POST /api/lab/start and POST /api/lab/stop."""

    success: bool
    message: str = ""
    error: Optional[str] = None


class KillActionResponse(BaseModel):
    """Response for POST /api/lab/kill."""

    success: bool
    mcp_processes_killed: int = 0
    containers_stopped: bool = False
    session_cleared: bool = False
    errors: list[str] = []


class ScenarioSummary(BaseModel):
    """Abbreviated scenario info for listing."""

    id: str
    name: str
    description: str
    difficulty: str
    mode: str
    estimated_minutes: int
    tags: list[str] = []
    containers_required: list[str] = []


class ConfigResponse(BaseModel):
    """Response for GET /api/config."""

    lab_name: str = ""
    network_subnet: str = ""
    containers: dict[str, bool] = {}
    run_storage_backend: str = "local"
