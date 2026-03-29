"""Attack models — MITRE ATT&CK-mapped attack steps and detections.

Ported from the original ``aptl.core.scenarios`` and
``aptl.core.detection`` modules. Provides OCSF-aligned detection
expectations for each attack step.
"""

from enum import IntEnum
from typing import Optional

from pydantic import BaseModel, Field

from aptl.core.sdl._base import SDLModel


class SeverityId(IntEnum):
    """OCSF severity_id values (0-6 scale)."""

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class ExpectedDetection(BaseModel):
    """An expected detection for an attack step, using OCSF field names."""

    product_name: str = Field(
        description="Detection source, normalized lowercase (e.g. 'wazuh', 'suricata')",
    )
    analytic_uid: Optional[str] = Field(
        default=None,
        description="Rule ID for exact match",
    )
    analytic_name: Optional[str] = Field(
        default=None,
        description="Rule name/group for substring match",
    )
    severity_id: SeverityId = Field(
        description="OCSF severity (0-6)",
    )
    description: str = Field(
        description="What the detection should identify",
    )
    max_detection_time_seconds: int = Field(
        default=60,
        description="Max seconds for detection after execution",
    )


class MitreReference(SDLModel):
    """MITRE ATT&CK tactic and technique references."""

    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class PlatformCommand(SDLModel):
    """A platform-specific command variant.

    Adapted from CALDERA's ``platforms.{os}.{shell}.command`` pattern.
    The ``cleanup`` field is from Atomic Red Team's ``cleanup_command``.
    """

    shell: str = "sh"
    command: str
    cleanup: str = ""


class AttackStep(SDLModel):
    """A single attack step combining technique info with expected detections."""

    step_number: int = Field(ge=1)
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    target: str
    vulnerability: str = ""
    commands: list[str] = Field(default_factory=list)
    platform_commands: dict[str, PlatformCommand] = Field(default_factory=dict)
    prerequisites: list[str] = Field(default_factory=list)
    expected_detections: list[ExpectedDetection] = Field(default_factory=list)
    investigation_hints: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
