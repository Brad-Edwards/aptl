"""Scenario data models.

Pydantic models for defining attack scenarios, techniques, expected
detections, and scoring criteria.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Difficulty(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class DetectionSource(str, Enum):
    WAZUH = "wazuh"
    SURICATA = "suricata"
    FALCO = "falco"
    SYSMON = "sysmon"
    CUSTOM = "custom"


class TechniqueStep(BaseModel):
    """A single MITRE ATT&CK technique within a scenario."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g. T1190)",
    )
    technique_name: str = Field(
        description="Human-readable technique name",
    )
    tactic: str = Field(
        description="ATT&CK tactic (e.g. Initial Access)",
    )
    description: str = Field(
        description="What the attacker does in this step",
    )
    target: str = Field(
        description="Target system (e.g. webapp, ad, victim)",
    )
    commands: list[str] = Field(
        default_factory=list,
        description="Example red team agent commands",
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Steps that must complete before this one",
    )


class ExpectedDetection(BaseModel):
    """An expected detection for a technique step."""

    source: DetectionSource = Field(
        description="Which detection system should fire",
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Expected Wazuh/Suricata rule ID",
    )
    rule_group: Optional[str] = Field(
        default=None,
        description="Expected rule group",
    )
    description: str = Field(
        description="What the detection should identify",
    )
    severity: Severity = Field(
        description="Expected alert severity",
    )
    max_detection_time_seconds: int = Field(
        default=60,
        description="Max seconds for detection after execution",
    )


class ScenarioStep(BaseModel):
    """A step combining an attack technique with expected detections."""

    step_number: int
    technique: TechniqueStep
    expected_detections: list[ExpectedDetection] = Field(default_factory=list)
    investigation_hints: list[str] = Field(
        default_factory=list,
        description="Hints for the blue team agent on how to investigate",
    )
    remediation: list[str] = Field(
        default_factory=list,
        description="Expected response actions",
    )


class Scenario(BaseModel):
    """A complete attack scenario with MITRE ATT&CK mapping."""

    id: str = Field(description="Unique scenario identifier")
    name: str = Field(description="Scenario name")
    description: str = Field(description="Scenario overview")
    difficulty: Difficulty
    estimated_time_minutes: int = Field(
        description="Expected completion time",
    )
    attack_chain: str = Field(
        description="Kill chain summary",
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Required lab profiles (e.g. ['enterprise', 'soc'])",
    )
    steps: list[ScenarioStep]
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="All MITRE ATT&CK tactics covered",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="All MITRE ATT&CK technique IDs covered",
    )


class DetectionResult(BaseModel):
    """Result of checking whether a detection fired."""

    step_number: int
    technique_id: str
    detected: bool
    detection_time_seconds: Optional[float] = None
    alert_id: Optional[str] = None
    alert_details: Optional[str] = None


class ScenarioScore(BaseModel):
    """Scoring results for a completed scenario run."""

    scenario_id: str
    total_steps: int
    detected_steps: int
    detection_coverage: float = Field(
        description="Fraction of steps detected (0.0-1.0)",
    )
    avg_detection_time_seconds: Optional[float] = None
    results: list[DetectionResult]
    mitre_coverage: dict[str, bool] = Field(
        default_factory=dict,
        description="Detection coverage per MITRE technique ID",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="Techniques that were not detected",
    )
