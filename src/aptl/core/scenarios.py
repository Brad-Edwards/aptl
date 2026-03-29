"""Scenario definition models, loading, and validation.

This module is a backward-compatibility shim that re-exports all
public names from the new ``aptl.core.sdl`` package. All existing
imports continue to work unchanged.

The canonical source for scenario models is now ``aptl.core.sdl``.
"""

from aptl.core.sdl.compat import (  # noqa: F401
    AttackStep,
    CommandOutputValidation,
    ContainerRequirements,
    Difficulty,
    ExpectedDetection,
    FileExistsValidation,
    Hint,
    MitreReference,
    Objective,
    ObjectiveSet,
    ObjectiveType,
    ObserverError,
    Precondition,
    PreconditionType,
    Scenario,
    ScenarioDefinition,
    ScenarioError,
    ScenarioMetadata,
    ScenarioMode,
    ScenarioNotFoundError,
    ScenarioStateError,
    ScenarioValidationError,
    ScoringConfig,
    SeverityId,
    TimeBonusConfig,
    WazuhAlertValidation,
    find_scenarios,
    load_scenario,
    validate_scenario_containers,
)
