"""Exact adapter selection and evidence preparation for RAES admission."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from raes import instantiate_scenario, parse_sdl_file

from aptl.backends.identity import (
    APTL_RAES_TARGET_NAME,
    APTL_RAES_TARGET_PROFILE,
    APTL_RAES_TARGET_VERSION,
    BackendIdentity,
)
from aptl.backends.raes_evidence import admit_sdl_evidence
from aptl.backends.scenario_capture import (
    ResolvedScenarioCapture,
    ScenarioCaptureContext,
)
from aptl.backends.scenario_capture_discovery import resolve_scenario_capture
from aptl.backends.scenario_startup import (
    ScenarioStartupSelection,
    select_scenario_startup,
)
from aptl.core.config import AptlConfig
from aptl.core.experiment.capture_plan import CapturePlan, empty_capture_plan
from aptl.core.scenario_bundle import ScenarioBundle


def resolve_admission_adapters(
    bundle: ScenarioBundle,
    config: AptlConfig,
    startup_selection: ScenarioStartupSelection | None,
) -> tuple[ScenarioStartupSelection, ResolvedScenarioCapture | None]:
    """Resolve startup and capture adapters once for one exact bundle."""

    startup = startup_selection or select_scenario_startup(bundle)
    identity = bundle.pack_identity
    capture = None
    if identity is not None:
        capture = resolve_scenario_capture(
            ScenarioCaptureContext(
                pack=identity,
                backend=BackendIdentity(
                    target_name=APTL_RAES_TARGET_NAME,
                    target_version=APTL_RAES_TARGET_VERSION,
                    profile=APTL_RAES_TARGET_PROFILE,
                    transport=config.deployment.provider,
                ),
            )
        )
    return startup, capture


def prepare_admission_scenario(
    bundle: ScenarioBundle,
    parameters: Mapping[str, object] | None,
    capture_selection: ResolvedScenarioCapture | None,
    *,
    parser: Callable[[Path], object] = parse_sdl_file,
) -> tuple[object, Mapping[str, object] | None, CapturePlan]:
    """Parse, bind, and admit evidence for one scenario exactly once."""

    scenario = parser(bundle.sdl_path)
    if parameters is None:
        from aptl.backends.scenario_runtime_parameters import (
            resolve_runtime_parameters,
        )

        parameters = resolve_runtime_parameters(bundle)
    capture_plan = empty_capture_plan()
    if getattr(scenario, "evidence_requirements", None):
        scenario = instantiate_scenario(scenario, parameters=parameters)
        parameters = None
        if capture_selection is None:
            capture_plan = admit_sdl_evidence(scenario)
        else:
            capture_plan = admit_sdl_evidence(
                scenario,
                registry=capture_selection.registry,
            )
    return scenario, parameters, capture_plan


__all__ = ["prepare_admission_scenario", "resolve_admission_adapters"]
