"""Public RAES SDL capture-demand admission for the APTL backend."""

from __future__ import annotations

from raes import canonical_instantiated_sdl_digest, canonical_sdl_digest
from raes.realization_designation import (
    designation_records,
    resolve_realization_designation,
)
from raes.scenario import InstantiatedScenario, Scenario
from raes_contracts.vocabulary import Closure
from raes_processor.capture_admission import compile_scenario_capture_demands

from aptl.core.experiment.capture_plan import (
    CaptureApparatus,
    CapturePlan,
    admit_capture_demands,
)
from aptl.core.experiment.errors import AdmissionRejection, diagnostic

_TRANSCRIPT_DEMAND_ID = "redteam-session-transcript"
_SQLI_DEMAND_ID = "suricata-login-sqli-alert"
_KALI_CAPTURE_FOOTPRINT = (
    "/nodes/kali-capture",
    "/nodes/kali/runtime/interactive-session-ingress",
    "/persistent_volumes/kali_captures",
)
_TRAFFIC_MIRROR_FOOTPRINT = (
    "/nodes/kali",
    "/nodes/suricata/runtime/network_detection_engines",
    "/nodes/webapp/runtime/applications",
)


def _capture_apparatus(
    scenario: Scenario | InstantiatedScenario,
    demand_ids: frozenset[str],
) -> tuple[CaptureApparatus, ...]:
    """Admit only observers genuinely required by the compiled demands."""

    apparatus: list[CaptureApparatus] = []
    if not demand_ids.intersection({_TRANSCRIPT_DEMAND_ID, _SQLI_DEMAND_ID}):
        return ()
    provenance = getattr(scenario, "instantiation_provenance", None)
    designation = getattr(scenario, "realization", None)
    if provenance is not None:
        records = provenance.realization_designations
    elif designation is not None:
        records = designation_records(designation)
    else:
        records = ()
    if _TRANSCRIPT_DEMAND_ID in demand_ids:
        resolutions = _require_open_footprint(
            records,
            _KALI_CAPTURE_FOOTPRINT,
            demand_id=_TRANSCRIPT_DEMAND_ID,
            message=(
                "The required session transcript needs an added observer, "
                "but its governing realization scope is closed."
            ),
        )
        apparatus.append(
            CaptureApparatus(
                apparatus_id="aptl.apparatus.kali-session-capture",
                service_name="kali-capture",
                container_name="aptl-kali-capture",
                purpose="complete-red-team-interactive-session-custody",
                target_refs=("nodes.kali",),
                governing_scopes=tuple(
                    sorted(
                        {
                            resolution.governing_scope
                            for resolution in resolutions
                            if resolution.governing_scope
                        }
                    )
                ),
                environment_visible=True,
                observer_effects=(
                    "sidecar container visible on the shared Docker daemon",
                    "PTY ingress is mediated by the capture broker",
                    "Kali native SSH moves to loopback TCP/2222 while capture is active",
                    "Kali authorizes its existing pivot key for the broker's loopback relay",
                    "session bytes and custody metadata consume bounded storage",
                ),
            )
        )
    if _SQLI_DEMAND_ID in demand_ids:
        resolutions = _require_open_footprint(
            records,
            _TRAFFIC_MIRROR_FOOTPRINT,
            demand_id=_SQLI_DEMAND_ID,
            message=(
                "The required native IDS evidence needs a host-boundary frame "
                "mirror, but its governing realization scope is closed."
            ),
        )
        apparatus.append(
            CaptureApparatus(
                apparatus_id="aptl.apparatus.suricata-traffic-mirror",
                service_name="backend-traffic-mirror",
                container_name="",
                purpose="native-suricata-visibility-of-kali-webapp-traffic",
                target_refs=("nodes.kali", "nodes.suricata", "nodes.webapp"),
                governing_scopes=tuple(
                    sorted(
                        {
                            resolution.governing_scope
                            for resolution in resolutions
                            if resolution.governing_scope
                        }
                    )
                ),
                environment_visible=True,
                observer_effects=(
                    "webapp ingress and egress frames are copied to the existing Suricata interface",
                    "participant delivery is not redirected, delayed, or modified",
                    "host traffic-control state consumes bounded backend resources",
                ),
            )
        )
    return tuple(apparatus)


def _require_open_footprint(
    records: object,
    pointers: tuple[str, ...],
    *,
    demand_id: str,
    message: str,
) -> tuple[object, ...]:
    """Resolve an apparatus footprint and reject any closed governing scope."""

    resolutions = tuple(
        resolve_realization_designation(records, field_pointer=pointer)
        for pointer in pointers
    )
    if any(resolution.closure is not Closure.OPEN_WORLD for resolution in resolutions):
        raise AdmissionRejection(
            (
                diagnostic(
                    "aptl.capture-apparatus.closed-realization-scope",
                    f"evidence_requirements.{demand_id}",
                    message,
                ),
            )
        )
    return resolutions


def admit_sdl_evidence(
    scenario: Scenario | InstantiatedScenario,
) -> CapturePlan:
    """Compile and admit every required SDL evidence demand without mutation."""

    digest = (
        canonical_instantiated_sdl_digest(scenario)
        if isinstance(scenario, InstantiatedScenario)
        else canonical_sdl_digest(scenario)
    ).value
    demands = compile_scenario_capture_demands(scenario)
    return admit_capture_demands(
        demands,
        source_identity=digest,
        apparatus=_capture_apparatus(
            scenario, frozenset(demand.demand_id for demand in demands)
        ),
    )
