"""Exact capture offers for the TechVault participant study."""

from aptl.core.experiment.capture_registry import CaptureLimits, CollectorRegistration
from aptl_techvault.capture_registrations import (
    _JSON_MEDIA_TYPE,
    _OfferSpec,
    _offer,
    _techvault_registration,
)

_PARTICIPANT_DELIVERY_LIMITS = CaptureLimits(2 * 1024 * 1024, 1, 600)
_RED_NODE = "nodes.kali"


def participant_delivery_registrations() -> tuple[CollectorRegistration, ...]:
    """Return exact offers for the four SDL-authored study deliveries."""

    specifications = (
        ("red", "start", _RED_NODE, "red participant start occurrence"),
        ("red", "stop", _RED_NODE, "red participant stop occurrence"),
        (
            "blue",
            "start",
            "nodes.soc-workstation",
            "blue participant start occurrence",
        ),
        (
            "blue",
            "stop",
            "nodes.soc-workstation",
            "blue participant stop occurrence",
        ),
    )
    return tuple(
        _techvault_registration(
            f"aptl.collector.participant-delivery.{role}-{phase}",
            offer=_offer(
                f"aptl.collector.participant-delivery.{role}-{phase}",
                _OfferSpec(
                    artifact_role="participant_instruction_delivery",
                    media_type=_JSON_MEDIA_TYPE,
                    capture_kind="observation",
                    source_refs=frozenset(
                        {
                            f"behavior_specifications.{role}-participant-study."
                            f"participant_inject_deliveries.{phase}"
                        }
                    ),
                    scope=f"SDL-authored {role} participant {phase} delivery",
                    scope_refs=frozenset({node, "entities.study-control"}),
                    channel_kind="participant-observation",
                    window_kinds=frozenset({window}),
                    integrity_mode="chain_of_custody",
                    redaction_policy="redact_secrets",
                    source_class="apparatus",
                ),
            ),
            limits=_PARTICIPANT_DELIVERY_LIMITS,
            chain_of_custody=True,
        )
        for role, phase, node, window in specifications
    )
