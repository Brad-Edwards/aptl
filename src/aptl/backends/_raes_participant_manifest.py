"""Optional manifest capabilities for SDL participant inject delivery."""

from dataclasses import replace

from raes_backend_protocols.capabilities import (
    ParticipantFeatureSupport,
    ParticipantRuntimeCapabilities,
    TIME_CAPABILITY_REQUIRED_CONTRACTS,
    TimeCapabilities,
)
from raes_contracts.vocabulary import ParticipantFeatureSupportLevel

_TIME = TimeCapabilities(
    name="aptl-logical-participant-sequence-time",
    supported_contract_versions=TIME_CAPABILITY_REQUIRED_CONTRACTS,
    supported_domain_kinds=frozenset({"logical"}),
    supported_authority_kinds=frozenset({"runtime"}),
    supported_advancement_modes=frozenset({"event_driven"}),
    supported_synchronization_modes=frozenset({"barrier"}),
    supported_mapping_kinds=frozenset(),
    supported_constraint_kinds=frozenset({"window"}),
    supported_reset_behaviors=frozenset({"unsupported"}),
    supported_replay_behaviors=frozenset({"unsupported"}),
    max_time_domains=1,
    max_clocks=1,
    supports_append_only_history=True,
    supports_run_provenance=True,
    constraints={
        "execution_scope": "sdl-authored-participant-inject-delivery-sequence",
    },
)


def participant_delivery_manifest_options(
    supported_contract_versions: frozenset[str],
    participant_runtime: ParticipantRuntimeCapabilities,
    *,
    enabled: bool,
) -> tuple[frozenset[str], ParticipantRuntimeCapabilities, dict[str, object]]:
    """Add exact participant delivery and logical time claims when selected."""

    if not enabled:
        return supported_contract_versions, participant_runtime, {}
    runtime = replace(
        participant_runtime,
        supported_behavior_features=(
            participant_runtime.supported_behavior_features
            | {
                "participant_directed_inject_delivery",
                "participant_ingress_admission",
            }
        ),
        feature_support=(
            *participant_runtime.feature_support,
            ParticipantFeatureSupport(
                feature="participant_ingress_admission",
                support_level=ParticipantFeatureSupportLevel.EXACT,
                constraint_refs=(
                    "constraint:participant-ingress:sdl-authored-delivery-policy",
                ),
                evidence_refs=(
                    "evidence:participant-ingress:api-423-crossing-occurrence",
                ),
            ),
            ParticipantFeatureSupport(
                feature="participant_directed_inject_delivery",
                support_level=ParticipantFeatureSupportLevel.EXACT,
                constraint_refs=(
                    "constraint:participant-inject-delivery:sdl-authored-ordered-sequence",
                    "constraint:participant-inject-delivery:claude-code-host-session",
                ),
                evidence_refs=(
                    "evidence:participant-inject-delivery:run-archive-occurrence",
                ),
            ),
        ),
    )
    return (
        supported_contract_versions | TIME_CAPABILITY_REQUIRED_CONTRACTS,
        runtime,
        {"time": _TIME},
    )
