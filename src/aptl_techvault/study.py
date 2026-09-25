"""Exact adapter declarations for the TechVault participant study pack."""

from aptl.backends.scenario_capture import (
    ScenarioCaptureContext,
    ScenarioCaptureContribution,
)

from aptl.validation.scenario_verification import QualifiedTarget, ScenarioIdentity
from aptl_techvault.capture import TechVaultCaptureProvider
from aptl_techvault.capture_registrations import (
    BUILTIN_REGISTRATIONS,
    participant_delivery_registrations,
)
from aptl_techvault.planning_compatibility import TechVaultPlanningCompatibilityProvider
from aptl_techvault.runtime_parameters import (
    STUDY_PACK_SET_DIGEST,
    TechVaultRuntimeParameterProvider,
)
from aptl_techvault.serving import TechVaultPackInteraction
from aptl_techvault.startup import TechVaultStartupProvider
from aptl_techvault.verification import TechVaultVerifier, _qualified_backend

PACK_ID = "techvault-participant-study"
PACK_VERSION = "0.1.0"


class StudyRuntimeParameters(TechVaultRuntimeParameterProvider):
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyStartup(TechVaultStartupProvider):
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyServing(TechVaultPackInteraction):
    provider_id = "techvault-study-aptl-serving"
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyPlanningCompatibility(TechVaultPlanningCompatibilityProvider):
    provider_id = "techvault-study-aptl-planning-compatibility"
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyCapture(TechVaultCaptureProvider):
    provider_id = "techvault-study-aptl-capture"
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)

    @staticmethod
    def resolve(context: ScenarioCaptureContext) -> ScenarioCaptureContribution:
        base = TechVaultCaptureProvider.resolve(context)
        return ScenarioCaptureContribution(
            registrations=(
                *BUILTIN_REGISTRATIONS,
                *participant_delivery_registrations(),
            ),
            native_registration_ids=base.native_registration_ids,
            runtime_environment_keys=base.runtime_environment_keys,
            transcript_registration_id=base.transcript_registration_id,
            runtime_adapter=base.runtime_adapter,
            proposition_interpreter=base.proposition_interpreter,
        )


class StudyVerifier(TechVaultVerifier):
    plugin_id = PACK_ID
    qualified_targets = tuple(
        QualifiedTarget(
            scenario=ScenarioIdentity(
                identity=PACK_ID,
                content_digest=STUDY_PACK_SET_DIGEST,
                source_kind="env-pack",
                version=PACK_VERSION,
            ),
            backend=_qualified_backend(transport),
        )
        for transport in ("docker-compose", "ssh-compose")
    )


runtime_parameters = StudyRuntimeParameters()
startup = StudyStartup()
serving = StudyServing()
planning_compatibility = StudyPlanningCompatibility()
capture = StudyCapture()
verifier = StudyVerifier()
