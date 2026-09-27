"""Exact adapter declarations for the TechVault participant study pack."""

from aptl.backends.scenario_capture import (
    ScenarioCaptureContext,
    ScenarioCaptureContribution,
)

from aptl.validation.scenario_verification import QualifiedTarget, ScenarioIdentity
from aptl_techvault.capture import TechVaultCaptureProvider
from aptl_techvault.capture_registrations import BUILTIN_REGISTRATIONS
from aptl_techvault.study_capture_registrations import (
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
    """Bind the study pack to the proven TechVault runtime parameters."""

    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyStartup(TechVaultStartupProvider):
    """Bind the study pack to the proven TechVault startup adapter."""

    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyServing(TechVaultPackInteraction):
    """Bind the study pack to the proven TechVault serving adapter."""

    provider_id = "techvault-study-aptl-serving"
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyPlanningCompatibility(TechVaultPlanningCompatibilityProvider):
    """Bind the study pack to TechVault planning compatibility."""

    provider_id = "techvault-study-aptl-planning-compatibility"
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)


class StudyCapture(TechVaultCaptureProvider):
    """Add four participant delivery captures to TechVault evidence."""

    provider_id = "techvault-study-aptl-capture"
    supported_pack_id = PACK_ID
    supported_pack_set_digests = (STUDY_PACK_SET_DIGEST,)

    @staticmethod
    def resolve(context: ScenarioCaptureContext) -> ScenarioCaptureContribution:
        """Return TechVault captures plus four participant deliveries."""

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
    """Qualify the exact study pack identity on supported transports."""

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
