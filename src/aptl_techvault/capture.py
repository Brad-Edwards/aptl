"""TechVault capture contribution for the installed adapter seam."""

from __future__ import annotations

from aptl.backends.scenario_capture import (
    EXTENSION_API_VERSION,
    ScenarioCaptureContext,
    ScenarioCaptureContribution,
)
from aptl_techvault.capture_registrations import BUILTIN_REGISTRATIONS
from aptl_techvault.evidence.proposition_truth import native_evidence_result
from aptl_techvault.evidence.techvault_native import TechVaultNativeEvidenceOwner
from aptl_techvault.evidence.transcript_parsing import (
    FinalizedTranscriptCollector,
    binding_from_projection,
)
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST

_NATIVE_REGISTRATIONS = frozenset(
    {
        "aptl.collector.cortex-enrichment",
        "aptl.collector.misp-authenticated-api-readiness",
        "aptl.collector.suricata-rule-readiness",
        "aptl.collector.suricata-wazuh-sqli",
        "aptl.collector.wazuh-agent-readiness",
    }
)
_TRANSCRIPT_REGISTRATION = "aptl.collector.redteam-session-transcript"


class TechVaultPropositionInterpreter:
    """Callable truth projection plus its bounded requirement vocabulary."""

    capability_ids = frozenset(
        {
            "cortex-enrichment-readback",
            "misp-authenticated-api-readiness",
            "suricata-local-rule-readiness",
            "wazuh-agent-readiness",
            "suricata-login-sqli-alert",
        }
    )

    def __call__(self, *args: object) -> object:
        return native_evidence_result(*args)  # type: ignore[arg-type]


class TechVaultCaptureRuntimeAdapter:
    """Narrow executable operations paired with admitted declarations."""

    @staticmethod
    def native_sources(request: object) -> object:
        environment = request.environment
        owner = TechVaultNativeEvidenceOwner(
            backend=request.backend,
            realization=request.realization,
            project_dir=request.project_dir,
            indexer_auth=(
                environment.get("INDEXER_USERNAME", ""),
                environment.get("INDEXER_PASSWORD", ""),
            ),
            thehive_api_key=environment.get("THEHIVE_API_KEY", ""),
        )
        return owner.sources()

    @staticmethod
    def binding_from_projection(value: object) -> object:
        return binding_from_projection(value)

    @staticmethod
    def finalized_transcript_collector(
        binding: object, payload: object, activated_at: str
    ) -> object:
        return FinalizedTranscriptCollector(binding, payload, activated_at)


class TechVaultCaptureProvider:
    """Supply TechVault declarations through exact pack/backend admission."""

    provider_id = "techvault-aptl-capture"
    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.0",)
    supported_pack_set_digests = (TECHVAULT_PACK_SET_DIGEST,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles = ("full-remote-control-plane",)
    backend_transports: tuple[str, ...] = ()

    @staticmethod
    def resolve(_context: ScenarioCaptureContext) -> ScenarioCaptureContribution:
        return ScenarioCaptureContribution(
            registrations=BUILTIN_REGISTRATIONS,
            native_registration_ids=_NATIVE_REGISTRATIONS,
            runtime_environment_keys=(
                "INDEXER_USERNAME",
                "INDEXER_PASSWORD",
                "THEHIVE_API_KEY",
            ),
            transcript_registration_id=_TRANSCRIPT_REGISTRATION,
            runtime_adapter=TechVaultCaptureRuntimeAdapter(),
            proposition_interpreter=TechVaultPropositionInterpreter(),
        )


provider = TechVaultCaptureProvider()

__all__ = ["TechVaultCaptureProvider", "provider"]
