"""Configured participant source acquisition and secret-free evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from aptl.utils.placeholders import contains_placeholder
from aptl.workbench.credentials import WorkbenchCredentialError

if TYPE_CHECKING:
    from aptl.core.config import ProcessEnvironmentCredentialSource

_MAX_CREDENTIAL_BYTES = 65_536


@dataclass
class CredentialBindingEvidence:
    """Secret-free facts about one configured credential acquisition."""

    provider: str
    run_id: str
    source_kind: str | None
    descriptor_sha256: str | None
    config_ref: str
    delivery_contract: str
    acquisition: str = "pending"
    acquisition_observed_at: str | None = None
    isolation: str = "not-verified"
    isolation_controls_applied: tuple[str, ...] = ()
    local_cleanup: str = "not-requested"
    cleanup_observed_at: str | None = None

    def to_payload(self) -> dict[str, object]:
        """Project only non-secret, non-locator lifecycle facts."""

        return {
            "schema": "aptl.participant-credential-binding/v1",
            "provider": self.provider,
            "run_id": self.run_id,
            "source_kind": self.source_kind,
            "resolver_contract": (
                "aptl.process-environment-credential-source/v1"
                if self.source_kind == "process-environment"
                else None
            ),
            "descriptor_sha256": self.descriptor_sha256,
            "config_ref": self.config_ref,
            "delivery_kind": "provider-native-environment",
            "delivery_contract": self.delivery_contract,
            "isolation_controls_applied": list(self.isolation_controls_applied),
            "acquisition": self.acquisition,
            "acquisition_observed_at": self.acquisition_observed_at,
            "isolation": self.isolation,
            "expiry": "unknown",
            "renewal": "unsupported",
            "upstream_revocation": "unsupported-by-aptl",
            "local_cleanup": self.local_cleanup,
            "cleanup_observed_at": self.cleanup_observed_at,
        }


class ProcessEnvironmentCredentialResolver:
    """Resolve exactly one configured parent-process variable."""

    def __init__(self, source_environment: Mapping[str, str]) -> None:
        self._source_environment = source_environment

    def acquire(
        self,
        provider: str,
        run_id: str,
        *,
        source: ProcessEnvironmentCredentialSource,
        delivery_alias: str,
        evidence: CredentialBindingEvidence | None = None,
    ) -> tuple[dict[str, str], CredentialBindingEvidence]:
        """Acquire one configured value and map it to one delivery alias."""

        evidence = evidence or configured_source_evidence(provider, source, run_id)
        evidence.acquisition_observed_at = _utc_now()
        value = self._source_environment.get(source.variable)
        if not value:
            evidence.acquisition = "source-unavailable"
            raise participant_binding_error(
                "configured participant credential is unavailable", evidence
            )
        if (
            not isinstance(value, str)
            or contains_placeholder(value)
            or "\x00" in value
            or len(value.encode("utf-8")) > _MAX_CREDENTIAL_BYTES
        ):
            evidence.acquisition = "source-invalid"
            raise participant_binding_error(
                "configured participant credential is invalid", evidence
            )
        evidence.acquisition = "succeeded"
        evidence.local_cleanup = "pending"
        return {delivery_alias: value}, evidence


def configured_source_evidence(
    provider: str,
    source: ProcessEnvironmentCredentialSource,
    run_id: str,
) -> CredentialBindingEvidence:
    """Describe one validated source before touching credential material."""

    return CredentialBindingEvidence(
        provider=provider,
        run_id=run_id,
        source_kind=source.kind,
        descriptor_sha256=source.descriptor_digest(),
        config_ref=f"experiment.participant_credential_sources.{provider}",
        delivery_contract=f"aptl.{provider}-credential-environment/v1",
    )


def observe_local_cleanup(
    evidence: CredentialBindingEvidence,
    *,
    succeeded: bool,
) -> None:
    """Record local reference cleanup without implying upstream revocation."""

    evidence.local_cleanup = "succeeded" if succeeded else "failed"
    evidence.cleanup_observed_at = _utc_now()


def participant_binding_error(
    message: str,
    evidence: CredentialBindingEvidence,
) -> WorkbenchCredentialError:
    """Attach typed evidence to the incumbent stable workbench error."""

    error = WorkbenchCredentialError(message)
    setattr(error, "evidence", evidence)
    return error


def evidence_from_error(exc: BaseException) -> CredentialBindingEvidence | None:
    """Read binding evidence only from an incumbent workbench error."""

    if not isinstance(exc, WorkbenchCredentialError):
        return None
    evidence = getattr(exc, "evidence", None)
    return evidence if isinstance(evidence, CredentialBindingEvidence) else None


def _utc_now() -> str:
    """Return one explicit UTC timestamp for lifecycle evidence."""

    return datetime.now(UTC).isoformat()
