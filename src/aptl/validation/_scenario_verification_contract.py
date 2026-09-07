"""Host-side validation for scenario verifier metadata, context, and reports."""

from __future__ import annotations

from collections.abc import Mapping
from math import isfinite
import re

from aptl.backends.identity import BackendIdentity
from aptl.utils.redaction import redact
from aptl.validation.scenario_verification import (
    EXTENSION_API_VERSION,
    REPORT_API_VERSION,
    PrerequisiteResult,
    PrerequisiteStatus,
    QualifiedTarget,
    ScenarioIdentity,
    VerificationCheck,
    VerificationContext,
    VerificationReport,
    VerificationStatus,
)

SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_METADATA_ITEMS = 64
MAX_PREREQUISITES = 64
MAX_CHECKS = 128
MAX_DIAGNOSTICS = 64
MAX_DIAGNOSTIC_LENGTH = 1024


class VerifierContractError(ValueError):
    """One stable, non-public discovery or report validation failure."""


def identifier(value: object, code: str = "verifier-metadata-invalid") -> str:
    """Return one bounded evidence-safe identifier or fail closed."""

    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise VerifierContractError(code)
    return value


def text(value: object, code: str = "verifier-metadata-invalid") -> str:
    """Return one bounded non-empty metadata value."""

    if not isinstance(value, str) or not value or len(value) > 256:
        raise VerifierContractError(code)
    return value


def qualified_targets(verifier: object) -> tuple[QualifiedTarget, ...]:
    """Read one explicit, bounded set of atomically qualified pairs.

    Declared identities go through the same validators as the admitted ones, so
    a plugin cannot qualify a digest or profile the host would refuse to accept
    as input. An empty declaration is rejected rather than read as a wildcard.
    """

    value = getattr(verifier, "qualified_targets", None)
    if not isinstance(value, tuple) or not value or len(value) > MAX_METADATA_ITEMS:
        raise VerifierContractError("verifier-metadata-invalid")
    for target in value:
        # ``QualifiedTarget`` is an ordinary dataclass, so its members are
        # whatever the plugin put there. Check their types before reading or
        # hashing them: dereferencing a wrong type would raise AttributeError,
        # and an unhashable one would raise TypeError at the duplicate check --
        # neither is a VerifierContractError, so both would escape discovery
        # instead of becoming the blocked report it promises.
        if (
            not isinstance(target, QualifiedTarget)
            or not isinstance(target.scenario, ScenarioIdentity)
            or not isinstance(target.backend, BackendIdentity)
        ):
            raise VerifierContractError("verifier-metadata-invalid")
        _validate_scenario_identity(target.scenario, "verifier-metadata-invalid")
        _validate_backend_identity(target.backend, "verifier-metadata-invalid")
    if len(set(value)) != len(value):
        raise VerifierContractError("verifier-metadata-invalid")
    return value


def _validate_scenario_identity(scenario: ScenarioIdentity, code: str) -> None:
    """Validate one scenario identity and its exact content digest."""

    identifier(scenario.identity, code)
    identifier(scenario.source_kind, code)
    text(scenario.version, code)
    digest = scenario.content_digest
    if not isinstance(digest, str) or SHA256_DIGEST.fullmatch(digest) is None:
        raise VerifierContractError(code)


def _validate_backend_identity(backend: BackendIdentity, code: str) -> None:
    """Validate every backend compatibility dimension exposed to plugins."""

    identifier(backend.target_name, code)
    text(backend.target_version, code)
    identifier(backend.profile, code)
    identifier(backend.provider, code)
    identifier(backend.transport, code)


def _valid_schedule_number(value: object, *, finite: bool) -> bool:
    """Return whether a deadline or interval is a usable real number."""

    valid = not isinstance(value, bool) and isinstance(value, (int, float))
    return valid and (not finite or isfinite(value))


def _validate_schedule(context: VerificationContext) -> None:
    """Validate the host-owned deadline and polling interval."""

    deadline = context.deadline_monotonic
    interval = context.poll_interval_seconds
    valid_deadline = _valid_schedule_number(deadline, finite=False) and deadline > 0
    valid_interval = (
        _valid_schedule_number(interval, finite=True) and 0 < interval <= 300
    )
    if not valid_deadline or not valid_interval:
        raise VerifierContractError("verification-context-invalid")


def _validate_observation_items(value: tuple | list, depth: int) -> None:
    """Validate a bounded sequence of framework observations recursively."""

    if len(value) > MAX_METADATA_ITEMS:
        raise VerifierContractError("verification-context-invalid")
    for item in value:
        _validate_observation(item, depth=depth + 1)


def _validate_observation_mapping(value: Mapping[object, object], depth: int) -> None:
    """Validate a bounded mapping of framework observations recursively."""

    if len(value) > MAX_METADATA_ITEMS:
        raise VerifierContractError("verification-context-invalid")
    for key, item in value.items():
        identifier(key, "verification-context-invalid")
        _validate_observation(item, depth=depth + 1)


def _validate_observation(value: object, *, depth: int = 0) -> None:
    """Validate one bounded JSON-like, already-redacted framework observation."""

    if depth > 4:
        raise VerifierContractError("verification-context-invalid")
    if isinstance(value, str):
        if len(value) > MAX_DIAGNOSTIC_LENGTH:
            raise VerifierContractError("verification-context-invalid")
    elif isinstance(value, (tuple, list)):
        _validate_observation_items(value, depth)
    elif isinstance(value, Mapping):
        _validate_observation_mapping(value, depth)
    elif not isinstance(value, (int, float, bool, type(None))):
        raise VerifierContractError("verification-context-invalid")


def _validate_observations(context: VerificationContext) -> None:
    """Validate the complete bounded observation surface."""

    observations = context.observations
    if not isinstance(observations, Mapping) or len(observations) > MAX_METADATA_ITEMS:
        raise VerifierContractError("verification-context-invalid")
    for key, value in observations.items():
        identifier(key, "verification-context-invalid")
        _validate_observation(value)


def validate_context(context: VerificationContext) -> None:
    """Reject malformed host input before any installed plugin code can run."""

    if not isinstance(context, VerificationContext):
        raise VerifierContractError("verification-context-invalid")
    identifier(context.run_id, "verification-context-invalid")
    identifier(context.attempt_id, "verification-context-invalid")
    _validate_scenario_identity(context.scenario, "verification-context-invalid")
    _validate_backend_identity(context.backend, "verification-context-invalid")
    if context.extension_api_version != EXTENSION_API_VERSION:
        raise VerifierContractError("verification-context-invalid")
    _validate_schedule(context)
    _validate_observations(context)


def diagnostics(value: object) -> tuple[str, ...]:
    """Validate, bound, redact, and immutably copy diagnostic text."""

    if not isinstance(value, tuple):
        raise VerifierContractError("verifier-report-invalid")
    valid_items = all(
        isinstance(item, str) and len(item) <= MAX_DIAGNOSTIC_LENGTH for item in value
    )
    if not valid_items or len(value) > MAX_DIAGNOSTICS:
        raise VerifierContractError("verifier-report-invalid")
    return tuple(redact(item) for item in value)


def _copy_prerequisite(item: PrerequisiteResult) -> PrerequisiteResult:
    """Return one validated host-owned prerequisite copy."""

    if not isinstance(item.status, PrerequisiteStatus):
        raise VerifierContractError("verifier-report-invalid")
    prerequisite_id = identifier(item.prerequisite_id, "verifier-report-invalid")
    return PrerequisiteResult(
        prerequisite_id=prerequisite_id,
        status=item.status,
        diagnostic=diagnostics((item.diagnostic,))[0],
    )


def validated_prerequisites(value: object) -> tuple[PrerequisiteResult, ...]:
    """Validate and copy typed prerequisite outcomes."""

    if not isinstance(value, tuple):
        raise VerifierContractError("verifier-report-invalid")
    valid_items = all(isinstance(item, PrerequisiteResult) for item in value)
    if not valid_items or len(value) > MAX_PREREQUISITES:
        raise VerifierContractError("verifier-report-invalid")
    copied = tuple(_copy_prerequisite(item) for item in value)
    identifiers = [item.prerequisite_id for item in copied]
    if len(set(identifiers)) != len(identifiers):
        raise VerifierContractError("verifier-report-invalid")
    return copied


def _copy_check(item: VerificationCheck) -> VerificationCheck:
    """Return one validated host-owned semantic-check copy."""

    if item.status not in (VerificationStatus.PASSED, VerificationStatus.FAILED):
        raise VerifierContractError("verifier-report-invalid")
    return VerificationCheck(
        check_id=identifier(item.check_id, "verifier-report-invalid"),
        status=item.status,
        diagnostic=diagnostics((item.diagnostic,))[0],
        category=identifier(item.category, "verifier-report-invalid"),
    )


def validated_checks(value: object) -> tuple[VerificationCheck, ...]:
    """Validate and copy typed semantic-check outcomes."""

    if not isinstance(value, tuple):
        raise VerifierContractError("verifier-report-invalid")
    valid_items = all(isinstance(item, VerificationCheck) for item in value)
    if not valid_items or len(value) > MAX_CHECKS:
        raise VerifierContractError("verifier-report-invalid")
    copied = tuple(_copy_check(item) for item in value)
    identifiers = [item.check_id for item in copied]
    if len(set(identifiers)) != len(identifiers):
        raise VerifierContractError("verifier-report-invalid")
    return copied


def validate_aggregate(
    status: object,
    prerequisites: tuple[PrerequisiteResult, ...],
    checks: tuple[VerificationCheck, ...],
    report_diagnostics: tuple[str, ...],
) -> VerificationStatus:
    """Require one report outcome that agrees with all typed members."""

    if not isinstance(status, VerificationStatus):
        raise VerifierContractError("verifier-report-invalid")
    if any(item.status is PrerequisiteStatus.UNSATISFIED for item in prerequisites):
        expected = VerificationStatus.BLOCKED
    elif any(item.status is VerificationStatus.FAILED for item in checks):
        expected = VerificationStatus.FAILED
    elif checks:
        expected = VerificationStatus.PASSED
    elif report_diagnostics:
        expected = VerificationStatus.BLOCKED
    else:
        raise VerifierContractError("verifier-report-invalid")
    if status is not expected:
        raise VerifierContractError("verifier-report-invalid")
    return status


def validated_report(
    report: object,
    context: VerificationContext,
    discovered: object,
    *,
    elapsed_seconds: float,
) -> VerificationReport:
    """Return the host-owned immutable copy of one valid plugin report."""

    if not isinstance(report, VerificationReport):
        raise VerifierContractError("verifier-report-invalid")
    identity_matches = (
        report.api_version == REPORT_API_VERSION
        and report.extension_api_version == EXTENSION_API_VERSION
        and report.scenario == context.scenario
        and report.backend == context.backend
        and report.run_id == context.run_id
        and report.attempt_id == context.attempt_id
    )
    if not identity_matches:
        raise VerifierContractError("verifier-report-invalid")
    prerequisites = validated_prerequisites(report.prerequisites)
    checks = validated_checks(report.checks)
    report_diagnostics = diagnostics(report.diagnostics)
    status = validate_aggregate(
        report.status, prerequisites, checks, report_diagnostics
    )
    return VerificationReport(
        status=status,
        scenario=context.scenario,
        backend=context.backend,
        api_version=REPORT_API_VERSION,
        run_id=context.run_id,
        attempt_id=context.attempt_id,
        plugin_id=discovered.plugin_id,
        distribution=discovered.distribution,
        distribution_version=discovered.distribution_version,
        entry_point=discovered.entry_point,
        extension_api_version=EXTENSION_API_VERSION,
        prerequisites=prerequisites,
        checks=checks,
        diagnostics=report_diagnostics,
        elapsed_seconds=elapsed_seconds,
    )
