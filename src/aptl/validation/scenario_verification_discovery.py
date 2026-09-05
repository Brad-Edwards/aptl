"""Finding, matching, and running the one compatible scenario verifier (#878).

Every path out of this module that is not "exactly one compatible plugin ran and
returned a well-formed report" ends in ``blocked``. That is the point: a range
whose verification could not run has not been verified, and saying so is the only
honest outcome. Silently skipping, picking the first of several candidates, or
falling back to a built-in adapter would each turn an unverified range into an
apparently good one.

Selection is by installed distribution metadata alone. Scenario data,
``aptl.json``, environment variables, and CLI arguments never supply a module,
class, path, or import string — otherwise scenario content could choose the code
that judges it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from importlib import metadata
from math import isfinite
from time import monotonic
from typing import TYPE_CHECKING

from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
from aptl.validation.scenario_verification import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    REPORT_API_VERSION,
    BackendIdentity,
    PrerequisiteResult,
    PrerequisiteStatus,
    ScenarioIdentity,
    VerificationCheck,
    VerificationContext,
    VerificationReport,
    VerificationStatus,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

log = get_logger("scenario-verification")

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_METADATA_ITEMS = 64
_MAX_PREREQUISITES = 64
_MAX_CHECKS = 128
_MAX_DIAGNOSTICS = 64
_MAX_DIAGNOSTIC_LENGTH = 1024


class _VerifierContractError(ValueError):
    """One stable, non-public discovery or report validation failure."""


class DiscoveredVerifier(object):
    """One installed verifier plus the host-observed facts about where it came from.

    The distribution name and version are read from installed metadata rather
    than taken from the plugin's own attributes, so a plugin cannot misreport its
    provenance in the evidence record.
    """

    __slots__ = (
        "verifier",
        "plugin_id",
        "distribution",
        "distribution_version",
        "entry_point",
    )

    def __init__(
        self,
        verifier: object,
        plugin_id: str,
        distribution: str,
        distribution_version: str,
        entry_point: str,
    ) -> None:
        self.verifier = verifier
        self.plugin_id = plugin_id
        self.distribution = distribution
        self.distribution_version = distribution_version
        self.entry_point = entry_point


def _blocked(
    context: VerificationContext,
    diagnostic: str,
    discovered: DiscoveredVerifier | None = None,
    *,
    elapsed_seconds: float = 0.0,
) -> VerificationReport:
    """Return a blocked report carrying one bounded, redacted diagnostic."""

    return VerificationReport(
        status=VerificationStatus.BLOCKED,
        scenario=context.scenario,
        backend=context.backend,
        run_id=context.run_id,
        attempt_id=context.attempt_id,
        plugin_id=discovered.plugin_id if discovered else "",
        distribution=discovered.distribution if discovered else "",
        distribution_version=discovered.distribution_version if discovered else "",
        entry_point=discovered.entry_point if discovered else "",
        diagnostics=(redact(diagnostic)[:_MAX_DIAGNOSTIC_LENGTH],),
        elapsed_seconds=max(0.0, elapsed_seconds),
    )


def _entry_points() -> Sequence[metadata.EntryPoint]:
    """Return every entry point registered in the verifier group."""

    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _selector(scenario: ScenarioIdentity, backend: BackendIdentity) -> str:
    """Return the non-executable installed family selector for this run."""

    return f"{scenario.identity}.{backend.target_name}"


def _validate_context(context: VerificationContext) -> None:
    """Reject malformed host input before any installed plugin code can run."""

    if not isinstance(context, VerificationContext):
        raise _VerifierContractError("verification-context-invalid")
    _identifier(context.run_id, "verification-context-invalid")
    _identifier(context.attempt_id, "verification-context-invalid")
    _identifier(context.scenario.identity, "verification-context-invalid")
    _identifier(context.scenario.source_kind, "verification-context-invalid")
    _text(context.scenario.version, "verification-context-invalid")
    if (
        not isinstance(context.scenario.content_digest, str)
        or _SHA256_DIGEST.fullmatch(context.scenario.content_digest) is None
    ):
        raise _VerifierContractError("verification-context-invalid")
    _identifier(context.backend.target_name, "verification-context-invalid")
    _text(context.backend.target_version, "verification-context-invalid")
    _identifier(context.backend.profile, "verification-context-invalid")
    _identifier(context.backend.provider, "verification-context-invalid")
    _identifier(context.backend.transport, "verification-context-invalid")
    if context.extension_api_version != EXTENSION_API_VERSION:
        raise _VerifierContractError("verification-context-invalid")
    deadline = context.deadline_monotonic
    poll_interval = context.poll_interval_seconds
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or deadline <= 0
        or isinstance(poll_interval, bool)
        or not isinstance(poll_interval, (int, float))
        or not isfinite(poll_interval)
        or not 0 < poll_interval <= 300
    ):
        raise _VerifierContractError("verification-context-invalid")
    observations = context.observations
    if not isinstance(observations, Mapping) or len(observations) > _MAX_METADATA_ITEMS:
        raise _VerifierContractError("verification-context-invalid")
    for key, value in observations.items():
        _identifier(key, "verification-context-invalid")
        _validate_observation(value)


def _validate_observation(value: object, *, depth: int = 0) -> None:
    """Validate one bounded JSON-like, already-redacted framework observation."""

    if depth > 4:
        raise _VerifierContractError("verification-context-invalid")
    if isinstance(value, str):
        if len(value) > _MAX_DIAGNOSTIC_LENGTH:
            raise _VerifierContractError("verification-context-invalid")
        return
    if isinstance(value, (int, float, bool, type(None))):
        return
    if isinstance(value, (tuple, list)):
        if len(value) > _MAX_METADATA_ITEMS:
            raise _VerifierContractError("verification-context-invalid")
        for item in value:
            _validate_observation(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_METADATA_ITEMS:
            raise _VerifierContractError("verification-context-invalid")
        for key, item in value.items():
            _identifier(key, "verification-context-invalid")
            _validate_observation(item, depth=depth + 1)
        return
    raise _VerifierContractError("verification-context-invalid")


def _identifier(value: object, code: str = "verifier-metadata-invalid") -> str:
    """Return one bounded evidence-safe identifier or fail closed."""

    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise _VerifierContractError(code)
    return value


def _text(value: object, code: str = "verifier-metadata-invalid") -> str:
    """Return one bounded non-empty metadata value."""

    if not isinstance(value, str) or not value or len(value) > 256:
        raise _VerifierContractError(code)
    return value


def _sequence(verifier: object, name: str) -> tuple[str, ...]:
    """Read one explicit, bounded tuple-of-strings compatibility claim."""

    value = getattr(verifier, name, None)
    if (
        not isinstance(value, tuple)
        or not value
        or len(value) > _MAX_METADATA_ITEMS
        or any(
            not isinstance(item, str) or not item or len(item) > 256 for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise _VerifierContractError("verifier-metadata-invalid")
    return value


def _load(entry_point: metadata.EntryPoint) -> DiscoveredVerifier | None:
    """Load one entry point, or return None if it is unusable.

    A plugin that fails to import, or whose target is not a verifier, is treated
    as absent rather than allowed to raise through the gate: the caller turns the
    absence into ``blocked`` with the reason attached.
    """

    try:
        target = entry_point.load()
    except Exception as exc:
        log.warning(
            "scenario verifier load failed: selector=%s exception=%s",
            entry_point.name,
            type(exc).__name__,
        )
        raise _VerifierContractError("verifier-load-failed") from None
    # A factory is allowed so a distribution need not construct its verifier at
    # import time; the result is what must satisfy the protocol.
    if isinstance(target, type) or (
        callable(target) and not callable(getattr(target, "run", None))
    ):
        try:
            target = target()
        except Exception as exc:
            log.warning(
                "scenario verifier factory failed: selector=%s exception=%s",
                entry_point.name,
                type(exc).__name__,
            )
            raise _VerifierContractError("verifier-load-failed") from None
    if not callable(getattr(target, "run", None)):
        raise _VerifierContractError("verifier-metadata-invalid")
    plugin_id = _identifier(getattr(target, "plugin_id", None))
    _text(getattr(target, "extension_api_version", None))
    _identifier(entry_point.name)
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        raise _VerifierContractError("verifier-metadata-invalid")
    distribution = _identifier(getattr(dist, "name", None))
    distribution_version = _text(getattr(dist, "version", None))
    return DiscoveredVerifier(
        verifier=target,
        plugin_id=plugin_id,
        distribution=distribution,
        distribution_version=distribution_version,
        entry_point=entry_point.name,
    )


def _incompatibility(
    discovered: DiscoveredVerifier,
    scenario: ScenarioIdentity,
    backend: BackendIdentity,
) -> str:
    """Return why this verifier does not fit, or an empty string if it does.

    Matching is exact in every dimension. A verifier that pinned content digests
    must match the admitted digest: content that changed is content the plugin
    was not written against, even when the scenario still answers to the same
    name.
    """

    verifier = discovered.verifier
    scalar_matches = (
        _text(getattr(verifier, "extension_api_version", None)) == EXTENSION_API_VERSION
        and _text(getattr(verifier, "scenario_identity", None)) == scenario.identity
        and _text(getattr(verifier, "backend_target_name", None)) == backend.target_name
    )
    if not scalar_matches:
        return "incompatible scalar claim"
    return _capability_mismatch(discovered, scenario, backend)


def _capability_mismatch(
    discovered: DiscoveredVerifier,
    scenario: ScenarioIdentity,
    backend: BackendIdentity,
) -> str:
    """Return why a name-matched verifier still does not fit, or an empty string.

    Content, backend target, and profile are each matched exactly; the first
    dimension that does not line up is the reported reason.
    """

    verifier = discovered.verifier
    source_kinds = _sequence(verifier, "scenario_source_kinds")
    scenario_versions = _sequence(verifier, "scenario_versions")
    digests = _sequence(verifier, "scenario_content_digests")
    target_versions = _sequence(verifier, "backend_target_versions")
    profiles = _sequence(verifier, "backend_profiles")
    providers = _sequence(verifier, "backend_providers")
    transports = _sequence(verifier, "backend_transports")
    checks = (
        (
            scenario.source_kind not in source_kinds,
            f"plugin {discovered.plugin_id!r} does not support scenario source "
            f"{scenario.source_kind!r}",
        ),
        (
            scenario.version not in scenario_versions,
            f"plugin {discovered.plugin_id!r} does not support scenario version "
            f"{scenario.version!r}",
        ),
        (
            scenario.content_digest not in digests,
            f"plugin {discovered.plugin_id!r} is pinned to different scenario "
            "content than the admitted scenario",
        ),
        (
            backend.target_version not in target_versions,
            f"plugin {discovered.plugin_id!r} does not support backend version "
            f"{backend.target_version!r}",
        ),
        (
            backend.profile not in profiles,
            f"plugin {discovered.plugin_id!r} does not support backend profile "
            f"{backend.profile!r}",
        ),
        (
            backend.provider not in providers,
            f"plugin {discovered.plugin_id!r} does not support backend provider "
            f"{backend.provider!r}",
        ),
        (
            backend.transport not in transports,
            f"plugin {discovered.plugin_id!r} does not support backend transport "
            f"{backend.transport!r}",
        ),
    )
    for failed, reason in checks:
        if failed:
            return reason
    return ""


def select_verifier(
    scenario: ScenarioIdentity, backend: BackendIdentity
) -> tuple[DiscoveredVerifier | None, str]:
    """Return the single compatible verifier, or None plus why not.

    Exactly one match is required. Several matches is an error rather than a
    choice: picking one would make the verdict depend on installation order.
    """

    selector = _selector(scenario, backend)
    candidates: list[DiscoveredVerifier] = []
    incompatibilities: list[str] = []
    exact = [
        entry_point for entry_point in _entry_points() if entry_point.name == selector
    ]
    try:
        for entry_point in exact:
            discovered = _load(entry_point)
            reason = _incompatibility(discovered, scenario, backend)
            if not reason:
                candidates.append(discovered)
            else:
                incompatibilities.append(reason)
    except _VerifierContractError as exc:
        return None, str(exc)

    if len(candidates) == 1:
        return candidates[0], ""
    if not candidates:
        detail = f" ({'; '.join(incompatibilities)})" if incompatibilities else ""
        return None, (
            f"no compatible scenario verifier is installed for selector {selector!r}"
            f"{detail}"
        )
    names = ", ".join(sorted(c.plugin_id for c in candidates))
    return None, (
        f"several scenario verifiers claim scenario {scenario.identity!r}: {names}. "
        "Exactly one must be installed."
    )


def verify_scenario(context: VerificationContext) -> VerificationReport:
    """Run the installed verifier for this scenario, or report why it could not.

    A plugin that raises, or returns something that is not a report, is
    normalized to ``blocked`` with a stable diagnostic. A raw exception must not
    become report text, and a broken plugin must not read as a broken range.
    """

    try:
        _validate_context(context)
    except _VerifierContractError as exc:
        return _blocked(context, str(exc))
    started = monotonic()
    if started >= context.deadline_monotonic:
        return _blocked(context, "verification-deadline-elapsed")
    discovered, reason = select_verifier(context.scenario, context.backend)
    if discovered is None:
        return _blocked(context, reason, elapsed_seconds=monotonic() - started)
    return _run_verifier(discovered, context, started)


def _run_verifier(
    discovered: DiscoveredVerifier,
    context: VerificationContext,
    started: float,
) -> VerificationReport:
    """Run one discovered verifier and normalize its result.

    Any exception the plugin raises, or any non-report it returns, becomes a
    stable ``blocked`` report: a raw exception must not become report text, and a
    broken plugin must not read as a broken range.
    """

    try:
        report = discovered.verifier.run(context)
    # Plugin code is not trusted to be total, so any failure is contained here.
    except Exception as exc:
        log.warning(
            "scenario verifier run failed: plugin=%s exception=%s",
            discovered.plugin_id,
            type(exc).__name__,
        )
        return _blocked(
            context,
            f"scenario verifier {discovered.plugin_id!r} failed while running",
            discovered,
            elapsed_seconds=monotonic() - started,
        )
    completed = monotonic()
    if completed > context.deadline_monotonic:
        return _blocked(
            context,
            "verification-deadline-elapsed",
            discovered,
            elapsed_seconds=completed - started,
        )
    try:
        return _validated_report(
            report,
            context,
            discovered,
            elapsed_seconds=completed - started,
        )
    except _VerifierContractError as exc:
        return _blocked(
            context,
            f"scenario verifier {discovered.plugin_id!r} returned a malformed report "
            f"({exc})",
            discovered,
            elapsed_seconds=completed - started,
        )


def _diagnostics(value: object) -> tuple[str, ...]:
    """Validate, bound, redact, and immutably copy diagnostic text."""

    if (
        not isinstance(value, tuple)
        or len(value) > _MAX_DIAGNOSTICS
        or any(
            not isinstance(item, str) or len(item) > _MAX_DIAGNOSTIC_LENGTH
            for item in value
        )
    ):
        raise _VerifierContractError("verifier-report-invalid")
    return tuple(redact(item) for item in value)


def _validated_prerequisites(value: object) -> tuple[PrerequisiteResult, ...]:
    """Validate and copy typed prerequisite outcomes."""

    if (
        not isinstance(value, tuple)
        or len(value) > _MAX_PREREQUISITES
        or any(not isinstance(item, PrerequisiteResult) for item in value)
    ):
        raise _VerifierContractError("verifier-report-invalid")
    copied: list[PrerequisiteResult] = []
    identifiers: set[str] = set()
    for item in value:
        if not isinstance(item.status, PrerequisiteStatus):
            raise _VerifierContractError("verifier-report-invalid")
        prerequisite_id = _identifier(item.prerequisite_id, "verifier-report-invalid")
        if prerequisite_id in identifiers:
            raise _VerifierContractError("verifier-report-invalid")
        identifiers.add(prerequisite_id)
        copied.append(
            PrerequisiteResult(
                prerequisite_id=prerequisite_id,
                status=item.status,
                diagnostic=_diagnostics((item.diagnostic,))[0],
            )
        )
    return tuple(copied)


def _validated_checks(value: object) -> tuple[VerificationCheck, ...]:
    """Validate and copy typed semantic-check outcomes."""

    if (
        not isinstance(value, tuple)
        or len(value) > _MAX_CHECKS
        or any(not isinstance(item, VerificationCheck) for item in value)
    ):
        raise _VerifierContractError("verifier-report-invalid")
    copied: list[VerificationCheck] = []
    identifiers: set[str] = set()
    for item in value:
        if item.status not in (VerificationStatus.PASSED, VerificationStatus.FAILED):
            raise _VerifierContractError("verifier-report-invalid")
        check_id = _identifier(item.check_id, "verifier-report-invalid")
        if check_id in identifiers:
            raise _VerifierContractError("verifier-report-invalid")
        identifiers.add(check_id)
        copied.append(
            VerificationCheck(
                check_id=check_id,
                status=item.status,
                diagnostic=_diagnostics((item.diagnostic,))[0],
                category=_identifier(item.category, "verifier-report-invalid"),
            )
        )
    return tuple(copied)


def _validate_aggregate(
    status: object,
    prerequisites: tuple[PrerequisiteResult, ...],
    checks: tuple[VerificationCheck, ...],
    diagnostics: tuple[str, ...],
) -> VerificationStatus:
    """Require one report outcome that agrees with all typed members."""

    if not isinstance(status, VerificationStatus):
        raise _VerifierContractError("verifier-report-invalid")
    unmet = any(item.status is PrerequisiteStatus.UNSATISFIED for item in prerequisites)
    if unmet:
        expected = VerificationStatus.BLOCKED
    elif checks:
        expected = (
            VerificationStatus.FAILED
            if any(item.status is VerificationStatus.FAILED for item in checks)
            else VerificationStatus.PASSED
        )
    elif diagnostics:
        expected = VerificationStatus.BLOCKED
    else:
        raise _VerifierContractError("verifier-report-invalid")
    if status is not expected:
        raise _VerifierContractError("verifier-report-invalid")
    return status


def _validated_report(
    report: object,
    context: VerificationContext,
    discovered: DiscoveredVerifier,
    *,
    elapsed_seconds: float,
) -> VerificationReport:
    """Return the host-owned immutable copy of one valid plugin report."""

    if not isinstance(report, VerificationReport):
        raise _VerifierContractError("verifier-report-invalid")
    if (
        report.api_version != REPORT_API_VERSION
        or report.extension_api_version != EXTENSION_API_VERSION
        or report.scenario != context.scenario
        or report.backend != context.backend
        or report.run_id != context.run_id
        or report.attempt_id != context.attempt_id
    ):
        raise _VerifierContractError("verifier-report-invalid")
    prerequisites = _validated_prerequisites(report.prerequisites)
    checks = _validated_checks(report.checks)
    diagnostics = _diagnostics(report.diagnostics)
    status = _validate_aggregate(report.status, prerequisites, checks, diagnostics)
    # Provenance is recorded from installed metadata, never from the plugin.
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
        diagnostics=diagnostics,
        elapsed_seconds=elapsed_seconds,
    )


__all__ = ["DiscoveredVerifier", "select_verifier", "verify_scenario"]
