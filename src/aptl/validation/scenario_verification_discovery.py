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

from importlib import metadata
from time import monotonic
from typing import TYPE_CHECKING

from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
from aptl.validation._scenario_verification_contract import (
    MAX_DIAGNOSTIC_LENGTH as _MAX_DIAGNOSTIC_LENGTH,
    VerifierContractError as _VerifierContractError,
    identifier as _identifier,
    qualified_targets as _qualified_targets,
    text as _text,
    validate_context as _validate_context,
    validated_report as _validated_report,
)
from aptl.validation.scenario_verification import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    BackendIdentity,
    QualifiedTarget,
    ScenarioIdentity,
    VerificationContext,
    VerificationReport,
    VerificationStatus,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

log = get_logger("scenario-verification")

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

    A qualified target is admitted whole. The admitted scenario and backend must
    equal one declared pair exactly, because a pair is the unit the plugin
    release actually qualified -- mixing dimensions across pairs would run
    against a combination nothing ever qualified.
    """

    verifier = discovered.verifier
    declared_api = _text(getattr(verifier, "extension_api_version", None))
    if declared_api != EXTENSION_API_VERSION:
        return "incompatible extension api version"
    targets = _qualified_targets(verifier)
    if QualifiedTarget(scenario=scenario, backend=backend) in targets:
        return ""
    return _nearest_mismatch(discovered, targets, scenario, backend)


def _mismatched_dimensions(
    target: QualifiedTarget,
    scenario: ScenarioIdentity,
    backend: BackendIdentity,
) -> tuple[str, ...]:
    """Return the reasons one declared pair does not admit this run."""

    reasons = (
        (
            target.scenario.identity != scenario.identity,
            f"does not support scenario {scenario.identity!r}",
        ),
        (
            target.scenario.source_kind != scenario.source_kind,
            f"does not support scenario source {scenario.source_kind!r}",
        ),
        (
            target.scenario.version != scenario.version,
            f"does not support scenario version {scenario.version!r}",
        ),
        (
            target.scenario.content_digest != scenario.content_digest,
            "is pinned to different scenario content than the admitted scenario",
        ),
        (
            target.backend.target_name != backend.target_name,
            f"does not support backend {backend.target_name!r}",
        ),
        (
            target.backend.target_version != backend.target_version,
            f"does not support backend version {backend.target_version!r}",
        ),
        (
            target.backend.profile != backend.profile,
            f"does not support backend profile {backend.profile!r}",
        ),
        (
            target.backend.provider != backend.provider,
            f"does not support backend provider {backend.provider!r}",
        ),
        (
            target.backend.transport != backend.transport,
            f"does not support backend transport {backend.transport!r}",
        ),
    )
    return tuple(reason for mismatched, reason in reasons if mismatched)


def _nearest_mismatch(
    discovered: DiscoveredVerifier,
    targets: tuple[QualifiedTarget, ...],
    scenario: ScenarioIdentity,
    backend: BackendIdentity,
) -> str:
    """Return the most specific reason no declared pair admits this run.

    With several declared pairs, the one that disagrees in the fewest dimensions
    is the closest thing to a qualification for this range, so its first
    disagreement is the actionable reason -- a digest divergence against the
    otherwise-matching release, rather than a scenario-name mismatch against
    some unrelated pair.
    """

    nearest = min(
        (_mismatched_dimensions(target, scenario, backend) for target in targets),
        key=len,
    )
    if not nearest:
        # No declared pair equals this range, yet no named dimension disagrees:
        # an identity gained a field the reasons above do not cover. Refusing
        # generically keeps discovery fail-closed, where indexing an empty
        # reason list would raise straight through the gate instead.
        return f"plugin {discovered.plugin_id!r} is not qualified for this range"
    return f"plugin {discovered.plugin_id!r} {nearest[0]}"


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
    selection: tuple[DiscoveredVerifier | None, str]
    try:
        for entry_point in exact:
            discovered = _load(entry_point)
            reason = _incompatibility(discovered, scenario, backend)
            if not reason:
                candidates.append(discovered)
            else:
                incompatibilities.append(reason)
    except _VerifierContractError as exc:
        selection = (None, str(exc))
    else:
        if len(candidates) == 1:
            selection = (candidates[0], "")
        elif not candidates:
            detail = (
                f" ({'; '.join(incompatibilities)})" if incompatibilities else ""
            )
            selection = (
                None,
                f"no compatible scenario verifier is installed for selector "
                f"{selector!r}{detail}",
            )
        else:
            names = ", ".join(sorted(c.plugin_id for c in candidates))
            selection = (
                None,
                f"several scenario verifiers claim scenario "
                f"{scenario.identity!r}: {names}. Exactly one must be installed.",
            )
    return selection


def verify_scenario(context: VerificationContext) -> VerificationReport:
    """Run the installed verifier for this scenario, or report why it could not.

    A plugin that raises, or returns something that is not a report, is
    normalized to ``blocked`` with a stable diagnostic. A raw exception must not
    become report text, and a broken plugin must not read as a broken range.
    """

    try:
        _validate_context(context)
    except _VerifierContractError as exc:
        result = _blocked(context, str(exc))
    else:
        started = monotonic()
        if started >= context.deadline_monotonic:
            result = _blocked(context, "verification-deadline-elapsed")
        else:
            discovered, reason = select_verifier(context.scenario, context.backend)
            if discovered is None:
                result = _blocked(
                    context, reason, elapsed_seconds=monotonic() - started
                )
            else:
                result = _run_verifier(discovered, context, started)
    return result


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
        result = _blocked(
            context,
            f"scenario verifier {discovered.plugin_id!r} failed while running",
            discovered,
            elapsed_seconds=monotonic() - started,
        )
    else:
        completed = monotonic()
        if completed > context.deadline_monotonic:
            result = _blocked(
                context,
                "verification-deadline-elapsed",
                discovered,
                elapsed_seconds=completed - started,
            )
        else:
            try:
                result = _validated_report(
                    report,
                    context,
                    discovered,
                    elapsed_seconds=completed - started,
                )
            except _VerifierContractError as exc:
                result = _blocked(
                    context,
                    f"scenario verifier {discovered.plugin_id!r} returned a "
                    f"malformed report ({exc})",
                    discovered,
                    elapsed_seconds=completed - started,
                )
    return result


__all__ = ["DiscoveredVerifier", "select_verifier", "verify_scenario"]
