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
from typing import TYPE_CHECKING

from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
from aptl.validation.scenario_verification import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    BackendIdentity,
    ScenarioIdentity,
    ScenarioVerifier,
    VerificationContext,
    VerificationReport,
    VerificationStatus,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

log = get_logger("scenario-verification")


class DiscoveredVerifier(object):
    """One installed verifier plus the host-observed facts about where it came from.

    The distribution name and version are read from installed metadata rather
    than taken from the plugin's own attributes, so a plugin cannot misreport its
    provenance in the evidence record.
    """

    __slots__ = ("verifier", "plugin_id", "distribution", "distribution_version")

    def __init__(
        self,
        verifier: ScenarioVerifier,
        plugin_id: str,
        distribution: str,
        distribution_version: str,
    ) -> None:
        self.verifier = verifier
        self.plugin_id = plugin_id
        self.distribution = distribution
        self.distribution_version = distribution_version


def _blocked(
    context: VerificationContext, diagnostic: str, discovered: DiscoveredVerifier | None = None
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
        diagnostics=(redact(diagnostic),),
    )


def _entry_points() -> "Sequence[metadata.EntryPoint]":
    """Return every entry point registered in the verifier group."""

    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _load(entry_point: metadata.EntryPoint) -> DiscoveredVerifier | None:
    """Load one entry point, or return None if it is unusable.

    A plugin that fails to import, or whose target is not a verifier, is treated
    as absent rather than allowed to raise through the gate: the caller turns the
    absence into ``blocked`` with the reason attached.
    """

    try:
        target = entry_point.load()
    except Exception as exc:  # noqa: BLE001 - any import failure is a load failure
        log.warning(
            "scenario verifier %r failed to load: %s", entry_point.name, redact(str(exc))
        )
        return None
    # A factory is allowed so a distribution need not construct its verifier at
    # import time; the result is what must satisfy the protocol.
    if callable(target) and not isinstance(target, ScenarioVerifier):
        try:
            target = target()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "scenario verifier factory %r failed: %s",
                entry_point.name,
                redact(str(exc)),
            )
            return None
    if not isinstance(target, ScenarioVerifier):
        log.warning(
            "scenario verifier %r does not satisfy the extension contract",
            entry_point.name,
        )
        return None
    distribution = ""
    distribution_version = ""
    dist = getattr(entry_point, "dist", None)
    if dist is not None:
        distribution = dist.name or ""
        distribution_version = dist.version or ""
    return DiscoveredVerifier(
        verifier=target,
        plugin_id=str(getattr(target, "plugin_id", entry_point.name)),
        distribution=distribution,
        distribution_version=distribution_version,
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
    if str(getattr(verifier, "extension_api_version", "")) != EXTENSION_API_VERSION:
        return (
            f"plugin {discovered.plugin_id!r} targets extension API "
            f"{getattr(verifier, 'extension_api_version', '')!r}, "
            f"core provides {EXTENSION_API_VERSION!r}"
        )
    if str(getattr(verifier, "scenario_identity", "")) != scenario.identity:
        return ""  # Not for this scenario at all; not an error, just no match.
    digests = tuple(getattr(verifier, "scenario_content_digests", ()) or ())
    if digests and scenario.content_digest not in digests:
        return (
            f"plugin {discovered.plugin_id!r} is pinned to different scenario "
            "content than the admitted scenario"
        )
    if str(getattr(verifier, "backend_target_name", "")) != backend.target_name:
        return (
            f"plugin {discovered.plugin_id!r} supports backend "
            f"{getattr(verifier, 'backend_target_name', '')!r}, "
            f"range was realized by {backend.target_name!r}"
        )
    profiles = tuple(getattr(verifier, "backend_profiles", ()) or ())
    if profiles and backend.profile not in profiles:
        return (
            f"plugin {discovered.plugin_id!r} does not support backend profile "
            f"{backend.profile!r}"
        )
    return ""


def select_verifier(
    scenario: ScenarioIdentity, backend: BackendIdentity
) -> tuple[DiscoveredVerifier | None, str]:
    """Return the single compatible verifier, or None plus why not.

    Exactly one match is required. Several matches is an error rather than a
    choice: picking one would make the verdict depend on installation order.
    """

    candidates: list[DiscoveredVerifier] = []
    reasons: list[str] = []
    for entry_point in _entry_points():
        discovered = _load(entry_point)
        if discovered is None:
            reasons.append(f"entry point {entry_point.name!r} could not be loaded")
            continue
        if str(getattr(discovered.verifier, "scenario_identity", "")) != scenario.identity:
            continue
        reason = _incompatibility(discovered, scenario, backend)
        if reason:
            reasons.append(reason)
            continue
        candidates.append(discovered)

    if len(candidates) == 1:
        return candidates[0], ""
    if not candidates:
        detail = "; ".join(reasons) if reasons else "none installed"
        return None, (
            f"no scenario verifier is installed for scenario "
            f"{scenario.identity!r} on backend {backend.target_name!r} ({detail})"
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

    discovered, reason = select_verifier(context.scenario, context.backend)
    if discovered is None:
        return _blocked(context, reason)

    try:
        report = discovered.verifier.run(context)
    except Exception as exc:  # noqa: BLE001 - plugin code is not trusted to be total
        log.warning(
            "scenario verifier %r raised: %s", discovered.plugin_id, redact(str(exc))
        )
        return _blocked(
            context,
            f"scenario verifier {discovered.plugin_id!r} failed while running",
            discovered,
        )
    if not isinstance(report, VerificationReport):
        return _blocked(
            context,
            f"scenario verifier {discovered.plugin_id!r} returned a malformed report",
            discovered,
        )
    # Provenance is recorded from installed metadata, never from the plugin.
    return VerificationReport(
        status=report.status,
        scenario=context.scenario,
        backend=context.backend,
        run_id=context.run_id,
        attempt_id=context.attempt_id,
        plugin_id=discovered.plugin_id,
        distribution=discovered.distribution,
        distribution_version=discovered.distribution_version,
        extension_api_version=EXTENSION_API_VERSION,
        prerequisites=tuple(report.prerequisites),
        checks=tuple(report.checks),
        diagnostics=tuple(redact(d) for d in report.diagnostics),
    )


__all__ = ["DiscoveredVerifier", "select_verifier", "verify_scenario"]
