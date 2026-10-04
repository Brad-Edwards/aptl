"""Runtime and recovery dispatch for admitted scenario startup providers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raes_processor.semantics.realization import (
    CONCERN_PAYLOAD_PATH,
    project_realization_concern,
)

if TYPE_CHECKING:
    from aptl.backends.scenario_startup import (
        ScenarioStartupSelection,
        StartupHookContext,
        StartupProviderProvenance,
    )
    from aptl.core.scenario_bundle import PackIdentity


def selected_runtime_provider(
    identity: PackIdentity | None,
    selection: ScenarioStartupSelection | None,
) -> object | None:
    """Use the admitted provider, including an admitted absence, when supplied."""

    from aptl.backends import scenario_startup as contract

    if selection is None:
        return _runtime_provider(identity)
    if selection.identity != identity:
        raise contract.ScenarioStartupProviderError("provider-identity-mismatch")
    return selection.provider


def _runtime_provider(identity: PackIdentity | None) -> object | None:
    """Select at most one installed adapter for an exact pack release."""

    from aptl.backends import scenario_startup as contract

    if identity is None:
        return None
    compatible: list[object] = []
    for entry in contract._entry_points():
        if entry.name != identity.pack_id:
            continue
        provider = contract._load(entry)
        if contract._compatible_identity(provider, identity):
            compatible.append(provider)
    if len(compatible) > 1:
        raise contract.ScenarioStartupProviderError("provider-ambiguous")
    return compatible[0] if compatible else None


def _declares_reset_action(provider: object, action_version: str) -> bool:
    """Return whether a handler explicitly supports a recorded reset version."""

    declared = getattr(provider, "supported_reset_action_versions", ())
    return isinstance(declared, tuple) and action_version in declared


def run_persisted_startup_reset(
    identity: PackIdentity,
    provenance: StartupProviderProvenance,
    context: StartupHookContext,
    *,
    action_version: str = "1",
) -> None:
    """Invoke the one installed handler authorized for a recorded pack reset.

    A handler must be registered under the recorded entry-point name and accept
    the exact admitted pack identity, including its set digest. It is then
    authorized either as the unchanged installation that admitted the pack or
    because it explicitly declares the recorded reset action version, so an
    upgraded adapter can finish its older pending cleanup without the old
    distribution version being installed.
    """

    from aptl.backends import scenario_startup as contract

    compatible: list[object] = []
    for entry in contract._entry_points():
        if entry.name != provenance.entry_point:
            continue
        provider = contract._load(entry)
        if (
            contract._compatible_identity(provider, identity)
            and callable(getattr(provider, "reset", None))
            and (
                contract._provenance(entry) == provenance
                or _declares_reset_action(provider, action_version)
            )
        ):
            compatible.append(provider)
    if len(compatible) > 1:
        raise contract.ScenarioStartupProviderError(
            "provider-reset-authority-ambiguous"
        )
    if not compatible:
        raise contract.ScenarioStartupProviderError(
            "provider-reset-authority-unavailable"
        )
    try:
        compatible[0].reset(context)
    except Exception as exc:
        contract.log.warning(
            "persisted scenario startup reset failed: selector=%s exception=%s",
            provenance.entry_point,
            type(exc).__name__,
        )
        raise contract.ScenarioStartupProviderError("provider-hook-failed") from None


def run_scenario_runtime(
    identity: PackIdentity | None,
    backend: object,
    nodes: tuple[object, ...],
    *,
    selection: ScenarioStartupSelection | None = None,
) -> list[str]:
    """Run installed, content-qualified post-start work for one scenario."""

    from aptl.backends import scenario_startup as contract

    try:
        provider = selected_runtime_provider(identity, selection)
    except contract.ScenarioStartupProviderError:
        return ["scenario runtime provider selection failed"]
    if provider is None:
        return []
    from aptl.backends.scenario_runtime_hooks import invoke_runtime_provider

    return invoke_runtime_provider(provider, identity, backend, nodes)


def observe_scenario_runtime_concerns(
    identity: PackIdentity | None,
    backend: object,
    node: object,
    *,
    selection: ScenarioStartupSelection | None = None,
) -> dict[tuple[str, ...], object]:
    """Return validated concern observations from the admitted provider."""

    from aptl.backends import scenario_startup as contract
    from aptl.backends.scenario_runtime_hooks import invoke_runtime_observer

    try:
        provider = selected_runtime_provider(identity, selection)
    except contract.ScenarioStartupProviderError:
        provider = None
    observed = invoke_runtime_observer(provider, identity, backend, node)
    kinds_by_path = {path: kind for kind, path in CONCERN_PAYLOAD_PATH.items()}
    if not isinstance(observed, dict) or any(
        not isinstance(path, tuple) or path not in kinds_by_path or value is None
        for path, value in observed.items()
    ):
        return {}
    try:
        for path, value in observed.items():
            project_realization_concern(kinds_by_path[path], value, observed=True)
    except (TypeError, ValueError):
        return {}
    return observed


__all__ = [
    "observe_scenario_runtime_concerns",
    "run_persisted_startup_reset",
    "run_scenario_runtime",
    "selected_runtime_provider",
]
