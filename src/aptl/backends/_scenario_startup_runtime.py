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


def run_persisted_startup_reset(
    identity: PackIdentity,
    provenance: StartupProviderProvenance,
    context: StartupHookContext,
) -> None:
    """Invoke the exact installed reset provider recorded by a prior start."""

    from aptl.backends import scenario_startup as contract

    compatible: list[object] = []
    for entry in contract._entry_points():
        if (
            entry.name != provenance.entry_point
            or contract._provenance(entry) != provenance
        ):
            continue
        provider = contract._load(entry)
        if contract._compatible_identity(provider, identity):
            compatible.append(provider)
    if len(compatible) != 1 or not callable(getattr(compatible[0], "reset", None)):
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
