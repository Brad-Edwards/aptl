"""Value-free choices a scenario runtime provider makes where the pack is open.

A provider declares them as ``runtime_selections``; the run record reports them
under ``backend_evidence`` so a run says what the backend chose, separately from
what the scenario authored.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioRuntimeSelection:
    """One backend choice; ``reference`` names the upstream declaration gap."""

    node: str
    subject: str
    choice: str
    reference: str = ""

    def details(self) -> dict[str, str]:
        """Return the bounded report entry for this selection."""

        return {
            "node": self.node,
            "subject": self.subject,
            "choice": self.choice,
            "reference": self.reference,
        }


def scenario_runtime_selection_details(
    selection: object | None,
) -> list[dict[str, str]]:
    """Report the admitted provider's value-free open-scope selections.

    A provider that declares none reports an empty list; a malformed
    declaration is reported as one bounded entry rather than dropped, so a run
    never claims it made no backend choice when it cannot say which.
    """

    provider = getattr(selection, "provider", None)
    declared = getattr(provider, "runtime_selections", ()) if provider else ()
    if not isinstance(declared, tuple) or not all(
        isinstance(item, ScenarioRuntimeSelection) for item in declared
    ):
        return [{"error": "scenario runtime selections are malformed"}]
    return [item.details() for item in declared]


__all__ = ["ScenarioRuntimeSelection", "scenario_runtime_selection_details"]
