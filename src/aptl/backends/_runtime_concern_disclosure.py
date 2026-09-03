"""Record and project one observed runtime realization concern (#876).

The two primitives every runtime-concern observer shares, split out of
:mod:`aptl.backends.raes_runtime_observation` so the observers and the two
modules of concern-specific corroboration can each depend on them without
depending on one another.

Both fail closed: an observation that raises is not recorded, and a value that
does not project is dropped, so the gate reads an omission rather than an echo
of the plan.
"""

from __future__ import annotations

from collections.abc import Callable

from raes_processor.semantics.realization import project_realization_concern

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger

log = get_logger("realization-observe")

# Classifications whose raw material must never be observed or disclosed. Kept in
# lockstep with RAES's own ``_PROTECTED`` set on the concern projectors.
_PROTECTED = frozenset({"redacted", "operator_secret"})


def _record(
    concerns: dict[tuple[str, ...], object],
    path: tuple[str, ...],
    observe: Callable[[], object | None],
) -> None:
    """Run one concern observation, failing closed on any error."""

    try:
        value = observe()
    except (BackendTimeoutError, OSError, ValueError, TypeError) as exc:
        log.warning("could not observe runtime concern %s (%s)", path, type(exc).__name__)
        return
    if value is not None:
        concerns[path] = value


def _disclose(concern_kind: str, observed_value: object) -> object | None:
    """Project an observed value into its secret-safe disclosed commitment.

    The ``observed=False`` pass converts realized raw material into commitments
    (and rejects protected raw material) rather than raising on a realized
    ``secret_fixture`` value; the ``observed=True`` pass runs the concern's
    observed-validator so a malformed observation fails closed here instead of
    landing an invalid value in the snapshot.
    """

    try:
        committed = project_realization_concern(concern_kind, observed_value, observed=False)
        return project_realization_concern(concern_kind, committed, observed=True)
    except (ValueError, TypeError) as exc:
        log.warning("dropping unprojectable %s observation (%s)", concern_kind, type(exc).__name__)
        return None
