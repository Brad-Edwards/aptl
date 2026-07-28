"""The single typed error for evidence-bundle export.

One typed exception with a stable machine-checkable ``reason`` (mirroring
:class:`aptl.utils.pathsafe.PathContainmentError`), not a new exception
hierarchy. A ``reason`` is one of the codes in :mod:`aptl.core.evidence_bundle.codes`
or a short local ``*`` label; callers translate it to their own message.
"""

from __future__ import annotations


class BundleError(Exception):
    """A bundle could not be built or verified.

    ``reason`` is a short, stable, machine-checkable code so callers can act on
    the failure without parsing prose out of ``str(exc)``.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


__all__ = ["BundleError"]
