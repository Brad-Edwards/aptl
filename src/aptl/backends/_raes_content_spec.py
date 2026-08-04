"""Read and reject one declared content-placement spec (#875).

The spec-level primitives every content lowering path shares, split out of
:mod:`aptl.backends.raes_content_realization` so the file/directory/pack/dataset
shapes can each depend on them without depending on one another: the single
fail-closed rejection diagnostic, the ``sensitive`` flag reader, and the
destination-path containment rule.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from raes_contracts.diagnostics import Diagnostic

from aptl.backends.raes_diagnostics import diagnostic

_SAFE_DEST_RELPATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _safe_dest_relpath(relpath: str) -> bool:
    """Return whether a destination relpath is safe to embed in a seed script."""

    return (
        ".." not in PurePosixPath(relpath).parts
        and _SAFE_DEST_RELPATH.match(relpath) is not None
    )


def _is_sensitive(spec: Mapping[str, Any]) -> bool:
    """Return the Content spec's `sensitive` flag as a plain bool."""

    value = spec.get("sensitive")
    return bool(value) if isinstance(value, (bool, str)) else False


def _reject(address: str, reason_code: str) -> Diagnostic:
    """Build a fail-closed content realization diagnostic."""

    return diagnostic(
        "aptl.provisioner.content-placement-rejected",
        address,
        (
            "RAES content placement was rejected by the APTL content "
            f"realization policy (reason={reason_code})."
        ),
    )
