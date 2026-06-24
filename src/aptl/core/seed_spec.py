"""Typed named-volume seed specification (ADR-043).

A small, dependency-free description of how a Compose project-scoped
named volume is materialized from checked-in host source at ``aptl lab
start``. Both the path/containment layer in :mod:`aptl.core.credentials`
(which builds canonical, contained specs) and the deployment backend
(which runs the seed container) depend on this leaf module, so it
imports nothing else from the package and cannot introduce an import
cycle.

The seam exists so a future generated-volume service is added by
registering another :class:`NamedVolumeSeed`, not by writing another
one-off Docker cleanup (ADR-043 §Extensibility).
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SeedFile:
    """One file copied from the seed source into the named volume.

    ``src`` is relative to the seed's ``source_dir`` (bind-mounted
    read-only at ``/src`` in the seeder container); ``dest`` is relative
    to the volume root (mounted at ``/dest``). Both are fixed,
    code-defined relative paths — never host- or operator-derived — so
    the backend can embed them in the seeder command after a charset
    check without leaking host state (ADR-043 §Security Layers).
    """

    src: str
    dest: str


@dataclass(frozen=True)
class NamedVolumeSeed:
    """How to seed one Compose project-scoped named volume.

    ``volume_suffix`` is the Compose volume key; the backend resolves the
    real volume name as ``<project>_<volume_suffix>`` so project scoping
    (ADR-037) is preserved and no explicit global volume name is set
    (ADR-043 forbids unscoped names).

    ``source_dir`` is an absolute, already-containment-checked host
    directory bind-mounted read-only into the seeder. ``files`` lists the
    copies to perform.

    ``legacy_retire_path`` is an optional absolute, contained host path
    left over from the pre-ADR-043 bind mount. Its owner may be UID 991
    (``systemd-network`` on Ubuntu hosts), so the host operator cannot
    delete it; the backend removes it with a narrow root container. It is
    ``None`` when there is nothing to retire (e.g. a fresh checkout).
    """

    volume_suffix: str
    source_dir: Path
    files: tuple[SeedFile, ...]
    legacy_retire_path: Path | None = None
