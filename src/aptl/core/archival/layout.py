"""Run-archive layout constants for the terminal-attempt seal (EXP-009 / ADR-050).

Single source of truth for the run-relative and store-relative paths the
archival subsystem owns, so the coordinator, seal, discovery index, and legacy
adapter never hardcode divergent strings. Evidence, provenance, and correlation
paths remain owned by their own modules; only the two artifacts EXP-009
introduces — the canonical RAES run manifest and the atomic seal marker — plus
the store-level discovery index live here.
"""

from __future__ import annotations

# The seal-marker path is owned by the run store (it enforces sealed-state
# immutability) and re-exported here so the archival package reads all its
# layout constants from one module without the store importing this package.
from aptl.core.runstore import SEAL_MARKER_RELPATH

#: Run-relative path of the canonical serialized public RAES ``ExperimentRunModel``
#: (``schema_version="experiment-run/v1"``). ADR-050: for a terminal attempt this
#: IS ``manifest.json`` — the single portable run record. The legacy
#: ``aptl.run-record/v2`` shape is never written to it again.
RUN_MANIFEST_RELPATH = "manifest.json"

#: Store-relative directory holding the derived discovery index journal and its
#: lock. Store-owned (never attacker-supplied) and skipped by ``list_runs`` since
#: it carries no ``manifest.json``.
INDEX_DIR = "index"

#: Basename of the append-safe discovery journal within :data:`INDEX_DIR`.
INDEX_JOURNAL_NAME = "journal.jsonl"

#: Basename of the discovery journal's cross-process lock within :data:`INDEX_DIR`.
INDEX_LOCK_NAME = "journal.lock"

#: Store-relative path of the append-safe discovery journal.
INDEX_JOURNAL_RELPATH = f"{INDEX_DIR}/{INDEX_JOURNAL_NAME}"

#: Store-relative path of the discovery journal's cross-process lock file.
INDEX_LOCK_RELPATH = f"{INDEX_DIR}/{INDEX_LOCK_NAME}"

#: Versioned identity of the seal-marker payload shape. Shared by the sealer
#: (writer) and the discovery index (which validates the complete committed
#: marker, not just one field).
SEAL_MARKER_SCHEMA_VERSION = "aptl.run-seal/v1"

#: Field in the seal marker carrying the ``sha256:<hex>`` digest of the canonical
#: run record. Both the sealer (writer) and the discovery index (verifier)
#: reference this one name so a committed index entry can be checked against the
#: bytes actually sealed on disk.
SEAL_MARKER_DIGEST_FIELD = "run_record_digest"
