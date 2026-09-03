"""Stable, code-owned reason/limitation codes for evidence-bundle export.

One flat namespace so diagnostics, inventory limitations, and the standalone
verifier all speak the same vocabulary. Codes are part of the versioned bundle
contract — never reword an existing one; add a new code instead.
"""

from __future__ import annotations

DOMAIN = "aptl.evidence-bundle"

#: No #444 verified seal is available; the bundle is exported unsealed.
SEAL_ABSENT = f"{DOMAIN}.seal-absent"
#: A referenced canonical/backend source is absent from the run closure.
MISSING_SOURCE = f"{DOMAIN}.missing-source"
#: A source was present but rejected by containment/shape/limit checks.
REJECTED_SOURCE = f"{DOMAIN}.rejected-source"
#: An evidence record failed RAES model validation.
INVALID_RECORD = f"{DOMAIN}.invalid-record"
#: A requested projection could not be produced (e.g. optional lib missing).
PROJECTION_UNAVAILABLE = f"{DOMAIN}.projection-unavailable"
#: A requested projection is ineligible for these records (declared loss rule).
PROJECTION_INELIGIBLE = f"{DOMAIN}.projection-ineligible"
#: A secret-shaped value in generated bundle METADATA was redacted (never the
#: canonical bytes — export is not the first redaction boundary).
METADATA_REDACTED = f"{DOMAIN}.metadata-redacted"

__all__ = [
    "DOMAIN",
    "SEAL_ABSENT",
    "MISSING_SOURCE",
    "REJECTED_SOURCE",
    "INVALID_RECORD",
    "PROJECTION_UNAVAILABLE",
    "PROJECTION_INELIGIBLE",
    "METADATA_REDACTED",
]
