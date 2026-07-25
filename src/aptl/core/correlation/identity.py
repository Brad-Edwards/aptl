"""Deterministic, non-secret identity helpers (OBS-002 Stage 1, issue #447).

Reuses the domain-separated SHA-256 pattern EXP-002 established in
``aptl.core.experiment.trial_plan``: stable identity comes from hashing a
fixed, versioned domain-separation prefix plus canonical parts — never
from an ambient wall clock, a process-random or universally-unique
identifier, or the order evidence happened to arrive in (preflight
"Extensibility Seam" / "Gotchas And Anti-Patterns": planned identity must
be derived from ACES inputs, never minted from time or ingestion order).

Two distinct identity shapes:

- **Planned** identity (:func:`derive_planned_ref`) is deterministic —
  the same ACES/plan inputs always derive the same ref, on any host, in
  any process, regardless of the interpreter's hash-randomization seed.
- **Attempt** identity (:func:`bind_attempt_ref`) accepts an externally
  supplied run/episode/action id (e.g. an experiment run's own run id)
  and validates it at the serialization boundary rather than deriving
  it — an attempt result is never minted here, only bound and checked,
  so it can never be mistaken for planned identity.

Every id this module produces or accepts is validated through
:func:`aptl.core.correlation.models.validate_correlation_id` before it is
returned.
"""

from __future__ import annotations

import hashlib

from aptl.core.correlation.models import assert_non_secret, validate_correlation_id

#: ASCII unit separator (0x1F) joining hash-input fields. Mirrors
#: ``aptl.core.experiment.trial_plan``'s ``_FIELD_SEP``: not a legal
#: character in any authored ACES identifier, so it cannot be abused to
#: fabricate a cross-field collision (e.g. by embedding the separator
#: inside one part to make two distinct part tuples hash to the same
#: input bytes).
_FIELD_SEP = b"\x1f"


def stable_ref(*parts: str, domain: bytes) -> str:
    """Return a filesystem-safe, non-secret, collision-resistant id.

    Derived via domain-separated SHA-256 over ``parts``: the exact same
    ``domain`` plus the exact same ``parts``, in the exact same order,
    always yields the exact same id — on any host, in any process,
    regardless of the interpreter's hash-randomization seed. Nothing
    here reads the system clock, mints a universally-unique token, draws
    on ambient process entropy, or depends on the order callers happened
    to invoke this in.

    Raises ``ValueError`` if ``domain`` or ``parts`` is empty. Raises
    ``TypeError`` if any part is not a ``str``.
    """
    if not domain:
        raise ValueError("stable_ref requires a non-empty domain")
    if not parts:
        raise ValueError("stable_ref requires at least one part")
    digest_input = domain
    for part in parts:
        if not isinstance(part, str):
            raise TypeError(f"stable_ref parts must be str, got {type(part)!r}")
        digest_input += _FIELD_SEP + part.encode("utf-8")
    digest_hex = hashlib.sha256(digest_input).hexdigest()
    return validate_correlation_id(digest_hex)


def derive_planned_ref(*parts: str, domain: bytes) -> str:
    """Deterministic *planned* identity: derive a ref purely from
    caller-supplied ACES/plan inputs (never an attempt/run result).

    A thin, deliberately distinct name for :func:`stable_ref` so a
    planned-identity call site can never be confused with an
    attempt-identity call site (:func:`bind_attempt_ref`) at a glance.
    """
    return stable_ref(*parts, domain=domain)


def bind_attempt_ref(external_id: str) -> str:
    """*Attempt* identity: bind an externally-supplied run/episode/action
    id as a correlation ref.

    Unlike :func:`derive_planned_ref`, nothing is hashed or derived here
    — an attempt id is supplied by the surface that actually executed
    (e.g. an experiment run's own run id, or a participant episode id),
    and this function only validates it (id-shaped and non-secret) at
    the serialization boundary. Keeping this a validate-only path —
    never a derive-and-hash path — means an attempt ref can never
    silently drift into looking like a deterministic planned ref.
    """
    ref = validate_correlation_id(external_id)
    return assert_non_secret(ref, field_name="external_id")
