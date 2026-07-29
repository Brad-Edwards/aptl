"""The run provenance records (REP-003 / issue #452).

Two deliberately distinct artifacts, because they answer at different
lifecycle boundaries:

* **Ready-to-seal** (:data:`PROVENANCE_RECORD_PATH`) — the canonical record,
  published by whoever owns the ADMITTED and EXECUTED run context. Writing it
  requires that context to be present; a collection with no admitted plan is
  refused rather than mislabelled.
* **Provisional** (:data:`PROVISIONAL_RECORD_PATH`) — what lab startup can
  honestly produce. Startup has configuration and a range snapshot but no
  admitted trial plan, no realized participants, and no execution outcome.

Keeping them apart is load-bearing rather than cosmetic. Publication is
create-once: if startup wrote the canonical path with experiment and
participant provenance missing, the real seal-boundary collector could never
publish the complete record — its write would hit the deliberate content
conflict and fail. The provisional artifact therefore lives at its own path and
declares its own seal state, leaving the canonical path free for the authority
that can fill it.

Both records are published through
:func:`aptl.core.evidence.content_store.create_run_json_once`: RFC 8785
canonical, descriptor-relative, no-follow, with the run store's secret
invariant applied to the whole payload. Neither is a seal — issue #444 owns
signing and the sealed archive state, and issue #472 owns which limitations
are fatal.
"""

from __future__ import annotations

from pathlib import Path

from aptl.core.evidence.content_store import create_run_json_once
from aptl.core.provenance.coordinator import ProvenanceCollection
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.runstore import LocalRunStore

#: Versioned identity of the record shape itself.
RECORD_SCHEMA_VERSION = "aptl.run-provenance/v1"

#: Run-relative path of the canonical ready-to-seal record.
PROVENANCE_RECORD_PATH = "provenance/run-provenance.json"

#: Run-relative path of the provisional startup record.
PROVISIONAL_RECORD_PATH = "provenance/startup-provenance.json"

#: What the canonical record claims to be. Deliberately not "sealed":
#: signing, attestation, and the sealed archive state belong to issue #444.
SEAL_STATE_READY = "ready-to-seal"

#: What the startup record claims to be.
SEAL_STATE_PROVISIONAL = "provisional"

#: The provider whose presence proves the authoritative run context was
#: available. Without an admitted plan there is no planned-trial identity, no
#: scenario snapshot digest, and no capture bindings.
_AUTHORITATIVE_PROVIDER_ID = "experiment"


class ProvenanceContextError(RuntimeError):
    """Raised when the canonical record is published without authoritative context."""


def build_provenance_record(
    *,
    run_id: str,
    collection: ProvenanceCollection,
    seal_state: str = SEAL_STATE_READY,
) -> dict[str, object]:
    """Return the canonical provenance record for ``run_id``.

    Carries no wall-clock timestamp: a collection time would change on every
    run and make an otherwise-unchanged apparatus look different, which is the
    identity drift the requirement's stability criterion prohibits. Run timing
    already lives in the run archive's own records.
    """
    projection = collection.projection()
    return {
        "schema_version": RECORD_SCHEMA_VERSION,
        "run_id": run_id,
        "seal_state": seal_state,
        "aggregate_identity": collection.aggregate_identity,
        "registry_declaration_digest": collection.registry_declaration_digest,
        "sections": projection["sections"],
        "limitations": projection["limitations"],
    }


def _has_authoritative_context(collection: ProvenanceCollection) -> bool:
    """Return whether the collection carries admitted run context."""
    section = collection.sections.get(_AUTHORITATIVE_PROVIDER_ID)
    return section is not None and section.status is ProvenanceStatus.COLLECTED


def publish_provenance_record(
    *, store: LocalRunStore, run_id: str, collection: ProvenanceCollection
) -> Path:
    """Publish the canonical ready-to-seal record create-once.

    Refuses a collection without admitted run context: publishing a record
    that reports the experiment and participant apparatus as unavailable, then
    labelling it ready-to-seal, would both misdescribe the run and permanently
    occupy the path the authoritative collector needs.

    Raises :class:`ProvenanceContextError` when that context is absent,
    :class:`~aptl.core.runstore.RunStoreConflictError` when a record already
    exists with different canonical bytes, and
    :class:`~aptl.core.runstore.SecretInvariantError` when the shared
    redaction policy would alter the payload.
    """
    if not _has_authoritative_context(collection):
        raise ProvenanceContextError(
            "the ready-to-seal provenance record requires admitted run context; "
            "publish the provisional record instead"
        )
    record = build_provenance_record(run_id=run_id, collection=collection)
    return create_run_json_once(store, run_id, PROVENANCE_RECORD_PATH, record)


def publish_provisional_provenance_record(
    *, store: LocalRunStore, run_id: str, collection: ProvenanceCollection
) -> Path:
    """Publish the provisional startup record create-once at its own path.

    Records what startup can honestly observe — apparatus manifests, effective
    configuration, detection content, dependency locks, realized images —
    without claiming the experiment context it does not have.
    """
    record = build_provenance_record(
        run_id=run_id, collection=collection, seal_state=SEAL_STATE_PROVISIONAL
    )
    return create_run_json_once(store, run_id, PROVISIONAL_RECORD_PATH, record)
