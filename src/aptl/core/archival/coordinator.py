"""The one terminal-attempt archive coordinator (EXP-009 / ADR-050).

:func:`finalize_terminal_attempt` is invoked exactly once when an execution
attempt reaches any terminal cause. It composes the validated public RAES run
record, publishes it as the canonical ``manifest.json`` create-once, reads and
checksums every already-written sealed artifact into a closed inventory, then
sequences the ADR-050 commit: a *prepared* discovery-index entry, the atomic
durable *seal marker*, and the *committed* index entry. A crash before the marker
leaves an unsealed recovery candidate — never a partially sealed run. Identical
finalization is idempotent; a differing record for the same attempt is a
conflict.

The coordinator does not rediscover facts from mutable state, calculate metrics,
reconstruct captures, or run another execution state machine — it consumes the
immutable :class:`~aptl.core.archival.context.TerminalAttemptContext` and seals.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from raes_contracts.contracts import ExperimentRunModel
from raes_contracts.satisfiability import canonical_contract_digest

from aptl.core.archival.context import TerminalAttemptContext
from aptl.core.archival.discovery_index import DiscoveryIndex, IndexEntry
from aptl.core.archival.layout import (
    RUN_MANIFEST_RELPATH,
    SEAL_MARKER_DIGEST_FIELD,
    SEAL_MARKER_RELPATH,
)
from aptl.core.archival.run_record import build_experiment_run_model
from aptl.core.archival.seal import (
    SealInventoryEntry,
    SealLimitation,
    SealMarkerInputs,
    SealedArtifactSpec,
    build_inventory_entry,
    build_seal_marker,
)
from aptl.core.runstore import LocalRunStore, RunStoreConflictError
from aptl.utils.logging import get_logger

log = get_logger("archival.coordinator")

_MANIFEST_SPEC = SealedArtifactSpec(
    path=RUN_MANIFEST_RELPATH, media_type="application/json", role="manifest"
)


@dataclass(frozen=True)
class SealResult:
    """The outcome of sealing one terminal attempt."""

    run: ExperimentRunModel
    run_record_digest: str
    manifest_path: Path
    seal_marker_path: Path
    inventory: tuple[SealInventoryEntry, ...]
    index_entry: IndexEntry
    idempotent: bool


def finalize_terminal_attempt(
    context: TerminalAttemptContext,
    *,
    store: LocalRunStore,
    index: DiscoveryIndex | None = None,
    completeness_statement: str | None = None,
) -> SealResult:
    """Compose, validate, and atomically seal one terminal attempt.

    Raises the RAES validators' errors when the record is not conformant (the
    seal gate) and :class:`RunStoreConflictError` when the attempt was already
    sealed with a different record.
    """
    run = build_experiment_run_model(context)
    run_record_digest = canonical_contract_digest(run)
    index = index or DiscoveryIndex(store.base_dir)

    index_entry = IndexEntry(
        run_id=run.run_id,
        run_version=run.run_version,
        manifest_digest=run_record_digest,
        seal_state="sealed",
        terminal_at=run.ended_at,
        location=RUN_MANIFEST_RELPATH,
    )

    # Hold the store-owned per-attempt finalization lock across compose
    # verification, manifest publication, inventory verification, and marker
    # commit so two finalizers of the same attempt cannot race (ADR-050).
    with store.finalization_lock(context.attempt_id):
        if _check_prior_seal(store, context.attempt_id, run_record_digest):
            # Already sealed with this exact record: idempotent replay. Rebuild
            # the result from the sealed bytes (reads only) — re-writing would
            # now hit the create-once sealed guard.
            return _existing_seal_result(store, context, run, run_record_digest, index_entry)

        # Ensure the run directory and publish the canonical RAES run record
        # create-once (immutable). A byte-identical replay is a no-op success.
        store.create_run(context.attempt_id)
        manifest_path = store.create_run_json_once(
            context.attempt_id, RUN_MANIFEST_RELPATH, run.model_dump(mode="json")
        )

        inventory = _build_inventory(store, context)
        limitations = list(context.accepted_limitations)
        statement = completeness_statement or _default_completeness_statement(
            run, inventory, limitations
        )
        marker = build_seal_marker(
            SealMarkerInputs(
                run_id=run.run_id,
                run_version=run.run_version,
                run_status=run.run_status,
                outcome_status=run.outcome_status,
                run_record_digest=run_record_digest,
                inventory=inventory,
                contract_versions=_sealed_contract_versions(run, context),
                limitations=limitations,
                completeness_statement=statement,
            )
        )

        # ADR-050 commit sequence: prepared entry names the expected identity,
        # then the atomic seal marker is the archive commit point, then the
        # committed entry. Each step is idempotent on identical bytes.
        index.prepare(index_entry)
        seal_marker_path = store.commit_seal_marker(context.attempt_id, marker)
        index.commit(index_entry)

    log.info(
        "sealed terminal attempt %s (run_status=%s, outcome=%s, artifacts=%d)",
        run.run_id,
        run.run_status,
        run.outcome_status,
        len(inventory),
    )
    return SealResult(
        run=run,
        run_record_digest=run_record_digest,
        manifest_path=manifest_path,
        seal_marker_path=seal_marker_path,
        inventory=tuple(inventory),
        index_entry=index_entry,
        idempotent=False,
    )


def _existing_seal_result(
    store: LocalRunStore,
    context: TerminalAttemptContext,
    run: ExperimentRunModel,
    run_record_digest: str,
    index_entry: IndexEntry,
) -> SealResult:
    """Rebuild the seal result for an already-sealed attempt (reads only)."""
    run_dir = store.get_run_path(context.attempt_id)
    inventory = _build_inventory(store, context)
    return SealResult(
        run=run,
        run_record_digest=run_record_digest,
        manifest_path=run_dir / RUN_MANIFEST_RELPATH,
        seal_marker_path=run_dir / SEAL_MARKER_RELPATH,
        inventory=tuple(inventory),
        index_entry=index_entry,
        idempotent=True,
    )


def _check_prior_seal(
    store: LocalRunStore, attempt_id: str, run_record_digest: str
) -> bool:
    """Return whether the attempt is already sealed with an identical record.

    A prior seal with a different run-record digest is a conflict (two different
    finalizations of one attempt); an identical one makes this call an idempotent
    replay.
    """
    existing = store.read_seal_marker(attempt_id)
    if existing is None:
        return False
    if existing.get(SEAL_MARKER_DIGEST_FIELD) != run_record_digest:
        raise RunStoreConflictError(
            f"attempt {attempt_id!r} is already sealed with a different run record"
        )
    return True


def _build_inventory(
    store: LocalRunStore, context: TerminalAttemptContext
) -> list[SealInventoryEntry]:
    """Read and checksum the manifest plus every sealed artifact into the inventory."""
    inventory = [build_inventory_entry(store, context.attempt_id, _MANIFEST_SPEC)]
    for spec in context.sealed_artifacts:
        inventory.append(build_inventory_entry(store, context.attempt_id, spec))
    return inventory


def _sealed_contract_versions(
    run: ExperimentRunModel, context: TerminalAttemptContext
) -> list[str]:
    """Collect the contract versions the sealed byte graph spans."""
    versions = {run.schema_version, run.apparatus_context.schema_version}
    if any("evidence" in spec.role for spec in context.sealed_artifacts):
        versions.add("experiment-evidence-record/v1")
    return sorted(versions)


def _default_completeness_statement(
    run: ExperimentRunModel,
    inventory: list[SealInventoryEntry],
    limitations: list[SealLimitation],
) -> str:
    """Return a safe, bounded default completeness statement.

    It names only IDs, statuses, and counts — never captured content — so it
    cannot leak evidence or secrets into the marker.
    """
    if limitations:
        limitation_clause = f"{len(limitations)} accepted limitation(s)"
    else:
        limitation_clause = "no accepted limitations"
    return (
        f"Sealed terminal attempt {run.run_id} run_version {run.run_version}: "
        f"run_status={run.run_status}, outcome_status={run.outcome_status}, "
        f"{len(inventory)} bound artifact(s), {limitation_clause}."
    )
