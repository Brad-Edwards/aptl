"""Correlation-projection persistence (OBS-002 Stage 2, issue #447).

Reads the run archive's ``manifest.json`` and ``orchestration/*/{result.json,
history.jsonl}`` files through the ``LocalRunStore`` path API, builds a
:class:`~aptl.core.correlation.models.CorrelationProjection` via
:func:`aptl.core.correlation.builder.build_correlation_projection`, and
persists it back into the *same* run directory as
``<run_id>/correlation.json``.

Persisting anywhere else is a real, previously-confirmed bug class here:
``aptl.core.exporter.export_local`` tars only ``<base_dir>/<run_id>/``
(``rglob`` + ``tar.add(run_path, ...)``); ``LocalRunStore.create_json_once``
writes to ``<base_dir>/<namespace>/<name>.json`` — a *sibling* of the run
tree, invisible to both ``list_runs()`` and the exporter. So this module
always writes through ``run_store.write_json(run_id, ...)``, never
``create_json_once``, and the persistence test asserts the exported tar
actually contains ``correlation.json`` end to end.

Every failure normalizes into the existing ADR-047 fail-closed diagnostic
shape (:class:`aces_contracts.diagnostics.Diagnostic` /
:class:`aptl.core.experiment.errors.AdmissionRejection`) rather than a new
exception hierarchy — a missing/corrupt manifest, an unreadable
orchestration file, or a builder ``ValueError`` (e.g. an invalid/secret-
shaped ref) all surface the same way callers already handle admission
failures.
"""

from __future__ import annotations

import json
from pathlib import Path

from aces_contracts.diagnostics import Diagnostic, Severity

from aptl.core.correlation.builder import CorrelationRuleSet, build_correlation_projection
from aptl.core.correlation.clock import ClockProvider, SystemClockProvider
from aptl.core.correlation.models import CorrelationProjection
from aptl.core.experiment.errors import AdmissionRejection
from aptl.core.runstore import RunStorageBackend
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

__all__ = ["build_and_persist_correlation", "persist_run_correlation_best_effort"]

_log = get_logger("obs-002-correlation")

_CORRELATION_DOMAIN = "obs-002-correlation"
_CORRELATION_RELATIVE_PATH = "correlation.json"


def _diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build one redacted correlation-persistence diagnostic.

    Mirrors ``aptl.core.experiment.errors.diagnostic()``'s exact shape
    (same ``Diagnostic``/``Severity`` types, same ``redact()`` pass on the
    message) but under this module's own domain — correlation persistence
    is not the experiment-admission boundary that module's constant names.
    """
    return Diagnostic(
        code=code,
        domain=_CORRELATION_DOMAIN,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def _read_manifest(run_store: RunStorageBackend, run_id: str) -> dict[str, object]:
    try:
        return run_store.get_run_manifest(run_id)
    except FileNotFoundError as exc:
        raise AdmissionRejection(
            (_diagnostic("aptl.correlation.manifest-missing", run_id, "run manifest.json not found"),)
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionRejection(
            (
                _diagnostic(
                    "aptl.correlation.manifest-unreadable",
                    run_id,
                    "run manifest.json could not be read or parsed",
                ),
            )
        ) from exc


def _read_orchestration_result(address_dir: Path, run_id: str, address: str) -> dict[str, object]:
    result_path = address_dir / "result.json"
    if not result_path.is_file():
        return {}
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdmissionRejection(
            (
                _diagnostic(
                    "aptl.correlation.orchestration-result-unreadable",
                    run_id,
                    f"orchestration result.json unreadable for address {address!r}",
                ),
            )
        ) from exc
    return payload if isinstance(payload, dict) else {}


def _read_orchestration_history(address_dir: Path, run_id: str, address: str) -> list[dict[str, object]]:
    history_path = address_dir / "history.jsonl"
    if not history_path.is_file():
        return []
    events: list[dict[str, object]] = []
    try:
        lines = history_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AdmissionRejection(
            (
                _diagnostic(
                    "aptl.correlation.orchestration-history-unreadable",
                    run_id,
                    f"orchestration history.jsonl unreadable for address {address!r}",
                ),
            )
        ) from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AdmissionRejection(
                (
                    _diagnostic(
                        "aptl.correlation.orchestration-history-invalid",
                        run_id,
                        f"orchestration history.jsonl has a malformed line for address {address!r}",
                    ),
                )
            ) from exc
        if isinstance(event, dict):
            events.append(event)
    return events


def _read_orchestration(run_store: RunStorageBackend, run_id: str) -> dict[str, dict[str, object]]:
    orchestration_dir = run_store.get_run_path(run_id) / "orchestration"
    orchestration: dict[str, dict[str, object]] = {}
    if not orchestration_dir.is_dir():
        return orchestration
    for address_dir in sorted(orchestration_dir.iterdir()):
        if not address_dir.is_dir():
            continue
        address = address_dir.name
        orchestration[address] = {
            "result": _read_orchestration_result(address_dir, run_id, address),
            "history": _read_orchestration_history(address_dir, run_id, address),
        }
    return orchestration


def build_and_persist_correlation(
    *,
    run_id: str,
    run_store: RunStorageBackend,
    clock_provider: ClockProvider,
    rules: CorrelationRuleSet | None = None,
) -> CorrelationProjection:
    """Read ``<run_id>``'s archive, build its correlation projection, and
    persist it as ``<run_id>/correlation.json``.

    Returns the built :class:`CorrelationProjection`. Raises
    :class:`AdmissionRejection` (never a raw exception) on a missing/
    unreadable archive or an invalid projection — every diagnostic message
    passes through :func:`aptl.utils.redaction.redact` and names no raw
    ACES payload content.
    """
    manifest = _read_manifest(run_store, run_id)
    orchestration = _read_orchestration(run_store, run_id)
    try:
        projection = build_correlation_projection(
            run_id=run_id,
            run_record=manifest,
            orchestration=orchestration,
            clock_provider=clock_provider,
            rules=rules,
        )
    except ValueError as exc:
        raise AdmissionRejection(
            (
                _diagnostic(
                    "aptl.correlation.build-failed",
                    run_id,
                    "correlation projection construction failed validation",
                ),
            )
        ) from exc
    run_store.write_json(run_id, _CORRELATION_RELATIVE_PATH, projection.to_canonical_dict())
    return projection


def persist_run_correlation_best_effort(
    *,
    run_id: str,
    run_store: RunStorageBackend,
    clock_provider: ClockProvider | None = None,
    rules: CorrelationRuleSet | None = None,
) -> CorrelationProjection | None:
    """Run-finalization hook: build + persist the correlation projection,
    returning ``None`` (and logging a redacted warning) on any failure so a
    correlation problem never fails the run itself.

    OBS-002's projection is auditing metadata layered over an already-sealed
    run record; a missing evaluator field or an unreadable orchestration file
    must degrade the *audit trail*, never turn a successful run into a failed
    one. The logged message names only the run id and the diagnostic
    *codes* (already redacted, no payload/timestamp content).
    """
    provider = clock_provider if clock_provider is not None else SystemClockProvider()
    try:
        return build_and_persist_correlation(
            run_id=run_id, run_store=run_store, clock_provider=provider, rules=rules
        )
    except AdmissionRejection as exc:
        codes = ", ".join(diag.code for diag in exc.diagnostics) or "unknown"
        _log.warning(
            "OBS-002: correlation projection not persisted for run %s (%s)", run_id, codes
        )
        return None
    except Exception:  # defensive: an OBS-002 audit projection is never fatal to the run
        _log.warning(
            "OBS-002: correlation projection not persisted for run %s (unexpected error)", run_id
        )
        return None
