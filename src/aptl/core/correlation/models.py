"""Typed correlation models (OBS-002 Stage 1, issue #447).

Implements the "Extensibility Seam" from
``docs/architecture/obs-002-correlation-identity-clock-preflight.md``: a
small versioned correlation projection whose nodes are existing ACES or
``LocalRunStore`` references and whose edges carry only ``source_ref``,
``target_ref``, ``association_method``, ``rule_id``, ``clock_context_ref``,
``confidence_or_status``, and ``disclosure_refs``. Timestamp proximity is
never a causal claim on its own: a ``TIME_WINDOW_CANDIDATE`` edge must
carry a ``clock_context_ref`` so its uncertainty travels with the claim,
and a ``DECLARED_RULE`` edge must name the ``rule_id`` that produced it.

Reuses two incumbents rather than re-deriving their policy locally
(preflight "Gotchas": "Do not duplicate ID validation separately"):

- ID/filesystem-safety validation delegates to the exact rule
  ``aptl.core.runstore`` already enforces for run/session/trace ids
  (:func:`validate_correlation_id`), so a correlation ref can never
  validate under a second, drifting definition.
- Non-secret validation delegates to the shared
  ``aptl.utils.redaction`` classification (:func:`assert_non_secret`),
  so an identity-bearing value that :func:`aptl.utils.redaction.redact`
  would alter is rejected at construction instead of silently persisted
  and redacted later.

Determinism and canonicalization follow
``aptl.core.experiment.trial_plan``'s pattern: RFC 8785 canonical JSON
over a projection dict, SHA-256 over the canonical bytes, immutable
frozen dataclasses, tuples (never lists) for every sequence field. Nodes,
edges, clock contexts, and the top-level disclosure list are graph-shaped
(semantically unordered) rather than an authored execution sequence, so
:meth:`CorrelationProjection.to_canonical_dict` sorts each of them before
hashing — two projections built from the same content in different
input order must still hash identically.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum

import rfc8785

from aptl.core.runstore import _validate_id as _runstore_validate_id
from aptl.utils.redaction import is_secret_shaped_value, is_sensitive_key

#: Versioned identity for the canonical projection shape itself (distinct
#: from any ACES ``schema_version`` literal — this is an APTL-internal
#: archive projection, never an ACES contract).
_PROJECTION_SCHEMA_VERSION = "aptl-correlation/v1"

#: Controlled vocabulary for :attr:`CorrelationNode.ref_kind`. Every entry
#: names an existing ACES or ``LocalRunStore`` identity kind (preflight
#: "Represent correlation as a graph of typed associations over existing
#: refs") — this package must never invent a new local tracing vocabulary.
_REF_KINDS: frozenset[str] = frozenset(
    {
        "experiment-spec",
        "task",
        "condition",
        "planned-trial",
        "attempt-run",
        "participant-episode",
        "action",
        "capture",
        "evidence",
        "evaluator-result",
    }
)


class AssociationMethod(str, Enum):
    """The minimum association methods a correlation edge may claim
    (preflight: "The minimum association methods are ``explicit_identifier``,
    ``declared_rule``, ``time_window_candidate``, and ``gap_or_unknown``.
    Timestamp proximity alone is never a causal link.")."""

    EXPLICIT_IDENTIFIER = "explicit_identifier"
    DECLARED_RULE = "declared_rule"
    TIME_WINDOW_CANDIDATE = "time_window_candidate"
    GAP_OR_UNKNOWN = "gap_or_unknown"


def validate_correlation_id(value: str) -> str:
    """Validate ``value`` as a correlation ref/id.

    Delegates to the exact ``LocalRunStore`` id-validation rule
    (:func:`aptl.core.runstore._validate_id`) — the single source of
    truth for the filesystem-safe id contract used throughout the run
    archive — instead of a second, locally-defined pattern. Raises
    ``ValueError`` on an invalid id; returns ``value`` unchanged
    otherwise.
    """
    return _runstore_validate_id(value, "correlation_id")


def assert_non_secret(value: str, *, field_name: str) -> str:
    """Reject an identity-bearing ``value`` that the shared redaction
    policy would treat as sensitive.

    Two independent checks, both backed by
    :mod:`aptl.utils.redaction` (never a second, locally-defined
    classification):

    - ``field_name`` itself reads as a sensitive key
      (:func:`aptl.utils.redaction.is_sensitive_key`) — e.g. a caller
      accidentally wiring a ``password``-named field through a
      correlation ref.
    - ``value`` is secret-shaped content
      (:func:`aptl.utils.redaction.is_secret_shaped_value`) — i.e.
      :func:`aptl.utils.redaction.redact` would alter it.

    Raises ``ValueError`` on either hit; returns ``value`` unchanged
    otherwise.
    """
    if is_sensitive_key(field_name):
        raise ValueError(
            f"{field_name!r} reads as a sensitive field name; "
            "correlation identities must be non-secret"
        )
    if is_secret_shaped_value(value):
        raise ValueError(
            f"{field_name} value is secret-shaped; correlation identities must be non-secret"
        )
    return value


def _validate_non_empty(field_name: str, value: str) -> None:
    """Raise ``ValueError`` if ``value`` is not a non-empty string."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


def _validate_ref(value: str, *, field_name: str) -> None:
    """Validate a required ref: id-shaped AND non-secret."""
    validate_correlation_id(value)
    assert_non_secret(value, field_name=field_name)


def _validate_optional_ref(value: str | None, *, field_name: str) -> None:
    """Validate an optional ref: ``None`` is always accepted; a present
    value must be id-shaped AND non-secret."""
    if value is None:
        return
    _validate_ref(value, field_name=field_name)


@dataclass(frozen=True)
class ClockContext:
    """APTL archive-local projection of one source's clock context.

    ACES's own ``ExperimentClockContextModel`` carries only ``clock_id``,
    ``authority``, ``time_domain``, and an optional free-text
    ``synchronization`` string — no structured offset or uncertainty.
    This type fills that gap: a per-source, per-timestamp-domain clock
    reading that can carry a measured offset and uncertainty band
    alongside the observer-effect disclosure that documents any injected
    metadata (preflight "Record clock context per evidence source and
    timestamp domain").
    """

    source_kind: str
    source_id: str
    timestamp_domain: str
    clock_source: str
    synchronization_status: str
    measured_offset: str | None
    uncertainty: str | None
    measurement_time: str
    observer_effect_ref: str | None

    def __post_init__(self) -> None:
        _validate_non_empty("source_kind", self.source_kind)
        _validate_non_empty("timestamp_domain", self.timestamp_domain)
        _validate_non_empty("clock_source", self.clock_source)
        _validate_non_empty("synchronization_status", self.synchronization_status)
        _validate_non_empty("measurement_time", self.measurement_time)
        _validate_ref(self.source_id, field_name="source_id")
        _validate_optional_ref(self.observer_effect_ref, field_name="observer_effect_ref")


@dataclass(frozen=True)
class CorrelationNode:
    """One ACES/``LocalRunStore`` reference in the correlation graph.

    ``ref`` is an existing ACES or run-store identity — never a new
    APTL-local tracing concept; ``ref_kind`` names which controlled
    vocabulary entry (:data:`_REF_KINDS`) it is.
    """

    ref: str
    ref_kind: str

    def __post_init__(self) -> None:
        _validate_ref(self.ref, field_name="ref")
        if self.ref_kind not in _REF_KINDS:
            raise ValueError(f"unknown ref_kind: {self.ref_kind!r}")


@dataclass(frozen=True)
class CorrelationEdge:
    """One typed association between two declared :class:`CorrelationNode` refs.

    Never a bare causal claim from timestamp proximity alone: a
    ``TIME_WINDOW_CANDIDATE`` edge MUST carry a ``clock_context_ref`` so
    its uncertainty travels with the claim, and a ``DECLARED_RULE`` edge
    MUST name the ``rule_id`` that produced it.
    """

    source_ref: str
    target_ref: str
    association_method: AssociationMethod
    rule_id: str | None
    clock_context_ref: str | None
    confidence_or_status: str | None
    disclosure_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_ref(self.source_ref, field_name="source_ref")
        _validate_ref(self.target_ref, field_name="target_ref")
        _validate_optional_ref(self.rule_id, field_name="rule_id")
        _validate_optional_ref(self.clock_context_ref, field_name="clock_context_ref")
        for ref in self.disclosure_refs:
            _validate_ref(ref, field_name="disclosure_refs")
        if self.association_method is AssociationMethod.DECLARED_RULE and self.rule_id is None:
            raise ValueError("a DECLARED_RULE edge requires rule_id")
        if (
            self.association_method is AssociationMethod.TIME_WINDOW_CANDIDATE
            and self.clock_context_ref is None
        ):
            raise ValueError(
                "a TIME_WINDOW_CANDIDATE edge requires clock_context_ref "
                "(uncertainty must be attached — never a bare causal claim)"
            )


def _node_projection(node: CorrelationNode) -> dict[str, object]:
    """Canonical dict projection of a node."""
    return {"ref": node.ref, "ref_kind": node.ref_kind}


def _node_sort_key(node: CorrelationNode) -> tuple[str, str]:
    """Sort key for deterministic node ordering."""
    return (node.ref, node.ref_kind)


def _edge_projection(edge: CorrelationEdge) -> dict[str, object]:
    """Canonical dict projection of an edge (disclosure_refs sorted)."""
    return {
        "source_ref": edge.source_ref,
        "target_ref": edge.target_ref,
        "association_method": edge.association_method.value,
        "rule_id": edge.rule_id,
        "clock_context_ref": edge.clock_context_ref,
        "confidence_or_status": edge.confidence_or_status,
        # Sorted: disclosure_refs is an unordered set of disclosure
        # documents attached to this edge, not an authored sequence.
        "disclosure_refs": sorted(edge.disclosure_refs),
    }


def _edge_sort_key(edge: CorrelationEdge) -> tuple[str, str, str, str, str, str, str]:
    """Sort key for deterministic edge ordering."""
    return (
        edge.source_ref,
        edge.target_ref,
        edge.association_method.value,
        edge.rule_id or "",
        edge.clock_context_ref or "",
        edge.confidence_or_status or "",
        ",".join(sorted(edge.disclosure_refs)),
    )


def _clock_context_projection(ctx: ClockContext) -> dict[str, object]:
    """Canonical dict projection of a clock context."""
    return {
        "source_kind": ctx.source_kind,
        "source_id": ctx.source_id,
        "timestamp_domain": ctx.timestamp_domain,
        "clock_source": ctx.clock_source,
        "synchronization_status": ctx.synchronization_status,
        "measured_offset": ctx.measured_offset,
        "uncertainty": ctx.uncertainty,
        "measurement_time": ctx.measurement_time,
        "observer_effect_ref": ctx.observer_effect_ref,
    }


def _clock_context_sort_key(ctx: ClockContext) -> tuple[str, str, str]:
    """Sort key for deterministic clock-context ordering."""
    return (ctx.source_kind, ctx.source_id, ctx.measurement_time)


def _clock_context_from_dict(data: Mapping[str, object]) -> ClockContext:
    """Reconstruct a ClockContext from its canonical dict projection."""
    return ClockContext(
        source_kind=data["source_kind"],
        source_id=data["source_id"],
        timestamp_domain=data["timestamp_domain"],
        clock_source=data["clock_source"],
        synchronization_status=data["synchronization_status"],
        measured_offset=data["measured_offset"],
        uncertainty=data["uncertainty"],
        measurement_time=data["measurement_time"],
        observer_effect_ref=data["observer_effect_ref"],
    )


def _edge_from_dict(data: Mapping[str, object]) -> CorrelationEdge:
    """Reconstruct a CorrelationEdge from its canonical dict projection."""
    return CorrelationEdge(
        source_ref=data["source_ref"],
        target_ref=data["target_ref"],
        association_method=AssociationMethod(data["association_method"]),
        rule_id=data["rule_id"],
        clock_context_ref=data["clock_context_ref"],
        confidence_or_status=data["confidence_or_status"],
        disclosure_refs=tuple(data["disclosure_refs"]),
    )


def _node_from_dict(data: Mapping[str, object]) -> CorrelationNode:
    """Reconstruct a CorrelationNode from its canonical dict projection."""
    return CorrelationNode(ref=data["ref"], ref_kind=data["ref_kind"])


@dataclass(frozen=True)
class CorrelationProjection:
    """The full versioned correlation projection for one run archive.

    Immutable: :attr:`canonical_bytes` (RFC 8785 canonical JSON of
    :meth:`to_canonical_dict`) and :attr:`projection_digest`
    (``sha256:<hex>`` of those bytes) are computed once at construction
    and never accepted as constructor input — a caller cannot pass a
    ``canonical_bytes`` that disagrees with the actual field content.

    Every edge endpoint (``source_ref``/``target_ref``) must reference a
    node declared in :attr:`nodes`; construction rejects a dangling edge
    rather than silently admitting it.
    """

    run_id: str
    nodes: tuple[CorrelationNode, ...]
    edges: tuple[CorrelationEdge, ...]
    clock_contexts: tuple[ClockContext, ...]
    disclosures: tuple[str, ...]
    schema_version: str = _PROJECTION_SCHEMA_VERSION
    canonical_bytes: bytes = field(init=False)
    projection_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_non_empty("schema_version", self.schema_version)
        _validate_ref(self.run_id, field_name="run_id")
        declared_refs = {node.ref for node in self.nodes}
        for edge in self.edges:
            if edge.source_ref not in declared_refs:
                raise ValueError(f"edge source_ref is not a declared node: {edge.source_ref!r}")
            if edge.target_ref not in declared_refs:
                raise ValueError(f"edge target_ref is not a declared node: {edge.target_ref!r}")
        for ref in self.disclosures:
            _validate_ref(ref, field_name="disclosures")

        canonical = rfc8785.dumps(self.to_canonical_dict())
        object.__setattr__(self, "canonical_bytes", canonical)
        object.__setattr__(
            self, "projection_digest", f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        )

    def to_canonical_dict(self) -> dict[str, object]:
        """Project to a canonical-JSON-ready dict.

        Nodes, edges, clock contexts, and disclosures are graph-shaped
        (semantically unordered) rather than an authored execution
        sequence, so each is sorted here — two projections built from the
        same content in different input order produce the identical
        dict, and therefore identical :attr:`canonical_bytes` /
        :attr:`projection_digest`. Excludes any wall-clock/host-path
        administrative metadata: every value below is authored content
        (a source's own recorded ``measurement_time`` is payload, not
        build-time provenance).
        """
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "nodes": [_node_projection(n) for n in sorted(self.nodes, key=_node_sort_key)],
            "edges": [_edge_projection(e) for e in sorted(self.edges, key=_edge_sort_key)],
            "clock_contexts": [
                _clock_context_projection(c)
                for c in sorted(self.clock_contexts, key=_clock_context_sort_key)
            ],
            "disclosures": sorted(self.disclosures),
        }

    @classmethod
    def from_canonical_dict(cls, data: Mapping[str, object]) -> "CorrelationProjection":
        """Reconstruct a :class:`CorrelationProjection` from
        :meth:`to_canonical_dict`'s output (or an equivalently-shaped
        mapping, e.g. after a JSON round-trip)."""
        nodes: Sequence[Mapping[str, object]] = data["nodes"]
        edges: Sequence[Mapping[str, object]] = data["edges"]
        clock_contexts: Sequence[Mapping[str, object]] = data["clock_contexts"]
        return cls(
            run_id=data["run_id"],
            nodes=tuple(_node_from_dict(n) for n in nodes),
            edges=tuple(_edge_from_dict(e) for e in edges),
            clock_contexts=tuple(_clock_context_from_dict(c) for c in clock_contexts),
            disclosures=tuple(data["disclosures"]),
            schema_version=data.get("schema_version", _PROJECTION_SCHEMA_VERSION),
        )
