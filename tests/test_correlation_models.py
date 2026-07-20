"""Tests for ``aptl.core.correlation.models`` (OBS-002 Stage 1, issue #447).

Covers: enum values; construction and frozen immutability of
``ClockContext``/``CorrelationNode``/``CorrelationEdge``/
``CorrelationProjection``; the two edge invariants (``DECLARED_RULE``
requires ``rule_id``; ``TIME_WINDOW_CANDIDATE`` requires
``clock_context_ref``); edge endpoints must reference a declared node;
id validation rejects a bad/secret-shaped id at construction;
``projection_digest`` stability across two builds of the same content
AND independence from node/edge/clock-context/disclosure input ordering;
and ``assert_non_secret`` rejecting a secret-shaped identity-bearing
value directly.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from aptl.core.correlation.models import (
    AssociationMethod,
    ClockContext,
    CorrelationEdge,
    CorrelationNode,
    CorrelationProjection,
    assert_non_secret,
    validate_correlation_id,
)

# ---------------------------------------------------------------------------
# Fixtures / builders
# ---------------------------------------------------------------------------


def _clock_context(**overrides) -> ClockContext:
    fields = {
        "source_kind": "kali-session",
        "source_id": "sess-1",
        "timestamp_domain": "host-utc",
        "clock_source": "system",
        "synchronization_status": "unknown",
        "measured_offset": None,
        "uncertainty": None,
        "measurement_time": "2026-01-01T00:00:00Z",
        "observer_effect_ref": None,
    }
    fields.update(overrides)
    return ClockContext(**fields)


def _node(ref: str = "exp-spec-1", ref_kind: str = "experiment-spec") -> CorrelationNode:
    return CorrelationNode(ref=ref, ref_kind=ref_kind)


def _edge(**overrides) -> CorrelationEdge:
    fields = {
        "source_ref": "exp-spec-1",
        "target_ref": "task-1",
        "association_method": AssociationMethod.EXPLICIT_IDENTIFIER,
        "rule_id": None,
        "clock_context_ref": None,
        "confidence_or_status": "high",
        "disclosure_refs": (),
    }
    fields.update(overrides)
    return CorrelationEdge(**fields)


def _projection(**overrides) -> CorrelationProjection:
    node_a = _node("exp-spec-1", "experiment-spec")
    node_b = _node("task-1", "task")
    fields = {
        "run_id": "run-1",
        "nodes": (node_a, node_b),
        "edges": (_edge(),),
        "clock_contexts": (_clock_context(),),
        "disclosures": (),
    }
    fields.update(overrides)
    return CorrelationProjection(**fields)


# ---------------------------------------------------------------------------
# AssociationMethod
# ---------------------------------------------------------------------------


class TestAssociationMethod:
    def test_values_match_the_preflight_controlled_vocabulary(self):
        assert AssociationMethod.EXPLICIT_IDENTIFIER.value == "explicit_identifier"
        assert AssociationMethod.DECLARED_RULE.value == "declared_rule"
        assert AssociationMethod.TIME_WINDOW_CANDIDATE.value == "time_window_candidate"
        assert AssociationMethod.GAP_OR_UNKNOWN.value == "gap_or_unknown"

    def test_is_a_str_enum(self):
        assert AssociationMethod.EXPLICIT_IDENTIFIER == "explicit_identifier"
        assert isinstance(AssociationMethod.EXPLICIT_IDENTIFIER, str)


# ---------------------------------------------------------------------------
# validate_correlation_id / assert_non_secret
# ---------------------------------------------------------------------------


class TestValidateCorrelationId:
    def test_accepts_a_well_formed_id(self):
        assert validate_correlation_id("run-abc123") == "run-abc123"

    def test_rejects_an_id_with_illegal_characters(self):
        with pytest.raises(ValueError):
            validate_correlation_id("bad id with spaces")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError):
            validate_correlation_id("../escape")

    def test_rejects_kv_shaped_secret_text(self):
        with pytest.raises(ValueError):
            validate_correlation_id("password=hunter2")


class TestAssertNonSecret:
    def test_returns_the_value_unchanged_when_safe(self):
        assert assert_non_secret("safe-value-1", field_name="ref") == "safe-value-1"

    def test_rejects_a_secret_shaped_value(self):
        with pytest.raises(ValueError):
            assert_non_secret("token=abc123def456", field_name="notes")

    def test_rejects_a_sensitive_field_name_even_with_a_bland_value(self):
        with pytest.raises(ValueError):
            assert_non_secret("bland-value", field_name="password")

    def test_rejects_an_authorization_bearer_shaped_value(self):
        with pytest.raises(ValueError):
            assert_non_secret("Bearer abc.def.ghi", field_name="notes")


# ---------------------------------------------------------------------------
# ClockContext
# ---------------------------------------------------------------------------


class TestClockContext:
    def test_constructs_with_valid_fields(self):
        ctx = _clock_context()
        assert ctx.source_kind == "kali-session"
        assert ctx.clock_source == "system"

    def test_is_frozen(self):
        ctx = _clock_context()
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.source_kind = "mutated"  # type: ignore[misc]

    def test_rejects_empty_source_kind(self):
        with pytest.raises(ValueError):
            _clock_context(source_kind="")

    def test_rejects_empty_measurement_time(self):
        with pytest.raises(ValueError):
            _clock_context(measurement_time="")

    def test_rejects_a_bad_source_id(self):
        with pytest.raises(ValueError):
            _clock_context(source_id="bad id")

    def test_rejects_a_secret_shaped_source_id(self):
        with pytest.raises(ValueError):
            _clock_context(source_id="password=hunter2")

    def test_accepts_none_for_optional_fields(self):
        ctx = _clock_context(measured_offset=None, uncertainty=None, observer_effect_ref=None)
        assert ctx.measured_offset is None
        assert ctx.uncertainty is None
        assert ctx.observer_effect_ref is None

    def test_accepts_present_optional_fields(self):
        ctx = _clock_context(measured_offset="12ms", uncertainty="5ms", observer_effect_ref="disc-1")
        assert ctx.measured_offset == "12ms"
        assert ctx.observer_effect_ref == "disc-1"

    def test_rejects_an_invalid_observer_effect_ref(self):
        with pytest.raises(ValueError):
            _clock_context(observer_effect_ref="not a valid ref")


# ---------------------------------------------------------------------------
# CorrelationNode
# ---------------------------------------------------------------------------


class TestCorrelationNode:
    def test_constructs_with_a_known_ref_kind(self):
        node = _node("evidence-1", "evidence")
        assert node.ref == "evidence-1"
        assert node.ref_kind == "evidence"

    def test_is_frozen(self):
        node = _node()
        with pytest.raises(dataclasses.FrozenInstanceError):
            node.ref = "mutated"  # type: ignore[misc]

    def test_rejects_an_unknown_ref_kind(self):
        with pytest.raises(ValueError):
            _node(ref_kind="not-a-controlled-kind")

    def test_rejects_a_bad_ref(self):
        with pytest.raises(ValueError):
            _node(ref="bad ref with spaces")

    def test_rejects_a_secret_shaped_ref(self):
        with pytest.raises(ValueError):
            _node(ref="password=hunter2")

    @pytest.mark.parametrize(
        "ref_kind",
        [
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
        ],
    )
    def test_accepts_every_controlled_ref_kind(self, ref_kind):
        node = _node(ref="ref-1", ref_kind=ref_kind)
        assert node.ref_kind == ref_kind


# ---------------------------------------------------------------------------
# CorrelationEdge
# ---------------------------------------------------------------------------


class TestCorrelationEdge:
    def test_constructs_a_minimal_explicit_identifier_edge(self):
        edge = _edge()
        assert edge.association_method is AssociationMethod.EXPLICIT_IDENTIFIER

    def test_is_frozen(self):
        edge = _edge()
        with pytest.raises(dataclasses.FrozenInstanceError):
            edge.source_ref = "mutated"  # type: ignore[misc]

    def test_disclosure_refs_is_a_tuple(self):
        edge = _edge(disclosure_refs=("disc-1", "disc-2"))
        assert isinstance(edge.disclosure_refs, tuple)

    def test_rejects_a_bad_source_ref(self):
        with pytest.raises(ValueError):
            _edge(source_ref="bad ref")

    def test_rejects_a_bad_target_ref(self):
        with pytest.raises(ValueError):
            _edge(target_ref="bad ref")

    def test_rejects_a_secret_shaped_disclosure_ref(self):
        with pytest.raises(ValueError):
            _edge(disclosure_refs=("password=hunter2",))

    def test_declared_rule_requires_rule_id(self):
        with pytest.raises(ValueError, match="DECLARED_RULE"):
            _edge(association_method=AssociationMethod.DECLARED_RULE, rule_id=None)

    def test_declared_rule_with_rule_id_succeeds(self):
        edge = _edge(association_method=AssociationMethod.DECLARED_RULE, rule_id="rule-1")
        assert edge.rule_id == "rule-1"

    def test_time_window_candidate_requires_clock_context_ref(self):
        with pytest.raises(ValueError, match="TIME_WINDOW_CANDIDATE"):
            _edge(
                association_method=AssociationMethod.TIME_WINDOW_CANDIDATE,
                clock_context_ref=None,
            )

    def test_time_window_candidate_with_clock_context_ref_succeeds(self):
        edge = _edge(
            association_method=AssociationMethod.TIME_WINDOW_CANDIDATE,
            clock_context_ref="clock-ctx-1",
        )
        assert edge.clock_context_ref == "clock-ctx-1"

    def test_explicit_identifier_does_not_require_rule_id_or_clock_context_ref(self):
        edge = _edge(
            association_method=AssociationMethod.EXPLICIT_IDENTIFIER,
            rule_id=None,
            clock_context_ref=None,
        )
        assert edge.rule_id is None
        assert edge.clock_context_ref is None

    def test_gap_or_unknown_does_not_require_rule_id_or_clock_context_ref(self):
        edge = _edge(
            association_method=AssociationMethod.GAP_OR_UNKNOWN,
            rule_id=None,
            clock_context_ref=None,
        )
        assert edge.association_method is AssociationMethod.GAP_OR_UNKNOWN


# ---------------------------------------------------------------------------
# CorrelationProjection
# ---------------------------------------------------------------------------


class TestCorrelationProjection:
    def test_constructs_with_valid_nodes_and_edges(self):
        proj = _projection()
        assert proj.run_id == "run-1"
        assert proj.schema_version == "aptl-correlation/v1"

    def test_is_frozen(self):
        proj = _projection()
        with pytest.raises(dataclasses.FrozenInstanceError):
            proj.run_id = "mutated"  # type: ignore[misc]

    def test_canonical_bytes_and_digest_are_populated(self):
        proj = _projection()
        assert isinstance(proj.canonical_bytes, bytes)
        assert proj.projection_digest.startswith("sha256:")

    def test_projection_digest_is_the_sha256_of_canonical_bytes(self):
        proj = _projection()
        expected = f"sha256:{hashlib.sha256(proj.canonical_bytes).hexdigest()}"
        assert proj.projection_digest == expected

    def test_rejects_an_edge_whose_source_ref_is_not_a_declared_node(self):
        node_b = _node("task-1", "task")
        with pytest.raises(ValueError, match="source_ref"):
            CorrelationProjection(
                run_id="run-1",
                nodes=(node_b,),
                edges=(_edge(source_ref="missing-node", target_ref="task-1"),),
                clock_contexts=(),
                disclosures=(),
            )

    def test_rejects_an_edge_whose_target_ref_is_not_a_declared_node(self):
        node_a = _node("exp-spec-1", "experiment-spec")
        with pytest.raises(ValueError, match="target_ref"):
            CorrelationProjection(
                run_id="run-1",
                nodes=(node_a,),
                edges=(_edge(source_ref="exp-spec-1", target_ref="missing-node"),),
                clock_contexts=(),
                disclosures=(),
            )

    def test_rejects_a_bad_run_id(self):
        with pytest.raises(ValueError):
            _projection(run_id="bad run id")

    def test_rejects_a_secret_shaped_run_id(self):
        with pytest.raises(ValueError):
            _projection(run_id="password=hunter2")

    def test_rejects_a_secret_shaped_disclosure(self):
        with pytest.raises(ValueError):
            _projection(disclosures=("password=hunter2",))

    def test_accepts_an_empty_graph(self):
        proj = CorrelationProjection(
            run_id="run-empty", nodes=(), edges=(), clock_contexts=(), disclosures=()
        )
        assert proj.nodes == ()
        assert proj.edges == ()

    # -- digest stability -----------------------------------------------

    def test_digest_is_stable_across_two_builds_of_the_same_content(self):
        proj1 = _projection()
        proj2 = _projection()
        assert proj1.canonical_bytes == proj2.canonical_bytes
        assert proj1.projection_digest == proj2.projection_digest

    def test_digest_is_independent_of_node_input_order(self):
        node_a = _node("exp-spec-1", "experiment-spec")
        node_b = _node("task-1", "task")
        edge = _edge()
        proj_ab = CorrelationProjection(
            run_id="run-1", nodes=(node_a, node_b), edges=(edge,), clock_contexts=(), disclosures=()
        )
        proj_ba = CorrelationProjection(
            run_id="run-1", nodes=(node_b, node_a), edges=(edge,), clock_contexts=(), disclosures=()
        )
        assert proj_ab.canonical_bytes == proj_ba.canonical_bytes
        assert proj_ab.projection_digest == proj_ba.projection_digest

    def test_digest_is_independent_of_edge_input_order(self):
        node_a = _node("exp-spec-1", "experiment-spec")
        node_b = _node("task-1", "task")
        node_c = _node("action-1", "action")
        edge1 = _edge(source_ref="exp-spec-1", target_ref="task-1")
        edge2 = _edge(source_ref="task-1", target_ref="action-1")
        proj_12 = CorrelationProjection(
            run_id="run-1",
            nodes=(node_a, node_b, node_c),
            edges=(edge1, edge2),
            clock_contexts=(),
            disclosures=(),
        )
        proj_21 = CorrelationProjection(
            run_id="run-1",
            nodes=(node_a, node_b, node_c),
            edges=(edge2, edge1),
            clock_contexts=(),
            disclosures=(),
        )
        assert proj_12.canonical_bytes == proj_21.canonical_bytes
        assert proj_12.projection_digest == proj_21.projection_digest

    def test_digest_is_independent_of_clock_context_input_order(self):
        node_a = _node("exp-spec-1", "experiment-spec")
        ctx1 = _clock_context(source_id="sess-1", measurement_time="2026-01-01T00:00:00Z")
        ctx2 = _clock_context(source_id="sess-2", measurement_time="2026-01-01T00:00:01Z")
        proj_12 = CorrelationProjection(
            run_id="run-1", nodes=(node_a,), edges=(), clock_contexts=(ctx1, ctx2), disclosures=()
        )
        proj_21 = CorrelationProjection(
            run_id="run-1", nodes=(node_a,), edges=(), clock_contexts=(ctx2, ctx1), disclosures=()
        )
        assert proj_12.canonical_bytes == proj_21.canonical_bytes
        assert proj_12.projection_digest == proj_21.projection_digest

    def test_digest_is_independent_of_disclosure_input_order(self):
        node_a = _node("exp-spec-1", "experiment-spec")
        proj_ab = CorrelationProjection(
            run_id="run-1",
            nodes=(node_a,),
            edges=(),
            clock_contexts=(),
            disclosures=("disc-a", "disc-b"),
        )
        proj_ba = CorrelationProjection(
            run_id="run-1",
            nodes=(node_a,),
            edges=(),
            clock_contexts=(),
            disclosures=("disc-b", "disc-a"),
        )
        assert proj_ab.canonical_bytes == proj_ba.canonical_bytes
        assert proj_ab.projection_digest == proj_ba.projection_digest

    def test_digest_is_independent_of_edge_disclosure_refs_order(self):
        node_a = _node("exp-spec-1", "experiment-spec")
        node_b = _node("task-1", "task")
        edge_ab = _edge(disclosure_refs=("disc-a", "disc-b"))
        edge_ba = _edge(disclosure_refs=("disc-b", "disc-a"))
        proj_ab = CorrelationProjection(
            run_id="run-1", nodes=(node_a, node_b), edges=(edge_ab,), clock_contexts=(), disclosures=()
        )
        proj_ba = CorrelationProjection(
            run_id="run-1", nodes=(node_a, node_b), edges=(edge_ba,), clock_contexts=(), disclosures=()
        )
        assert proj_ab.canonical_bytes == proj_ba.canonical_bytes

    def test_different_content_yields_a_different_digest(self):
        proj1 = _projection()
        proj2 = _projection(run_id="run-2")
        assert proj1.projection_digest != proj2.projection_digest

    # -- roundtrip ---------------------------------------------------------

    def test_to_canonical_dict_from_canonical_dict_roundtrip_preserves_digest(self):
        proj = _projection()
        rebuilt = CorrelationProjection.from_canonical_dict(proj.to_canonical_dict())
        assert rebuilt.projection_digest == proj.projection_digest
        assert rebuilt.canonical_bytes == proj.canonical_bytes

    def test_to_canonical_dict_is_json_shaped(self):
        proj = _projection()
        d = proj.to_canonical_dict()
        assert d["run_id"] == "run-1"
        assert isinstance(d["nodes"], list)
        assert isinstance(d["edges"], list)
        assert isinstance(d["clock_contexts"], list)
        assert isinstance(d["disclosures"], list)


# ---------------------------------------------------------------------------
# Fuzz (property-based)
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_ID_ALPHABET = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=20,
).filter(lambda s: s[0].isalnum() or s[0] in "_")


@pytest.mark.fuzz
class TestFuzzProjectionOrderingInvariance:
    @given(
        node_refs=st.lists(_ID_ALPHABET, min_size=1, max_size=8, unique=True),
        seed=st.integers(min_value=0, max_value=2**32 - 1),
    )
    @settings(max_examples=25, deadline=None)
    def test_shuffled_node_order_never_changes_the_digest(self, node_refs, seed):
        import random

        rng = random.Random(seed)  # noqa: S311 - test-only shuffling
        nodes = tuple(_node(ref=r, ref_kind="task") for r in node_refs)
        shuffled = list(nodes)
        rng.shuffle(shuffled)

        proj_original = CorrelationProjection(
            run_id="run-fuzz", nodes=nodes, edges=(), clock_contexts=(), disclosures=()
        )
        proj_shuffled = CorrelationProjection(
            run_id="run-fuzz", nodes=tuple(shuffled), edges=(), clock_contexts=(), disclosures=()
        )
        assert proj_original.canonical_bytes == proj_shuffled.canonical_bytes
        assert proj_original.projection_digest == proj_shuffled.projection_digest

    @given(ref=_ID_ALPHABET)
    @settings(max_examples=25, deadline=None)
    def test_valid_ids_always_round_trip_through_validate_correlation_id(self, ref):
        assert validate_correlation_id(ref) == ref
