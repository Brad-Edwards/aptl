"""Tests for ``aptl.core.correlation.identity`` (OBS-002 Stage 1, issue #447).

Covers: ``stable_ref`` deterministic across calls AND across subprocesses
with different ``PYTHONHASHSEED`` (mirrors
``tests/test_experiment_trial_plan.py``'s
``test_plan_digest_is_stable_across_separate_processes_with_different_hash_seeds``);
different inputs yield different ids; every produced/accepted id
validates through ``aptl.core.correlation.models.validate_correlation_id``;
``derive_planned_ref`` is a deterministic alias of ``stable_ref``;
``bind_attempt_ref`` validates (never derives) an externally-supplied id.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap

import pytest

from aptl.core.correlation.identity import bind_attempt_ref, derive_planned_ref, stable_ref
from aptl.core.correlation.models import validate_correlation_id

_DOMAIN = b"aptl.correlation.test/v1"
_OTHER_DOMAIN = b"aptl.correlation.test-other/v1"


# ---------------------------------------------------------------------------
# stable_ref
# ---------------------------------------------------------------------------


class TestStableRef:
    def test_is_deterministic_across_calls(self):
        first = stable_ref("a", "b", domain=_DOMAIN)
        second = stable_ref("a", "b", domain=_DOMAIN)
        assert first == second

    def test_returns_a_validated_id(self):
        ref = stable_ref("a", "b", domain=_DOMAIN)
        assert validate_correlation_id(ref) == ref

    def test_looks_like_a_hex_sha256_digest(self):
        ref = stable_ref("a", "b", domain=_DOMAIN)
        assert re.fullmatch(r"[0-9a-f]{64}", ref)

    def test_different_parts_yield_different_ids(self):
        ref1 = stable_ref("a", "b", domain=_DOMAIN)
        ref2 = stable_ref("a", "c", domain=_DOMAIN)
        assert ref1 != ref2

    def test_different_part_order_yields_different_ids(self):
        ref1 = stable_ref("a", "b", domain=_DOMAIN)
        ref2 = stable_ref("b", "a", domain=_DOMAIN)
        assert ref1 != ref2

    def test_different_domain_yields_different_ids_for_the_same_parts(self):
        ref1 = stable_ref("a", "b", domain=_DOMAIN)
        ref2 = stable_ref("a", "b", domain=_OTHER_DOMAIN)
        assert ref1 != ref2

    def test_a_single_part_is_accepted(self):
        ref = stable_ref("only-one", domain=_DOMAIN)
        assert validate_correlation_id(ref) == ref

    def test_many_parts_are_accepted(self):
        ref = stable_ref("a", "b", "c", "d", "e", domain=_DOMAIN)
        assert validate_correlation_id(ref) == ref

    def test_rejects_an_empty_domain(self):
        with pytest.raises(ValueError):
            stable_ref("a", domain=b"")

    def test_rejects_no_parts(self):
        with pytest.raises(ValueError):
            stable_ref(domain=_DOMAIN)

    def test_rejects_a_non_string_part(self):
        with pytest.raises(TypeError):
            stable_ref("a", 123, domain=_DOMAIN)  # type: ignore[arg-type]

    def test_field_separator_cannot_be_used_to_forge_a_collision(self):
        """Concatenating parts across a field boundary must not collide
        with hashing them as two separate parts (domain separation via
        the 0x1F unit separator prevents ``("ab", "c")`` colliding with
        ``("a", "bc")``)."""
        ref1 = stable_ref("ab", "c", domain=_DOMAIN)
        ref2 = stable_ref("a", "bc", domain=_DOMAIN)
        assert ref1 != ref2


# ---------------------------------------------------------------------------
# derive_planned_ref
# ---------------------------------------------------------------------------


class TestDerivePlannedRef:
    def test_matches_stable_ref_for_the_same_inputs(self):
        assert derive_planned_ref("a", "b", domain=_DOMAIN) == stable_ref("a", "b", domain=_DOMAIN)

    def test_is_deterministic_across_calls(self):
        first = derive_planned_ref("cond-1", "0", domain=_DOMAIN)
        second = derive_planned_ref("cond-1", "0", domain=_DOMAIN)
        assert first == second

    def test_different_inputs_yield_different_refs(self):
        ref1 = derive_planned_ref("cond-1", "0", domain=_DOMAIN)
        ref2 = derive_planned_ref("cond-1", "1", domain=_DOMAIN)
        assert ref1 != ref2

    def test_returns_a_validated_id(self):
        ref = derive_planned_ref("cond-1", "0", domain=_DOMAIN)
        assert validate_correlation_id(ref) == ref


# ---------------------------------------------------------------------------
# bind_attempt_ref
# ---------------------------------------------------------------------------


class TestBindAttemptRef:
    def test_returns_the_external_id_unchanged_when_valid(self):
        assert bind_attempt_ref("run-abc123") == "run-abc123"

    def test_rejects_an_invalid_external_id(self):
        with pytest.raises(ValueError):
            bind_attempt_ref("not a valid id")

    def test_rejects_a_secret_shaped_external_id(self):
        with pytest.raises(ValueError):
            bind_attempt_ref("password=hunter2")

    def test_does_not_derive_a_new_value_it_only_validates(self):
        """Unlike `derive_planned_ref`, this must not hash the input —
        the returned ref is exactly the externally-supplied id."""
        external_id = "episode-99"
        assert bind_attempt_ref(external_id) == external_id


# ---------------------------------------------------------------------------
# Determinism across processes / hash seeds
# ---------------------------------------------------------------------------


class TestDeterminismAcrossProcesses:
    def test_stable_ref_is_stable_across_separate_processes_with_different_hash_seeds(self):
        """A same-process double-call cannot catch a stray Python
        ``hash()`` call, because ``PYTHONHASHSEED`` is fixed for the
        lifetime of one process. Run the derivation in subprocesses with
        different hash seeds and confirm the id still matches."""
        script = textwrap.dedent(
            """
            from aptl.core.correlation.identity import stable_ref

            print(stable_ref("cond-a", "0", "seed-a", domain=b"aptl.correlation.test/v1"))
            """
        )
        refs = set()
        repo_src = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
        )
        for seed in ("0", "1", "3391772699"):
            result = subprocess.run(
                [sys.executable, "-c", script],
                env={
                    **os.environ,
                    "PYTHONHASHSEED": seed,
                    "PYTHONPATH": repo_src + os.pathsep + os.environ.get("PYTHONPATH", ""),
                },
                capture_output=True,
                text=True,
                check=True,
            )
            refs.add(result.stdout.strip())
        assert len(refs) == 1

    def test_derive_planned_ref_is_stable_across_separate_processes_with_different_hash_seeds(self):
        script = textwrap.dedent(
            """
            from aptl.core.correlation.identity import derive_planned_ref

            print(derive_planned_ref("cond-a", "0", domain=b"aptl.correlation.test/v1"))
            """
        )
        refs = set()
        repo_src = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
        )
        for seed in ("0", "2", "4242424242"):
            result = subprocess.run(
                [sys.executable, "-c", script],
                env={
                    **os.environ,
                    "PYTHONHASHSEED": seed,
                    "PYTHONPATH": repo_src + os.pathsep + os.environ.get("PYTHONPATH", ""),
                },
                capture_output=True,
                text=True,
                check=True,
            )
            refs.add(result.stdout.strip())
        assert len(refs) == 1


# ---------------------------------------------------------------------------
# Fuzz (property-based)
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_PART_TEXT = st.text(min_size=1, max_size=40)


@pytest.mark.fuzz
class TestFuzzStableRef:
    @given(parts=st.lists(_PART_TEXT, min_size=1, max_size=6))
    @settings(max_examples=50, deadline=None)
    def test_random_parts_always_produce_a_stable_valid_id(self, parts):
        ref1 = stable_ref(*parts, domain=_DOMAIN)
        ref2 = stable_ref(*parts, domain=_DOMAIN)
        assert ref1 == ref2
        assert validate_correlation_id(ref1) == ref1
        assert re.fullmatch(r"[0-9a-f]{64}", ref1)

    @given(parts_a=st.lists(_PART_TEXT, min_size=1, max_size=6), parts_b=st.lists(_PART_TEXT, min_size=1, max_size=6))
    @settings(max_examples=50, deadline=None)
    def test_different_part_lists_are_extremely_unlikely_to_collide(self, parts_a, parts_b):
        if parts_a == parts_b:
            return
        ref_a = stable_ref(*parts_a, domain=_DOMAIN)
        ref_b = stable_ref(*parts_b, domain=_DOMAIN)
        assert ref_a != ref_b
