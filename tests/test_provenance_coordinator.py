"""Tests for the REP-003 provenance coordinator (issue #452).

Covers the preflight's bounded-collection contract: every internal failure
becomes one of the small typed statuses, limits are enforced, ordering never
perturbs identity, and no source silently degrades to success.
"""

import pytest

from aptl.core.provenance.coordinator import collect_provenance
from aptl.core.provenance.identity import leaf_identity
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    ProvenanceProviderRegistry,
    SealPoint,
    SealProfile,
)

_PROFILE = SealProfile(seal_point=SealPoint.RUN_READY_TO_SEAL)


def _registration(provider_id: str, *, max_bytes=1024, max_entries=8, timeout_s=5):
    return ProvenanceProviderRegistration(
        provider_id=provider_id,
        implementation_version="1.0.0",
        provenance_kind=provider_id,
        owner_adapter="tests",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key=f"{provider_id}-required",
        limits=ProvenanceLimits(
            max_bytes=max_bytes, max_entries=max_entries, timeout_s=timeout_s
        ),
    )


class _StubProvider:
    """A provider whose behavior each test dictates."""

    def __init__(self, provider_id, *, result=None, raises=None, elapsed=0.0):
        self.provider_id = provider_id
        self._result = result
        self._raises = raises
        self._elapsed = elapsed
        self.calls = 0

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        self.calls += 1
        context.clock.advance(self._elapsed)
        if self._raises is not None:
            raise self._raises
        if self._result is not None:
            return self._result
        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=(leaf_identity("a", b"1"),),
            payload={"kind": self.provider_id},
        )


class _FakeClock:
    """A monotonic clock the test advances explicitly."""

    def __init__(self):
        self._now = 0.0

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def _collect(providers, registrations=None, profile=_PROFILE, clock=None):
    registry = ProvenanceProviderRegistry(
        tuple(registrations or [_registration(p.provider_id) for p in providers])
    )
    return collect_provenance(
        providers=providers,
        registry=registry,
        profile=profile,
        monotonic=clock or _FakeClock(),
    )


class TestSuccessfulCollection:
    """A collected provider contributes a section with a framed identity."""

    def test_section_carries_status_identity_and_payload(self):
        collection = _collect([_StubProvider("apparatus")])
        section = collection.sections["apparatus"]
        assert section.status is ProvenanceStatus.COLLECTED
        assert section.content_identity.startswith("sha256:")
        assert section.payload["kind"] == "apparatus"

    def test_section_records_the_pinned_declaration_digest(self):
        """A reader can tell the provider's declared capability changed."""
        collection = _collect([_StubProvider("apparatus")])
        registration = _registration("apparatus")
        assert (
            collection.sections["apparatus"].declaration_digest
            == registration.effective_config_digest()
        )

    def test_no_limitation_for_a_collected_source(self):
        collection = _collect([_StubProvider("apparatus")])
        assert collection.limitations == ()

    def test_aggregate_identity_is_provider_order_independent(self):
        forward = _collect([_StubProvider("apparatus"), _StubProvider("detection-content")])
        backward = _collect([_StubProvider("detection-content"), _StubProvider("apparatus")])
        assert forward.aggregate_identity == backward.aggregate_identity

    def test_a_changed_leaf_changes_only_its_section_and_the_aggregate(self):
        stable = _StubProvider("apparatus")
        changed = _StubProvider(
            "detection-content",
            result=ProvenanceResult(
                provider_id="detection-content",
                status=ProvenanceStatus.COLLECTED,
                leaves=(leaf_identity("a", b"changed"),),
                payload={"kind": "detection-content"},
            ),
        )
        before = _collect([_StubProvider("apparatus"), _StubProvider("detection-content")])
        after = _collect([stable, changed])
        assert (
            before.sections["apparatus"].content_identity
            == after.sections["apparatus"].content_identity
        )
        assert (
            before.sections["detection-content"].content_identity
            != after.sections["detection-content"].content_identity
        )
        assert before.aggregate_identity != after.aggregate_identity


class TestFailureBecomesAnExplicitLimitation:
    """No source silently disappears or degrades to success."""

    def test_a_raising_provider_becomes_failed_not_an_exception(self):
        collection = _collect([_StubProvider("apparatus", raises=RuntimeError("boom"))])
        assert collection.sections["apparatus"].status is ProvenanceStatus.FAILED
        assert [item.provider_id for item in collection.limitations] == ["apparatus"]

    def test_a_raising_provider_never_leaks_its_exception_text(self):
        secret = "token=abc123 /home/user/.env"
        collection = _collect([_StubProvider("apparatus", raises=RuntimeError(secret))])
        rendered = repr(collection.projection())
        assert "abc123" not in rendered
        assert ".env" not in rendered

    def test_a_failed_provider_contributes_no_content_identity(self):
        """A failure must not produce a fabricated digest."""
        collection = _collect([_StubProvider("apparatus", raises=RuntimeError())])
        assert collection.sections["apparatus"].content_identity is None

    @pytest.mark.parametrize(
        "status",
        [
            ProvenanceStatus.UNAVAILABLE,
            ProvenanceStatus.DENIED,
            ProvenanceStatus.UNSUPPORTED,
            ProvenanceStatus.TRUNCATED,
        ],
    )
    def test_every_reported_non_success_becomes_a_limitation(self, status):
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(provider_id="apparatus", status=status),
        )
        collection = _collect([provider])
        assert [item.status for item in collection.limitations] == [status]

    def test_overrunning_the_declared_deadline_is_timed_out(self):
        clock = _FakeClock()
        provider = _StubProvider("apparatus", elapsed=9.0)
        collection = _collect(
            [provider], registrations=[_registration("apparatus", timeout_s=5)], clock=clock
        )
        assert collection.sections["apparatus"].status is ProvenanceStatus.TIMED_OUT
        assert collection.limitations[0].status is ProvenanceStatus.TIMED_OUT

    def test_a_timed_out_provider_discards_its_partial_content(self):
        clock = _FakeClock()
        provider = _StubProvider("apparatus", elapsed=9.0)
        collection = _collect(
            [provider], registrations=[_registration("apparatus", timeout_s=5)], clock=clock
        )
        assert collection.sections["apparatus"].content_identity is None

    def test_exceeding_the_declared_entry_limit_is_truncated(self):
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                leaves=tuple(leaf_identity(f"leaf-{index}", b"x") for index in range(9)),
            ),
        )
        collection = _collect(
            [provider], registrations=[_registration("apparatus", max_entries=8)]
        )
        assert collection.sections["apparatus"].status is ProvenanceStatus.TRUNCATED

    def test_a_provider_with_no_registration_is_unsupported(self):
        """An unregistered provider is never trusted into the record."""
        registry = ProvenanceProviderRegistry((_registration("apparatus"),))
        collection = collect_provenance(
            providers=[_StubProvider("rogue")],
            registry=registry,
            profile=_PROFILE,
            monotonic=_FakeClock(),
        )
        assert collection.sections["rogue"].status is ProvenanceStatus.UNSUPPORTED

    def test_a_result_claiming_another_providers_id_is_rejected(self):
        """A provider cannot write into a sibling's section."""
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="detection-content", status=ProvenanceStatus.COLLECTED
            ),
        )
        collection = _collect([provider])
        assert collection.sections["apparatus"].status is ProvenanceStatus.FAILED


class TestRequiredProviders:
    """A policy-required provider that never ran is reported, not assumed."""

    def test_a_missing_required_provider_is_recorded_as_unavailable(self):
        registry = ProvenanceProviderRegistry(
            (_registration("apparatus"), _registration("detection-content"))
        )
        profile = SealProfile(
            seal_point=SealPoint.RUN_READY_TO_SEAL,
            required_provider_ids=frozenset({"detection-content"}),
        )
        collection = collect_provenance(
            providers=[_StubProvider("apparatus")],
            registry=registry,
            profile=profile,
            monotonic=_FakeClock(),
        )
        assert collection.sections["detection-content"].status is ProvenanceStatus.UNAVAILABLE
        assert "detection-content" in {item.provider_id for item in collection.limitations}

    def test_required_provider_ids_are_validated_against_the_registry(self):
        from aptl.core.provenance.registry import ProvenanceRegistrationError

        registry = ProvenanceProviderRegistry((_registration("apparatus"),))
        profile = SealProfile(
            seal_point=SealPoint.RUN_READY_TO_SEAL,
            required_provider_ids=frozenset({"nonexistent"}),
        )
        providers = [_StubProvider("apparatus")]
        clock = _FakeClock()
        with pytest.raises(ProvenanceRegistrationError):
            collect_provenance(
                providers=providers, registry=registry, profile=profile, monotonic=clock
            )


class TestPayloadSafety:
    """Provider payloads are bounded and secret-free before they reach a record."""

    def test_a_secret_shaped_payload_is_rejected_not_redacted_into_the_record(self):
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                payload={"api_key": "AKIAIOSFODNN7EXAMPLE"},
            ),
        )
        collection = _collect([provider])
        assert collection.sections["apparatus"].status is ProvenanceStatus.FAILED
        assert "AKIAIOSFODNN7EXAMPLE" not in repr(collection.projection())

    def test_an_unserializable_payload_fails_closed(self):
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                payload={"handle": object()},
            ),
        )
        collection = _collect([provider])
        assert collection.sections["apparatus"].status is ProvenanceStatus.FAILED

    def test_a_payload_exceeding_the_key_ceiling_is_rejected(self):
        """The coordinator's hard ceilings must be enforced, not just documented."""
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                payload={f"key-{index}": index for index in range(65)},
            ),
        )
        assert _collect([provider]).sections["apparatus"].status is ProvenanceStatus.FAILED

    def test_a_payload_exceeding_the_depth_ceiling_is_rejected(self):
        nested: dict = {"leaf": 1}
        for _ in range(8):
            nested = {"next": nested}
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                payload=nested,
            ),
        )
        assert _collect([provider]).sections["apparatus"].status is ProvenanceStatus.FAILED

    def test_a_payload_exceeding_the_string_ceiling_is_rejected(self):
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                payload={"note": "x" * 4097},
            ),
        )
        assert _collect([provider]).sections["apparatus"].status is ProvenanceStatus.FAILED

    def test_a_payload_within_every_ceiling_is_accepted(self):
        """The ceilings must not reject ordinary provider output."""
        provider = _StubProvider(
            "apparatus",
            result=ProvenanceResult(
                provider_id="apparatus",
                status=ProvenanceStatus.COLLECTED,
                leaves=(leaf_identity("a", b"1"),),
                payload={"note": "x" * 4096, "nested": {"a": {"b": {"c": 1}}}},
            ),
        )
        assert _collect([provider]).sections["apparatus"].status is ProvenanceStatus.COLLECTED

    def test_projection_is_deterministic(self):
        first = _collect([_StubProvider("apparatus"), _StubProvider("detection-content")])
        second = _collect([_StubProvider("detection-content"), _StubProvider("apparatus")])
        assert first.projection() == second.projection()

    def test_projection_lists_limitations_in_a_stable_order(self):
        collection = _collect(
            [
                _StubProvider(
                    "detection-content",
                    result=ProvenanceResult(
                        provider_id="detection-content", status=ProvenanceStatus.DENIED
                    ),
                ),
                _StubProvider(
                    "apparatus",
                    result=ProvenanceResult(
                        provider_id="apparatus", status=ProvenanceStatus.DENIED
                    ),
                ),
            ]
        )
        ordered = [item["provider_id"] for item in collection.projection()["limitations"]]
        assert ordered == sorted(ordered)
