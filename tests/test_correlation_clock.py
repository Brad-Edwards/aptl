"""Tests for ``aptl.core.correlation.clock`` (OBS-002 Stage 1, issue #447).

Covers: ``SystemClockProvider`` reports an honest (not fabricated)
domain/sync/source; ``FixedClockProvider`` is fully deterministic and
injectable; ``utc_now()`` returns an RFC3339 UTC string; and a
source-scan test forbidding ``datetime.now``/``uuid``/``random`` tokens
in ``identity.py`` (identity must never be derived from the clock or
ambient randomness).
"""

from __future__ import annotations

import inspect
import re
from datetime import UTC, datetime

import pytest

from aptl.core.correlation import identity as identity_module
from aptl.core.correlation.clock import (
    ClockProvider,
    FixedClockProvider,
    SystemClockProvider,
    utc_now,
)
from aptl.core.correlation.models import ClockContext

_RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)


# ---------------------------------------------------------------------------
# utc_now
# ---------------------------------------------------------------------------


class TestUtcNow:
    def test_returns_an_rfc3339_utc_string(self):
        value = utc_now()
        assert _RFC3339_UTC_RE.match(value), value

    def test_is_parseable_and_close_to_the_real_current_time(self):
        before = datetime.now(UTC)
        value = utc_now()
        after = datetime.now(UTC)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        assert before <= parsed <= after

    def test_two_calls_are_monotonic_non_decreasing(self):
        # Parse rather than compare raw strings: `datetime.isoformat()`
        # omits the fractional-second component entirely when
        # microsecond == 0, so two RFC3339 strings that are both valid
        # can have different lengths and are not safe to compare
        # lexicographically.
        first = datetime.fromisoformat(utc_now().replace("Z", "+00:00"))
        second = datetime.fromisoformat(utc_now().replace("Z", "+00:00"))
        assert first <= second


# ---------------------------------------------------------------------------
# SystemClockProvider
# ---------------------------------------------------------------------------


class TestSystemClockProvider:
    def test_satisfies_the_clock_provider_protocol(self):
        provider: ClockProvider = SystemClockProvider()
        assert hasattr(provider, "now")
        assert hasattr(provider, "clock_context")

    def test_now_returns_rfc3339_utc(self):
        provider = SystemClockProvider()
        assert _RFC3339_UTC_RE.match(provider.now())

    def test_clock_context_reports_honest_unknown_synchronization(self):
        """A bare system clock has not been NTP-audited by this provider,
        so it must not fabricate a "synchronized" claim."""
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert ctx.synchronization_status == "unknown"

    def test_clock_context_reports_no_measured_offset_or_uncertainty(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert ctx.measured_offset is None
        assert ctx.uncertainty is None

    def test_clock_context_reports_system_clock_source_and_host_utc_domain(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert ctx.clock_source == "system"
        assert ctx.timestamp_domain == "host-utc"

    def test_clock_context_carries_through_source_kind_and_source_id(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="wazuh", source_id="alert-stream")
        assert ctx.source_kind == "wazuh"
        assert ctx.source_id == "alert-stream"

    def test_clock_context_defaults_observer_effect_ref_to_none(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert ctx.observer_effect_ref is None

    def test_clock_context_accepts_an_observer_effect_ref(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(
            source_kind="kali-session", source_id="sess-1", observer_effect_ref="disc-1"
        )
        assert ctx.observer_effect_ref == "disc-1"

    def test_clock_context_returns_a_clock_context_instance(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert isinstance(ctx, ClockContext)

    def test_measurement_time_matches_rfc3339_shape(self):
        provider = SystemClockProvider()
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert _RFC3339_UTC_RE.match(ctx.measurement_time)


# ---------------------------------------------------------------------------
# FixedClockProvider
# ---------------------------------------------------------------------------


class TestFixedClockProvider:
    def test_now_returns_the_injected_measurement_time(self):
        provider = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        assert provider.now() == "2026-01-01T00:00:00Z"

    def test_now_is_stable_across_repeated_calls(self):
        provider = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        assert provider.now() == provider.now() == provider.now()

    def test_clock_context_uses_the_injected_measurement_time(self):
        provider = FixedClockProvider(measurement_time="2026-06-15T12:00:00Z")
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert ctx.measurement_time == "2026-06-15T12:00:00Z"

    def test_clock_context_uses_injected_defaults(self):
        provider = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        ctx = provider.clock_context(source_kind="kali-session", source_id="sess-1")
        assert ctx.clock_source == "fixed"
        assert ctx.timestamp_domain == "host-utc"
        assert ctx.synchronization_status == "unknown"
        assert ctx.measured_offset is None
        assert ctx.uncertainty is None

    def test_clock_context_honors_overridden_fields(self):
        provider = FixedClockProvider(
            measurement_time="2026-01-01T00:00:00Z",
            clock_source="ntp",
            timestamp_domain="pcap-monotonic",
            synchronization_status="synchronized",
            measured_offset="3ms",
            uncertainty="1ms",
        )
        ctx = provider.clock_context(source_kind="pcap", source_id="eth0")
        assert ctx.clock_source == "ntp"
        assert ctx.timestamp_domain == "pcap-monotonic"
        assert ctx.synchronization_status == "synchronized"
        assert ctx.measured_offset == "3ms"
        assert ctx.uncertainty == "1ms"

    def test_two_providers_with_the_same_fields_are_equal(self):
        provider1 = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        provider2 = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        assert provider1 == provider2

    def test_is_frozen(self):
        import dataclasses

        provider = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        with pytest.raises(dataclasses.FrozenInstanceError):
            provider.measurement_time = "mutated"  # type: ignore[misc]

    def test_repeated_clock_context_calls_are_byte_identical(self):
        provider = FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        ctx1 = provider.clock_context(source_kind="k", source_id="s")
        ctx2 = provider.clock_context(source_kind="k", source_id="s")
        assert ctx1 == ctx2


# ---------------------------------------------------------------------------
# identity.py must never derive from the clock or ambient randomness
# ---------------------------------------------------------------------------


class TestIdentityModuleForbidsNondeterministicPrimitives:
    """OBS-002 preflight "Gotchas": identity must not be minted from wall
    clock, UUIDs, or ambient/library RNG. A stray ``datetime.now(UTC)``,
    ``uuid4()``, or ``random.random()`` call inside ``identity.py`` would
    make planned refs silently host- or run-dependent."""

    def test_identity_module_source_never_references_forbidden_tokens(self):
        source = inspect.getsource(identity_module)
        forbidden_substrings = [
            "uuid",
            "random.",
            "import random",
            "time.time",
            "datetime.now",
            "datetime.utcnow",
            " hash(",
            "(hash(",
        ]
        for token in forbidden_substrings:
            assert token not in source, f"forbidden nondeterministic token found in identity.py: {token!r}"

    def test_identity_module_does_not_import_uuid_or_random(self):
        assert not hasattr(identity_module, "uuid")
        assert not hasattr(identity_module, "random")
