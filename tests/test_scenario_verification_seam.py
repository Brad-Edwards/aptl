"""The plugin seam is fail-closed and ships no adapters (#878).

The seam's value is entirely in what it refuses. If an uninstalled, duplicated,
mismatched, or broken verifier produced anything other than ``blocked``, an
unverified range would read as a verified one — which is worse than no seam at
all, because it looks like evidence.

These tests drive the real discovery path with real entry points rather than
asserting on shapes, because the failure mode being guarded is precisely that
discovery silently finds nothing and the caller treats that as fine.
"""

from __future__ import annotations

from importlib import metadata

import pytest

from aptl.validation.scenario_verification import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    BackendIdentity,
    PrerequisiteResult,
    PrerequisiteStatus,
    ScenarioIdentity,
    VerificationCheck,
    VerificationContext,
    VerificationReport,
    VerificationStatus,
)
from aptl.validation import scenario_verification_discovery as discovery

SCENARIO = ScenarioIdentity(
    identity="techvault-operational", content_digest="sha256:" + "a" * 64
)
BACKEND = BackendIdentity(
    target_name="aptl", target_version="1", profile="full-remote-control-plane"
)


def _context() -> VerificationContext:
    return VerificationContext(
        run_id="run", attempt_id="attempt", scenario=SCENARIO, backend=BACKEND
    )


class _Verifier(object):
    """A minimal conforming verifier, used only inside these tests."""

    def __init__(self, status=VerificationStatus.PASSED, **overrides):
        self.plugin_id = overrides.get("plugin_id", "test-verifier")
        self.extension_api_version = overrides.get(
            "extension_api_version", EXTENSION_API_VERSION
        )
        self.scenario_identity = overrides.get("scenario_identity", SCENARIO.identity)
        self.scenario_content_digests = overrides.get("scenario_content_digests", ())
        self.backend_target_name = overrides.get("backend_target_name", "aptl")
        self.backend_profiles = overrides.get("backend_profiles", ())
        self._status = status
        self._raises = overrides.get("raises", False)
        self._malformed = overrides.get("malformed", False)

    def run(self, context):
        if self._raises:
            raise RuntimeError("credential=hunter2 leaked from a broken plugin")
        if self._malformed:
            return {"status": "passed"}
        return VerificationReport(
            status=self._status,
            scenario=context.scenario,
            backend=context.backend,
            plugin_id="self-reported-and-untrusted",
            distribution="self-reported-and-untrusted",
            prerequisites=(
                PrerequisiteResult("stack-ready", PrerequisiteStatus.SATISFIED),
            ),
            checks=(VerificationCheck("detection", self._status),),
        )


def _install(monkeypatch, *verifiers):
    """Point discovery at the given verifiers as if they were installed."""

    class _Dist:
        def __init__(self, name):
            self.name = name
            self.version = "9.9.9"

    class _EP:
        def __init__(self, verifier, index):
            self.name = f"verifier-{index}"
            self.dist = _Dist(f"aptl-verifier-{index}")
            self._verifier = verifier

        def load(self):
            if isinstance(self._verifier, Exception):
                raise self._verifier
            return self._verifier

    monkeypatch.setattr(
        discovery,
        "_entry_points",
        lambda: [_EP(v, i) for i, v in enumerate(verifiers)],
    )


def test_core_registers_no_scenario_verifier():
    """The whole rule of the seam: core ships the framework and zero adapters.

    Not a fallback, not an example, not a test-only adapter. If APTL's own
    distribution ever registers one, every scenario silently gains a verifier it
    did not install, and "blocked" stops meaning anything.
    """

    aptl_entry_points = [
        entry_point
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP)
        if getattr(entry_point, "dist", None) is not None
        and entry_point.dist.name in {"aptl", "aptl-labs"}
    ]

    assert aptl_entry_points == []


def test_no_installed_verifier_blocks(monkeypatch):
    """An unverified range must not read as a verified one."""

    _install(monkeypatch)
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert report.status is not VerificationStatus.PASSED
    assert "no scenario verifier is installed" in report.diagnostics[0]


def test_two_matching_verifiers_block_rather_than_picking_one(monkeypatch):
    """Choosing would make the verdict depend on installation order."""

    _install(monkeypatch, _Verifier(), _Verifier(plugin_id="other-verifier"))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "several scenario verifiers" in report.diagnostics[0]


def test_extension_api_mismatch_blocks(monkeypatch):
    """A plugin built against a different contract is refused, not run."""

    _install(monkeypatch, _Verifier(extension_api_version="0"))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED


def test_pinned_content_digest_must_match_the_admitted_scenario(monkeypatch):
    """Same name, different content, is not the scenario the plugin was written for."""

    _install(
        monkeypatch,
        _Verifier(scenario_content_digests=("sha256:" + "b" * 64,)),
    )
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "pinned to different scenario content" in report.diagnostics[0]


def test_backend_profile_mismatch_blocks(monkeypatch):
    """A verifier written for another profile cannot judge this range."""

    _install(monkeypatch, _Verifier(backend_profiles=("provisioning-only",)))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED


def test_a_plugin_that_raises_blocks_without_leaking_the_exception(monkeypatch):
    """A broken plugin is not a broken range, and its text is not report text."""

    _install(monkeypatch, _Verifier(raises=True))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    joined = " ".join(report.diagnostics)
    assert "hunter2" not in joined
    assert "failed while running" in joined


def test_a_plugin_that_fails_to_import_blocks(monkeypatch):
    """Import failure is absence, reported as such rather than raised."""

    _install(monkeypatch, ImportError("no module named nope"))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED


def test_a_malformed_report_blocks(monkeypatch):
    """Returning something report-shaped is not returning a report."""

    _install(monkeypatch, _Verifier(malformed=True))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "malformed report" in report.diagnostics[0]


def test_a_single_compatible_verifier_runs_and_its_provenance_is_host_observed(
    monkeypatch,
):
    """The happy path, and the plugin does not get to author its own provenance."""

    _install(monkeypatch, _Verifier())
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.PASSED
    assert report.checks[0].check_id == "detection"
    # Reported identity comes from installed metadata, not the plugin's claim.
    assert report.distribution == "aptl-verifier-0"
    assert report.distribution_version == "9.9.9"
    assert report.distribution != "self-reported-and-untrusted"
    assert report.plugin_id == "test-verifier"


def test_a_failing_verifier_reports_failed_not_blocked(monkeypatch):
    """A real disproof must stay distinguishable from an unrunnable check."""

    _install(monkeypatch, _Verifier(status=VerificationStatus.FAILED))
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.FAILED
    assert report.failures()


def test_the_report_has_no_boolean_named_passed():
    """The redactor treats keys containing 'pass' as credential-shaped.

    A boolean named ``passed`` would be redacted out of persisted evidence, and
    could contradict ``status`` besides. ``status`` is the only outcome.
    """

    fields = set(VerificationReport.__dataclass_fields__)

    assert "passed" not in fields
    assert "status" in fields


@pytest.mark.parametrize(
    "status", [VerificationStatus.PASSED, VerificationStatus.FAILED]
)
def test_blocked_is_distinct_from_both_other_outcomes(status):
    """Three states, never collapsed to two."""

    assert VerificationStatus.BLOCKED is not status


def test_the_techvault_verifier_is_a_separate_distribution():
    """"Core ships zero adapters" has to be checkable, not just asserted.

    The TechVault verifier lives in this repository for now, but it builds and
    installs as its own distribution. If it were ever folded into ``aptl-labs``,
    every scenario would silently gain a verifier nobody installed and the
    blocked outcome would stop meaning anything — so the distribution boundary is
    the thing worth testing, not the file layout.
    """

    from importlib import metadata

    entry_points = {
        entry_point.name: entry_point
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP)
    }
    techvault = entry_points.get("techvault-operational")
    if techvault is None:
        pytest.skip("aptl-techvault-verifier is not installed in this environment")

    assert techvault.dist is not None
    assert techvault.dist.name == "aptl-techvault-verifier"
    assert techvault.dist.name not in {"aptl", "aptl-labs"}


def test_core_holds_no_techvault_answer_key_behind_the_seam():
    """The point of extracting (#879): core must not know who the attacker is.

    The seam and the operations surface it hands a plugin are both
    scenario-neutral by construction. If a scenario constant -- the attacker
    node, the defensive stack's product names -- appeared in either, the plugin
    quadrant would have leaked back into core, and a second scenario would need
    core edits rather than a second installed plugin. The in-core semantic module
    that used to hold these answer keys is now deleted; the TechVault knowledge
    lives only in aptl-techvault-verifier.
    """

    import re
    from pathlib import Path

    seam_modules = (
        "scenario_verification.py",
        "scenario_verification_discovery.py",
        "_live_gate_operations.py",
    )
    answer_keys = re.compile(r"aptl-kali|wazuh|suricata|thehive|misp", re.I)
    root = Path(__file__).resolve().parent.parent / "src" / "aptl" / "validation"

    offenders = {
        name: sorted(set(answer_keys.findall((root / name).read_text())))
        for name in seam_modules
        if answer_keys.search((root / name).read_text())
    }

    assert not offenders, f"scenario knowledge leaked into the seam: {offenders}"

    # And the retired in-core scenario module is gone, not merely bypassed.
    assert not (root / "_live_gate_semantic.py").exists()
