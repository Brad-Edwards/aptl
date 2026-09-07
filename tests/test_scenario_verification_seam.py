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

from dataclasses import replace
from importlib import metadata
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.validation.scenario_verification import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_MIN_CORE_RELEASE,
    EXTENSION_API_VERSION,
    BackendIdentity,
    PrerequisiteResult,
    PrerequisiteStatus,
    QualifiedTarget,
    ScenarioIdentity,
    VerificationCheck,
    VerificationContext,
    VerificationReport,
    VerificationStatus,
)
from aptl.validation import scenario_verification_discovery as discovery

SCENARIO = ScenarioIdentity(
    identity="techvault",
    content_digest="sha256:" + "a" * 64,
    source_kind="env-pack",
    version="0.1.0",
)
BACKEND = BackendIdentity(
    target_name="aptl",
    target_version="0.1.0",
    profile="full-remote-control-plane",
    provider="docker-compose",
    transport="docker-compose",
)
TARGET = QualifiedTarget(scenario=SCENARIO, backend=BACKEND)


def _context(*, deadline_monotonic: float = float("inf")) -> VerificationContext:
    return VerificationContext(
        run_id="run",
        attempt_id="attempt",
        scenario=SCENARIO,
        backend=BACKEND,
        deadline_monotonic=deadline_monotonic,
    )


class _Verifier(object):
    """A minimal conforming verifier, used only inside these tests."""

    def __init__(self, status=VerificationStatus.PASSED, **overrides):
        self.plugin_id = overrides.get("plugin_id", "test-verifier")
        self.extension_api_version = overrides.get(
            "extension_api_version", EXTENSION_API_VERSION
        )
        self.qualified_targets = overrides.get("qualified_targets", (TARGET,))
        self._status = status
        self._raises = overrides.get("raises", False)
        self._malformed = overrides.get("malformed", False)
        self._prerequisites = overrides.get(
            "prerequisites",
            (PrerequisiteResult("stack-ready", PrerequisiteStatus.SATISFIED),),
        )
        self._checks = overrides.get(
            "checks", (VerificationCheck("detection", status),)
        )
        self._diagnostics = overrides.get("diagnostics", ())
        self.calls = 0

    def run(self, context):
        self.calls += 1
        if self._raises:
            raise RuntimeError("credential=hunter2 leaked from a broken plugin")
        if self._malformed:
            return {"status": "passed"}
        return VerificationReport(
            status=self._status,
            scenario=context.scenario,
            backend=context.backend,
            run_id=context.run_id,
            attempt_id=context.attempt_id,
            plugin_id="self-reported-and-untrusted",
            distribution="self-reported-and-untrusted",
            prerequisites=self._prerequisites,
            checks=self._checks,
            diagnostics=self._diagnostics,
        )


def _install(monkeypatch, *verifiers):
    """Point discovery at the given verifiers as if they were installed."""

    class _Dist:
        def __init__(self, name):
            self.name = name
            self.version = "9.9.9"

    class _EP:
        def __init__(self, verifier, index):
            self.name = "techvault.aptl"
            self.dist = _Dist(f"aptl-verifier-{index}")
            self._verifier = verifier
            self.loaded = False

        def load(self):
            self.loaded = True
            if isinstance(self._verifier, Exception):
                raise self._verifier
            return self._verifier

    monkeypatch.setattr(
        discovery,
        "_entry_points",
        lambda: [_EP(v, i) for i, v in enumerate(verifiers)],
    )


class _EntryPoint:
    """Entry-point double that records whether discovery executed its target."""

    def __init__(self, name: str, target: object) -> None:
        self.name = name
        self.dist = SimpleNamespace(name="test-distribution", version="1.2.3")
        self.target = target
        self.loaded = False

    def load(self) -> object:
        self.loaded = True
        if isinstance(self.target, BaseException):
            raise self.target
        return self.target


def _install_entry_points(monkeypatch, *entry_points: _EntryPoint) -> None:
    monkeypatch.setattr(discovery, "_entry_points", lambda: list(entry_points))


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
    assert "no compatible scenario verifier" in report.diagnostics[0]


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


def test_unrelated_entry_points_are_filtered_before_loading(monkeypatch):
    """Installed code outside the exact scenario/backend family is not executed."""

    unrelated = _EntryPoint("other-scenario.aptl", RuntimeError("must not load"))
    exact = _EntryPoint("techvault.aptl", _Verifier())
    _install_entry_points(monkeypatch, unrelated, exact)

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.PASSED
    assert unrelated.loaded is False
    assert exact.loaded is True


@pytest.mark.parametrize(
    ("metadata_name", "metadata_value"),
    [
        ("qualified_targets", ()),
        ("qualified_targets", [TARGET]),
        ("qualified_targets", (TARGET, TARGET)),
        ("qualified_targets", ("techvault.aptl",)),
        (
            "qualified_targets",
            (replace(TARGET, scenario=replace(SCENARIO, content_digest="any")),),
        ),
        (
            "qualified_targets",
            (replace(TARGET, scenario=replace(SCENARIO, identity="not a safe id")),),
        ),
        ("plugin_id", "not a bounded plugin id"),
    ],
)
def test_malformed_or_wildcard_metadata_blocks(
    monkeypatch, metadata_name, metadata_value
):
    """An omitted or unqualified declaration cannot silently claim future inputs."""

    _install(monkeypatch, _Verifier(**{metadata_name: metadata_value}))

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "metadata" in report.diagnostics[0]


@pytest.mark.parametrize(
    "target",
    [
        replace(TARGET, scenario=replace(SCENARIO, source_kind="project-tree")),
        replace(TARGET, scenario=replace(SCENARIO, version="0.0.9")),
        replace(TARGET, backend=replace(BACKEND, target_version="0.0.9")),
        replace(TARGET, backend=replace(BACKEND, provider="other-provider")),
        replace(TARGET, backend=replace(BACKEND, transport="ssh-compose")),
        replace(TARGET, backend=replace(BACKEND, profile="provisioning-only")),
    ],
)
def test_every_compatibility_dimension_is_matched_exactly(monkeypatch, target):
    _install(monkeypatch, _Verifier(qualified_targets=(target,)))

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "no compatible scenario verifier" in report.diagnostics[0]


def test_pinned_content_digest_must_match_the_admitted_scenario(monkeypatch):
    """Same name, different content, is not the scenario the plugin was written for."""

    _install(
        monkeypatch,
        _Verifier(
            qualified_targets=(
                replace(
                    TARGET,
                    scenario=replace(SCENARIO, content_digest="sha256:" + "b" * 64),
                ),
            )
        ),
    )
    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "pinned to different scenario content" in report.diagnostics[0]


def test_an_unqualified_combination_of_qualified_declarations_blocks(monkeypatch):
    """Qualification is atomic: a pair is admitted, never a dimension.

    This is what parallel version and digest lists could not express. A plugin
    that qualified release 0.1.0 at digest A and release 0.2.0 at digest B has
    said nothing about 0.1.0 at digest B, and running against that combination
    would be running against content no release ever qualified.
    """

    release_a = replace(TARGET, scenario=replace(SCENARIO, version="0.1.0"))
    release_b = replace(
        TARGET,
        scenario=replace(
            SCENARIO, version="0.2.0", content_digest="sha256:" + "b" * 64
        ),
    )
    _install(monkeypatch, _Verifier(qualified_targets=(release_a, release_b)))

    # The cross combination: release A's version with release B's content.
    unqualified = replace(
        _context(),
        scenario=replace(
            SCENARIO, version="0.1.0", content_digest="sha256:" + "b" * 64
        ),
    )
    report = discovery.verify_scenario(unqualified)

    assert report.status is VerificationStatus.BLOCKED
    assert "pinned to different scenario content" in report.diagnostics[0]

    # Both declared pairs themselves still run.
    for qualified in (release_a, release_b):
        admitted = replace(
            _context(), scenario=qualified.scenario, backend=qualified.backend
        )
        assert discovery.verify_scenario(admitted).status is VerificationStatus.PASSED


@pytest.mark.parametrize(
    "target",
    [
        QualifiedTarget(scenario=object(), backend=BACKEND),
        QualifiedTarget(scenario=SCENARIO, backend=object()),
        QualifiedTarget(scenario=SCENARIO, backend=["unhashable"]),
    ],
)
def test_a_malformed_qualified_target_member_blocks(monkeypatch, target):
    """A wrong member type must block, not raise through the gate.

    ``QualifiedTarget`` is an ordinary dataclass, so a plugin can put anything
    in it. Reading a wrong type raises AttributeError and hashing an unhashable
    one raises TypeError; discovery catches neither, so without a type check the
    promised terminal blocked report becomes an exception escaping
    ``verify_scenario``.
    """

    _install(monkeypatch, _Verifier(qualified_targets=(target,)))

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "metadata" in report.diagnostics[0]


def test_an_unnamed_identity_dimension_still_blocks(monkeypatch):
    """Fail closed when a mismatch has no name yet.

    The refusal reason enumerates the identity fields by hand, so an identity
    that gains a field would leave a pair that is unequal while no named
    dimension disagrees. Discovery must still refuse: the alternative is
    indexing an empty reason list, which raises through the gate rather than
    blocking it.
    """

    _install(monkeypatch, _Verifier())
    monkeypatch.setattr(discovery, "_mismatched_dimensions", lambda *_a: ())
    monkeypatch.setattr(
        discovery, "QualifiedTarget", lambda **_k: object()
    )

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "is not qualified for this range" in report.diagnostics[0]


def test_a_second_qualified_backend_needs_no_core_change(monkeypatch):
    """Extensibility: another qualified transport is a plugin declaration."""

    ssh_backend = replace(BACKEND, provider="ssh-compose", transport="ssh-compose")
    _install(
        monkeypatch,
        _Verifier(
            qualified_targets=(TARGET, replace(TARGET, backend=ssh_backend)),
        ),
    )

    report = discovery.verify_scenario(replace(_context(), backend=ssh_backend))

    assert report.status is VerificationStatus.PASSED


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


def test_an_internally_inconsistent_report_blocks(monkeypatch):
    """A plugin cannot claim passed while returning a failed semantic check."""

    _install(
        monkeypatch,
        _Verifier(
            status=VerificationStatus.PASSED,
            checks=(VerificationCheck("detection", VerificationStatus.FAILED),),
        ),
    )

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "malformed report" in report.diagnostics[0]


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "prerequisites": (
                PrerequisiteResult("stack-ready", PrerequisiteStatus.SATISFIED),
                PrerequisiteResult("stack-ready", PrerequisiteStatus.SATISFIED),
            )
        },
        {
            "checks": (
                VerificationCheck("detection", VerificationStatus.PASSED),
                VerificationCheck("detection", VerificationStatus.PASSED),
            )
        },
    ],
)
def test_duplicate_report_member_ids_are_malformed(monkeypatch, overrides):
    _install(monkeypatch, _Verifier(**overrides))

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "malformed report" in report.diagnostics[0]


def test_an_unmet_prerequisite_cannot_be_reported_as_passed(monkeypatch):
    _install(
        monkeypatch,
        _Verifier(
            prerequisites=(
                PrerequisiteResult("stack-ready", PrerequisiteStatus.UNSATISFIED),
            ),
        ),
    )

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "malformed report" in report.diagnostics[0]


def test_an_elapsed_deadline_blocks_without_running_the_plugin(monkeypatch):
    verifier = _Verifier()
    _install(monkeypatch, verifier)
    monkeypatch.setattr(discovery, "monotonic", lambda: 10_001.0)

    report = discovery.verify_scenario(_context(deadline_monotonic=10_000.0))

    assert report.status is VerificationStatus.BLOCKED
    assert "deadline" in report.diagnostics[0]
    assert verifier.calls == 0


@pytest.mark.parametrize(
    "context",
    [
        replace(_context(), run_id="../run"),
        replace(_context(), scenario=replace(SCENARIO, identity="not a safe id")),
        replace(_context(), scenario=replace(SCENARIO, content_digest="")),
        replace(_context(), backend=replace(BACKEND, transport="")),
    ],
)
def test_invalid_context_blocks_before_loading_installed_code(monkeypatch, context):
    entry_point = _EntryPoint("techvault.aptl", RuntimeError("must not load"))
    _install_entry_points(monkeypatch, entry_point)

    report = discovery.verify_scenario(context)

    assert report.status is VerificationStatus.BLOCKED
    assert "context" in report.diagnostics[0]
    assert entry_point.loaded is False


def test_plugin_diagnostics_are_redacted_before_projection(monkeypatch):
    _install(
        monkeypatch,
        _Verifier(
            status=VerificationStatus.BLOCKED,
            checks=(),
            diagnostics=("credential=hunter2 unavailable",),
        ),
    )

    report = discovery.verify_scenario(_context())

    assert report.status is VerificationStatus.BLOCKED
    assert "hunter2" not in report.diagnostics[0]


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
    assert report.entry_point == "techvault.aptl"


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
    """ "Core ships zero adapters" has to be checkable, not just asserted.

    The TechVault verifier lives in this repository for now, but it builds and
    installs as its own distribution. If it were ever folded into ``aptl-labs``,
    every scenario would silently gain a verifier nobody installed and the
    blocked outcome would stop meaning anything — so the distribution boundary is
    the thing worth testing, not the file layout.
    """

    import tomllib

    root = Path(__file__).resolve().parents[1]
    core = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    plugin = tomllib.loads(
        (root / "plugins/aptl-techvault-verifier/pyproject.toml").read_text(
            encoding="utf-8"
        )
    )

    assert core["project"]["name"] == "aptl-labs"
    assert "aptl.scenario_verifiers" not in core["project"].get("entry-points", {})
    assert plugin["project"]["name"] == "aptl-techvault-verifier"
    assert plugin["project"]["entry-points"][ENTRY_POINT_GROUP] == {
        "techvault.aptl": "aptl_techvault_verifier:verifier"
    }
    assert plugin["project"]["entry-points"]["aptl.participant_mcp_smoke_plans"] == {
        "guided-purple.techvault-attacker-target": (
            "aptl_techvault_verifier.participant_smoke:PARTICIPANT_SMOKE_OPERATIONS"
        )
    }


def test_the_plugin_floor_names_the_release_that_carries_its_contract():
    """A dependency floor below the contract is a broken install, not a refusal.

    The plugin imports types this extension API introduced. Admitting an earlier
    released core means pip can install the pair, and then the entry point fails
    at *import* -- before the version admission that exists to refuse exactly
    this. So the floor must be the first release carrying the API, which is not
    the same as the newest release: this repository's source still builds as the
    already-published 5.2.0 while the API moved on after it.
    """

    import tomllib

    root = Path(__file__).resolve().parents[1]
    plugin = tomllib.loads(
        (root / "plugins/aptl-techvault-verifier/pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    released = json.loads(
        (root / ".release-please-manifest.json").read_text(encoding="utf-8")
    )["."]

    assert plugin["project"]["dependencies"] == [
        f"aptl-labs>={EXTENSION_API_MIN_CORE_RELEASE},<6"
    ]
    # And the recorded first-carrying release is not one that shipped before the
    # current API existed. Equality is the post-release steady state; anything
    # lower means the floor admits a core without the contract.
    assert _version(EXTENSION_API_MIN_CORE_RELEASE) >= _version(released)


def _version(value: str) -> tuple[int, ...]:
    """Return a comparable release tuple for a plain ``x.y.z`` version."""

    return tuple(int(part) for part in value.split("."))


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


def test_core_source_contains_no_known_verification_answer_keys():
    """The wheel bundles all of ``src``, so ownership must cover the whole tree."""

    root = Path(__file__).resolve().parent.parent / "src" / "aptl"
    markers = (
        "aptl-live-gate-invalid",
        "_RECENT_SSH_ALERT_QUERY",
        "mcp.red.ssh-authentication-attack",
        "_PLUGIN_CHECK_CATEGORY",
        "_is_correlated_wazuh_alert",
        "kali nmap + failed-ssh-auth",
    )
    offenders = {
        str(path.relative_to(root)): [marker for marker in markers if marker in text]
        for path in root.rglob("*.py")
        if (text := path.read_text(encoding="utf-8"))
        and any(marker in text for marker in markers)
    }

    assert not offenders, f"verification answer keys remain in core: {offenders}"
