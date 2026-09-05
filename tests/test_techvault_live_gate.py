"""Live validation gate tests (SCN-010F / issue #323).

The fast unit suite drives the scenario-generic orchestrator composed in
``aptl.validation.techvault_live_gate`` and every check branch in
``aptl.validation._live_gate_checks`` without a live lab, by monkeypatching the
lifecycle / snapshot / collector entry points. The destructive end-to-end live
boot is the integration-marked, ``APTL_LIVE_GATE``-gated test at the bottom.
"""

import functools
import json
import os
import tempfile
import types
from pathlib import Path

import pytest

from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult, StartupOutcome
from aptl.core.runstore import LocalRunStore
from aptl.validation.scenario_verification import (
    VerificationReport,
    VerificationStatus,
)
from aptl.validation import _live_gate_checks as lgc
from aptl.validation import techvault_live_gate as tlg
from aptl.validation import _live_gate_probes as lgp
from aptl.validation import _live_gate_telemetry as lgt
from aptl.validation.techvault_live_gate import (
    CATEGORY_RAES_SPECIFICATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_EVIDENCE_CAPTURE,
    CATEGORY_KALI_REACHABILITY,
    CHECK_CATEGORY,
    FAILURE_CATEGORIES,
    LiveGateCheck,
    LiveGateOptions,
    LiveGateReport,
    LiveGateState,
    validate_live_deployment,
)
from tests.helpers import techvault_scenario_bundle

PROJECT_ROOT = Path(__file__).resolve().parents[1]
# The default TechVault scenario now ships as the bundled env-pack (#875); stage
# it once for the module and drive the live gate from its validated SDL.
BUNDLE = techvault_scenario_bundle(Path(tempfile.mkdtemp(prefix="aptl-live-gate-")))
SCENARIO = BUNDLE.sdl_path


# --------------------------------------------------------------------------- #
# Fakes.
# --------------------------------------------------------------------------- #


class _Sev:
    def __init__(self, value):
        self.value = value


class _Diag:
    def __init__(self, severity="error", code="x", message="m"):
        self.severity = _Sev(severity)
        self.code = code
        self.message = message


class _Realization:
    def __init__(self, nodes, profiles, diagnostics=()):
        self._details = {"nodes": list(nodes), "profiles": sorted(profiles)}
        self.nodes = tuple(nodes)
        self.profiles = frozenset(profiles)
        self.diagnostics = tuple(diagnostics)
        self.spec = object()

    def details(self):
        return self._details

    def deployment_spec(self, profiles):
        assert profiles == sorted(self.profiles)
        return self.spec


class _Manager:
    def __init__(self, target):
        self.target = target

    def plan(self, scenario, artifact_availability=None):
        return types.SimpleNamespace(provisioning=object())


class _Snapshot:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data


class _Backend:
    def __init__(self, returncode=0, stdout=""):
        self._returncode = returncode
        self._stdout = stdout
        self.calls = []

    def container_exec(self, name, cmd, timeout=None):
        self.calls.append((name, cmd))
        return types.SimpleNamespace(returncode=self._returncode, stdout=self._stdout)


def _config():
    return AptlConfig(lab={"name": "techvault"})


def _node(name, profiles, aliases=None, declared_health=None):
    return {
        "name": name,
        "aliases": aliases or [name],
        "profiles": list(profiles),
        "declared_health": declared_health,
    }


def _container(
    name,
    *,
    status="Up 2 minutes (healthy)",
    health="healthy",
    networks=None,
    restart_policy="",
):
    return {
        "name": name,
        "status": status,
        "health": health,
        "networks": networks or {},
        "restart_policy": restart_policy,
    }


def _wire_boot(
    monkeypatch, *, outcome=StartupOutcome.READY, realization=None, snapshot=None
):
    """Monkeypatch the boot path's leaf dependencies for the happy path."""
    realization = realization or _Realization(
        [_node("webapp", ["dmz"])], ["dmz", "soc"]
    )
    snapshot = snapshot or {
        "containers": [
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"})
        ]
    }
    # The realization + boot probes moved to `_live_gate_probes` (lgp); their
    # leaf deps are looked up there. `select_backend_profiles` is still called
    # directly in `check_raes_driven_boot` (lgc), so it stays patched on lgc.
    monkeypatch.setattr(lgp, "get_backend", lambda config, project_dir: _Backend())
    monkeypatch.setattr(lgp, "create_aptl_runtime_target", lambda **k: object())
    monkeypatch.setattr(lgp, "RuntimeManager", _Manager)
    monkeypatch.setattr(lgp, "interpret_provisioning_plan", lambda **k: realization)
    monkeypatch.setattr(
        lgc, "select_backend_profiles", lambda config, profiles: ["dmz", "soc"]
    )
    monkeypatch.setattr(
        lgp,
        "clean_boot_lab",
        lambda p, *, remove_volumes=True, scenario_path=None: LabResult(
            success=True, outcome=outcome
        ),
    )
    monkeypatch.setattr(
        lgp, "capture_snapshot", lambda config_dir, backend: _Snapshot(snapshot)
    )


# --------------------------------------------------------------------------- #
# Report / category taxonomy.
# --------------------------------------------------------------------------- #


def test_check_category_map_covers_every_check_with_valid_categories():
    assert set(CHECK_CATEGORY).issuperset(
        {
            "static_prerequisite",
            "boot_inputs_match_public_path",
            "raes_driven_boot",
            "defensive_stack_readiness",
            "kali_reachability",
            "telemetry_evidence_path",
            "run_archive_manifest",
            "scenario_variation",
        }
    )
    assert all(cat in FAILURE_CATEGORIES for cat in CHECK_CATEGORY.values())


def test_live_gate_report_passed_failures_categories_and_render():
    ok = LiveGateCheck("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True)
    bad = LiveGateCheck(
        "kali_reachability", CATEGORY_KALI_REACHABILITY, False, ("unreachable",)
    )
    report = LiveGateReport("scn", "provisioning-only", "rid", (ok, bad))
    assert isinstance(report, VerificationReport)
    assert all(type(check).__name__ == "VerificationCheck" for check in report.checks)
    assert report.passed is False
    assert tuple(check.check_id for check in report.failures()) == (
        "kali_reachability",
    )
    assert report.failure_categories() == (CATEGORY_KALI_REACHABILITY,)
    text = report.render()
    assert "FAIL" in text
    assert "unreachable" in text
    assert "failing layers" in text
    assert LiveGateReport("s", "p", "r", (ok,)).passed is True


def test_live_gate_preserves_blocked_as_a_distinct_terminal_status():
    blocked = LiveGateCheck(
        "scenario_verification",
        CATEGORY_EVIDENCE_CAPTURE,
        VerificationStatus.BLOCKED,
        ("no compatible verifier",),
    )
    report = LiveGateReport("scn", "profile", "rid", (blocked,))

    assert blocked.status is VerificationStatus.BLOCKED
    assert report.status is VerificationStatus.BLOCKED
    assert report.passed is False
    assert "BLOCKED" in report.render()


# --------------------------------------------------------------------------- #
# Orchestrator composition.
# --------------------------------------------------------------------------- #


def test_validate_live_deployment_composes_all_checks(monkeypatch):
    # Stubs use each check's EXACT keyword signature so a drift between the
    # orchestrator's call sites and the check signatures raises TypeError here
    # (the `*a, **k` shape would silently mask a missing kwarg — the live smoke
    # run caught exactly that for `check_scenario_variation(state=...)`).
    def static(scenario_path, *, project_dir, config, options):
        return object(), LiveGateCheck(
            "static_prerequisite", CATEGORY_RAES_SPECIFICATION, True
        )

    def inputs(scenario_path, *, project_dir, options):
        return LiveGateCheck(
            "boot_inputs_match_public_path", CATEGORY_BACKEND_INSTANTIATION, True
        )

    def boot(scenario, *, project_dir, config, options, state, scenario_path):
        assert scenario_path == SCENARIO
        return LiveGateCheck("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True)

    def readiness(*, state):
        return LiveGateCheck(
            "defensive_stack_readiness", CATEGORY_DEFENSIVE_STACK_READINESS, True
        )

    def semantic(ctx, state):
        # Semantic verification runs through the plugin seam now; the orchestrator
        # reaches it at one call site. Stub that site so this test stays about
        # composition, not discovery (the seam has its own tests).
        return [
            LiveGateCheck("kali_reachability", CATEGORY_KALI_REACHABILITY, True),
            LiveGateCheck("telemetry_evidence_path", CATEGORY_EVIDENCE_CAPTURE, True),
        ]

    def archive(
        scenario_path, *, project_dir, config, run_store, run_id, state, prior_checks
    ):
        return LiveGateCheck("run_archive_manifest", CATEGORY_EVIDENCE_CAPTURE, True)

    def variation(*, project_dir, config, state):
        return LiveGateCheck(
            "scenario_variation", CATEGORY_BACKEND_INTERPRETATION, True
        )

    def orchestration(*, project_dir, config, state):
        return LiveGateCheck(
            "runtime_orchestration_containment",
            CATEGORY_BACKEND_INSTANTIATION,
            True,
        )

    monkeypatch.setattr(lgc, "check_static_prerequisite", static)
    monkeypatch.setattr(lgc, "check_boot_inputs_match_public_path", inputs)
    monkeypatch.setattr(lgc, "check_raes_driven_boot", boot)
    monkeypatch.setattr(lgc, "check_defensive_stack_readiness", readiness)
    monkeypatch.setattr(lgc, "check_runtime_orchestration_containment", orchestration)
    monkeypatch.setattr(tlg, "_semantic_checks", semantic)
    monkeypatch.setattr(lgc, "check_run_archive_manifest", archive)
    monkeypatch.setattr(lgc, "check_scenario_variation", variation)
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config()
    )
    assert report.passed
    assert {c.name for c in report.checks} == {
        "run_id_input",
        "static_prerequisite",
        "boot_inputs_match_public_path",
        "raes_driven_boot",
        "defensive_stack_readiness",
        "kali_reachability",
        "telemetry_evidence_path",
        "runtime_orchestration_containment",
        "run_archive_manifest",
        "scenario_variation",
    }
    # F2 regression guard: the manifest (durable audit artifact) must be written
    # AFTER scenario_variation, so the persisted run archive reflects the
    # complete check set and cannot disagree with the returned report.
    names = [c.name for c in report.checks]
    assert names.index("scenario_variation") < names.index("run_archive_manifest")


def test_validate_live_deployment_short_circuits_on_static_failure(monkeypatch):
    monkeypatch.setattr(
        lgc,
        "check_static_prerequisite",
        lambda *a, **k: (
            None,
            LiveGateCheck(
                "static_prerequisite", CATEGORY_RAES_SPECIFICATION, False, ("bad",)
            ),
        ),
    )
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config()
    )
    assert not report.passed
    assert [c.name for c in report.checks] == ["run_id_input", "static_prerequisite"]


def test_validate_live_deployment_records_archive_on_boot_failure(monkeypatch):
    monkeypatch.setattr(
        lgc,
        "check_static_prerequisite",
        lambda *a, **k: (
            object(),
            LiveGateCheck("static_prerequisite", CATEGORY_RAES_SPECIFICATION, True),
        ),
    )
    monkeypatch.setattr(
        lgc,
        "check_raes_driven_boot",
        lambda *a, **k: LiveGateCheck(
            "raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, False, ("boom",)
        ),
    )
    archive_calls = []
    monkeypatch.setattr(
        lgc,
        "check_run_archive_manifest",
        lambda *a, **k: (
            archive_calls.append(1)
            or LiveGateCheck("run_archive_manifest", CATEGORY_EVIDENCE_CAPTURE, True)
        ),
    )
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config()
    )
    assert not report.passed
    assert [c.name for c in report.checks] == [
        "run_id_input",
        "static_prerequisite",
        "boot_inputs_match_public_path",
        "raes_driven_boot",
        "run_archive_manifest",
    ]
    assert archive_calls == [1]


# --------------------------------------------------------------------------- #
# 1. Static prerequisite.
# --------------------------------------------------------------------------- #


def test_check_static_prerequisite_passes_and_parses(monkeypatch):
    report = types.SimpleNamespace(passed=True, failures=lambda: ())
    monkeypatch.setattr(lgc, "validate_scenario", lambda *a, **k: report)
    monkeypatch.setattr(lgc, "parse_sdl_file", lambda path: "SCENARIO-OBJ")
    scenario, check = lgc.check_static_prerequisite(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions()
    )
    assert scenario == "SCENARIO-OBJ"
    assert check.passed
    assert check.category == CATEGORY_RAES_SPECIFICATION


def test_check_static_prerequisite_blocks_on_static_failure(monkeypatch):
    failing = LiveGateCheck("compile", "x", False, ("semantic error",))
    report = types.SimpleNamespace(passed=False, failures=lambda: (failing,))
    monkeypatch.setattr(lgc, "validate_scenario", lambda *a, **k: report)
    scenario, check = lgc.check_static_prerequisite(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions()
    )
    assert scenario is None
    assert not check.passed
    assert any("static gate failed" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# 2. RAES-driven boot.
# --------------------------------------------------------------------------- #


def test_check_raes_driven_boot_happy_populates_state(monkeypatch):
    _wire_boot(monkeypatch)
    state = LiveGateState()
    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(),
        state=state,
    )
    assert check.passed
    assert check.category == CATEGORY_BACKEND_INSTANTIATION
    assert state.realization_details["nodes"]
    assert state.selected_profiles == ["dmz", "soc"]
    assert state.deployment_spec is not None
    assert state.snapshot["containers"]


def test_runtime_orchestration_containment_uses_post_work_backend_attestation(
    monkeypatch,
):
    spec = object()
    backend = types.SimpleNamespace(
        verify_runtime_orchestration=lambda observed: (
            LabResult(success=True) if observed is spec else LabResult(success=False)
        )
    )
    monkeypatch.setattr(lgc, "get_backend", lambda *_args: backend)
    state = LiveGateState(deployment_spec=spec)

    check = lgc.check_runtime_orchestration_containment(
        project_dir=PROJECT_ROOT,
        config=_config(),
        state=state,
    )

    assert check.passed


def test_runtime_orchestration_containment_fails_closed(monkeypatch):
    backend = types.SimpleNamespace(
        verify_runtime_orchestration=lambda _spec: LabResult(
            success=False,
            error="Docker authority propagated to spawned child node/template.",
        )
    )
    monkeypatch.setattr(lgc, "get_backend", lambda *_args: backend)
    state = LiveGateState(deployment_spec=object())

    check = lgc.check_runtime_orchestration_containment(
        project_dir=PROJECT_ROOT,
        config=_config(),
        state=state,
    )

    assert not check.passed
    assert "spawned child" in check.diagnostics[0]


def test_check_raes_driven_boot_fails_on_interpretation_error(monkeypatch):
    bad = _Realization(
        [_node("webapp", ["dmz"])], ["dmz"], diagnostics=(_Diag("error"),)
    )
    _wire_boot(monkeypatch, realization=bad)
    state = LiveGateState()
    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(),
        state=state,
    )
    assert not check.passed
    assert check.category == CATEGORY_BACKEND_INTERPRETATION


def test_check_raes_driven_boot_fails_on_empty_realization(monkeypatch):
    _wire_boot(monkeypatch, realization=_Realization([], []))
    state = LiveGateState()
    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(),
        state=state,
    )
    assert not check.passed
    assert any("no RAES nodes" in d for d in check.diagnostics)


def test_check_raes_driven_boot_fails_on_boot_failed(monkeypatch):
    _wire_boot(monkeypatch, outcome=StartupOutcome.FAILED)
    state = LiveGateState()
    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(),
        state=state,
    )
    assert not check.passed
    assert check.category == CATEGORY_BACKEND_INSTANTIATION
    assert any("public lab start failed" in d for d in check.diagnostics)


def test_check_raes_driven_boot_skips_cleanup_and_reboot_when_requested(monkeypatch):
    boots = []
    _wire_boot(monkeypatch)
    monkeypatch.setattr(
        lgp,
        "clean_boot_lab",
        lambda *a, **k: (
            boots.append(1) or LabResult(success=True, outcome=StartupOutcome.READY)
        ),
    )
    state = LiveGateState()
    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(skip_clean_boot=True),
        state=state,
    )
    # Non-destructive: no clean boot (cleanup+reboot), but the running lab is
    # still snapshotted and the realization matrix is still computed.
    assert boots == []
    assert check.passed
    assert state.snapshot["containers"]


def test_check_raes_driven_boot_fails_when_clean_boot_fails(monkeypatch):
    """A failed clean boot (e.g. fatal cleanup) fails the gate, no snapshot."""
    _wire_boot(monkeypatch)
    monkeypatch.setattr(
        lgp,
        "clean_boot_lab",
        lambda *a, **k: LabResult(
            success=False,
            error="clean-state cleanup failed; lab not booted",
            outcome=StartupOutcome.FAILED,
        ),
    )
    state = LiveGateState()
    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(),
        state=state,
    )
    assert not check.passed
    assert check.category == CATEGORY_BACKEND_INSTANTIATION
    assert any("public lab start failed" in d for d in check.diagnostics)


def test_check_raes_driven_boot_passes_selected_scenario_to_public_start(monkeypatch):
    _wire_boot(monkeypatch)
    boots = []
    monkeypatch.setattr(
        lgp,
        "clean_boot_lab",
        lambda p, *, remove_volumes=True, scenario_path=None: (
            boots.append((p, scenario_path))
            or LabResult(success=True, outcome=StartupOutcome.READY)
        ),
    )
    state = LiveGateState()
    selected = PROJECT_ROOT / "scenarios" / "custom.sdl.yaml"

    check = lgc.check_raes_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(),
        state=state,
        scenario_path=selected,
    )

    assert check.passed
    assert boots == [(PROJECT_ROOT, selected)]


# --------------------------------------------------------------------------- #
# 2a. Boot-input / public-start-path agreement (F1 regression).
# --------------------------------------------------------------------------- #


def test_boot_inputs_pass_for_default_scenario_and_profile():
    check = lgc.check_boot_inputs_match_public_path(
        SCENARIO, project_dir=PROJECT_ROOT, options=LiveGateOptions()
    )
    assert check.passed
    assert check.category == CATEGORY_BACKEND_INSTANTIATION


def test_boot_inputs_pass_for_custom_scenario_when_profile_matches():
    other = PROJECT_ROOT / "scenarios" / "other.sdl.yaml"
    check = lgc.check_boot_inputs_match_public_path(
        other, project_dir=PROJECT_ROOT, options=LiveGateOptions()
    )
    assert check.passed


def test_boot_inputs_fail_for_mismatched_profile():
    check = lgc.check_boot_inputs_match_public_path(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        options=LiveGateOptions(profile="evaluation"),
    )
    assert not check.passed
    assert any("capability profile" in d for d in check.diagnostics)


def test_validate_live_deployment_short_circuits_on_profile_mismatch(monkeypatch):
    # Profile mismatch still fails loud before destructive boot; scenario
    # mismatch does not, because public start now accepts a selected scenario.
    monkeypatch.setattr(
        lgc,
        "check_static_prerequisite",
        lambda *a, **k: (
            object(),
            LiveGateCheck("static_prerequisite", CATEGORY_RAES_SPECIFICATION, True),
        ),
    )
    booted = []
    monkeypatch.setattr(
        lgc,
        "check_raes_driven_boot",
        lambda *a, **k: (
            booted.append(1)
            or LiveGateCheck("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True)
        ),
    )
    report = validate_live_deployment(
        PROJECT_ROOT / "scenarios" / "other.sdl.yaml",
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(profile="evaluation"),
    )
    assert not report.passed
    assert [c.name for c in report.checks] == [
        "run_id_input",
        "static_prerequisite",
        "boot_inputs_match_public_path",
    ]
    assert booted == []


# --------------------------------------------------------------------------- #
# 3. Defensive-stack readiness.
# --------------------------------------------------------------------------- #


def _readiness_state(nodes, containers, selected=None):
    state = LiveGateState()
    state.realization_details = {"nodes": nodes}
    state.snapshot = {"containers": containers}
    state.selected_profiles = selected or []
    return state


def test_readiness_passes_when_all_nodes_healthy():
    state = _readiness_state(
        [_node("webapp", ["dmz"]), _node("wazuh-manager", ["soc"])],
        [_container("aptl-webapp"), _container("aptl-wazuh-manager")],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert check.passed


def test_readiness_fails_on_missing_node_container():
    state = _readiness_state([_node("webapp", ["dmz"])], [_container("aptl-other")])
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed
    assert any("no live container" in d for d in check.diagnostics)


def test_readiness_fails_on_unhealthy_node_container():
    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [_container("aptl-webapp", status="Up 1m (unhealthy)", health="unhealthy")],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed
    assert any("unhealthy" in d for d in check.diagnostics)


def test_readiness_fails_on_stopped_node_container():
    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [_container("aptl-webapp", status="Exited (1) 5s ago", health="")],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed
    assert any("not running" in d for d in check.diagnostics)


def test_readiness_fails_on_a_container_no_declared_node_accounts_for():
    """ADR-048 parity runs both ways: nothing may run that nothing declares.

    This previously asserted the opposite -- an undeclared container was
    tolerated and merely logged, so range content could drift away from the
    scenario without ever failing a run. The rule is now absolute and carries no
    allowance list, because an exception for "infrastructure" is precisely the
    silent approximation SEM-218 I2 forbids.

    The observability collector here is a real example: it is a genuine part of
    the range, and the correct response is for the scenario to declare it, which
    the default TechVault scenario now does.
    """

    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [
            _container("aptl-webapp"),
            _container("aptl-otel-collector"),
        ],
    )
    check = lgc.check_defensive_stack_readiness(state=state)

    assert not check.passed
    assert any("aptl-otel-collector" in d for d in check.diagnostics)
    assert any("no declared node accounts for it" in d for d in check.diagnostics)


def test_readiness_fails_an_exited_run_to_completion_container():
    """A restart:"no" container that exited is a readiness failure, no exemption.

    ADR-088 (issue #889) retired APTL's only run-to-completion service (the
    Cortex Elasticsearch index initializer, replaced by the native
    service-search-index-schema materializer): every declared node must now be
    running, restart policy notwithstanding.
    """

    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [
            _container(
                "aptl-webapp",
                status="Exited (0) 5 minutes ago",
                health="",
                restart_policy="no",
            ),
        ],
    )
    check = lgc.check_defensive_stack_readiness(state=state)

    assert not check.passed


def test_readiness_still_fails_a_service_that_exited():
    """A container configured to stay up (unless-stopped) that has exited fails."""

    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [
            _container(
                "aptl-webapp",
                status="Exited (0) 1 minute ago",
                health="",
                restart_policy="unless-stopped",
            ),
        ],
    )
    check = lgc.check_defensive_stack_readiness(state=state)

    assert not check.passed


def test_readiness_passes_when_every_container_maps_to_a_declared_node():
    """The other side of the same rule: full parity is what passing means."""

    state = _readiness_state(
        [_node("webapp", ["dmz"]), _node("otel-collector", ["dmz"])],
        [_container("aptl-webapp"), _container("aptl-otel-collector")],
    )
    check = lgc.check_defensive_stack_readiness(state=state)

    assert check.passed, check.diagnostics


def test_readiness_skips_nodes_in_unselected_profiles():
    # A declared node whose profile is not in the started subset (e.g. mail when
    # the mail profile is disabled) is correctly absent and must not fail.
    state = _readiness_state(
        [_node("webapp", ["enterprise"]), _node("mailserver", ["mail"])],
        [_container("aptl-webapp")],
        selected=["enterprise", "soc"],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert check.passed


def test_readiness_requires_selected_node_even_when_filtering():
    state = _readiness_state(
        [_node("webapp", ["enterprise"])],
        [_container("aptl-other")],
        selected=["enterprise"],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed
    assert any("no live container" in d for d in check.diagnostics)


def test_readiness_fails_on_empty_snapshot():
    state = _readiness_state([_node("webapp", ["dmz"])], [])
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed


def test_readiness_passes_when_declared_health_met():
    state = _readiness_state(
        [_node("webapp", ["dmz"], declared_health="healthy")],
        [_container("aptl-webapp")],  # default container health == "healthy"
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert check.passed


def test_readiness_fails_when_one_node_reports_unhealthy_alongside_a_healthy_node():
    # Health is observed, never declared (raes 0.21.0 removed authored
    # `runtime.health`, RAES #761), so there is no declared expectation left to
    # mismatch against. The container's own healthcheck is the expectation
    # instead: once it reports a health state at all, that state must be
    # "healthy". A sibling node with no healthcheck (tolerated on its own, see
    # test_readiness_tolerates_unreported_health_when_node_declares_none) must
    # not mask a node whose own healthcheck is reporting non-healthy.
    state = _readiness_state(
        [_node("webapp", ["dmz"]), _node("wazuh-manager", ["soc"])],
        [
            _container("aptl-webapp", status="Up 2 minutes", health=""),
            _container(
                "aptl-wazuh-manager",
                status="Up 1 minute (unhealthy)",
                health="unhealthy",
            ),
        ],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed
    assert any("wazuh-manager" in d and "not 'healthy'" in d for d in check.diagnostics)


def test_readiness_fails_when_container_health_still_starting():
    # A container mid-healthcheck ("starting") has reported a health state
    # that is not yet "healthy", so it must still fail the gate rather than be
    # treated as ready.
    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [
            _container(
                "aptl-webapp", status="Up 5s (health: starting)", health="starting"
            )
        ],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert not check.passed
    assert any("'starting'" in d and "not 'healthy'" in d for d in check.diagnostics)


def test_readiness_tolerates_unreported_health_when_node_declares_none():
    # No declared health → an empty container health stays tolerated, preserving
    # behavior for nodes that declare no health expectation.
    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [_container("aptl-webapp", status="Up 2 minutes", health="")],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert check.passed


# --------------------------------------------------------------------------- #
# 6. Run-archive manifest.
# --------------------------------------------------------------------------- #


class _RecordingStore:
    def __init__(self):
        self.json_writes = []
        self.created = []

    def create_run(self, run_id):
        self.created.append(run_id)

    def write_json(self, run_id, relative_path, obj):
        self.json_writes.append((run_id, relative_path, obj))


def _archive_state():
    state = LiveGateState()
    state.realization_details = {
        "nodes": [_node("webapp", ["dmz"])],
        "profiles": ["dmz", "soc"],
    }
    state.selected_profiles = ["dmz", "soc"]
    state.snapshot = {"containers": [_container("aptl-webapp")]}
    state.evidence = {"telemetry": {"suricata_eve_count": 3}}
    return state


def test_run_archive_writes_manifest_through_redacting_boundary():
    store = _RecordingStore()
    prior = (LiveGateCheck("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True),)
    check = lgc.check_run_archive_manifest(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        config=_config(),
        run_store=store,
        run_id="rid",
        state=_archive_state(),
        prior_checks=prior,
    )
    assert check.passed
    assert store.created == ["rid"]
    # Exactly one write, via write_json (the redacting boundary), not write_file.
    assert len(store.json_writes) == 1
    _, path, manifest = store.json_writes[0]
    assert path == "live-gate/manifest.json"
    assert manifest["raes_provenance"]["realization"]["nodes"]
    assert manifest["raes_provenance"]["selected_profiles"] == ["dmz", "soc"]
    assert manifest["evaluator_surfaces"]["profile"] == "full-remote-control-plane"
    assert (
        manifest["evaluator_surfaces"]["execution_state_integration"]
        == "aptl.backends.raes_evaluator.AptlEvaluator"
    )
    assert manifest["participant_runtime_surfaces"]["contracts"] == [
        "participant-episode-state-envelope-v1",
        "participant-episode-history-event-stream-v1",
        "participant-behavior-history-event-stream-v1",
    ]
    assert manifest["scenario"]["name"] == "techvault"


def test_run_archive_roundtrips_to_local_store(tmp_path):
    store = LocalRunStore(tmp_path)
    check = lgc.check_run_archive_manifest(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        config=_config(),
        run_store=store,
        run_id="rid",
        state=_archive_state(),
        prior_checks=(LiveGateCheck("x", CATEGORY_EVIDENCE_CAPTURE, True),),
    )
    assert check.passed
    manifest_path = tmp_path / "rid" / "live-gate" / "manifest.json"
    written = manifest_path.read_text()
    assert "raes_provenance" in written
    assert "realization" in written
    # Regression guard: the validation outcome key must survive the run-archive
    # redaction boundary (a `passed` key would be masked as [REDACTED]).
    reloaded = json.loads(written)
    assert reloaded["validation"]["status"] == "passed"
    assert reloaded["validation"]["checks"][0]["status"] == "passed"


def test_run_archive_records_failing_final_check_as_not_ok():
    # F2 regression: when a check that runs before the manifest fails (e.g.
    # scenario_variation), the persisted manifest must reflect it — validation
    # ok=False and the failing check present — so the durable audit artifact
    # cannot disagree with the returned report.
    store = _RecordingStore()
    prior = (
        LiveGateCheck("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True),
        LiveGateCheck(
            "scenario_variation",
            CATEGORY_BACKEND_INTERPRETATION,
            False,
            ("collapsed",),
        ),
    )
    check = lgc.check_run_archive_manifest(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        config=_config(),
        run_store=store,
        run_id="rid",
        state=_archive_state(),
        prior_checks=prior,
    )
    assert check.passed  # the manifest write itself succeeded
    _, _, manifest = store.json_writes[0]
    assert manifest["validation"]["status"] == "failed"
    recorded = {c["name"]: c["status"] for c in manifest["validation"]["checks"]}
    assert recorded["scenario_variation"] == "failed"


def test_run_archive_fails_without_realization():
    state = LiveGateState()
    state.snapshot = {"containers": [_container("aptl-webapp")]}
    check = lgc.check_run_archive_manifest(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        config=_config(),
        run_store=_RecordingStore(),
        run_id="rid",
        state=state,
        prior_checks=(),
    )
    assert not check.passed
    assert any("realization" in d for d in check.diagnostics)


def test_run_archive_fails_on_write_error():
    class _BoomStore(_RecordingStore):
        def write_json(self, *a, **k):
            raise OSError("disk full")

    check = lgc.check_run_archive_manifest(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        config=_config(),
        run_store=_BoomStore(),
        run_id="rid",
        state=_archive_state(),
        prior_checks=(LiveGateCheck("x", CATEGORY_EVIDENCE_CAPTURE, True),),
    )
    assert not check.passed
    assert any("write failed" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# 7. Scenario variation.
# --------------------------------------------------------------------------- #


def _variation_state(nodes):
    state = LiveGateState()
    state.realization_details = {"nodes": nodes}
    return state


def _write_compose(project_dir: Path, services: dict[str, list[str]]) -> None:
    """Write a minimal compose file mapping service names to profiles.

    Mirrors the helper in ``test_raes_backend.py``; lets variation tests drive
    the real ``interpret_provisioning_plan`` compose-profile resolution against a
    hermetic ``tmp_path`` instead of the repo's live ``docker-compose.yml``.
    """
    lines = ["services:"]
    for service_name, profiles in services.items():
        rendered = ", ".join(f'"{profile}"' for profile in profiles)
        lines.extend(
            [
                f"  {service_name}:",
                f"    profiles: [{rendered}]",
                "    image: example:latest",
            ]
        )
    (project_dir / "docker-compose.yml").write_text("\n".join(lines))


def test_variation_passes_on_distinct_realizations(monkeypatch):
    results = iter(
        [
            _Realization([_node("kali", ["kali"])], ["kali"]),
            _Realization([_node("webapp", ["dmz"])], ["dmz"]),
        ]
    )
    monkeypatch.setattr(lgc, "interpret_provisioning_plan", lambda **k: next(results))
    state = _variation_state([_node("kali", ["kali"]), _node("webapp", ["dmz"])])
    check = lgc.check_scenario_variation(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert check.passed


def test_variation_accepts_core_otel_public_start_profile(tmp_path):
    config = AptlConfig(
        lab={"name": "techvault"},
        containers={"enterprise": True, "wazuh": False, "victim": False, "kali": False},
    )
    _write_compose(tmp_path, {"ad": ["enterprise"], "aptl-grafana-otel": ["otel"]})
    state = _variation_state(
        [_node("ad", ["enterprise"]), _node("aptl-grafana-otel", ["otel"])]
    )

    check = lgc.check_scenario_variation(
        project_dir=tmp_path, config=config, state=state
    )

    assert check.passed


def test_variation_fails_on_collapse(monkeypatch):
    same = _Realization([_node("x", ["p"])], ["p"])
    monkeypatch.setattr(lgc, "interpret_provisioning_plan", lambda **k: same)
    state = _variation_state([_node("kali", ["kali"]), _node("webapp", ["dmz"])])
    check = lgc.check_scenario_variation(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert not check.passed
    assert any("collapsed" in d for d in check.diagnostics)


def test_variation_fails_without_two_distinct_nodes():
    state = _variation_state([_node("kali", ["kali"]), _node("kali2", ["kali"])])
    check = lgc.check_scenario_variation(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert not check.passed
    assert any("fewer than two distinct" in d for d in check.diagnostics)


def test_variation_fails_on_realization_error(monkeypatch):
    results = iter(
        [
            _Realization(
                [_node("kali", ["kali"])], ["kali"], diagnostics=(_Diag("error"),)
            ),
            _Realization([_node("webapp", ["dmz"])], ["dmz"]),
        ]
    )
    monkeypatch.setattr(lgc, "interpret_provisioning_plan", lambda **k: next(results))
    state = _variation_state([_node("kali", ["kali"]), _node("webapp", ["dmz"])])
    check = lgc.check_scenario_variation(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert not check.passed
    assert any("failed to realize" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# End-to-end live boot — destructive, integration-marked, explicitly gated.
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(
    os.getenv("APTL_LIVE_GATE", "0") != "1",
    reason="Set APTL_LIVE_GATE=1 to run the destructive live deployment gate",
)
def test_live_gate_passes_on_techvault():
    from aptl.core.config import load_config

    config = load_config(PROJECT_ROOT / "aptl.json")
    report = validate_live_deployment(SCENARIO, project_dir=PROJECT_ROOT, config=config)
    assert report.passed, report.render()


# --------------------------------------------------------------------------- #
# CLI: `aptl lab validate-live`.
# --------------------------------------------------------------------------- #


def _patch_cli(mocker, *, passed=True):
    from typer.testing import CliRunner

    report = LiveGateReport(
        "scn",
        "full-remote-control-plane",
        "rid",
        (LiveGateCheck("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, passed),),
    )
    mocker.patch(
        "aptl.cli._common.resolve_config_for_cli",
        return_value=(_config(), PROJECT_ROOT),
    )
    mocker.patch("aptl.cli._common.resolve_run_store", return_value=object())
    run = mocker.patch(
        "aptl.validation.techvault_live_gate.validate_live_deployment",
        return_value=report,
    )
    return CliRunner(), run


def test_validate_live_deployment_rejects_unsafe_run_id():
    report = validate_live_deployment(
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(run_id="../escape"),
    )
    assert not report.passed
    assert any("run_id" in d for check in report.checks for d in check.diagnostics)


def test_cli_validate_live_rejects_traversal_run_id(mocker):
    from aptl.cli.main import app

    runner, run = _patch_cli(mocker, passed=True)
    result = runner.invoke(
        app,
        ["lab", "validate-live", "--skip-clean-boot", "--run-id", "../escape"],
    )
    assert result.exit_code != 0
    run.assert_not_called()


def test_cli_validate_live_help():
    from typer.testing import CliRunner

    from aptl.cli.main import app

    result = CliRunner().invoke(app, ["lab", "validate-live", "--help"])
    assert result.exit_code == 0
    assert "DESTRUCTIVE" in result.stdout


def test_cli_validate_live_skip_clean_boot_passes(mocker):
    from aptl.cli.main import app

    runner, run = _patch_cli(mocker, passed=True)
    result = runner.invoke(app, ["lab", "validate-live", "--skip-clean-boot"])
    assert result.exit_code == 0
    run.assert_called_once()
    assert run.call_args.kwargs["options"].skip_clean_boot is True


def test_cli_validate_live_failure_exits_1(mocker):
    from aptl.cli.main import app

    runner, _ = _patch_cli(mocker, passed=False)
    result = runner.invoke(app, ["lab", "validate-live", "--yes"])
    assert result.exit_code == 1


def test_cli_validate_live_aborts_without_confirmation(mocker):
    from aptl.cli.main import app

    runner, run = _patch_cli(mocker, passed=True)
    result = runner.invoke(app, ["lab", "validate-live"], input="n\n")
    assert result.exit_code == 0
    assert "Aborted" in result.stdout
    run.assert_not_called()


def test_cli_validate_live_yes_runs_destructive(mocker):
    from aptl.cli.main import app

    runner, run = _patch_cli(mocker, passed=True)
    result = runner.invoke(app, ["lab", "validate-live", "--yes"])
    assert result.exit_code == 0
    run.assert_called_once()
    assert run.call_args.kwargs["options"].skip_clean_boot is False


def test_trigger_is_redriven_on_every_poll(monkeypatch):
    """Host monitoring becomes ready after boot, so a one-shot trigger is lost.

    A trigger fired once before the SIEM path is live produces events that never
    arrive, and polling afterwards cannot recover them — the observed failure was
    a window with Suricata evidence, Wazuh alerts flowing, and zero correlated
    alerts. Re-driving asks whether the path works within the window.
    """
    from aptl.validation import _live_gate_probes as probes

    attempts = {"n": 0}
    monkeypatch.setattr(probes, "collect_suricata_eve", lambda *a, **k: [])

    def _alerts(*_a, **_k):
        # Correlates only once the trigger has been re-driven, mimicking a path
        # that becomes ready partway through the window.
        if attempts["n"] >= 2:
            return [{"rule": {"id": "5710"}, "data": {"dstuser": "test-marker"}}]
        return [{"rule": {"id": "1002"}, "data": {"srcip": "10.0.0.1"}}]

    monkeypatch.setattr(probes, "collect_wazuh_alerts", _alerts)

    _eve, alerts = probes._collect_until_evidence(
        object(),
        "2026-01-01T00:00:00+00:00",
        deadline_monotonic=60.0,
        poll_interval_seconds=10.0,
        indexer_url="https://localhost:9200",
        indexer_auth=("u", "p"),
        alert_matches=lambda alert: "test-marker" in str(alert),
        sleep_fn=lambda _s: None,
        monotonic_fn=lambda: 0.0,
        regenerate=lambda: attempts.__setitem__("n", attempts["n"] + 1),
    )

    assert attempts["n"] >= 2, "trigger was not re-driven while waiting"
    assert any("test-marker" in str(alert) for alert in alerts)


def test_without_redrive_a_lost_trigger_is_never_recovered(monkeypatch):
    """The pre-fix behaviour: one-shot triggering cannot recover readiness lag."""
    from aptl.validation import _live_gate_probes as probes

    monkeypatch.setattr(probes, "collect_suricata_eve", lambda *a, **k: [])
    monkeypatch.setattr(
        probes,
        "collect_wazuh_alerts",
        lambda *a, **k: [{"rule": {"id": "1002"}, "data": {"srcip": "10.0.0.1"}}],
    )

    _eve, alerts = probes._collect_until_evidence(
        object(),
        "2026-01-01T00:00:00+00:00",
        deadline_monotonic=30.0,
        poll_interval_seconds=10.0,
        indexer_url="https://localhost:9200",
        indexer_auth=("u", "p"),
        alert_matches=lambda alert: "test-marker" in str(alert),
        sleep_fn=lambda _s: None,
        monotonic_fn=lambda: 0.0,
    )

    assert not any("test-marker" in str(alert) for alert in alerts)


def test_poll_does_not_redrive_after_sleep_reaches_the_deadline(monkeypatch):
    from aptl.validation import _live_gate_probes as probes

    now = iter((0.0, 0.0, 10.0))
    attempts = []

    _eve, alerts = probes._collect_until_evidence(
        object(),
        "2026-01-01T00:00:00+00:00",
        deadline_monotonic=10.0,
        poll_interval_seconds=10.0,
        indexer_url="https://localhost:9200",
        indexer_auth=("u", "p"),
        alert_matches=lambda _alert: False,
        sleep_fn=lambda _seconds: None,
        monotonic_fn=lambda: next(now),
        regenerate=lambda: attempts.append("triggered"),
    )

    assert attempts == []
    assert alerts == []


def test_structural_half_of_the_gate_holds_no_scenario_answer_key():
    """#877: core's structural checks must carry no scenario-derived constant.

    The point of the split is that the modules deciding *whether the range
    matches the admitted graph* work for any scenario. If a TechVault name leaks
    back into them the boundary has been reopened, and the plugin seam built on
    top of it (#878/#879) would be resting on nothing.

    ``techvault_live_gate`` itself is excluded: it is the orchestrator and is
    named for the scenario that proved it, which #878 renames along with the
    report. The check is on the modules that make structural decisions.
    """

    import re
    from pathlib import Path

    structural = (
        "_live_gate_checks.py",
        "_live_gate_readiness.py",
    )
    # Scenario answer keys, not merely the string "techvault": a docstring may
    # legitimately mention the proving scenario, but a *constant* naming the
    # attacker node or the defensive stack is an answer key.
    answer_keys = re.compile(r"aptl-kali|wazuh|suricata|_KALI_CONTAINER", re.I)
    root = Path(__file__).resolve().parent.parent / "src" / "aptl" / "validation"

    offenders = {
        name: sorted(set(answer_keys.findall((root / name).read_text())))
        for name in structural
        if answer_keys.search((root / name).read_text())
    }

    assert not offenders, f"scenario answer keys leaked back into core: {offenders}"


def test_semantic_verification_runs_only_through_the_plugin_seam():
    """The orchestrator must reach scenario knowledge only via discovery (#879).

    Semantic verification is now an installed plugin found through
    ``scenario_verification_discovery``. The orchestrator must not also import a
    scenario-specific check module or name an attacker/defensive-stack constant:
    if it did, the seam it stands on would be decorative and a second scenario
    would need core edits.
    """

    import re
    from pathlib import Path

    source = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "aptl"
        / "validation"
        / "techvault_live_gate.py"
    ).read_text()

    # The discovery seam is reached, and the retired in-core scenario module is
    # gone entirely.
    assert "scenario_verification_discovery" in source
    assert "_live_gate_semantic" not in source
    # No scenario answer key is named in the orchestrator itself.
    assert not re.search(r"aptl-kali|_KALI_CONTAINER", source)


def test_report_and_plugin_admission_share_canonical_bundle_identities():
    scenario, backend = tlg._verification_identities(
        SCENARIO,
        BUNDLE,
        "full-remote-control-plane",
        "docker-compose",
    )

    assert scenario.identity == BUNDLE.identity
    assert scenario.source_kind == BUNDLE.source_kind.value
    assert scenario.version == BUNDLE.pack_identity.pack_version
    assert scenario.content_digest == BUNDLE.pack_identity.set_digest
    assert backend.target_name == "aptl"
    assert backend.target_version == "0.1.0"
    assert backend.profile == "full-remote-control-plane"
    assert backend.provider == "docker-compose"
    assert backend.transport == "docker-compose"
