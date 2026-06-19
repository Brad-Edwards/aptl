"""Live validation gate tests (SCN-010F / issue #323).

The fast unit suite drives the scenario-generic orchestrator composed in
``aptl.validation.techvault_live_gate`` and every check branch in
``aptl.validation._live_gate_checks`` without a live lab, by monkeypatching the
lifecycle / snapshot / collector entry points. The destructive end-to-end live
boot is the integration-marked, ``APTL_LIVE_GATE``-gated test at the bottom.
"""

import json
import os
import types
from pathlib import Path

import pytest

from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult, StartupOutcome
from aptl.core.runstore import LocalRunStore
from aptl.validation import _live_gate_checks as lgc
from aptl.validation import _live_gate_probes as lgp
from aptl.validation.techvault_live_gate import (
    CATEGORY_ACES_SPECIFICATION,
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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"


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

    def details(self):
        return self._details


class _Manager:
    def __init__(self, target):
        self.target = target

    def plan(self, scenario):
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


def _node(name, profiles, aliases=None):
    return {"name": name, "aliases": aliases or [name], "profiles": list(profiles)}


def _container(name, *, status="Up 2 minutes (healthy)", health="healthy", networks=None):
    return {
        "name": name,
        "status": status,
        "health": health,
        "networks": networks or {},
    }


def _wire_boot(monkeypatch, *, outcome=StartupOutcome.READY, realization=None, snapshot=None):
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
    # directly in `check_aces_driven_boot` (lgc), so it stays patched on lgc.
    monkeypatch.setattr(lgp, "get_backend", lambda config, project_dir: _Backend())
    monkeypatch.setattr(lgp, "create_aptl_runtime_target", lambda **k: object())
    monkeypatch.setattr(lgp, "RuntimeManager", _Manager)
    monkeypatch.setattr(lgp, "interpret_provisioning_plan", lambda **k: realization)
    monkeypatch.setattr(
        lgc, "select_backend_profiles", lambda config, profiles: ["dmz", "soc"]
    )
    monkeypatch.setattr(lgp, "stop_lab", lambda **k: LabResult(success=True))
    monkeypatch.setattr(
        lgp, "orchestrate_lab_start", lambda p: LabResult(success=True, outcome=outcome)
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
            "aces_driven_boot",
            "defensive_stack_readiness",
            "kali_reachability",
            "telemetry_evidence_path",
            "run_archive_manifest",
            "scenario_variation",
        }
    )
    assert all(cat in FAILURE_CATEGORIES for cat in CHECK_CATEGORY.values())


def test_live_gate_report_passed_failures_categories_and_render():
    ok = LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True)
    bad = LiveGateCheck(
        "kali_reachability", CATEGORY_KALI_REACHABILITY, False, ("unreachable",)
    )
    report = LiveGateReport("scn", "provisioning-only", "rid", (ok, bad))
    assert report.passed is False
    assert report.failures() == (bad,)
    assert report.failure_categories() == (CATEGORY_KALI_REACHABILITY,)
    text = report.render()
    assert "FAIL" in text and "unreachable" in text and "failing layers" in text
    assert LiveGateReport("s", "p", "r", (ok,)).passed is True


# --------------------------------------------------------------------------- #
# Orchestrator composition.
# --------------------------------------------------------------------------- #


def test_validate_live_deployment_composes_all_checks(monkeypatch):
    # Stubs use each check's EXACT keyword signature so a drift between the
    # orchestrator's call sites and the check signatures raises TypeError here
    # (the `*a, **k` shape would silently mask a missing kwarg — the live smoke
    # run caught exactly that for `check_scenario_variation(state=...)`).
    def static(scenario_path, *, project_dir, config, options):
        return object(), LiveGateCheck("static_prerequisite", CATEGORY_ACES_SPECIFICATION, True)

    def inputs(scenario_path, *, project_dir, options):
        return LiveGateCheck("boot_inputs_match_public_path", CATEGORY_BACKEND_INSTANTIATION, True)

    def boot(scenario, *, project_dir, config, options, state):
        return LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True)

    def readiness(*, state):
        return LiveGateCheck("defensive_stack_readiness", CATEGORY_DEFENSIVE_STACK_READINESS, True)

    def reachability(*, project_dir, config, state):
        return LiveGateCheck("kali_reachability", CATEGORY_KALI_REACHABILITY, True)

    def telemetry(*, project_dir, config, options, state):
        return LiveGateCheck("telemetry_evidence_path", CATEGORY_EVIDENCE_CAPTURE, True)

    def archive(scenario_path, *, project_dir, config, run_store, run_id, state, prior_checks):
        return LiveGateCheck("run_archive_manifest", CATEGORY_EVIDENCE_CAPTURE, True)

    def variation(*, project_dir, config, state):
        return LiveGateCheck("scenario_variation", CATEGORY_BACKEND_INTERPRETATION, True)

    monkeypatch.setattr(lgc, "check_static_prerequisite", static)
    monkeypatch.setattr(lgc, "check_boot_inputs_match_public_path", inputs)
    monkeypatch.setattr(lgc, "check_aces_driven_boot", boot)
    monkeypatch.setattr(lgc, "check_defensive_stack_readiness", readiness)
    monkeypatch.setattr(lgc, "check_kali_reachability", reachability)
    monkeypatch.setattr(lgc, "check_telemetry_evidence_path", telemetry)
    monkeypatch.setattr(lgc, "check_run_archive_manifest", archive)
    monkeypatch.setattr(lgc, "check_scenario_variation", variation)
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config()
    )
    assert report.passed
    assert {c.name for c in report.checks} == {
        "static_prerequisite",
        "boot_inputs_match_public_path",
        "aces_driven_boot",
        "defensive_stack_readiness",
        "kali_reachability",
        "telemetry_evidence_path",
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
        lambda *a, **k: (None, LiveGateCheck("static_prerequisite", CATEGORY_ACES_SPECIFICATION, False, ("bad",))),
    )
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config()
    )
    assert not report.passed
    assert [c.name for c in report.checks] == ["static_prerequisite"]


def test_validate_live_deployment_records_archive_on_boot_failure(monkeypatch):
    monkeypatch.setattr(
        lgc,
        "check_static_prerequisite",
        lambda *a, **k: (object(), LiveGateCheck("static_prerequisite", CATEGORY_ACES_SPECIFICATION, True)),
    )
    monkeypatch.setattr(
        lgc,
        "check_aces_driven_boot",
        lambda *a, **k: LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, False, ("boom",)),
    )
    archive_calls = []
    monkeypatch.setattr(
        lgc,
        "check_run_archive_manifest",
        lambda *a, **k: archive_calls.append(1)
        or LiveGateCheck("run_archive_manifest", CATEGORY_EVIDENCE_CAPTURE, True),
    )
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config()
    )
    assert not report.passed
    assert [c.name for c in report.checks] == [
        "static_prerequisite",
        "boot_inputs_match_public_path",
        "aces_driven_boot",
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
    assert check.passed and check.category == CATEGORY_ACES_SPECIFICATION


def test_check_static_prerequisite_blocks_on_static_failure(monkeypatch):
    failing = LiveGateCheck("compile", "x", False, ("semantic error",))
    report = types.SimpleNamespace(passed=False, failures=lambda: (failing,))
    monkeypatch.setattr(lgc, "validate_scenario", lambda *a, **k: report)
    scenario, check = lgc.check_static_prerequisite(
        SCENARIO, project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions()
    )
    assert scenario is None and not check.passed
    assert any("static gate failed" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# 2. ACES-driven boot.
# --------------------------------------------------------------------------- #


def test_check_aces_driven_boot_happy_populates_state(monkeypatch):
    _wire_boot(monkeypatch)
    state = LiveGateState()
    check = lgc.check_aces_driven_boot(
        object(), project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions(), state=state
    )
    assert check.passed and check.category == CATEGORY_BACKEND_INSTANTIATION
    assert state.realization_details["nodes"]
    assert state.selected_profiles == ["dmz", "soc"]
    assert state.snapshot["containers"]


def test_check_aces_driven_boot_fails_on_interpretation_error(monkeypatch):
    bad = _Realization([_node("webapp", ["dmz"])], ["dmz"], diagnostics=(_Diag("error"),))
    _wire_boot(monkeypatch, realization=bad)
    state = LiveGateState()
    check = lgc.check_aces_driven_boot(
        object(), project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions(), state=state
    )
    assert not check.passed and check.category == CATEGORY_BACKEND_INTERPRETATION


def test_check_aces_driven_boot_fails_on_empty_realization(monkeypatch):
    _wire_boot(monkeypatch, realization=_Realization([], []))
    state = LiveGateState()
    check = lgc.check_aces_driven_boot(
        object(), project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions(), state=state
    )
    assert not check.passed
    assert any("no ACES nodes" in d for d in check.diagnostics)


def test_check_aces_driven_boot_fails_on_boot_failed(monkeypatch):
    _wire_boot(monkeypatch, outcome=StartupOutcome.FAILED)
    state = LiveGateState()
    check = lgc.check_aces_driven_boot(
        object(), project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions(), state=state
    )
    assert not check.passed and check.category == CATEGORY_BACKEND_INSTANTIATION
    assert any("public lab start failed" in d for d in check.diagnostics)


def test_check_aces_driven_boot_skips_cleanup_and_reboot_when_requested(monkeypatch):
    stops, boots = [], []
    _wire_boot(monkeypatch)
    monkeypatch.setattr(lgp, "stop_lab", lambda **k: stops.append(1) or LabResult(success=True))
    monkeypatch.setattr(
        lgp,
        "orchestrate_lab_start",
        lambda p: boots.append(1) or LabResult(success=True, outcome=StartupOutcome.READY),
    )
    state = LiveGateState()
    check = lgc.check_aces_driven_boot(
        object(),
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(skip_clean_boot=True),
        state=state,
    )
    # Non-destructive: neither cleanup nor reboot, but the running lab is still
    # snapshotted and the realization matrix is still computed.
    assert stops == [] and boots == []
    assert check.passed and state.snapshot["containers"]


# --------------------------------------------------------------------------- #
# 2a. Boot-input / public-start-path agreement (F1 regression).
# --------------------------------------------------------------------------- #


def test_boot_inputs_pass_for_default_scenario_and_profile():
    check = lgc.check_boot_inputs_match_public_path(
        SCENARIO, project_dir=PROJECT_ROOT, options=LiveGateOptions()
    )
    assert check.passed and check.category == CATEGORY_BACKEND_INSTANTIATION


def test_boot_inputs_fail_for_mismatched_scenario():
    # A scenario other than the one the public start path boots would validate
    # one model while booting another — a hard failure before any boot.
    other = PROJECT_ROOT / "scenarios" / "other.sdl.yaml"
    check = lgc.check_boot_inputs_match_public_path(
        other, project_dir=PROJECT_ROOT, options=LiveGateOptions()
    )
    assert not check.passed
    assert any("does not match" in d for d in check.diagnostics)


def test_boot_inputs_fail_for_mismatched_profile():
    check = lgc.check_boot_inputs_match_public_path(
        SCENARIO, project_dir=PROJECT_ROOT, options=LiveGateOptions(profile="evaluation")
    )
    assert not check.passed
    assert any("capability profile" in d for d in check.diagnostics)


def test_validate_live_deployment_short_circuits_on_input_mismatch(monkeypatch):
    # F1: a mismatched scenario/profile must fail loud BEFORE the destructive
    # boot is attempted — boot/readiness/etc. checks never run.
    monkeypatch.setattr(
        lgc,
        "check_static_prerequisite",
        lambda *a, **k: (object(), LiveGateCheck("static_prerequisite", CATEGORY_ACES_SPECIFICATION, True)),
    )
    booted = []
    monkeypatch.setattr(
        lgc,
        "check_aces_driven_boot",
        lambda *a, **k: booted.append(1)
        or LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True),
    )
    report = validate_live_deployment(
        PROJECT_ROOT / "scenarios" / "other.sdl.yaml",
        project_dir=PROJECT_ROOT,
        config=_config(),
    )
    assert not report.passed
    assert [c.name for c in report.checks] == [
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


def test_readiness_tolerates_unhealthy_non_node_infra():
    state = _readiness_state(
        [_node("webapp", ["dmz"])],
        [
            _container("aptl-webapp"),
            _container("aptl-otel-collector", status="Up 1m (unhealthy)", health="unhealthy"),
        ],
    )
    check = lgc.check_defensive_stack_readiness(state=state)
    assert check.passed


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


# --------------------------------------------------------------------------- #
# 4. Kali reachability.
# --------------------------------------------------------------------------- #


def _reach_state(containers):
    state = LiveGateState()
    state.snapshot = {"containers": containers}
    return state


def test_reachability_passes_when_shared_targets_reachable(monkeypatch):
    monkeypatch.setattr(lgc, "get_backend", lambda c, p: _Backend(returncode=0))
    state = _reach_state(
        [
            _container("aptl-kali", networks={"aptl-dmz-net": "172.20.1.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )
    check = lgc.check_kali_reachability(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert check.passed
    assert state.evidence["kali_reachability_targets"] == ["aptl-webapp"]


def test_reachability_fails_when_target_unreachable(monkeypatch):
    monkeypatch.setattr(lgc, "get_backend", lambda c, p: _Backend(returncode=1))
    state = _reach_state(
        [
            _container("aptl-kali", networks={"aptl-dmz-net": "172.20.1.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )
    check = lgc.check_kali_reachability(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert not check.passed
    assert any("cannot reach" in d for d in check.diagnostics)


def test_reachability_fails_without_kali():
    state = _reach_state([_container("aptl-webapp", networks={"n": "1.2.3.4"})])
    check = lgc.check_kali_reachability(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert not check.passed
    assert any("Kali container not present" in d for d in check.diagnostics)


def test_reachability_fails_without_shared_network():
    state = _reach_state(
        [
            _container("aptl-kali", networks={"aptl-redteam-net": "172.30.0.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )
    check = lgc.check_kali_reachability(
        project_dir=PROJECT_ROOT, config=_config(), state=state
    )
    assert not check.passed
    assert any("share a network" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# 5. Telemetry / evidence path.
# --------------------------------------------------------------------------- #


def _telemetry_state():
    state = LiveGateState()
    state.snapshot = {
        "containers": [
            _container("aptl-kali", networks={"aptl-dmz-net": "172.20.1.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    }
    return state


def test_telemetry_passes_when_traffic_evidence_collected(monkeypatch):
    monkeypatch.setattr(lgc, "get_backend", lambda c, p: _Backend())
    monkeypatch.setattr(lgp.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        lgp, "collect_suricata_eve", lambda s, e, b: [{"event_type": "alert"}, {"event_type": "flow"}]
    )
    monkeypatch.setattr(lgp, "collect_wazuh_alerts", lambda s, e: [])
    state = _telemetry_state()
    check = lgc.check_telemetry_evidence_path(
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(event_window_seconds=10),
        state=state,
    )
    assert check.passed
    telemetry = state.evidence["telemetry"]
    assert telemetry["suricata_traffic_event_count"] == 2
    assert telemetry["suricata_event_types"] == {"alert": 1, "flow": 1}


def test_telemetry_fails_on_stats_only_events(monkeypatch):
    # Suricata emits `stats` regardless of traffic; the check must not pass on
    # them alone (otherwise it would pass on any quiet lab).
    monkeypatch.setattr(lgc, "get_backend", lambda c, p: _Backend())
    monkeypatch.setattr(lgp.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        lgp, "collect_suricata_eve", lambda s, e, b: [{"event_type": "stats"}, {"event_type": "stats"}]
    )
    monkeypatch.setattr(lgp, "collect_wazuh_alerts", lambda s, e: [])
    state = _telemetry_state()
    check = lgc.check_telemetry_evidence_path(
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(event_window_seconds=10),
        state=state,
    )
    assert not check.passed
    assert state.evidence["telemetry"]["suricata_traffic_event_count"] == 0
    assert any("stats-only" in d for d in check.diagnostics)


def test_telemetry_fails_when_no_evidence(monkeypatch):
    monkeypatch.setattr(lgc, "get_backend", lambda c, p: _Backend())
    monkeypatch.setattr(lgp.time, "sleep", lambda s: None)
    monkeypatch.setattr(lgp, "collect_suricata_eve", lambda s, e, b: [])
    monkeypatch.setattr(lgp, "collect_wazuh_alerts", lambda s, e: [])
    state = _telemetry_state()
    check = lgc.check_telemetry_evidence_path(
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=LiveGateOptions(event_window_seconds=10),
        state=state,
    )
    assert not check.passed
    assert any("no traffic-derived" in d for d in check.diagnostics)


def test_telemetry_fails_without_target(monkeypatch):
    state = LiveGateState()
    state.snapshot = {"containers": [_container("aptl-kali", networks={"n": "1.1.1.1"})]}
    check = lgc.check_telemetry_evidence_path(
        project_dir=PROJECT_ROOT, config=_config(), options=LiveGateOptions(), state=state
    )
    assert not check.passed


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
    prior = (LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True),)
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
    assert manifest["aces_provenance"]["realization"]["nodes"]
    assert manifest["aces_provenance"]["selected_profiles"] == ["dmz", "soc"]
    assert manifest["evaluator_surfaces_deferred"]["objectives"] == "#312"
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
    assert "aces_provenance" in written and "realization" in written
    # Regression guard: the validation outcome key must survive the run-archive
    # redaction boundary (a `passed` key would be masked as [REDACTED]).
    reloaded = json.loads(written)
    assert reloaded["validation"]["ok"] is True
    assert reloaded["validation"]["checks"][0]["ok"] is True


def test_run_archive_records_failing_final_check_as_not_ok():
    # F2 regression: when a check that runs before the manifest fails (e.g.
    # scenario_variation), the persisted manifest must reflect it — validation
    # ok=False and the failing check present — so the durable audit artifact
    # cannot disagree with the returned report.
    store = _RecordingStore()
    prior = (
        LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, True),
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
    assert manifest["validation"]["ok"] is False
    recorded = {c["name"]: c["ok"] for c in manifest["validation"]["checks"]}
    assert recorded["scenario_variation"] is False


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
            _Realization([_node("kali", ["kali"])], ["kali"], diagnostics=(_Diag("error"),)),
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
    config = AptlConfig(lab={"name": "techvault"})
    report = validate_live_deployment(
        SCENARIO, project_dir=PROJECT_ROOT, config=config
    )
    assert report.passed, report.render()


# --------------------------------------------------------------------------- #
# CLI: `aptl lab validate-live`.
# --------------------------------------------------------------------------- #


def _patch_cli(mocker, *, passed=True):
    from typer.testing import CliRunner

    report = LiveGateReport(
        "scn",
        "provisioning-only",
        "rid",
        (LiveGateCheck("aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, passed),),
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
