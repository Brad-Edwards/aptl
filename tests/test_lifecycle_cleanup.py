"""Regression contract for issue #1179: pending lab cleanup survives upgrades."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.core.lab_types import LabResult

BASELINE = Path(".aptl/realization/wazuh-agent-identity/baseline.json")
LEGACY_DIR = Path(".aptl/lifecycle/startup-reset-v1")
LEGACY_DONE_DIR = Path(".aptl/lifecycle/startup-reset-completed-v1")
ACTION_DIR = Path(".aptl/lifecycle/cleanup-actions-v1")
ACTION_DONE_DIR = Path(".aptl/lifecycle/cleanup-actions-completed-v1")
TECHVAULT_DIGEST = (
    "sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b"
)
OTHER_DIGEST = "sha256:" + "b" * 64

# Byte-exact receipt written by an aptl-labs 5.5.0 development build (#601).
RECEIPT_5_5_0 = (
    b'{"admission_id":"f789eb926507311e2db6e35332ac4b0f03b82ef9424d4955efcb758c'
    b'dfe2ddd5","distribution":"aptl-labs","distribution_version":"5.5.0",'
    b'"entry_point":"techvault","pack_id":"techvault","pack_set_digest":'
    b'"sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b",'
    b'"pack_version":"0.1.0","schema_version":"aptl-startup-reset-authority/v1"}\n'
)


def _canonical(payload: dict[str, str]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _write_record(root: Path, directory: Path, encoded: bytes) -> Path:
    path = root / directory / f"{hashlib.sha256(encoded).hexdigest()}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return path


def _legacy(
    root: Path,
    *,
    pack_id: str = "techvault",
    digest: str = TECHVAULT_DIGEST,
    distribution: str = "aptl-labs",
    version: str = "6.0.0",
    admission: str = "a" * 64,
) -> Path:
    return _write_record(
        root,
        LEGACY_DIR,
        _canonical(
            {
                "schema_version": "aptl-startup-reset-authority/v1",
                "admission_id": admission,
                "distribution": distribution,
                "distribution_version": version,
                "entry_point": pack_id,
                "pack_id": pack_id,
                "pack_set_digest": digest,
                "pack_version": "0.1.0" if pack_id.startswith("techvault") else "1.0.0",
            }
        ),
    )


def _baseline(root: Path) -> Path:
    path = root / BASELINE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"db":"001"}\n', encoding="utf-8")
    return path


def _no_installed_providers(monkeypatch) -> None:
    from aptl.backends import scenario_startup

    monkeypatch.setattr(scenario_startup, "_entry_points", lambda: [])


def _provider(**extra: object) -> SimpleNamespace:
    return SimpleNamespace(
        extension_api_version="1",
        supported_pack_id="otherpack",
        supported_pack_versions=("1.0.0",),
        supported_pack_set_digests=(OTHER_DIGEST,),
        resolve=lambda _bundle: None,
        **extra,
    )


def _install(monkeypatch, *providers: tuple[str, object]) -> None:
    from aptl.backends import scenario_startup

    entries = [
        SimpleNamespace(
            name="otherpack",
            dist=SimpleNamespace(name="otherpack-adapter", version=version),
            load=lambda provider=provider: provider,
        )
        for version, provider in providers
    ]
    monkeypatch.setattr(scenario_startup, "_entry_points", lambda: entries)


def test_old_techvault_receipts_complete_without_old_distribution(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    _no_installed_providers(monkeypatch)
    receipts = [
        _write_record(tmp_path, LEGACY_DIR, RECEIPT_5_5_0),
        _legacy(tmp_path, digest=OTHER_DIGEST, version="6.0.0"),
        _legacy(tmp_path, pack_id="techvault-participant-study", version="6.0.0"),
    ]
    original = {path: path.read_bytes() for path in receipts}
    baseline = _baseline(tmp_path)

    report = run_pending_cleanup(tmp_path, object())

    assert report.pending == ()
    assert report.completed == 3
    assert not baseline.exists()
    assert {path: path.read_bytes() for path in receipts} == original
    assert sorted(p.name for p in (tmp_path / LEGACY_DONE_DIR).iterdir()) == sorted(
        path.name for path in receipts
    )
    again = run_pending_cleanup(tmp_path, object())
    assert (again.completed, again.pending) == (0, ())


def test_interrupted_cleanup_retries_to_one_recorded_completion(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core import lifecycle_cleanup, startup_reset_state

    _no_installed_providers(monkeypatch)
    receipt = _write_record(tmp_path, LEGACY_DIR, RECEIPT_5_5_0)
    baseline = _baseline(tmp_path)
    real_complete = startup_reset_state.complete_pending_cleanup

    def crash_after_effect(*_args: object) -> None:
        raise OSError("interrupted before the completion marker")

    monkeypatch.setattr(
        lifecycle_cleanup, "complete_pending_cleanup", crash_after_effect
    )
    first = lifecycle_cleanup.run_pending_cleanup(tmp_path, object())

    assert not baseline.exists()
    assert [item.reason for item in first.pending] == ["completion-record-failed"]
    assert not (tmp_path / LEGACY_DONE_DIR).exists()

    monkeypatch.setattr(lifecycle_cleanup, "complete_pending_cleanup", real_complete)
    second = lifecycle_cleanup.run_pending_cleanup(tmp_path, object())
    third = lifecycle_cleanup.run_pending_cleanup(tmp_path, object())

    assert (second.completed, second.pending) == (1, ())
    assert (third.completed, third.pending) == (0, ())
    assert [p.name for p in (tmp_path / LEGACY_DONE_DIR).iterdir()] == [receipt.name]


def test_absent_host_state_is_complete(tmp_path: Path, monkeypatch) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    _no_installed_providers(monkeypatch)
    _legacy(tmp_path)

    report = run_pending_cleanup(tmp_path, object())

    assert (report.completed, report.pending) == (1, ())
    assert not (tmp_path / ".aptl/realization").exists()


def test_symlinked_baseline_is_refused_and_stays_pending(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    _no_installed_providers(monkeypatch)
    _legacy(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("keep\n", encoding="utf-8")
    link = tmp_path / BASELINE
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)

    report = run_pending_cleanup(tmp_path, object())

    assert [item.reason for item in report.pending] == ["host-state-unsafe"]
    assert outside.read_text(encoding="utf-8") == "keep\n"
    assert link.is_symlink()
    assert not (tmp_path / LEGACY_DONE_DIR).exists()


def test_pack_reset_without_compatible_installed_handler_stays_pending(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    calls: list[object] = []
    # The upgraded adapter supports the admitted release but never declared
    # that it can finish cleanup recorded by another distribution version.
    _install(monkeypatch, ("2.0.0", _provider(reset=calls.append)))
    receipt = _legacy(
        tmp_path,
        pack_id="otherpack",
        digest=OTHER_DIGEST,
        distribution="otherpack-adapter",
        version="1.0.0",
    )

    report = run_pending_cleanup(tmp_path, object())

    assert calls == []
    assert len(report.pending) == 1
    failure = report.pending[0]
    assert failure.action == "pack.reset"
    assert failure.subject == "otherpack 1.0.0"
    assert failure.reason == "provider-reset-authority-unavailable"
    assert failure.record == f"startup-reset-v1/{receipt.name[:12]}"
    assert not (tmp_path / LEGACY_DONE_DIR).exists()


def test_declared_pack_handler_finishes_cleanup_after_upgrade(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    calls: list[object] = []
    handler = _provider(reset=calls.append, supported_reset_action_versions=("1",))
    _install(monkeypatch, ("2.0.0", handler))
    _legacy(
        tmp_path,
        pack_id="otherpack",
        digest=OTHER_DIGEST,
        distribution="otherpack-adapter",
        version="1.0.0",
    )
    backend = object()

    report = run_pending_cleanup(tmp_path, backend)

    assert (report.completed, report.pending) == (1, ())
    assert [context.backend for context in calls] == [backend]


def test_pack_handler_for_another_digest_is_never_dispatched(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    calls: list[object] = []
    handler = _provider(reset=calls.append, supported_reset_action_versions=("1",))
    _install(monkeypatch, ("2.0.0", handler))
    _legacy(
        tmp_path,
        pack_id="otherpack",
        digest="sha256:" + "c" * 64,
        distribution="otherpack-adapter",
        version="1.0.0",
    )

    report = run_pending_cleanup(tmp_path, object())

    assert calls == []
    assert [item.reason for item in report.pending] == [
        "provider-reset-authority-unavailable"
    ]


def test_ambiguous_pack_handlers_stay_pending(tmp_path: Path, monkeypatch) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    calls: list[object] = []
    declared = {"reset": calls.append, "supported_reset_action_versions": ("1",)}
    _install(
        monkeypatch, ("2.0.0", _provider(**declared)), ("3.0.0", _provider(**declared))
    )
    _legacy(
        tmp_path,
        pack_id="otherpack",
        digest=OTHER_DIGEST,
        distribution="otherpack-adapter",
        version="1.0.0",
    )

    report = run_pending_cleanup(tmp_path, object())

    assert calls == []
    assert [item.reason for item in report.pending] == [
        "provider-reset-authority-ambiguous"
    ]


def test_failing_pack_handler_stays_pending_then_completes_on_retry(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    attempts: list[object] = []

    def reset(context: object) -> None:
        attempts.append(context)
        if len(attempts) == 1:
            raise RuntimeError("transient")

    _install(monkeypatch, ("1.0.0", _provider(reset=reset)))
    _legacy(
        tmp_path,
        pack_id="otherpack",
        digest=OTHER_DIGEST,
        distribution="otherpack-adapter",
        version="1.0.0",
    )

    first = run_pending_cleanup(tmp_path, object())
    second = run_pending_cleanup(tmp_path, object())

    assert [item.reason for item in first.pending] == ["provider-hook-failed"]
    assert (second.completed, second.pending) == (1, ())
    assert len(attempts) == 2


def test_malformed_records_stay_pending_without_hiding_valid_work(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    _no_installed_providers(monkeypatch)
    valid = _legacy(tmp_path)
    tampered = tmp_path / LEGACY_DIR / ("d" * 64 + ".json")
    tampered.write_bytes(b'{"schema_version":"aptl-startup-reset-authority/v1"}\n')
    stray = tmp_path / LEGACY_DIR / "notes.txt"
    stray.write_bytes(b"left by hand\n")
    unknown = _write_record(
        tmp_path,
        ACTION_DIR,
        _canonical(
            {
                "schema_version": "aptl-lifecycle-cleanup-action/v1",
                "action": "aptl.future-thing.clear",
                "action_version": "1",
                "admission_id": "e" * 64,
                "distribution": "",
                "distribution_version": "",
                "entry_point": "",
                "pack_id": "",
                "pack_set_digest": "",
                "pack_version": "",
            }
        ),
    )
    other = _legacy(tmp_path, digest=OTHER_DIGEST)
    bad_marker = tmp_path / LEGACY_DONE_DIR / other.name
    bad_marker.parent.mkdir(parents=True)
    bad_marker.write_bytes(b"{}\n")
    before = {
        path: path.read_bytes()
        for path in (tampered, stray, unknown, other, bad_marker)
    }

    report = run_pending_cleanup(tmp_path, object())

    assert report.completed == 1
    assert (tmp_path / LEGACY_DONE_DIR / valid.name).exists()
    assert sorted((item.record, item.reason) for item in report.pending) == sorted(
        [
            (f"startup-reset-v1/{'d' * 12}", "cleanup-record-malformed"),
            ("startup-reset-v1/notes.txt", "cleanup-record-malformed"),
            (f"cleanup-actions-v1/{unknown.name[:12]}", "cleanup-action-unsupported"),
            (f"startup-reset-v1/{other.name[:12]}", "cleanup-record-malformed"),
        ]
    )
    assert {path: path.read_bytes() for path in before} == before


def test_admitted_cleanup_actions_round_trip(tmp_path: Path, monkeypatch) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup
    from aptl.core.startup_reset_state import (
        ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE,
        ACTION_PACK_RESET,
        CleanupAction,
        persist_cleanup_action,
    )

    calls: list[object] = []
    _install(monkeypatch, ("1.0.0", _provider(reset=calls.append)))
    provenance = {
        "admission_id": "f" * 64,
        "pack_id": "otherpack",
        "pack_version": "1.0.0",
        "pack_set_digest": OTHER_DIGEST,
        "distribution": "otherpack-adapter",
        "distribution_version": "1.0.0",
        "entry_point": "otherpack",
    }
    for action in (ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE, ACTION_PACK_RESET):
        persist_cleanup_action(tmp_path, CleanupAction(action, "1", **provenance))
        persist_cleanup_action(tmp_path, CleanupAction(action, "1", **provenance))
    baseline = _baseline(tmp_path)

    report = run_pending_cleanup(tmp_path, object())

    assert (report.completed, report.pending) == (2, ())
    assert not baseline.exists()
    assert len(calls) == 1
    assert len(list((tmp_path / ACTION_DONE_DIR).iterdir())) == 2
    anonymous = CleanupAction(ACTION_PACK_RESET, "1", **{**provenance, "pack_id": ""})
    with pytest.raises(ValueError):
        persist_cleanup_action(tmp_path, anonymous)


class _Backend:
    def __init__(self, result: LabResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], bool]] = []

    def stop(self, profiles: list[str], remove_volumes: bool = False) -> LabResult:
        self.calls.append((profiles, remove_volumes))
        return self.result


def test_stop_reports_pending_host_cleanup_after_verified_volume_removal(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lab import stop_lab

    _install(monkeypatch, ("2.0.0", _provider(reset=lambda _context: None)))
    _legacy(
        tmp_path,
        pack_id="otherpack",
        digest=OTHER_DIGEST,
        distribution="otherpack-adapter",
        version="1.0.0",
    )
    _legacy(tmp_path)
    baseline = _baseline(tmp_path)

    result = stop_lab(
        remove_volumes=True,
        project_dir=tmp_path,
        backend=_Backend(LabResult(success=True)),
    )

    assert result.success is False
    assert result.error.startswith("[lifecycle-host-cleanup-pending]")
    assert "Docker teardown completed" in result.error
    assert "1 host-side cleanup action remains pending" in result.error
    assert "pack.reset for otherpack 1.0.0" in result.error
    assert "provider-reset-authority-unavailable" in result.error
    assert "aptl lab stop -v --yes" in result.error
    # Independent APTL-owned work still completed.
    assert not baseline.exists()


def test_stop_distinguishes_docker_failure_from_pending_host_cleanup(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lab import stop_lab

    _no_installed_providers(monkeypatch)
    _legacy(tmp_path)
    baseline = _baseline(tmp_path)

    result = stop_lab(
        remove_volumes=True,
        project_dir=tmp_path,
        backend=_Backend(LabResult(success=False, error="volume still in use")),
    )

    assert result.success is False
    assert result.error.startswith("[lifecycle-docker-teardown-failed]")
    assert "volume still in use" in result.error
    assert "Host-side cleanup was not attempted" in result.error
    assert "1 action remains pending" in result.error
    assert "aptl lab stop -v --yes" in result.error
    assert baseline.exists()
    assert not (tmp_path / LEGACY_DONE_DIR).exists()


def test_repeat_stop_finishes_pending_cleanup_when_docker_is_already_gone(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lab import stop_lab

    _no_installed_providers(monkeypatch)
    _write_record(tmp_path, LEGACY_DIR, RECEIPT_5_5_0)
    baseline = _baseline(tmp_path)
    backend = _Backend(LabResult(success=True))

    first = stop_lab(remove_volumes=True, project_dir=tmp_path, backend=backend)
    second = stop_lab(remove_volumes=True, project_dir=tmp_path, backend=backend)

    assert first.success is True
    assert second.success is True
    assert not baseline.exists()
    assert len(list((tmp_path / LEGACY_DONE_DIR).iterdir())) == 1


def test_start_persists_aptl_owned_and_declared_pack_cleanup(tmp_path: Path) -> None:
    from aptl.backends.scenario_startup import (
        ScenarioStartupPlan,
        ScenarioStartupSelection,
        StartupHook,
        StartupProviderProvenance,
    )
    from aptl.core.config import AptlConfig
    from aptl.core.lab import StartSelection, _LabStartContext, _persist_start_recovery
    from aptl.core.scenario_bundle import (
        PackIdentity,
        ScenarioBundle,
        ScenarioSourceKind,
    )
    from aptl.core.startup_reset_state import load_pending_cleanup

    identity = PackIdentity("otherpack", "1.0.0", OTHER_DIGEST)
    plan = ScenarioStartupPlan(
        "scripts/seed.sh",
        ("blue-team",),
        ("blue-team",),
        startup_hooks=frozenset({StartupHook.RESET}),
    )
    selection = ScenarioStartupSelection(
        identity,
        object(),
        plan,
        StartupProviderProvenance("otherpack-adapter", "1.0.0", "otherpack"),
    )
    bundle = ScenarioBundle(
        "otherpack",
        tmp_path,
        tmp_path / "otherpack.sdl.yaml",
        ScenarioSourceKind.ENV_PACK,
        identity,
    )
    ctx = _LabStartContext(tmp_path, skip_seed=False)
    ctx.selected_profiles = ["blue-team"]
    ctx.start_selection = StartSelection(AptlConfig(), bundle, plan, selection)

    assert _persist_start_recovery(ctx) is None

    pending, malformed = load_pending_cleanup(tmp_path)
    assert malformed == ()
    assert sorted(item.action.action for item in pending) == [
        "aptl.wazuh-enrollment-baseline.clear",
        "pack.reset",
    ]
    assert {item.action.pack_set_digest for item in pending} == {OTHER_DIGEST}
    assert not (tmp_path / LEGACY_DIR).exists()


def test_start_without_pack_still_records_aptl_owned_cleanup(tmp_path: Path) -> None:
    from aptl.core.lab import _LabStartContext, _persist_start_recovery
    from aptl.core.startup_reset_state import load_pending_cleanup

    ctx = _LabStartContext(tmp_path, skip_seed=False)
    ctx.selected_profiles = ["wazuh"]

    assert _persist_start_recovery(ctx) is None

    pending, _ = load_pending_cleanup(tmp_path)
    assert [(item.action.action, item.action.pack_id) for item in pending] == [
        ("aptl.wazuh-enrollment-baseline.clear", "")
    ]


def test_techvault_adapter_no_longer_owns_aptl_host_state() -> None:
    from aptl_techvault.startup import TechVaultStartupProvider

    assert not hasattr(TechVaultStartupProvider, "reset")


def test_start_fails_closed_when_cleanup_cannot_be_recorded(tmp_path: Path) -> None:
    from aptl.core.lab import _LabStartContext, _persist_start_recovery

    ctx = _LabStartContext(tmp_path, skip_seed=False)
    ctx.selected_profiles = ["wazuh"]
    (tmp_path / ".aptl" / "lifecycle").mkdir(parents=True)
    (tmp_path / ACTION_DIR).symlink_to(tmp_path)

    result = _persist_start_recovery(ctx)

    assert result is not None
    assert result.success is False
    assert "pending lab cleanup records" in result.error


def test_invalid_completion_markers_are_reported_not_ignored(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core.lifecycle_cleanup import run_pending_cleanup

    _no_installed_providers(monkeypatch)
    done = tmp_path / LEGACY_DONE_DIR
    done.mkdir(parents=True)
    stray = done / "hand-edited.json"
    stray.write_bytes(b"{}\n")
    orphan = done / ("9" * 64 + ".json")
    orphan.write_bytes(b"{}\n")
    valid = _legacy(tmp_path)

    report = run_pending_cleanup(tmp_path, object())

    assert report.completed == 1
    assert (done / valid.name).exists()
    assert sorted((item.record, item.reason) for item in report.pending) == [
        (f"startup-reset-completed-v1/{'9' * 12}", "cleanup-record-malformed"),
        ("startup-reset-completed-v1/hand-edited.json", "cleanup-record-malformed"),
    ]
    assert stray.read_bytes() == orphan.read_bytes() == b"{}\n"
