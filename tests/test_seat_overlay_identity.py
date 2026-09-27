"""A disposable seat keeps one private identity across its own reboots."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from aptl.appliance.seat import overlay_identity
from aptl.appliance.seat.overlay_identity import (
    ApplianceBootstrapError,
    initialize_overlay_state,
)


def test_identity_is_created_once_and_reused_without_new_entropy(tmp_path: Path) -> None:
    calls = iter((b"i" * 32, b"c" * 32))
    state = tmp_path / "seat-state"
    created = initialize_overlay_state(state, entropy=lambda _size: next(calls))

    def no_new_entropy(_size: int) -> bytes:
        pytest.fail("reboot generated a new overlay identity")

    restored = initialize_overlay_state(state, entropy=no_new_entropy)

    assert restored == created
    assert created.instance_id.startswith("sha256:")
    assert len(created.bootstrap_credential) == 43
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "identity.json").stat().st_mode) == 0o600


def test_state_directory_rejects_symlink_and_broad_permissions(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ApplianceBootstrapError, match="must not be a symlink"):
        initialize_overlay_state(link)

    target.chmod(0o755)
    with pytest.raises(ApplianceBootstrapError, match="owner-only"):
        initialize_overlay_state(target)


def test_existing_identity_rejects_symlink_and_changed_permissions(
    tmp_path: Path,
) -> None:
    state = tmp_path / "seat-state"
    initialize_overlay_state(state)
    identity = state / "identity.json"
    saved = identity.read_bytes()
    identity.unlink()
    target = tmp_path / "outside.json"
    target.write_bytes(saved)
    identity.symlink_to(target)

    with pytest.raises(ApplianceBootstrapError, match="must not be a symlink"):
        initialize_overlay_state(state)

    identity.unlink()
    identity.write_bytes(saved)
    identity.chmod(0o644)
    with pytest.raises(ApplianceBootstrapError, match="owner-only"):
        initialize_overlay_state(state)


def test_existing_identity_rejects_malformed_content(tmp_path: Path) -> None:
    state = tmp_path / "seat-state"
    initialize_overlay_state(state)
    identity = state / "identity.json"
    payload = json.loads(identity.read_text())
    payload["bootstrap_credential"] = "invalid"
    identity.write_text(json.dumps(payload))

    with pytest.raises(ApplianceBootstrapError, match="identity is invalid"):
        initialize_overlay_state(state)


def test_short_entropy_is_rejected_before_persisting(tmp_path: Path) -> None:
    state = tmp_path / "seat-state"
    with pytest.raises(ApplianceBootstrapError, match="entropy source"):
        initialize_overlay_state(state, entropy=lambda _size: b"short")
    assert not (state / "identity.json").exists()


def test_concurrent_initializer_uses_the_identity_that_won(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "seat-state"
    winner = overlay_identity._new_identity(lambda _size: b"w" * 32)

    def lost_race(path: Path, _candidate: object) -> bool:
        path.write_bytes(winner.model_dump_json().encode())
        path.chmod(0o600)
        return False

    monkeypatch.setattr(overlay_identity, "_persist_create_once", lost_race)
    restored = initialize_overlay_state(state, entropy=lambda _size: b"l" * 32)
    assert restored == winner
