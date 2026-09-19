"""CLI tests for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.persistence import persist_seat_record
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.cli.main import app

runner = CliRunner()


def _seat_record() -> SeatRecord:
    return SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        selected_release_id="aptl-v1",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )


def _common_seat_args() -> list[str]:
    return [
        "--seat-root",
        "/tmp/seat",
        "--release-dir",
        "/tmp/release",
        "--release-public-key",
        "/tmp/release.pem",
        "--qualification-public-key",
        "/tmp/qualification.pem",
    ]


def test_seat_help_lists_supported_commands() -> None:
    result = runner.invoke(app, ["seat", "--help"])

    assert result.exit_code == 0
    assert "stage" in result.stdout
    assert "reset" in result.stdout
    assert "recover" in result.stdout
    assert "open-kiosk" in result.stdout
    assert "install" in result.stdout


def test_seat_install_targets_private_default_layout(tmp_path: Path) -> None:
    state_home = tmp_path / "state"
    cache_home = tmp_path / "cache"
    release_key = tmp_path / "release.pem"
    qualification_key = tmp_path / "qualification.pem"
    release_key.write_text("release")
    qualification_key.write_text("qualification")
    installed = __import__(
        "aptl.appliance.public_install", fromlist=["PublicReleaseInstallResult"]
    ).PublicReleaseInstallResult(
        release_id="aptl-v5.5.0-x86_64",
        release_dir=state_home / "aptl" / "seat" / "launch" / "release",
        reused=False,
    )
    with patch(
        "aptl.cli.seat.install_public_release", return_value=installed
    ) as install:
        result = runner.invoke(
            app,
            [
                "seat",
                "install",
                "--tag",
                "v5.5.0",
                "--release-public-key",
                str(release_key),
                "--qualification-public-key",
                str(qualification_key),
            ],
            env={
                "XDG_STATE_HOME": str(state_home),
                "XDG_CACHE_HOME": str(cache_home),
            },
        )

    assert result.exit_code == 0, result.output
    assert install.call_args.kwargs["seat_root"] == state_home / "aptl" / "seat"
    assert install.call_args.kwargs["cache_dir"] == cache_home / "aptl" / "appliance"
    assert install.call_args.kwargs["selection"].release_id == "aptl-v5.5.0-x86_64"


def test_seat_status_emits_bounded_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["seat", "status", "--seat-root", str(tmp_path)])

    assert result.exit_code == 0
    assert "lifecycle_state" in result.stdout
    assert "credential" not in result.stdout.lower()


def test_seat_status_uses_owner_state_directory_by_default(tmp_path: Path) -> None:
    state_home = tmp_path / "state"
    with patch("aptl.cli.seat.status_seat") as status:
        status.return_value = __import__(
            "aptl.appliance.seat.models", fromlist=["SeatStatusProjection"]
        ).SeatStatusProjection(
            seat_id="",
            lifecycle_state="empty",
            taint_state="clean",
            selected_release_id="",
            launch_descriptor_digest="",
            host_observation_id="",
        )
        result = runner.invoke(
            app,
            ["seat", "status"],
            env={"XDG_STATE_HOME": str(state_home)},
        )

    assert result.exit_code == 0, result.output
    status.assert_called_once_with(state_home / "aptl" / "seat")


def test_seat_stage_error_is_bounded() -> None:
    with patch(
        "aptl.cli.seat.stage_seat",
        side_effect=__import__(
            "aptl.appliance.seat.errors", fromlist=["SeatLauncherError"]
        ).SeatLauncherError("no-kvm", "hardware virtualization is unavailable"),
    ):
        result = runner.invoke(app, ["seat", "stage", *_common_seat_args()])

    assert result.exit_code == 2
    assert "no-kvm" in result.stderr
    assert "qemu-img" not in result.stderr


def test_seat_stage_success_emits_json() -> None:
    record = _seat_record().model_copy(update={"lifecycle_state": "staged"})
    with patch("aptl.cli.seat.stage_seat", return_value=record):
        result = runner.invoke(app, ["seat", "stage", *_common_seat_args()])

    assert result.exit_code == 0
    assert '"staged":true' in result.stdout.replace(" ", "")


def test_seat_stage_parses_typed_outer_mapping() -> None:
    record = _seat_record().model_copy(update={"lifecycle_state": "staged"})
    with patch("aptl.cli.seat.stage_seat", return_value=record) as stage:
        result = runner.invoke(
            app,
            [
                "seat",
                "stage",
                *_common_seat_args(),
                "--mapping",
                "participant,tcp,127.0.0.1,10443,127.0.0.1,443",
            ],
        )

    assert result.exit_code == 0, result.output
    mapping = stage.call_args.kwargs["mappings"][0]
    assert mapping == BoundaryEndpoint(
        audience="participant",
        protocol="tcp",
        address="127.0.0.1",
        port=10443,
        guest_address="127.0.0.1",
        guest_port=443,
    )


def test_seat_stage_rejects_invalid_outer_mapping() -> None:
    result = runner.invoke(
        app,
        [
            "seat",
            "stage",
            *_common_seat_args(),
            "--mapping",
            "participant,tcp,127.0.0.1,not-a-port,127.0.0.1,443",
        ],
    )

    assert result.exit_code == 2
    assert "invalid-mapping" in result.stderr


def test_seat_start_success_emits_json() -> None:
    with (
        patch("aptl.cli.seat.release_requires_host_access", return_value=False),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()),
    ):
        result = runner.invoke(app, ["seat", "start", *_common_seat_args()])

    assert result.exit_code == 0
    assert '"started":true' in result.stdout.replace(" ", "")


def test_seat_start_uses_installed_release_and_owner_state_by_default(
    tmp_path: Path,
) -> None:
    state_home = tmp_path / "state"
    seat_root = state_home / "aptl" / "seat"
    with (
        patch("aptl.cli.seat.release_requires_host_access", return_value=False),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()) as start,
    ):
        result = runner.invoke(
            app,
            ["seat", "start"],
            env={"XDG_STATE_HOME": str(state_home)},
        )

    assert result.exit_code == 0, result.output
    assert start.call_args.args == (seat_root,)
    assert start.call_args.kwargs["release_dir"] == seat_root / "launch" / "release"
    assert (
        start.call_args.kwargs["release_public_key"]
        == seat_root / "launch" / "release-public.pem"
    )
    assert (
        start.call_args.kwargs["qualification_public_key"]
        == seat_root / "launch" / "qualification-public.pem"
    )


def test_seat_start_auto_enrolls_current_user_for_required_host_access(
    tmp_path: Path,
) -> None:
    state_home = tmp_path / "state"
    seat_root = state_home / "aptl" / "seat"
    private = seat_root / "access" / "transport-key"
    public = seat_root / "access" / "transport-key.pub"
    public.parent.mkdir(parents=True)
    public.write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZhY2lsaXRhdG9yLXRlc3Qta2V5"
    )
    with (
        patch("aptl.cli.seat.release_requires_host_access", return_value=True),
        patch(
            "aptl.cli.seat.ensure_transport_identity",
            return_value=(private, public),
        ),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()) as start,
    ):
        result = runner.invoke(
            app,
            ["seat", "start"],
            env={"XDG_STATE_HOME": str(state_home)},
        )

    assert result.exit_code == 0, result.output
    options = start.call_args.kwargs["options"]
    assert options.access_enrollment is not None
    assert options.access_identity_file == private
    assert options.access_project_dir == Path.cwd()
    assert options.access_clients == ("claude", "codex")


def test_seat_start_error_is_bounded() -> None:
    with (
        patch("aptl.cli.seat.release_requires_host_access", return_value=False),
        patch(
            "aptl.cli.seat.start_seat",
            side_effect=__import__(
                "aptl.appliance.seat.errors", fromlist=["SeatLauncherError"]
            ).SeatLauncherError(
                "boundary.host-listener-missing", "host boundary inventory failed"
            ),
        ),
    ):
        result = runner.invoke(app, ["seat", "start", *_common_seat_args()])

    assert result.exit_code == 2
    assert "boundary.host-listener-missing" in result.stderr


def test_seat_stop_success_emits_json() -> None:
    with patch(
        "aptl.cli.seat.stop_seat",
        return_value=_seat_record().model_copy(update={"lifecycle_state": "staged"}),
    ):
        result = runner.invoke(app, ["seat", "stop", "--seat-root", "/tmp/seat"])

    assert result.exit_code == 0
    assert '"stopped":true' in result.stdout.replace(" ", "")


def test_seat_reset_and_recover_success_emit_json() -> None:
    staged = _seat_record().model_copy(update={"lifecycle_state": "staged"})
    with patch("aptl.cli.seat.reset_seat", return_value=staged):
        reset = runner.invoke(app, ["seat", "reset", *_common_seat_args()])
    with patch("aptl.cli.seat.recover_seat", return_value=_seat_record()):
        recover = runner.invoke(app, ["seat", "recover", *_common_seat_args()])

    assert reset.exit_code == 0
    assert '"reset":true' in reset.stdout.replace(" ", "")
    assert recover.exit_code == 0
    assert '"recovered":true' in recover.stdout.replace(" ", "")


def test_seat_reconcile_success_emits_json() -> None:
    with patch(
        "aptl.cli.seat.reconcile_seat_after_reboot",
        return_value=_seat_record().model_copy(update={"host_boot_id": "boot-2"}),
    ):
        result = runner.invoke(app, ["seat", "reconcile", "--seat-root", "/tmp/seat"])

    assert result.exit_code == 0
    assert '"reconciled":true' in result.stdout.replace(" ", "")


def test_open_kiosk_dry_run_does_not_spawn_browser() -> None:
    with patch("aptl.appliance.seat.kiosk.subprocess.Popen") as popen:
        result = runner.invoke(
            app,
            ["seat", "open-kiosk", "--dry-run"],
        )

    assert result.exit_code == 0
    popen.assert_not_called()
    assert "https://127.0.0.1:443/" in result.stdout


def test_open_kiosk_honors_browser_command() -> None:
    with patch("aptl.appliance.seat.kiosk.subprocess.Popen") as popen:
        result = runner.invoke(
            app,
            [
                "seat",
                "open-kiosk",
                "--browser-command",
                "/usr/bin/custom-browser",
                "--dry-run",
            ],
        )

    assert result.exit_code == 0
    popen.assert_not_called()
    assert "/usr/bin/custom-browser" in result.stdout


def test_open_kiosk_uses_persisted_participant_mapping(tmp_path: Path) -> None:
    mapping = BoundaryEndpoint(
        audience="participant",
        address="127.0.0.1",
        port=10443,
        protocol="tcp",
        guest_address="127.0.0.1",
        guest_port=443,
    )
    record = _seat_record().model_copy(
        update={
            "schema_version": "aptl.seat-record/v2",
            "mappings": (mapping,),
        }
    )
    persist_seat_record(tmp_path, record)

    result = runner.invoke(
        app,
        ["seat", "open-kiosk", "--seat-root", str(tmp_path), "--dry-run"],
    )

    assert result.exit_code == 0
    assert "https://127.0.0.1:10443/" in result.stdout
