"""CLI tests for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.persistence import persist_seat_record
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.cli.main import app
from aptl.cli.seat import DEFAULT_SEAT_IMAGE

runner = CliRunner()


def _seat_record() -> SeatRecord:
    return SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/brad-edwards/aptl-seat:latest",
        image_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
        "--image",
        "ghcr.io/brad-edwards/aptl-seat:latest",
        "--image-cache",
        "/tmp/image-cache",
    ]


def test_seat_help_lists_supported_commands() -> None:
    result = runner.invoke(app, ["seat", "--help"])

    assert result.exit_code == 0
    assert "stage" in result.stdout
    assert "reset" in result.stdout
    assert "recover" in result.stdout
    assert "open-kiosk" in result.stdout
    assert "update" in result.stdout
    assert "images" in result.stdout
    # There is nothing to install: a start pulls what it needs.
    assert "install" not in result.stdout


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
            image_reference="",
            image_digest="",
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


def test_seat_stage_resolves_relative_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    record = _seat_record().model_copy(update={"lifecycle_state": "staged"})
    with patch("aptl.cli.seat.stage_seat", return_value=record) as stage:
        result = runner.invoke(
            app,
            ["seat", "stage", "--seat-root", "relative-seat", *_common_seat_args()[2:]],
        )

    assert result.exit_code == 0, result.output
    assert stage.call_args.args[0] == tmp_path / "relative-seat"


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
        patch("aptl.cli.seat.image_requires_host_access", return_value=False),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()),
    ):
        result = runner.invoke(app, ["seat", "start", *_common_seat_args()])

    assert result.exit_code == 0
    assert '"started":true' in result.stdout.replace(" ", "")


def test_seat_start_needs_no_arguments_at_all(tmp_path: Path) -> None:
    # The whole point: a bare `aptl seat start` pulls the published image into
    # the current user's private cache and runs it. No release directory, no
    # trust anchors, no install step.
    state_home = tmp_path / "state"
    cache_home = tmp_path / "cache"
    seat_root = state_home / "aptl" / "seat"
    with (
        patch("aptl.cli.seat.image_requires_host_access", return_value=False),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()) as start,
    ):
        result = runner.invoke(
            app,
            ["seat", "start"],
            env={
                "XDG_STATE_HOME": str(state_home),
                "XDG_CACHE_HOME": str(cache_home),
            },
        )

    assert result.exit_code == 0, result.output
    assert start.call_args.args == (seat_root,)
    assert start.call_args.kwargs["image_reference"] == DEFAULT_SEAT_IMAGE
    assert (
        start.call_args.kwargs["image_cache_dir"] == cache_home / "aptl" / "appliance"
    )


def test_seat_start_cannot_adopt_an_image_update() -> None:
    result = runner.invoke(app, ["seat", "start", "--update"])

    assert result.exit_code == 2
    assert "No such option: --update" in result.output


def test_seat_start_accepts_another_image_source(tmp_path: Path) -> None:
    with (
        patch("aptl.cli.seat.image_requires_host_access", return_value=False),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()) as start,
    ):
        result = runner.invoke(
            app,
            ["seat", "start", "--image", "registry.example/mine/seat:pinned"],
            env={"XDG_STATE_HOME": str(tmp_path / "state")},
        )

    assert result.exit_code == 0, result.output
    assert (
        start.call_args.kwargs["image_reference"] == "registry.example/mine/seat:pinned"
    )


def test_seat_start_auto_enrolls_current_user_for_required_host_access(
    tmp_path: Path,
) -> None:
    state_home = tmp_path / "state"
    seat_root = state_home / "aptl" / "seat"
    private = seat_root / "access" / "transport-key"
    public = seat_root / "access" / "transport-key.pub"
    public.parent.mkdir(parents=True)
    private.write_text("private")
    public.write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZhY2lsaXRhdG9yLXRlc3Qta2V5"
    )
    with (
        patch("aptl.cli.seat.image_requires_host_access", return_value=True),
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


def test_seat_start_resolves_explicit_host_client_paths(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    public = tmp_path / "caller.pub"
    identity = tmp_path / "caller"
    project = tmp_path / "client"
    public.write_text("ssh-ed25519 " + "a" * 64)
    identity.write_text("private")
    project.mkdir()
    with (
        patch("aptl.cli.seat.image_requires_host_access", return_value=True),
        patch("aptl.cli.seat.start_seat", return_value=_seat_record()) as start,
    ):
        result = runner.invoke(
            app,
            [
                "seat",
                "start",
                *_common_seat_args(),
                "--access-owner",
                "operator",
                "--access-public-key",
                public.name,
                "--access-identity-file",
                identity.name,
                "--access-project-dir",
                project.name,
            ],
        )

    assert result.exit_code == 0, result.output
    options = start.call_args.kwargs["options"]
    assert options.access_identity_file == identity
    assert options.access_project_dir == project


def test_seat_start_error_is_bounded() -> None:
    with (
        patch("aptl.cli.seat.image_requires_host_access", return_value=False),
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
    assert "http://127.0.0.1:443/" in result.stdout


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
    assert "http://127.0.0.1:10443/" in result.stdout
