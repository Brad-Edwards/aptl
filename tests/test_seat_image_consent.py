"""Consent must precede any registry access from the operator CLI."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app
from aptl.appliance.seat.image import SeatImageError


@pytest.mark.parametrize("command", ["stage", "start", "reset", "recover", "update"])
@pytest.mark.parametrize("reply", ["n\n", ""])
def test_refusal_and_eof_do_not_contact_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, reply: str
) -> None:
    monkeypatch.chdir(tmp_path)
    network = Mock(side_effect=AssertionError("download without consent"))
    monkeypatch.setattr("aptl.appliance.seat.image.fetch_https_metadata", network)
    result = CliRunner().invoke(
        app,
        ["seat", command, "--image-cache", str(tmp_path / "cache")],
        input=reply,
        env={"XDG_STATE_HOME": str(tmp_path / "state")},
    )
    assert network.call_count == 0
    assert result.exit_code != 0
    assert "[y/N]" in result.output
    assert not (tmp_path / "cache").exists()


@pytest.mark.parametrize("approval", [["--yes"], ["-y"], []])
def test_explicit_approval_allows_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, approval: list[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    download = Mock(side_effect=SeatImageError("fixture acquisition attempted"))
    monkeypatch.setattr("aptl.appliance.seat.image_selection.resolve_seat_image", download)
    result = CliRunner().invoke(
        app,
        ["seat", "stage", "--image-cache", str(tmp_path / "cache"), *approval],
        input="y\n",
        env={"XDG_STATE_HOME": str(tmp_path / "state")},
    )
    assert download.call_count == 1
    assert "fixture acquisition attempted" in result.output


def test_configured_source_never_falls_back_to_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    reference = "registry.example/operator/seat:pinned"
    (tmp_path / "aptl.json").write_text(
        '{"seat":{"image":"' + reference + '"}}'
    )
    download = Mock(side_effect=SeatImageError("fixture acquisition attempted"))
    monkeypatch.setattr("aptl.appliance.seat.image_selection.resolve_seat_image", download)
    result = CliRunner().invoke(
        app, ["seat", "stage", "--yes", "--image-cache", str(tmp_path / "cache")],
        env={"XDG_STATE_HOME": str(tmp_path / "state")},
    )
    assert download.call_count == 1, result.output
    assert str(download.call_args.args[0]) == reference


def test_declining_alternate_image_does_not_persist_its_trust(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    key = tmp_path / "publisher.pub"
    key.write_text("not read before consent")
    result = CliRunner().invoke(
        app, ["seat", "stage", "--image", "registry.example/seat:stable",
              "--public-key", str(key), "--image-cache", str(tmp_path / "cache")],
        input="n\n", env={"XDG_STATE_HOME": str(tmp_path / "state")},
    )
    assert "[y/N]" in result.output
    assert not (tmp_path / "cache").exists()


@pytest.mark.parametrize("command", ["stage", "start"])
def test_invalid_mapping_is_rejected_before_acquisition(tmp_path, monkeypatch, command):
    acquisition = Mock()
    monkeypatch.setattr("aptl.cli.seat._prepare_seat_image", acquisition)
    result = CliRunner().invoke(app, ["seat", command, "--seat-root", str(tmp_path / "seat"),
                                 "--mapping", "invalid", "--yes"])
    assert result.exit_code == 2
    acquisition.assert_not_called()
