"""CLI tests for appliance build, seal, verify, and guest bootstrap."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aptl.appliance.build import GoldenImageBuildRequest
from aptl.appliance.manifest import ApplianceReleaseInspection
from aptl.cli.main import app
from aptl.core.lab_types import LabResult

runner = CliRunner()


def test_appliance_help_lists_local_overlay_creation() -> None:
    result = runner.invoke(app, ["appliance", "--help"])

    assert result.exit_code == 0
    assert "create-overlay" in result.stdout
    assert "prepare-launch" in result.stdout


def test_appliance_verify_and_inspect_emit_only_safe_release_projection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    release = tmp_path / "release"
    release.mkdir()
    public_key = tmp_path / "release-public.pem"
    public_key.write_text("public")
    qualification_key = tmp_path / "qualification-public.pem"
    qualification_key.write_text("qualification")
    inspection = ApplianceReleaseInspection(
        release_id="aptl-v5.1.1-x86_64",
        aptl_version="5.1.1",
        source_commit="1" * 40,
        manifest_digest="sha256:" + "a" * 64,
        payload_digest="sha256:" + "b" * 64,
        artifact_count=9,
        architecture="x86_64",
        minimum_host_vcpus=8,
        minimum_host_memory_bytes=16 * 1024**3,
        minimum_host_disk_bytes=100 * 1024**3,
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.verify_release_directory",
        lambda release_dir, public_key_path, **kwargs: inspection,
    )

    verified = runner.invoke(
        app,
        [
            "appliance",
            "verify",
            "--release-dir",
            str(release),
            "--public-key",
            str(public_key),
            "--qualification-public-key",
            str(qualification_key),
        ],
    )
    inspected = runner.invoke(
        app,
        [
            "appliance",
            "inspect",
            "--release-dir",
            str(release),
            "--public-key",
            str(public_key),
            "--qualification-public-key",
            str(qualification_key),
        ],
    )

    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.stdout)["passed"] is True
    projection = json.loads(inspected.stdout)
    assert projection["release_id"] == inspection.release_id
    assert projection["aptl_version"] == inspection.aptl_version
    assert projection["payload_digest"] == inspection.payload_digest
    assert "artifacts/" not in inspected.stdout
    assert "machine_id" not in inspected.stdout
    assert "credential" not in inspected.stdout


def test_appliance_build_reports_bounded_failure_without_tool_stderr(
    tmp_path: Path,
    monkeypatch,
) -> None:
    base = tmp_path / "inputs/base.qcow2"
    payload = tmp_path / "inputs/offline-payload.tar"
    provisioner = tmp_path / "inputs/provision-offline.sh"
    scanner = tmp_path / "inputs/scan-golden.sh"
    base.parent.mkdir()
    base.write_bytes(b"pinned")
    payload.write_bytes(b"offline")
    provisioner.write_text("#!/bin/sh\n")
    scanner.write_text("#!/bin/sh\n")
    request = GoldenImageBuildRequest(
        schema_version="aptl.golden-image-build/v1",
        base_image_path="inputs/base.qcow2",
        base_image_digest=f"sha256:{hashlib.sha256(base.read_bytes()).hexdigest()}",
        offline_payload_path="inputs/offline-payload.tar",
        offline_payload_digest=(
            f"sha256:{hashlib.sha256(payload.read_bytes()).hexdigest()}"
        ),
        provisioner_path="inputs/provision-offline.sh",
        provisioner_digest=(
            f"sha256:{hashlib.sha256(provisioner.read_bytes()).hexdigest()}"
        ),
        scanner_path="inputs/scan-golden.sh",
        scanner_digest=f"sha256:{hashlib.sha256(scanner.read_bytes()).hexdigest()}",
        output_image_path="output/aptl-golden.qcow2",
        inventory_output_path="output/golden-inventory.json",
        virtual_size_bytes=120 * 1024**3,
    )
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json())
    fake_tools = tmp_path / "fake-tools"
    fake_tools.mkdir()
    qemu_img = fake_tools / "qemu-img"
    qemu_img.write_text(
        "#!/bin/sh\necho 'unsafe raw detail from qemu-img' >&2\nexit 1\n"
    )
    qemu_img.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_tools}:{os.environ['PATH']}")

    result = runner.invoke(
        app,
        [
            "appliance",
            "build",
            "--build-root",
            str(tmp_path),
            "--request",
            str(request_path),
        ],
    )

    assert result.exit_code == 2
    assert result.stderr == "error: golden image build failed\n"
    assert "unsafe raw detail" not in result.output


def test_appliance_bootstrap_command_never_prints_the_credential(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"

    first = runner.invoke(
        app,
        [
            "appliance",
            "bootstrap-overlay",
            "--state-dir",
            str(state_dir),
        ],
    )
    credential = json.loads((state_dir / "identity.json").read_text())[
        "bootstrap_credential"
    ]
    second = runner.invoke(
        app,
        [
            "appliance",
            "bootstrap-overlay",
            "--state-dir",
            str(state_dir),
        ],
    )

    assert first.exit_code == second.exit_code == 0
    assert credential not in first.output
    assert credential not in second.output
    assert json.loads(first.stdout)["initialized"] is True
    assert json.loads(second.stdout)["initialized"] is True


def test_lab_start_forwards_offline_staged_mode(tmp_path: Path, monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_start(project_dir, **kwargs):
        calls.append({"project_dir": project_dir, **kwargs})
        return LabResult(success=True, message="ready")

    monkeypatch.setattr("aptl.cli.lab.orchestrate_lab_start", fake_start)
    monkeypatch.setattr(
        "aptl.cli.lab.resolve_scenario_selection",
        lambda *args, **kwargs: None,
    )

    result = runner.invoke(
        app,
        [
            "lab",
            "start",
            "--project-dir",
            str(tmp_path),
            "--offline-staged",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["appliance"].offline_staged is True


@pytest.mark.parametrize(
    "launch_args",
    [
        ["--appliance-launch-descriptor", "launch.json"],
        ["--appliance-release-public-key", "release-public.pem"],
        ["--appliance-qualification-public-key", "qualification-public.pem"],
        [
            "--appliance-launch-descriptor",
            "launch.json",
            "--appliance-release-public-key",
            "release-public.pem",
        ],
        [
            "--appliance-launch-descriptor",
            "launch.json",
            "--appliance-qualification-public-key",
            "qualification-public.pem",
        ],
        [
            "--appliance-release-public-key",
            "release-public.pem",
            "--appliance-qualification-public-key",
            "qualification-public.pem",
        ],
        [
            "--appliance-launch-descriptor",
            "launch.json",
            "--appliance-release-public-key",
            "release-public.pem",
            "--appliance-qualification-public-key",
            "qualification-public.pem",
        ],
    ],
)
def test_lab_start_rejects_partial_or_online_appliance_launch(
    tmp_path: Path,
    monkeypatch,
    launch_args: list[str],
) -> None:
    monkeypatch.setattr(
        "aptl.cli.lab.resolve_scenario_selection",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "aptl.cli.lab.orchestrate_lab_start",
        lambda *args, **kwargs: pytest.fail("invalid launch reached orchestration"),
    )

    result = runner.invoke(
        app,
        ["lab", "start", "--project-dir", str(tmp_path), *launch_args],
    )

    assert result.exit_code == 2
    assert result.stderr == (
        "error: appliance launch requires both trust anchors and --offline-staged\n"
    )
