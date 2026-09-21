"""CLI tests for appliance build, seal, verify, and guest bootstrap."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

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
    assert "doctor" in result.stdout
    assert "fetch-distribution" in result.stdout


@pytest.mark.parametrize("candidate_trust", [False, True])
def test_guest_proxy_uses_the_explicit_release_trust_mode(
    tmp_path: Path, monkeypatch, candidate_trust: bool
) -> None:
    from aptl.appliance import candidate

    calls: list[tuple[str, tuple[Path, ...]]] = []
    release = SimpleNamespace(boundary_policy=object())

    def production(*args: Path):
        calls.append(("production", args))
        return release

    def qualification(*args: Path):
        calls.append(("candidate", args))
        return release

    monkeypatch.setattr("aptl.cli.appliance.verify_launch_descriptor", production)
    monkeypatch.setattr(candidate, "verify_candidate_launch_descriptor", qualification)
    monkeypatch.setattr(
        "aptl.cli.appliance.build_proxy_bindings", lambda policy, **_: (policy,)
    )
    monkeypatch.setattr("aptl.cli.appliance.serve_proxy_bindings", lambda _: None)
    descriptor = tmp_path / "launch.json"
    public_key = tmp_path / "release.pem"
    qualification_key = tmp_path / "qualification.pem"
    command = [
        "appliance", "proxy-loopback", "--launch-descriptor", str(descriptor),
        "--release-public-key", str(public_key),
        "--qualification-public-key", str(qualification_key),
    ]
    if candidate_trust:
        command.append("--candidate-trust")

    result = runner.invoke(app, command)

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "candidate" if candidate_trust else "production",
            (descriptor, public_key)
            if candidate_trust
            else (descriptor, public_key, qualification_key),
        )
    ]


def test_appliance_doctor_reports_missing_build_tools_without_installing(
    tmp_path: Path, monkeypatch
) -> None:
    report = SimpleNamespace(
        passed=False,
        findings=(
            SimpleNamespace(code="missing-virt-customize", passed=False),
            SimpleNamespace(code="missing-virt-sysprep", passed=False),
        ),
    )
    monkeypatch.setattr("aptl.cli.appliance.check_build_host", lambda **_: report)

    result = runner.invoke(
        app,
        ["appliance", "doctor", "--build-root", str(tmp_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "passed": False,
        "findings": [
            {"code": "missing-virt-customize", "passed": False},
            {"code": "missing-virt-sysprep", "passed": False},
        ],
    }


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


def test_lab_start_forwards_guest_readiness_channel(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[dict[str, object]] = []

    def fake_start(project_dir, **kwargs):
        calls.append({"project_dir": project_dir, **kwargs})
        return LabResult(success=True, message="ready")

    monkeypatch.setattr("aptl.cli.lab.orchestrate_lab_start", fake_start)
    monkeypatch.setattr(
        "aptl.cli.lab.resolve_scenario_selection",
        lambda *args, **kwargs: None,
    )
    launch = tmp_path / "launch"
    result = runner.invoke(
        app,
        [
            "lab",
            "start",
            "--project-dir",
            str(tmp_path),
            "--offline-staged",
            "--appliance-launch-descriptor",
            str(launch / "appliance-launch.json"),
            "--appliance-release-public-key",
            str(launch / "release-public.pem"),
            "--appliance-qualification-public-key",
            str(launch / "qualification-public.pem"),
            "--appliance-readiness-challenge",
            str(launch / "readiness-challenge.json"),
            "--appliance-readiness-device",
            "/dev/virtio-ports/org.aptl.readiness",
        ],
    )

    assert result.exit_code == 0, result.output
    appliance = calls[0]["appliance"]
    assert appliance.readiness_challenge == launch / "readiness-challenge.json"
    assert str(appliance.readiness_device).endswith("org.aptl.readiness")


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


def test_appliance_distribution_commands_emit_authenticated_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    digest = "sha256:" + "a" * 64
    downloaded = SimpleNamespace(
        path=tmp_path / "cache/artifact",
        reused=True,
        sha256=digest,
        size_bytes=7,
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.stage_https_artifact", lambda **kwargs: downloaded
    )
    staged = runner.invoke(
        app,
        [
            "appliance",
            "stage-download",
            "--url",
            "https://example.test/artifact",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--filename",
            "artifact",
            "--sha256",
            digest,
            "--size-bytes",
            "7",
        ],
    )
    assert staged.exit_code == 0, staged.output
    assert json.loads(staged.stdout)["reused"] is True

    split_result = SimpleNamespace(
        index=SimpleNamespace(artifact_sha256=digest, chunks=(1, 2)),
        index_path=tmp_path / "disk.index.json",
        signature_path=tmp_path / "disk.index.sig",
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.split_distribution_artifact",
        lambda **kwargs: split_result,
    )
    split = runner.invoke(
        app,
        [
            "appliance",
            "split-distribution",
            "--source",
            str(tmp_path / "disk.qcow2"),
            "--output-dir",
            str(tmp_path / "chunks"),
            "--release-id",
            "aptl-v1",
            "--manifest-digest",
            digest,
            "--private-key",
            str(tmp_path / "private.pem"),
            "--chunk-size",
            "1024",
        ],
    )
    assert split.exit_code == 0, split.output
    assert json.loads(split.stdout)["chunks"] == 2

    monkeypatch.setattr(
        "aptl.cli.appliance.reconstruct_distribution",
        lambda **kwargs: tmp_path / "reconstructed.qcow2",
    )
    reconstructed = runner.invoke(
        app,
        [
            "appliance",
            "reconstruct-distribution",
            "--index",
            str(tmp_path / "disk.index.json"),
            "--signature",
            str(tmp_path / "disk.index.sig"),
            "--chunks-dir",
            str(tmp_path / "chunks"),
            "--public-key",
            str(tmp_path / "public.pem"),
            "--output",
            str(tmp_path / "disk.qcow2"),
        ],
    )
    assert reconstructed.exit_code == 0, reconstructed.output
    assert json.loads(reconstructed.stdout)["output"] == "reconstructed.qcow2"

    monkeypatch.setattr(
        "aptl.cli.appliance.github_distribution_urls",
        lambda **kwargs: ("https://index", "https://signature", "https://chunks"),
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.fetch_distribution_artifact",
        lambda **kwargs: tmp_path / "public.qcow2",
    )
    fetched = runner.invoke(
        app,
        [
            "appliance",
            "fetch-distribution",
            "--repository",
            "owner/repository",
            "--tag",
            "v1",
            "--release-id",
            "aptl-v1",
            "--artifact-name",
            "disk.qcow2",
            "--public-key",
            str(tmp_path / "public.pem"),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(tmp_path / "public.qcow2"),
        ],
    )
    assert fetched.exit_code == 0, fetched.output
    assert json.loads(fetched.stdout)["output"].endswith("public.qcow2")


def test_appliance_build_planning_bundle_overlay_and_launch_wrappers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    digest = "sha256:" + "b" * 64
    monkeypatch.setattr(
        "aptl.cli.appliance.prepare_golden_image_request",
        lambda *args, **kwargs: SimpleNamespace(base_image_digest=digest),
    )
    planned = runner.invoke(
        app,
        [
            "appliance",
            "plan-build",
            "--build-root",
            str(tmp_path),
            "--base-image",
            "base.qcow2",
            "--offline-payload",
            "offline.tar",
            "--provisioner",
            "provision.sh",
            "--scanner",
            "scan.sh",
            "--output-image",
            "golden.qcow2",
            "--inventory-output",
            "inventory.json",
            "--request",
            "request.json",
        ],
    )
    assert planned.exit_code == 0, planned.output
    assert json.loads(planned.stdout)["base"] == digest

    monkeypatch.setattr(
        "aptl.cli.appliance.build_offline_payload",
        lambda *args: SimpleNamespace(sha256=digest, size_bytes=42),
    )
    bundled = runner.invoke(
        app,
        [
            "appliance",
            "bundle",
            "--staging-dir",
            str(tmp_path / "staging"),
            "--output",
            str(tmp_path / "offline.tar"),
        ],
    )
    assert bundled.exit_code == 0, bundled.output
    assert json.loads(bundled.stdout)["size_bytes"] == 42

    request = tmp_path / "overlay.json"
    request.write_text(
        json.dumps(
            {
                "schema_version": "aptl.overlay-create/v1",
                "golden_image_path": "golden.qcow2",
                "golden_image_digest": digest,
                "launch_descriptor_path": "launch.json",
                "launch_descriptor_digest": digest,
                "overlay_path": "instances/seat.qcow2",
            }
        )
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.create_disposable_overlay",
        lambda *args: SimpleNamespace(golden_image_digest=digest),
    )
    overlay = runner.invoke(
        app,
        [
            "appliance",
            "create-overlay",
            "--request",
            str(request),
            "--appliance-root",
            str(tmp_path),
        ],
    )
    assert overlay.exit_code == 0, overlay.output
    assert json.loads(overlay.stdout)["golden_image_digest"] == digest

    descriptor = SimpleNamespace(
        release_id="aptl-v1",
        manifest_digest=digest,
        payload_digest="sha256:" + "c" * 64,
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.prepare_launch_descriptor",
        lambda *args, **kwargs: descriptor,
    )
    launch = runner.invoke(
        app,
        [
            "appliance",
            "prepare-launch",
            "--release-dir",
            str(tmp_path / "release"),
            "--public-key",
            str(tmp_path / "release.pem"),
            "--qualification-public-key",
            str(tmp_path / "qualification.pem"),
            "--output",
            str(tmp_path / "launch.json"),
            "--host-observation-id",
            "host-1",
        ],
    )
    assert launch.exit_code == 0, launch.output
    assert json.loads(launch.stdout)["release_id"] == "aptl-v1"


def test_appliance_candidate_qualification_commands_project_safe_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from aptl.appliance import candidate, qualification

    digest = "sha256:" + "d" * 64
    monkeypatch.setattr(
        candidate,
        "prepare_candidate_manifest",
        lambda *args: SimpleNamespace(candidate_id="candidate-1"),
    )
    monkeypatch.setattr(
        candidate,
        "seal_candidate",
        lambda *args: SimpleNamespace(manifest_digest=digest),
    )
    monkeypatch.setattr(
        candidate,
        "verify_candidate_directory",
        lambda *args: (
            SimpleNamespace(candidate_id="candidate-1"),
            SimpleNamespace(manifest_digest=digest, payload_digest=digest),
        ),
    )
    monkeypatch.setattr(
        candidate,
        "prepare_candidate_launch_descriptor",
        lambda *args, **kwargs: SimpleNamespace(release_id="candidate-1"),
    )
    common = ["--candidate-dir", str(tmp_path / "candidate")]
    prepared = runner.invoke(
        app,
        ["appliance", "prepare-candidate", *common, "--template", "template.json"],
    )
    sealed = runner.invoke(
        app,
        ["appliance", "seal-candidate", *common, "--private-key", "private.pem"],
    )
    verified = runner.invoke(
        app,
        ["appliance", "verify-candidate", *common, "--public-key", "public.pem"],
    )
    launched = runner.invoke(
        app,
        [
            "appliance",
            "prepare-candidate-launch",
            *common,
            "--public-key",
            "public.pem",
            "--output",
            "launch.json",
            "--host-observation-id",
            "host-1",
        ],
    )
    assert [result.exit_code for result in (prepared, sealed, verified, launched)] == [
        0,
        0,
        0,
        0,
    ]
    assert json.loads(verified.stdout)["payload_digest"] == digest

    monkeypatch.setattr(
        qualification,
        "record_machine_drill",
        lambda **kwargs: SimpleNamespace(machine_id="machine-1"),
    )
    monkeypatch.setattr(
        qualification,
        "aggregate_machine_drills",
        lambda **kwargs: SimpleNamespace(machines=("machine-1", "machine-2")),
    )
    monkeypatch.setattr(
        qualification,
        "build_participant_qualification",
        lambda **kwargs: SimpleNamespace(profile_id="full-techvault"),
    )
    recorded = runner.invoke(
        app,
        [
            "appliance",
            "record-machine-drill",
            *common,
            "--candidate-public-key",
            "candidate.pem",
            "--seat-root",
            "seat-a",
            "--probe-receipt",
            "probe-a.json",
            "--failed-candidate-receipt",
            "failed.json",
            "--output",
            "machine.json",
        ],
    )
    aggregated = runner.invoke(
        app,
        [
            "appliance",
            "aggregate-machine-drills",
            *common,
            "--candidate-public-key",
            "candidate.pem",
            "--report",
            "machine-a.json",
            "--report",
            "machine-b.json",
            "--output",
            "drill.json",
        ],
    )
    qualified = runner.invoke(
        app,
        [
            "appliance",
            "build-participant-qualification",
            *common,
            "--candidate-public-key",
            "candidate.pem",
            "--runtime-evidence",
            "runtime.json",
            "--browser-probe",
            "browser.json",
            "--client-receipt",
            "claude.json",
            "--client-receipt",
            "codex.json",
            "--measurements",
            "measurements.json",
            "--qualification-private-key",
            "qualification.pem",
            "--output-dir",
            "evidence",
        ],
    )
    assert recorded.exit_code == aggregated.exit_code == qualified.exit_code == 0
    assert json.loads(aggregated.stdout)["machines"] == 2
    assert json.loads(qualified.stdout)["profile_id"] == "full-techvault"


def test_appliance_release_and_canonical_input_commands_emit_safe_projections(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from aptl.appliance import inputs
    from aptl.utils import deterministic_archive

    digest = "sha256:" + "e" * 64
    inspection = SimpleNamespace(
        release_id="aptl-v1",
        manifest_digest=digest,
        payload_digest="sha256:" + "f" * 64,
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.seal_release_directory",
        lambda *args, **kwargs: inspection,
    )
    sealed = runner.invoke(
        app,
        [
            "appliance",
            "seal",
            "--release-dir",
            str(tmp_path / "release"),
            "--private-key",
            str(tmp_path / "private.pem"),
            "--qualification-public-key",
            str(tmp_path / "qualification.pem"),
        ],
    )
    assert sealed.exit_code == 0, sealed.output
    assert json.loads(sealed.stdout)["manifest_digest"] == digest

    manifest = SimpleNamespace(
        release_id="aptl-v1",
        payload_digest=inspection.payload_digest,
        artifacts=(1, 2, 3),
    )
    monkeypatch.setattr(
        "aptl.cli.appliance.prepare_release_manifest", lambda *args: manifest
    )
    prepared = runner.invoke(
        app,
        [
            "appliance",
            "prepare",
            "--release-dir",
            str(tmp_path / "release"),
            "--template",
            str(tmp_path / "template.json"),
        ],
    )
    assert prepared.exit_code == 0, prepared.output
    assert json.loads(prepared.stdout)["artifact_count"] == 3

    image_roles = tmp_path / "image-roles.json"
    image_roles.write_text("{}")
    canonical = SimpleNamespace(schema_version="aptl.canonical-inputs/v1")
    monkeypatch.setattr(inputs, "stage_canonical_inputs", lambda **kwargs: canonical)
    monkeypatch.setattr(
        deterministic_archive, "hash_file_nofollow", lambda path: (digest, 10)
    )
    assembled = runner.invoke(
        app,
        [
            "appliance",
            "assemble-inputs",
            "--staging-dir",
            str(tmp_path / "staging"),
            "--wheelhouse",
            str(tmp_path / "wheelhouse"),
            "--image-archive",
            str(tmp_path / "images.tar"),
            "--image-roles",
            str(image_roles),
            "--system-packages",
            str(tmp_path / "system-packages"),
            "--system-packages-lock",
            str(tmp_path / "system-packages.sha256"),
            "--target-python-version",
            "3.12",
            "--target-architecture",
            "x86_64",
        ],
    )
    assert assembled.exit_code == 0, assembled.output
    assert json.loads(assembled.stdout)["sha256"] == digest

    monkeypatch.setattr(
        inputs, "acquire_canonical_images", lambda **kwargs: {"one": 1, "two": 2}
    )
    acquired = runner.invoke(
        app,
        [
            "appliance",
            "acquire-images",
            "--image-archive",
            str(tmp_path / "images.tar"),
            "--image-roles",
            str(image_roles),
        ],
    )
    assert acquired.exit_code == 0, acquired.output
    assert json.loads(acquired.stdout)["roles"] == 2

    validated_inputs = SimpleNamespace(
        qualification="inputs-only",
        scenario_pack=SimpleNamespace(pack_id="techvault-full-v1"),
    )
    monkeypatch.setattr(
        inputs, "validate_canonical_inputs", lambda path: validated_inputs
    )
    validated = runner.invoke(
        app,
        [
            "appliance",
            "validate-inputs",
            "--staging-dir",
            str(tmp_path / "staging"),
        ],
    )
    assert validated.exit_code == 0, validated.output
    assert json.loads(validated.stdout)["scenario_pack"] == "techvault-full-v1"


def test_appliance_redistribution_review_writes_validated_notices(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from aptl.appliance import manifest, redistribution, release_validation
    from aptl.utils import strict_json

    artifacts = (
        SimpleNamespace(kind="canonical-inputs", path="evidence/inputs.json"),
        SimpleNamespace(kind="redistribution-review", path="evidence/review.json"),
    )
    release = SimpleNamespace(artifacts=artifacts)
    canonical = SimpleNamespace()
    review = SimpleNamespace()

    def validate(model, payload):
        del payload
        return {
            "ApplianceReleaseManifest": release,
            "CanonicalInputs": canonical,
            "RedistributionReview": review,
        }[model.__name__]

    monkeypatch.setattr(strict_json, "model_validate_json_strict", validate)
    monkeypatch.setattr(
        release_validation, "read_release_artifact", lambda *args: b"{}"
    )
    calls = []
    monkeypatch.setattr(
        redistribution,
        "validate_redistribution_review",
        lambda *args: calls.append(args),
    )
    monkeypatch.setattr(
        redistribution, "render_third_party_notices", lambda value: "approved\n"
    )
    monkeypatch.setattr(
        manifest,
        "_write_create_once",
        lambda path, payload, **kwargs: path.write_bytes(payload),
    )
    notices = tmp_path / "THIRD_PARTY_NOTICES.txt"

    result = runner.invoke(
        app,
        [
            "appliance",
            "verify-redistribution-review",
            "--release-dir",
            str(tmp_path / "release"),
            "--notices-output",
            str(notices),
        ],
    )

    assert result.exit_code == 0, result.output
    assert notices.read_text() == "approved\n"
    assert calls == [(review, release, canonical)]
