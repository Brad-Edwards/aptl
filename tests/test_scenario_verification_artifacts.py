"""Built-artifact proof for the scenario-verification extension boundary."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "aptl-techvault-verifier"

ANSWER_KEY_MARKERS = (
    b"aptl-live-gate-invalid",
    b"mcp.red.ssh-authentication-attack",
    b"kali nmap + failed-ssh-auth",
)


def _build_wheel(source: Path, output: Path) -> Path:
    if shutil.which("uv") is None:
        pytest.skip("uv is required for the repository's locked wheel-build proof")
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--out-dir",
            str(output),
            str(source),
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    wheels = sorted(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _wheel_members(wheel: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _run(venv: Path, script: str) -> None:
    executable = venv / (
        "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    )
    completed = subprocess.run(
        [str(executable), "-c", script],
        cwd=venv,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.integration
def test_core_and_verifier_wheels_prove_the_installed_seam(tmp_path: Path) -> None:
    """Core-only blocks; adding the separate wheel discovers exact provenance."""

    core_wheel = _build_wheel(REPO_ROOT, tmp_path / "core-dist")
    plugin_wheel = _build_wheel(PLUGIN_ROOT, tmp_path / "plugin-dist")
    core_members = _wheel_members(core_wheel)
    plugin_members = _wheel_members(plugin_wheel)

    core_entry_points = b"\n".join(
        content
        for name, content in core_members.items()
        if name.endswith("entry_points.txt")
    )
    assert b"aptl.scenario_verifiers" not in core_entry_points
    assert b"aptl.participant_mcp_smoke_plans" not in core_entry_points
    assert not any("aptl_techvault_verifier" in name for name in core_members)
    core_payload = b"\n".join(
        content
        for name, content in core_members.items()
        if name.startswith("aptl/") and name.endswith(".py")
    )
    assert not any(marker in core_payload for marker in ANSWER_KEY_MARKERS)

    plugin_entry_points = b"\n".join(
        content
        for name, content in plugin_members.items()
        if name.endswith("entry_points.txt")
    )
    assert b"aptl.scenario_verifiers" in plugin_entry_points
    assert b"techvault.aptl" in plugin_entry_points
    assert b"aptl.participant_mcp_smoke_plans" in plugin_entry_points
    assert b"guided-purple.techvault-attacker-target" in plugin_entry_points
    plugin_payload = b"\n".join(plugin_members.values())
    assert ANSWER_KEY_MARKERS[0] in plugin_payload

    venv = tmp_path / "clean-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    pip = venv / ("Scripts/pip.exe" if sys.platform == "win32" else "bin/pip")
    subprocess.run(
        [str(pip), "install", "--no-deps", str(core_wheel)],
        cwd=venv,
        check=True,
        capture_output=True,
    )

    context_script = """
from aptl.backends.identity import BackendIdentity
from aptl.validation.scenario_verification import ScenarioIdentity, VerificationContext, VerificationStatus
from aptl.validation.scenario_verification_discovery import verify_scenario

context = VerificationContext(
    run_id="artifact-run",
    attempt_id="artifact-attempt",
    scenario=ScenarioIdentity(
        identity="techvault",
        version="0.1.0",
        source_kind="env-pack",
        content_digest="sha256:f1c807f70540ca68c640cde72e8b5606b928f4ec40cc00a44d7fd37d6bbfd55f",
    ),
    backend=BackendIdentity(
        target_name="aptl",
        target_version="0.1.0",
        profile="full-remote-control-plane",
        provider="docker-compose",
        transport="docker-compose",
    ),
)
report = verify_scenario(context)
assert report.status is VerificationStatus.BLOCKED
assert report.status is not VerificationStatus.PASSED
"""
    _run(venv, context_script)

    subprocess.run(
        [str(pip), "install", "--no-deps", str(plugin_wheel)],
        cwd=venv,
        check=True,
        capture_output=True,
    )
    installed_script = context_script.replace(
        "report = verify_scenario(context)",
        """
from types import SimpleNamespace
class Operations:
    def reachability_from(self, origin):
        return SimpleNamespace(reached=True, diagnostics=())
    def shared_network_targets(self, origin):
        return (("target", "192.0.2.10"),)
    def tcp_reachable_from(self, origin, address, port):
        return True
    def execute_in_node(self, origin, argv, *, timeout_seconds):
        return True
    def collect_evidence(self, **kwargs):
        kwargs["trigger"]()
        assert kwargs["alert_matches"]({"rule": {}, "marker": "aptl-live-gate-invalid"})
        assert not kwargs["alert_matches"]({"rule": {}, "marker": "unrelated"})
        return SimpleNamespace(observed=True, diagnostics=())
context = VerificationContext(**{**context.__dict__, "operations": Operations(), "observations": {"containers": ("aptl-kali", "aptl-wazuh-manager", "aptl-suricata")}})
report = verify_scenario(context)
""",
    ).replace(
        "assert report.status is VerificationStatus.BLOCKED\nassert report.status is not VerificationStatus.PASSED",
        (
            "assert report.status is VerificationStatus.PASSED\n"
            'assert report.distribution == "aptl-techvault-verifier"\n'
            'assert report.distribution_version == "0.1.0"\n'
            'assert report.entry_point == "techvault.aptl"'
        ),
    )
    _run(venv, installed_script)
