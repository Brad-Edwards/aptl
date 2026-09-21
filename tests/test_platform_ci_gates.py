"""Behavioral contracts for the required platform checks in issue #969."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "checks.yml"
BASELINE = ROOT / ".github" / "branch-protection-baseline.json"


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _run_step(job: str, step_name: str) -> str:
    return next(
        step["run"]
        for step in _jobs()[job]["steps"]
        if step.get("name") == step_name
    )


def _stub(tmp_path: Path, name: str, body: str) -> None:
    path = tmp_path / "bin" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _shell(script: str, tmp_path: Path, **extra_env: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(extra_env)
    env["PATH"] = f"{tmp_path / 'bin'}:{env['PATH']}"
    return subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_dev_requires_existing_platform_job_contexts() -> None:
    jobs = _jobs()
    contexts = set(
        json.loads(BASELINE.read_text(encoding="utf-8"))["branches"]["dev"][
            "required_status_checks"
        ]["contexts"]
    )
    platform_jobs = {
        "pre-commit",
        "python-tests",
        "mcp-tests",
        "dependency-audit",
        "clean-install-lab-boot",
    }
    assert {jobs[job]["name"] for job in platform_jobs} <= contexts


def test_python_audit_covers_shipped_exports_and_fails_closed(tmp_path: Path) -> None:
    script = _run_step("dependency-audit", "pip-audit (Python dependencies) — blocking")
    for export in ("runtime.txt", "web.txt", "ci.txt"):
        assert f"requirements/{export}" in script
    assert "pip install -e ." not in script
    assert "--strict" in script
    _stub(tmp_path, "pip", "exit 0")
    _stub(tmp_path, "pip-audit", "exit 9")
    assert _shell(script, tmp_path).returncode != 0


def test_python_audit_rejects_scanner_install_failure(tmp_path: Path) -> None:
    script = _run_step("dependency-audit", "pip-audit (Python dependencies) — blocking")
    _stub(tmp_path, "pip", "exit 8")
    _stub(tmp_path, "pip-audit", "exit 0")
    assert _shell(script, tmp_path).returncode != 0


def test_node_audit_discovers_new_mcp_package_and_propagates_finding(tmp_path: Path) -> None:
    for package in (tmp_path / "web", tmp_path / "mcp" / "new-server"):
        package.mkdir(parents=True)
        (package / "package.json").write_text("{}\n", encoding="utf-8")
        (package / "package-lock.json").write_text("{}\n", encoding="utf-8")
    log = tmp_path / "npm.log"
    _stub(
        tmp_path,
        "npm",
        'printf "%s|%s\\n" "$PWD" "$*" >> "$AUDIT_LOG"\n'
        'case "$PWD:$1" in */mcp/new-server:audit) exit 9;; esac\n'
        "exit 0",
    )
    script = _run_step("dependency-audit", "npm audit (JS/TS workspaces)")
    result = _shell(script, tmp_path, AUDIT_LOG=str(log))
    calls = log.read_text(encoding="utf-8")
    assert "mcp/new-server|audit" in calls
    assert "--omit=dev" in calls
    assert result.returncode != 0


def test_node_audit_rejects_missing_adjacent_lock(tmp_path: Path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    (web / "package.json").write_text("{}\n", encoding="utf-8")
    _stub(tmp_path, "npm", "exit 0")
    script = _run_step("dependency-audit", "npm audit (JS/TS workspaces)")
    assert _shell(script, tmp_path).returncode != 0


def test_wheel_smoke_scopes_native_effect_and_always_proves_cleanup() -> None:
    steps = _jobs()["clean-install-lab-boot"]["steps"]
    native = next(step["run"] for step in steps if step.get("name") == "Start and verify the materialization envelope")
    assert "com.docker.compose.project=" in native
    assert "aptl.node.address=provision.node.smoke-box" in native
    assert "-eq 1" in native

    stop = next(step for step in steps if step.get("name") == "Stop the lab and remove its volumes")
    cleanup = next(
        step for step in steps if step.get("name") == "Assert no project containers, networks, or volumes remain"
    )
    assert stop["if"] == "always()"
    assert cleanup["if"] == "always()"
    assert '"$GITHUB_WORKSPACE/scripts/ci/assert_project_teardown.py"' in cleanup["run"]


class TestBootRealizationCoverage:
    """The boot job must verify what the shared fixture actually declares (#993).

    These read the SDL rather than grepping the workflow for assertion strings:
    a job that names a port the scenario no longer publishes, or that keeps its
    verifier step after the declaration behind it was dropped, is exactly the
    silently-vacuous gate issue #993 exists to prevent.
    """

    FIXTURE = ROOT / "tests" / "fixtures" / "materialization-envelope.sdl.yaml"
    NODE = "smoke-box"

    def _scenario(self) -> dict:
        return yaml.safe_load(self.FIXTURE.read_text(encoding="utf-8"))

    def _runtime(self) -> dict:
        return self._scenario()["nodes"][self.NODE]["runtime"]

    def _verifier_step(self) -> str:
        return _run_step(
            "clean-install-lab-boot",
            "Verify the realization regressions the scenario declares",
        )

    def test_the_fixture_declares_the_whole_causal_chain(self) -> None:
        """Content, service, listener and published port must all be present."""

        scenario = self._scenario()
        runtime = self._runtime()

        content = scenario["content"]["smoke-sshd-config"]
        assert content["target"] == self.NODE
        assert runtime["service_manager_units"]
        assert runtime["service_listeners"]
        assert runtime["network"]["published_ports"]
        assert scenario["workflows"]

    def test_the_declared_content_configures_the_declared_listener_port(self) -> None:
        """The chain is causal only while the content names the listener's port."""

        scenario = self._scenario()
        runtime = self._runtime()
        listener = runtime["service_listeners"][0]
        content_text = scenario["content"]["smoke-sshd-config"]["text"]

        assert f"Port {listener['port']}" in content_text
        assert listener["port"] != 22, "the package default proves nothing"

    def test_the_verifier_is_invoked_with_the_values_the_scenario_declares(
        self,
    ) -> None:
        """Every parameter the job passes must match the SDL, not a stale copy."""

        scenario = self._scenario()
        runtime = self._runtime()
        step = self._verifier_step()
        content = scenario["content"]["smoke-sshd-config"]
        listener = runtime["service_listeners"][0]
        published = runtime["network"]["published_ports"][0]
        unit = runtime["service_manager_units"][0]

        assert "scripts/ci/assert_boot_realization.py" in step
        assert f"--content-path {content['path']}" in step
        assert f"--unit-name {unit['unit_name']}" in step
        assert f"--container-port {listener['port']}" in step
        assert f"--protocol {listener['protocol']}" in step
        assert f"--host-ip {published['host_ip']}" in step
        assert f"--host-port {published['host_port']}" in step
        for name in scenario["workflows"]:
            assert f"--workflow-address orchestration.workflow.{name}" in step

    def test_the_host_publication_stays_loopback_only(self) -> None:
        """ADR-034: a scenario-declared host port never lands on every interface."""

        for published in self._runtime()["network"]["published_ports"]:
            assert published["host_ip"] == "127.0.0.1"

    def test_the_verifier_runs_from_the_installed_clean_venv(self) -> None:
        """A checkout interpreter would not prove the installed artifact."""

        step = self._verifier_step()

        assert '"$RUNNER_TEMP/clean-venv/bin/python"' in step
        assert "uv run" not in step

    def test_the_verifier_runs_before_teardown_and_cleanup_still_always_runs(
        self,
    ) -> None:
        """Verification must see a running lab; cleanup must run regardless."""

        steps = _jobs()["clean-install-lab-boot"]["steps"]
        names = [step.get("name") for step in steps]
        verify = names.index("Verify the realization regressions the scenario declares")
        stop = names.index("Stop the lab and remove its volumes")
        cleanup = names.index("Assert no project containers, networks, or volumes remain")

        assert verify < stop < cleanup
        assert steps[stop]["if"] == "always()"
        assert steps[cleanup]["if"] == "always()"
        assert "if" not in steps[verify], "a skipped verifier is a green boot gate"

    def test_the_job_keeps_a_bounded_timeout(self) -> None:
        """A boot gate with no bound can hang the required check set."""

        assert _jobs()["clean-install-lab-boot"]["timeout-minutes"] == 60


def test_the_boot_gate_requires_the_service_to_answer_not_just_the_port() -> None:
    """Docker publishes the host port whether or not anything listens behind it.

    Without an expected greeting the connection probe passes on the publication
    alone, which `_binding_failures` already covers — so the job must name one.
    """

    step = _run_step(
        "clean-install-lab-boot",
        "Verify the realization regressions the scenario declares",
    )

    assert "--endpoint-banner-prefix SSH-" in step
