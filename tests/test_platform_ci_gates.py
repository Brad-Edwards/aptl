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
