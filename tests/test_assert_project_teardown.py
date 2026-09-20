"""The installed-wheel cleanup proof must use the effective workspace scope."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aptl.core.deployment._compose_resource_ownership import WorkspaceOwnership
from aptl.core.deployment.docker_compose import DockerComposeBackend

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "assert_project_teardown.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("assert_project_teardown", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_effective_workspace_resources_fail_cleanup_proof(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    config_path = tmp_path / "aptl.json"
    config_path.write_text("{}\n", encoding="utf-8")
    ownership = WorkspaceOwnership.ensure(tmp_path, "lab")
    assert ownership.project_name != "lab"
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        if cmd[:3] == ["docker", "ps", "-aq"]:
            found = f"label=com.docker.compose.project={ownership.project_name}" in cmd
            return subprocess.CompletedProcess(cmd, 0, "leftover-container\n" if found else "")
        if cmd[:3] == ["docker", "network", "ls"]:
            found = f"label=com.docker.compose.project={ownership.project_name}" in cmd
            return subprocess.CompletedProcess(cmd, 0, "leftover-network\n" if found else "")
        if cmd[:3] == ["docker", "volume", "ls"]:
            return subprocess.CompletedProcess(cmd, 0, f"{ownership.project_name}_orphan\n")
        raise AssertionError(f"unexpected Docker command: {cmd}")

    monkeypatch.setattr(backend, "_run", fake_run)
    script = _load_script()
    monkeypatch.setattr(script, "find_config", lambda project_dir: config_path)
    monkeypatch.setattr(
        script,
        "load_config",
        lambda path: SimpleNamespace(
            deployment=SimpleNamespace(project_name="lab", provider="docker-compose")
        ),
    )
    monkeypatch.setattr(script, "get_backend", lambda config, project_dir: backend)

    assert script.main(["assert_project_teardown.py", str(tmp_path)]) == 1
    error = capsys.readouterr().err
    assert "project container(s) remain" in error
    assert "project network(s) remain" in error
    assert "project volume(s) remain" in error
    assert any(f"label=com.docker.compose.project={ownership.project_name}" in cmd for cmd in commands)
    assert backend._project_name == ownership.project_name
