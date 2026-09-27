"""The installed-wheel cleanup proof must use the effective workspace scope."""

from __future__ import annotations

import importlib.util
import json
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


# ---------------------------------------------------------------------------
# Daemon leftovers the project scope cannot see.
#
# The proof above is project-scoped: containers and networks by the project
# label, volumes by the ``<project>_`` prefix. Two kinds of debris carry
# neither, so it reported a clean teardown with both still on the daemon:
# anonymous volumes (hash-named, unlabelled) and ephemeral helper containers
# (labelled only with their role). Neither can be attributed to a project after
# the fact, so the proof compares the daemon against a baseline recorded before
# the lab started. It only observes; it never prunes.
# ---------------------------------------------------------------------------


class _Daemon:
    """A scripted daemon: a clean project, plus configurable leftovers."""

    def __init__(self, *, dangling=(), helpers=(), fail_on=None):
        self.dangling = list(dangling)
        self.helpers = list(helpers)
        self.fail_on = fail_on

    def __call__(self, cmd, *, timeout):
        if self.fail_on and cmd[:3] == self.fail_on:
            return subprocess.CompletedProcess(cmd, 1, "", "daemon unavailable")
        if cmd[:3] == ["docker", "volume", "ls"] and "dangling=true" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "".join(f"{v}\n" for v in self.dangling))
        if cmd[:2] == ["docker", "ps"] and any("aptl.ephemeral.role" in c for c in cmd):
            return subprocess.CompletedProcess(cmd, 0, "".join(f"{h}\n" for h in self.helpers))
        # The project itself is clean.
        return subprocess.CompletedProcess(cmd, 0, "")


def _script_with(monkeypatch, tmp_path, daemon):
    config_path = tmp_path / "aptl.json"
    config_path.write_text("{}\n", encoding="utf-8")
    WorkspaceOwnership.ensure(tmp_path, "lab")
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")
    monkeypatch.setattr(backend, "_run", daemon)
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
    return script


def test_a_baseline_records_what_the_daemon_already_holds(tmp_path, monkeypatch):
    daemon = _Daemon(dangling=["pre-existing-vol"], helpers=["someone-elses-helper"])
    script = _script_with(monkeypatch, tmp_path, daemon)
    baseline = tmp_path / "baseline.json"

    assert script.main(["x", str(tmp_path), "--record-baseline", str(baseline)]) == 0

    recorded = json.loads(baseline.read_text(encoding="utf-8"))
    assert recorded == {
        "dangling_volumes": ["pre-existing-vol"],
        "ephemeral_containers": ["someone-elses-helper"],
    }


def test_an_anonymous_volume_left_by_the_lab_fails_the_proof(
    tmp_path, monkeypatch, capsys
):
    """The debris a rootless lab left for days, which the proof passed."""

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"dangling_volumes": ["pre-existing-vol"], "ephemeral_containers": []}),
        encoding="utf-8",
    )
    daemon = _Daemon(dangling=["pre-existing-vol", "4ba575662a3d"])
    script = _script_with(monkeypatch, tmp_path, daemon)

    assert script.main(["x", str(tmp_path), "--baseline", str(baseline)]) == 1

    error = capsys.readouterr().err
    assert "4ba575662a3d" in error
    assert "pre-existing-vol" not in error


def test_a_helper_container_left_by_the_lab_fails_the_proof(
    tmp_path, monkeypatch, capsys
):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"dangling_volumes": [], "ephemeral_containers": []}), encoding="utf-8"
    )
    daemon = _Daemon(helpers=["aptl-boundary-apply-0123456789ab"])
    script = _script_with(monkeypatch, tmp_path, daemon)

    assert script.main(["x", str(tmp_path), "--baseline", str(baseline)]) == 1

    assert "aptl-boundary-apply-0123456789ab" in capsys.readouterr().err


def test_leftovers_that_predate_the_lab_do_not_fail_the_proof(
    tmp_path, monkeypatch, capsys
):
    """A baseline exists so another workload's debris is not this lab's failure."""

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {"dangling_volumes": ["pre-existing-vol"], "ephemeral_containers": ["theirs"]}
        ),
        encoding="utf-8",
    )
    daemon = _Daemon(dangling=["pre-existing-vol"], helpers=["theirs"])
    script = _script_with(monkeypatch, tmp_path, daemon)

    assert script.main(["x", str(tmp_path), "--baseline", str(baseline)]) == 0


def test_a_leftover_query_that_fails_fails_the_proof(tmp_path, monkeypatch, capsys):
    """Absence that cannot be proved is a failure, not a clean result."""

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"dangling_volumes": [], "ephemeral_containers": []}), encoding="utf-8"
    )
    daemon = _Daemon(fail_on=["docker", "volume", "ls"])
    script = _script_with(monkeypatch, tmp_path, daemon)

    assert script.main(["x", str(tmp_path), "--baseline", str(baseline)]) == 1

    assert "could not be listed" in capsys.readouterr().err


def test_an_unreadable_baseline_fails_the_proof(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("not json", encoding="utf-8")
    script = _script_with(monkeypatch, tmp_path, _Daemon())

    assert script.main(["x", str(tmp_path), "--baseline", str(baseline)]) == 2
