"""Exercise Shuffle seed convergence and failures through its Docker boundary."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
_DOCKER = r"""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
state_path = pathlib.Path(os.environ["APTL_TEST_STATE"])
state = json.loads(state_path.read_text())
curl = args[args.index("curl") + 1:]
config = {}
if "--config" in curl:
    for line in sys.stdin.read().splitlines():
        key, value = line.split(" = ", 1)
        config[key] = json.loads(value)
method = config.get("request", curl[curl.index("-X") + 1] if "-X" in curl else "GET")
url = config.get("url", curl[-1])
body = config.get("data", curl[curl.index("-d") + 1] if "-d" in curl else "")
operation = method + " " + url.split("/api/v1/")[-1]
state["calls"].append({"operation": operation, "argv": args})
state_path.write_text(json.dumps(state))
if operation == state.get("fail"):
    if "-f" in "".join(curl):
        sys.exit(22)
    print("{}\n503" if "-w" in curl else "{}")
    sys.exit(0)
if operation == state.get("reject"):
    print(json.dumps({"success": False, "reason": "private-upstream-detail"}))
    sys.exit(0)
if "-o" in curl:
    print("200", end="")
    sys.exit(0)
if method == "GET" and url.endswith("/workflows"):
    result = [state["workflow"]] if state.get("workflow") else []
elif method == "POST" and url.endswith("/workflows"):
    result = json.loads(body)
    result["id"] = "workflow-1"
    result["triggers"][0]["id"] = "server-trigger"
    state["workflow"] = result
elif method == "GET":
    result = state["workflow"]
elif method == "PUT":
    result = json.loads(body)
    state["workflow"] = result
else:
    state["hook"] = json.loads(body)
    result = {"success": True}
state_path.write_text(json.dumps(state))
print(json.dumps(result))
if "-w" in curl:
    print("200")
"""


def _run_seed(tmp_path, *, existing=True, fail="", trigger=True, reject=""):
    scripts = tmp_path / "project/scripts"
    scripts.mkdir(parents=True)
    for name in ("seed-shuffle.sh", "aptl-env.sh"):
        shutil.copy2(ROOT / "scripts" / name, scripts)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(_DOCKER)
    docker.chmod(0o755)
    workflow = {
        "id": "workflow-1",
        "name": "APTL Alert to Case",
        "start": "old-trigger",
        "triggers": [{"id": "server-trigger", "trigger_type": "WEBHOOK"}]
        if trigger
        else [],
        "actions": [
            {"label": label, "parameters": [{"name": "headers", "value": "stale"}]}
            for label in ("misp_ip_lookup", "create_thehive_case")
        ],
        "description": "operator annotation",
    }
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "workflow": workflow if existing else None,
                "calls": [],
                "fail": fail,
                "reject": reject,
            }
        )
    )
    hook = tmp_path / "webhook"
    result = subprocess.run(
        ["bash", str(scripts / "seed-shuffle.sh")],
        env={
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "APTL_TEST_STATE": str(state_path),
            "APTL_SHUFFLE_WEBHOOK_FILE": str(hook),
            "SHUFFLE_API_KEY": "shuffle-fixture",
            "THEHIVE_API_KEY": "thehive-fixture+/=",
            "MISP_API_KEY": "misp-fixture",
            "SHUFFLE_CONTAINER": "workspace-shuffle",
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return result, json.loads(state_path.read_text()), hook


@pytest.mark.parametrize("existing", [False, True])
def test_seed_converges_workflow_and_webhook_without_rotating_identity(
    tmp_path, existing
):
    result, state, hook = _run_seed(tmp_path, existing=existing)
    assert result.returncode == 0, result.stdout + result.stderr
    workflow = state["workflow"]
    assert workflow["id"] == "workflow-1"
    assert workflow["start"] == "server-trigger"
    headers = {
        action["label"]: next(
            p["value"] for p in action["parameters"] if p["name"] == "headers"
        )
        for action in workflow["actions"]
    }
    assert "thehive-fixture+/=" in headers["create_thehive_case"]
    assert "misp-fixture" in headers["misp_ip_lookup"]
    assert state["hook"]["id"] == "server-trigger"
    assert hook.read_text().strip().endswith("/hooks/webhook_server-trigger")
    assert hook.stat().st_mode & 0o777 == 0o600
    if existing:
        assert workflow["description"] == "operator annotation"
        assert not any(c["operation"] == "POST workflows" for c in state["calls"])
    assert all("workspace-shuffle" in c["argv"] for c in state["calls"])
    argv = json.dumps([c["argv"] for c in state["calls"]])
    for credential in ("shuffle-fixture", "misp-fixture", "thehive-fixture"):
        assert credential not in argv
        assert credential not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "operation",
    [
        "GET workflows",
        "GET workflows/workflow-1",
        "PUT workflows/workflow-1",
        "POST hooks/new",
    ],
)
def test_seed_fails_without_publishing_webhook_on_api_failure(tmp_path, operation):
    result, _state, hook = _run_seed(tmp_path, fail=operation)
    assert result.returncode != 0
    assert not hook.exists()
    assert "Seed Complete" not in result.stdout


def test_seed_rejects_existing_workflow_without_webhook_trigger(tmp_path):
    result, _state, hook = _run_seed(tmp_path, trigger=False)
    assert result.returncode != 0
    assert not hook.exists()


@pytest.mark.parametrize("operation", ["PUT workflows/workflow-1", "POST hooks/new"])
def test_seed_rejects_application_failure_even_with_http_success(tmp_path, operation):
    result, _state, hook = _run_seed(tmp_path, reject=operation)
    assert result.returncode != 0
    assert not hook.exists()
    assert "Seed Complete" not in result.stdout
    assert "private-upstream-detail" not in result.stdout + result.stderr
