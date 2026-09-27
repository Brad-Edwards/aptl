"""Structural gate for the first-time user documentation in issue #851."""

from __future__ import annotations

import json
from pathlib import Path
import re

import yaml
from typer.main import get_command

from aptl.api.routers import config, kill, lab, scenarios, terminal
from aptl.cli.main import app as cli_app


ROOT = Path(__file__).parents[1]
DOCS = ROOT / "docs"


def _document(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _section(relative_path: str, heading: str) -> str:
    document = _document(relative_path)
    match = re.search(
        rf"(?ms)^## {re.escape(heading)}\s*$\n(.*?)(?=^## |\Z)", document
    )
    assert match is not None, f"{relative_path} must contain a {heading!r} section"
    return match.group(1)


def _table(relative_path: str, heading: str) -> list[dict[str, str]]:
    lines = [
        line
        for line in _section(relative_path, heading).splitlines()
        if line.startswith("|")
    ]
    assert len(lines) >= 3, f"{relative_path} {heading!r} must contain a table"
    headers = [cell.strip() for cell in lines[0].strip("|").split("|")]
    rows: list[dict[str, str]] = []
    for line in lines[2:]:
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if len(cells) == len(headers):
            rows.append(dict(zip(headers, cells, strict=True)))
    return rows


def _links(document: str) -> dict[str, str]:
    return {
        label: target
        for label, target in re.findall(r"\[([^]]+)]\(([^)]+)\)", document)
    }


def _headings(relative_path: str) -> list[str]:
    return re.findall(r"(?m)^## (.+)$", _document(relative_path))


def _slug(heading: str) -> str:
    return re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")


def test_navigation_puts_operator_tasks_before_design_records() -> None:
    mkdocs = _document("mkdocs.yml").replace(
        "!!python/name:pymdownx.superfences.fence_code_format",
        "'pymdownx.superfences.fence_code_format'",
    )
    nav = yaml.safe_load(mkdocs)["nav"]
    top_level = [next(iter(item)) for item in nav]

    assert top_level[:4] == ["Home", "Lab Guide", "Interfaces", "Operations"]
    assert top_level.index("Lab Guide") < top_level.index("Architecture")
    assert top_level.index("Interfaces") < top_level.index("Decisions")


def test_home_links_directly_to_the_complete_first_time_journey() -> None:
    links = _links(_document("docs/index.md"))
    task_targets = {
        "Check prerequisites": "getting-started/prerequisites.md",
        "Install APTL": "getting-started/installation.md",
        "Start and verify the lab": (
            "getting-started/quick-start.md#start-and-verify-the-lab"
        ),
        "Choose a scenario": "getting-started/quick-start.md#choose-a-scenario",
        "Inspect the running lab": (
            "getting-started/quick-start.md#inspect-the-running-lab"
        ),
        "Generate safe test activity": (
            "getting-started/quick-start.md#generate-safe-test-activity"
        ),
        "Inspect results": "getting-started/quick-start.md#inspect-results",
        "Troubleshoot": "troubleshooting/index.md",
        "Stop or reset the lab": (
            "getting-started/quick-start.md#stop-or-reset-the-lab"
        ),
    }
    assert {label: links.get(label) for label in task_targets} == task_targets

    for target in task_targets.values():
        path_text, _, fragment = target.partition("#")
        target_path = DOCS / path_text
        assert target_path.is_file()
        if fragment:
            assert fragment in {
                _slug(heading) for heading in _headings(f"docs/{path_text}")
            }


def test_quick_start_follows_the_operator_workflow_in_order() -> None:
    headings = _headings("docs/getting-started/quick-start.md")
    required_order = [
        "Choose The Execution Boundary",
        "Choose A Scenario",
        "Start And Verify The Lab",
        "Inspect The Running Lab",
        "Generate Safe Test Activity",
        "Inspect Results",
        "Stop Or Reset The Lab",
    ]
    assert [heading for heading in headings if heading in required_order] == required_order


def test_cli_reference_tracks_every_registered_command_group() -> None:
    rows = _table("docs/reference/cli.md", "Command Groups")
    documented = {row["Command"].removeprefix("aptl ") for row in rows}
    registered = set(get_command(cli_app).commands)

    assert documented == registered


def test_mcp_reference_tracks_built_and_enabled_server_surfaces() -> None:
    rows = _table("docs/reference/mcp.md", "Server Availability")
    documented = {
        row["Artifact"]: {
            "client": row["Generated client entry"],
            "prefix": row["Tool prefix"],
            "enabled": row["Default client config"] == "yes",
        }
        for row in rows
    }
    generated = json.loads(_document(".mcp.json.example"))["mcpServers"]
    expected: dict[str, dict[str, str | bool]] = {}
    for config_path in sorted((ROOT / "mcp").glob("mcp-*/docker-lab-config.json")):
        config_doc = json.loads(config_path.read_text(encoding="utf-8"))
        artifact = config_path.parent.name
        client = f"aptl-{artifact.removeprefix('mcp-')}"
        expected[artifact] = {
            "client": client,
            "prefix": config_doc["server"]["toolPrefix"],
            "enabled": client in generated,
        }

    assert documented == expected


def test_web_reference_tracks_cli_defaults_and_supported_api() -> None:
    defaults = {
        row["Setting"]: row["Default"]
        for row in _table("docs/reference/web.md", "Serve Defaults")
    }
    serve = get_command(cli_app).commands["web"].commands["serve"]
    parameters = {parameter.name: parameter.default for parameter in serve.params}
    assert defaults["Bind address"] == parameters["host"]
    assert int(defaults["Port"]) == parameters["port"]

    documented_routes = {
        row["Method and path"]
        for row in _table("docs/reference/web.md", "Supported API Surface")
    }
    runtime_routes = {"GET /api/health", "GET /api/auth/login"}
    for router in (lab.router, config.router, terminal.router, kill.router, scenarios.router):
        for route in router.routes:
            path = f"/api{route.path}"
            methods = getattr(route, "methods", None)
            if methods:
                runtime_routes.update(f"{method} {path}" for method in methods)
            else:
                runtime_routes.add(f"WEBSOCKET {path}")

    assert documented_routes == runtime_routes


def test_support_and_security_actions_use_the_canonical_repository_policies() -> None:
    for relative_path in ("README.md", "docs/index.md"):
        links = _links(_document(relative_path))
        assert links["Contribute"] == (
            "https://github.com/Brad-Edwards/aptl/blob/dev/CONTRIBUTING.md"
        )
        assert links["Get support"] == (
            "https://github.com/Brad-Edwards/aptl/blob/dev/SUPPORT.md"
        )
        assert links["Report a vulnerability privately"] == (
            "https://github.com/Brad-Edwards/aptl/security/advisories/new"
        )
