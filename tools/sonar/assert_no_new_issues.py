#!/usr/bin/env python3
"""Fail CI when SonarCloud reports open issues on new code."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SONARCLOUD_API = "https://sonarcloud.io/api/issues/search"
OPEN_ISSUE_STATUSES = "OPEN,CONFIRMED"


@dataclass(frozen=True)
class AnalysisScope:
    query_key: str
    query_value: str

    @property
    def label(self) -> str:
        if self.query_key == "pullRequest":
            return f"PR {self.query_value}"
        return f"branch {self.query_value}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-key", required=True, help="SonarCloud project key.")
    parser.add_argument("--pull-request", help="Pull request number to inspect.")
    parser.add_argument("--branch", help="Branch name to inspect when this is not a PR run.")
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=60,
        help="How long to retry transient SonarCloud API failures.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=10,
        help="Seconds between transient-failure retries.",
    )
    return parser.parse_args(argv)


def resolve_scope(args: argparse.Namespace) -> AnalysisScope:
    if args.pull_request:
        return AnalysisScope("pullRequest", args.pull_request)
    if args.branch:
        return AnalysisScope("branch", args.branch)

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        pull_request = event.get("pull_request")
        if isinstance(pull_request, dict) and pull_request.get("number"):
            return AnalysisScope("pullRequest", str(pull_request["number"]))

    ref_name = os.environ.get("GITHUB_REF_NAME")
    if ref_name:
        return AnalysisScope("branch", ref_name)

    raise SystemExit("Unable to determine SonarCloud PR or branch scope.")


def build_request_url(project_key: str, scope: AnalysisScope, page: int) -> str:
    query = {
        "componentKeys": project_key,
        scope.query_key: scope.query_value,
        "issueStatuses": OPEN_ISSUE_STATUSES,
        "sinceLeakPeriod": "true",
        "p": str(page),
        "ps": "500",
    }
    return f"{SONARCLOUD_API}?{urllib.parse.urlencode(query)}"


def fetch_json(url: str, token: str) -> dict[str, Any]:
    encoded = base64.b64encode(f"{token}:".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(url, headers={"Authorization": f"Basic {encoded}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_issues(project_key: str, scope: AnalysisScope, token: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    page = 1
    total = 0
    while page == 1 or len(issues) < total:
        payload = fetch_json(build_request_url(project_key, scope, page), token)
        total = int(payload.get("total", 0))
        issues.extend(payload.get("issues", []))
        if not payload.get("issues"):
            break
        page += 1
    return issues


def fetch_issues_with_retry(
    project_key: str,
    scope: AnalysisScope,
    token: str,
    wait_seconds: int,
    poll_interval: int,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            return fetch_issues(project_key, scope, token)
        except Exception as exc:  # noqa: BLE001 - CI gate should retry any transient API failure.
            if time.monotonic() >= deadline:
                raise SystemExit(f"SonarCloud issue lookup failed: {exc}") from exc
            print(f"SonarCloud issue lookup failed, retrying: {exc}", file=sys.stderr)
            time.sleep(poll_interval)


def render_issue(issue: dict[str, Any]) -> str:
    component = issue.get("component", "")
    line = issue.get("line")
    location = f"{component}:{line}" if line else component
    return (
        f"- {issue.get('severity', 'UNKNOWN')} {issue.get('type', 'ISSUE')} "
        f"{issue.get('rule', 'unknown-rule')} at {location}: {issue.get('message', '')}"
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    token = os.environ.get("SONAR_TOKEN")
    if not token:
        print("SONAR_TOKEN is required for the SonarCloud new-issue gate.", file=sys.stderr)
        return 2

    scope = resolve_scope(args)
    issues = fetch_issues_with_retry(
        args.project_key,
        scope,
        token,
        args.wait_seconds,
        args.poll_interval,
    )
    if not issues:
        print(f"SonarCloud new-issue gate passed for {scope.label}.")
        return 0

    print(f"SonarCloud new-issue gate failed for {scope.label}: {len(issues)} issue(s).", file=sys.stderr)
    for issue in issues:
        print(render_issue(issue), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
