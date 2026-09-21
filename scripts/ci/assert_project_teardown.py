"""Prove a stopped lab left no project-scoped Docker resources behind.

The clean-install regression gate (issue #951) boots a lab from the built wheel
and tears it down; this asserts the teardown actually removed everything. It
runs against the *installed* package, so it reuses the same identities and query
rules production teardown uses rather than restating them:

- containers and networks through ``DeploymentBackend.observe_project_runtime``,
  which counts stopped containers and both admitted project labels;
- volumes through ``project_scoped_volume_names``, whose ``<project>_`` prefix
  catches ADR-043 seeded volumes that carry no Compose label at all.

Both are scoped to the effective workspace-owned Compose project identity,
resolved from the lab's validated ``aptl.json`` and durable ownership state.
A name prefix such as ``aptl-*`` is never the authority, and nothing here
prunes daemon-wide state.

Absence that cannot be *proved* is a failure: a Docker query that errors exits
non-zero rather than reporting a clean lab.

Two kinds of debris carry no project identity at all, so the project scope
cannot see them: anonymous volumes (hash-named and unlabelled) and ephemeral
helper containers (labelled only with their role). Neither can be attributed to
a project after the fact. With ``--record-baseline`` before the lab starts and
``--baseline`` here, the proof fails on any of either that the daemon did not
already hold. That comparison observes; it deletes nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from aptl.core.config import find_config, load_config
from aptl.core.deployment import get_backend
from aptl.core.deployment._compose_resource_ownership import OwnershipConflictError
from aptl.core.deployment._compose_volume_cleanup import project_scoped_volume_names
from aptl.core.ephemeral_containers import EPHEMERAL_ROLE_LABEL

_VOLUME_QUERY_TIMEOUT = 60
_LEFTOVER_QUERIES: dict[str, list[str]] = {
    "dangling_volumes": ["docker", "volume", "ls", "-q", "--filter", "dangling=true"],
    "ephemeral_containers": [
        "docker",
        "ps",
        "-a",
        "--format",
        "{{.Names}}",
        "--filter",
        f"label={EPHEMERAL_ROLE_LABEL}",
    ],
}
_LEFTOVER_NAMES = {
    "dangling_volumes": "anonymous or dangling volume(s)",
    "ephemeral_containers": "ephemeral helper container(s)",
}


def _daemon_leftovers(
    run: Callable[..., object],
) -> tuple[dict[str, list[str]], list[str]]:
    """Return the daemon's unattributable leftovers, and any query failures."""

    leftovers: dict[str, list[str]] = {}
    failures: list[str] = []
    for kind, command in _LEFTOVER_QUERIES.items():
        result = run(command, timeout=_VOLUME_QUERY_TIMEOUT)
        if result.returncode != 0:
            failures.append(f"{_LEFTOVER_NAMES[kind]} could not be listed")
            continue
        leftovers[kind] = sorted(
            line.strip() for line in result.stdout.splitlines() if line.strip()
        )
    return leftovers, failures


def _new_leftover_failures(
    run: Callable[..., object], baseline_path: Path
) -> list[str] | None:
    """Return failures for leftovers the baseline did not hold; None if unreadable."""

    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        before = {kind: set(baseline[kind]) for kind in _LEFTOVER_QUERIES}
    except (OSError, ValueError, KeyError, TypeError):
        return None
    current, failures = _daemon_leftovers(run)
    for kind, names in current.items():
        new = sorted(set(names) - before[kind])
        if new:
            failures.append(f"{_LEFTOVER_NAMES[kind]} left behind: {', '.join(new)}")
    return failures


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("project_dir", nargs="?", default=".", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--record-baseline",
        type=Path,
        help="record the daemon's unattributable leftovers before the lab starts",
    )
    mode.add_argument(
        "--baseline",
        type=Path,
        help="also fail on unattributable leftovers the baseline did not hold",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Return 0 only when the project owns no containers, networks, or volumes."""

    args = _parse_args(argv[1:])
    project_dir = args.project_dir.resolve()
    config_path = find_config(project_dir)
    if config_path is None:
        print(f"No aptl.json found in {project_dir}", file=sys.stderr)
        return 2
    config = load_config(config_path)
    if config.deployment.provider != "docker-compose":
        print("Cleanup proof requires local Docker Compose", file=sys.stderr)
        return 2
    backend = get_backend(config, project_dir)
    if args.record_baseline is not None:
        return _record_baseline(backend._run, args.record_baseline)
    try:
        ownership = backend._load_resource_ownership()
    except OwnershipConflictError:
        print("Project ownership state could not be loaded", file=sys.stderr)
        return 2
    if ownership is None:
        print("Project ownership state is missing", file=sys.stderr)
        return 2
    project_name = ownership.project_name

    failures: list[str] = []
    presence = backend.observe_project_runtime()
    if presence.error:
        failures.append(f"runtime presence could not be observed: {presence.error}")
    if presence.container_count:
        failures.append(f"{presence.container_count} project container(s) remain")
    if presence.network_count:
        failures.append(f"{presence.network_count} project network(s) remain")

    # `_compose_stop` calls this helper with the backend's own runner; reuse the
    # same pairing so the gate and teardown ask Docker the identical question.
    volumes, volume_error = project_scoped_volume_names(
        project_name, backend._run, timeout=_VOLUME_QUERY_TIMEOUT
    )
    if volume_error:
        failures.append(f"project volumes could not be listed: {volume_error}")
    if volumes:
        failures.append(f"project volume(s) remain: {', '.join(sorted(volumes))}")

    if args.baseline is not None:
        leftover_failures = _new_leftover_failures(backend._run, args.baseline)
        if leftover_failures is None:
            print("Daemon baseline could not be read", file=sys.stderr)
            return 2
        failures.extend(leftover_failures)

    if failures:
        print(f"Teardown left project '{project_name}' dirty:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"Project '{project_name}': no containers, networks, or volumes remain.")
    return 0


def _record_baseline(run: Callable[..., object], path: Path) -> int:
    """Write the daemon's unattributable leftovers so teardown can diff them."""

    leftovers, failures = _daemon_leftovers(run)
    if failures:
        for failure in failures:
            print(f"Baseline not recorded: {failure}", file=sys.stderr)
        return 2
    path.write_text(json.dumps(leftovers, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "Recorded daemon baseline: "
        + ", ".join(f"{len(names)} {_LEFTOVER_NAMES[kind]}" for kind, names in leftovers.items())
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
