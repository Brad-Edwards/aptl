"""Prove a stopped lab left no project-scoped Docker resources behind.

The clean-install regression gate (issue #951) boots a lab from the built wheel
and tears it down; this asserts the teardown actually removed everything. It
runs against the *installed* package, so it reuses the same identities and query
rules production teardown uses rather than restating them:

- containers and networks through ``DeploymentBackend.observe_project_runtime``,
  which counts stopped containers and both admitted project labels;
- volumes through ``project_scoped_volume_names``, whose ``<project>_`` prefix
  catches ADR-043 seeded volumes that carry no Compose label at all.

Both are scoped to the validated Compose project identity from the lab's own
``aptl.json``. A name prefix such as ``aptl-*`` is never the authority, and
nothing here prunes daemon-wide state.

Absence that cannot be *proved* is a failure: a Docker query that errors exits
non-zero rather than reporting a clean lab.
"""

from __future__ import annotations

import sys
from pathlib import Path

from aptl.core.config import find_config, load_config
from aptl.core.deployment import get_backend
from aptl.core.deployment._compose_volume_cleanup import project_scoped_volume_names

_VOLUME_QUERY_TIMEOUT = 60


def main(argv: list[str]) -> int:
    """Return 0 only when the project owns no containers, networks, or volumes."""

    project_dir = Path(argv[1] if len(argv) > 1 else ".").resolve()
    config_path = find_config(project_dir)
    if config_path is None:
        print(f"No aptl.json found in {project_dir}", file=sys.stderr)
        return 2
    config = load_config(config_path)
    backend = get_backend(config, project_dir)
    project_name = config.deployment.project_name

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

    if failures:
        print(f"Teardown left project '{project_name}' dirty:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"Project '{project_name}': no containers, networks, or volumes remain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
