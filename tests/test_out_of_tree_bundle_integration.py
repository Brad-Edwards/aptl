"""Issue #874, live: a scenario bundle rooted OUTSIDE the engine checkout is
realized on real Docker entirely from its own root.

This is the differential proof in its strongest form — the one the unit tests
only approximate with monkeypatch capture and argv assertions. There is no
acquired-pack resolver yet (that is #875's stream and an explicit non-goal
here), so the test constructs the out-of-tree bundle directly: two distinct
roots, each holding a build context the other lacks, and asserts the running
container was built from the *bundle*'s tree, never the engine checkout the
backend was configured with.

It is marked ``integration`` and uses a unique Compose project name, so it never
touches a real ``aptl`` lab. Run it on demand:

    uv run pytest -m integration tests/test_out_of_tree_bundle_integration.py
"""

from __future__ import annotations

import shutil
import subprocess
from textwrap import dedent

import pytest

from aptl.core.deployment.docker_compose import DockerComposeBackend

pytestmark = pytest.mark.integration

# A unique project name: its volumes/containers/networks are prefix-scoped
# ``aptl-oot-874-*``, disjoint from a real ``aptl`` lab, so this test can never
# tear one down.
_PROJECT = "aptl-oot-874"
_CONTAINER = "aptl-oot-874-widget"


def _write(path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content), encoding="utf-8")


def _stage_widget(root, origin_marker: str) -> None:
    """Stage a one-service scenario whose image records where it was built."""

    _write(
        root / "containers" / "widget" / "Dockerfile",
        f"""\
        FROM alpine:3
        RUN echo {origin_marker} > /origin
        CMD ["sleep", "600"]
        """,
    )
    _write(
        root / "docker-compose.yml",
        f"""\
        services:
          widget:
            build: ./containers/widget
            container_name: {_CONTAINER}
            command: ["sleep", "600"]
        """,
    )


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_out_of_tree_bundle_realizes_from_its_own_root_not_the_engine(tmp_path):
    engine = tmp_path / "engine"  # the checkout the backend is configured with
    bundle = tmp_path / "acquired"  # the scenario handed to APTL, rooted elsewhere

    # Contradictory decoys: the engine tree holds a widget that must NOT win.
    _stage_widget(engine, "engine-built")
    _stage_widget(bundle, "bundle-built")
    # Operator secret lives on the control-plane engine root; the bundle-local
    # .env is a decoy that must never be bound.
    _write(engine / ".env", "OOT_ORIGIN=operator\n")
    _write(bundle / ".env", "OOT_ORIGIN=bundle-decoy\n")

    backend = DockerComposeBackend(engine, project_name=_PROJECT)
    try:
        result = backend.start([], scenario_root=bundle)
        assert result.success, f"out-of-tree start failed: {result.error}"

        # The running container was BUILT FROM THE BUNDLE tree, proving Compose
        # resolved the relative build context against --project-directory=bundle,
        # not the engine checkout it was configured with.
        origin = subprocess.run(
            ["docker", "exec", _CONTAINER, "cat", "/origin"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert origin.returncode == 0, origin.stderr
        assert origin.stdout.strip() == "bundle-built", (
            "realization reached into the engine tree instead of the bundle root"
        )
    finally:
        # Teardown is scenario-agnostic (identity-based); it takes no root.
        backend.stop([], remove_volumes=True)
        # Belt-and-suspenders: force-remove in case the boot failed mid-build.
        subprocess.run(
            ["docker", "rm", "-f", _CONTAINER], capture_output=True, timeout=60
        )
