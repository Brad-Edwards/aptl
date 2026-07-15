"""Property-based fuzz tests for content-placement path containment (#689).

Guards the ADR-046 TechVault addendum's fail-closed rule: a content
placement whose declared source path escapes the project root must never
be realized, at either the ACES interpreter boundary
(`aces_content_realization.resolve_content_placement`) or the backend seed
boundary (`content_seed.build_content_volume_seeds`, independently
re-checked per ADR-043's defense-in-depth precedent). Mirrors the
`../../etc/passwd`-style escape pattern already used for credential path
containment (see `docs/testing/property-based-parser-tests.md`).

Run with ``pytest -m fuzz tests/test_content_realization_fuzz.py``;
excluded from the default suite by ``pyproject.toml`` (``addopts = "-m
'not fuzz'"``).
"""

from __future__ import annotations

import pytest
from aces_contracts.planning import PlannedResource, RuntimeDomain
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aptl.backends.aces_content_realization import resolve_content_placement
from aptl.core.content_seed import build_content_volume_seeds
from aptl.core.credentials import PathContainmentError
from aptl.core.deployment.realization import DeploymentContentRealization

pytestmark = pytest.mark.fuzz

# Lowercase-ASCII-and-digit-only segments. The project directory below is
# named with an uppercase-containing literal ("ProjectRoot") that this
# alphabet can never spell, so no fuzzed `../segment/...` path can ever
# accidentally re-descend back inside the project root by coincidence —
# every generated path is a genuine escape attempt.
_SEGMENT = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=10)
_DEPTH = st.integers(min_value=1, max_value=10)
_SEGMENTS = st.lists(_SEGMENT, min_size=1, max_size=5)


def _escaping_source_name(depth: int, segments: list[str]) -> str:
    return "/".join([".."] * depth + segments)


def _content_payload(source_name: str) -> dict:
    return {
        "name": "fuzz",
        "content_name": "fuzz",
        "target_node": "fileshare",
        "target_address": "provision.node.fileshare",
        "spec": {
            "type": "file",
            "description": "",
            "target": "fileshare",
            "path": "public/fuzz.txt",
            "destination": "",
            "text": None,
            "source": {"name": source_name, "version": "*", "build": None},
            "format": "",
            "items": [],
            "sensitive": False,
            "tags": [],
        },
    }


@given(depth=_DEPTH, segments=_SEGMENTS)
@settings(
    max_examples=150,
    deadline=2000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_interpreter_never_realizes_an_escaping_content_source(tmp_path, depth, segments):
    """`resolve_content_placement` fails closed for any project-root escape."""
    project_dir = tmp_path / "ProjectRoot"
    project_dir.mkdir(exist_ok=True)
    source_name = _escaping_source_name(depth, segments)
    payload = _content_payload(source_name)
    resource = PlannedResource(
        address="provision.content-placement.fuzz",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload=payload,
    )

    content, diagnostics = resolve_content_placement(
        resource=resource,
        payload=payload,
        target_address="provision.node.fileshare",
        target_service="fileshare",
        project_dir=project_dir,
    )

    assert content is None
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "aptl.provisioner.content-placement-rejected"
    assert diagnostics[0].is_error


@given(depth=_DEPTH, segments=_SEGMENTS)
@settings(
    max_examples=150,
    deadline=2000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_backend_seed_builder_rejects_escaping_source_independently(
    tmp_path, depth, segments
):
    """`build_content_volume_seeds` re-checks containment (ADR-043 defense in depth)."""
    project_dir = tmp_path / "ProjectRoot"
    project_dir.mkdir(exist_ok=True)
    source_relpath = _escaping_source_name(depth, segments)
    item = DeploymentContentRealization(
        address="provision.content-placement.fuzz",
        target_address="provision.node.fileshare",
        content_name="fuzz",
        volume_suffix="fileshare_data",
        dest_relpath="public/fuzz.txt",
        source_kind="project-file",
        source_relpath=source_relpath,
    )

    with pytest.raises(PathContainmentError):
        build_content_volume_seeds(project_dir, [item])
