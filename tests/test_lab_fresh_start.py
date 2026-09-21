"""Fresh-install preflight against the product-neutral materialization envelope.

The fixture starts from the public ``aptl lab init`` asset materializer, then
selects the same small SDL used by the real-Docker materializer integration
test. The scenario intentionally belongs to APTL's test suite rather than to a
scenario adapter: it proves the generic parse, plan, qualification, generated
model, and pre-mutation lifecycle path without borrowing TechVault semantics.

The live clean-wheel job continues from this boundary through public CLI start,
status, native readback, and teardown. Keeping the preflight here separately
makes failures before Docker mutation fast and precise.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MATERIALIZATION_ENVELOPE = (
    _REPO_ROOT / "tests" / "fixtures" / "materialization-envelope.sdl.yaml"
)


@pytest.fixture(scope="module")
def admitted_fresh_lab(tmp_path_factory):
    """Materialize a clean project and admit the generic smoke SDL once."""

    from aptl.core.assets import materialize
    from aptl.core.lab import _LabStartContext, _step_load_config, _step_load_env

    project_dir = tmp_path_factory.mktemp("fresh") / "fresh-lab"
    materialize(project_dir)
    selected = project_dir / "scenarios" / "materialization-envelope.sdl.yaml"
    selected.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_MATERIALIZATION_ENVELOPE, selected)

    assert not (project_dir / "config" / "soc_certs").exists()
    assert not (project_dir / ".aptl").exists()

    ctx = _LabStartContext(
        project_dir=project_dir,
        skip_seed=True,
        scenario_path=Path("scenarios/materialization-envelope.sdl.yaml"),
    )
    assert _step_load_env(ctx) is None
    result = _step_load_config(ctx)
    assert result is None, result
    return ctx


@pytest.mark.integration
def test_fresh_init_admits_product_neutral_materialization_envelope(
    admitted_fresh_lab,
):
    """Fresh project admission reaches no scenario-specific adapter surface."""

    from aptl.core.scenario_bundle import ScenarioSourceKind

    ctx = admitted_fresh_lab
    admitted = ctx.admitted_start
    surface = ctx.admitted_surface
    assert admitted is not None
    assert admitted.runtime_materialization_failure is None
    assert admitted.bundle.pack_identity is None
    assert surface is not None
    assert surface.source_kind is ScenarioSourceKind.PROJECT_TREE
    assert surface.bundle_root == ctx.project_dir
    assert surface.selected_profiles == ()


@pytest.mark.integration
def test_fresh_init_qualification_is_read_only(admitted_fresh_lab):
    """Admission and backend qualification publish no lifecycle state."""

    ctx = admitted_fresh_lab
    assert not (ctx.project_dir / "config" / "soc_certs").exists()
    assert not (
        ctx.project_dir / ".aptl" / "lifecycle" / "workspace-ownership-v1.json"
    ).exists()


@pytest.mark.integration
def test_fresh_init_passes_bind_mount_preflight_without_adapter_state(
    admitted_fresh_lab,
):
    """The admitted generated model, not an unrelated product model, is checked."""

    from aptl.core.lab import _step_check_bind_mounts, _step_generate_soc_certs

    ctx = admitted_fresh_lab
    assert ctx.stateful_artifact_ownership == frozenset()
    assert _step_generate_soc_certs(ctx) is None
    assert _step_check_bind_mounts(ctx) is None
    assert not (ctx.project_dir / "config" / "soc_certs").exists()
