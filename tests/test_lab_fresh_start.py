"""Issue #951: lab start's pre-flight must pass on a freshly installed lab.

The regression this file guards shipped to PyPI in 5.2.0 and was invisible to
every existing test. Two things hid it:

- the unit suite asserted the *old* behaviour directly — a scenario path that
  resolves to nothing left ownership empty and returned success;
- every developer checkout that has ever booted a lab carries the gitignored
  ``config/soc_certs/`` and ``.aptl/`` trees, so the bind-mount pre-flight found
  the sources it wanted and passed for the wrong reason.

So these tests start from a directory materialized by the public ``aptl lab
init`` path and assert those generated roots are absent before anything runs.
They then drive the real ordered lab-start steps that produced the failure —
load the environment, admit the configured scenario, prepare SOC TLS material,
    check bind mounts — against the acquired env-pack default, with no stubs on the
admission seam.

Integration-marked and integration-named: admitting the default scenario stages
the acquired pack and asks the deployment backend for component-image
availability, so it needs Docker and does not belong in the fast suite. That
admission is also expensive enough that the module admits **once** and both
tests assert against the same result — admitting per test built the component
image set twice per CI job.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def admitted_fresh_lab(tmp_path_factory):
    """Materialize a lab the way ``aptl lab init`` does, then admit it once.

    Returns the startup context after the real `_step_load_env` and
    `_step_load_config` have run, so the assertions below read one admission.
    """
    from aptl.core.assets import materialize
    from aptl.core.lab import _LabStartContext, _step_load_config, _step_load_env

    project_dir = tmp_path_factory.mktemp("fresh") / "fresh-lab"
    materialize(project_dir)

    # No pre-existing generated state: a developer's ignored trees are exactly
    # what masked this failure, so they must not be a fixture here.
    assert not (project_dir / "config" / "soc_certs").exists()
    assert not (project_dir / ".aptl").exists()

    ctx = _LabStartContext(project_dir=project_dir, skip_seed=True)
    assert _step_load_env(ctx) is None
    load_config_result = _step_load_config(ctx)
    assert load_config_result is None, load_config_result
    return ctx


@pytest.mark.integration
def test_fresh_init_directory_passes_bind_mount_preflight_integration(
    admitted_fresh_lab,
):
    """A clean install reaches the end of the bind-mount pre-flight.

    Before the fix this failed with eight missing ``config/soc_certs/`` sources
    for `misp`, `thehive`, `shuffle-frontend`, and `cortex` — services the
    env-pack realization starts from a *generated* Compose base that never binds
    those paths, described by a static ``docker-compose.yml`` the run does not
    use.
    """
    from aptl.core.lab import _step_check_bind_mounts, _step_generate_soc_certs

    ctx = admitted_fresh_lab
    # The configured default is the acquired env-pack, and admission must have
    # resolved it rather than substituting a scenario path deleted in #908.
    assert ctx.admitted_surface is not None
    assert ctx.stateful_artifact_ownership

    assert _step_generate_soc_certs(ctx) is None
    assert _step_check_bind_mounts(ctx) is None


@pytest.mark.integration
def test_fresh_init_admits_the_compose_model_the_run_applies_integration(
    admitted_fresh_lab,
):
    """The admitted bundle root, not the project directory, holds the model.

    The env-pack ships no ``docker-compose.yml``; the backend generates the base
    Compose model from the realization. The materialized project directory does
    ship one, so a pre-flight that reads the project directory is reading a file
    with no bearing on the run.
    """
    from aptl.core.scenario_bundle import ScenarioSourceKind

    ctx = admitted_fresh_lab
    surface = ctx.admitted_surface
    assert surface is not None
    assert surface.source_kind is ScenarioSourceKind.ENV_PACK
    assert (Path(ctx.project_dir) / "docker-compose.yml").is_file()
    assert surface.bundle_root != ctx.project_dir
    assert not (surface.bundle_root / "docker-compose.yml").exists()
