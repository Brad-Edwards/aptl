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
They drive the real environment/config/admission steps against the bundled
env-pack default, with no stubs on the admission seam.  The default TechVault
pack now correctly stops at the runtime-materialization gate on shared Docker,
so the fixture captures that real admission and then hands its already-admitted
surface to the two downstream bind-model assertions.  Production startup never
runs those later mutations after the gate fails.

Integration-marked and integration-named: admitting the default scenario stages
the bundled pack and asks the deployment backend for component-image
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

    Returns the startup context and the expected shared-Docker limitation after
    the real `_step_load_env` and `_step_load_config` have run.  A capturing
    wrapper retains the one real admission result for the downstream regression
    assertions; it does not replace or alter admission.
    """
    import aptl.core.lab as lab_module
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
    captured = {}
    real_admit = lab_module.admit_start_surface

    def capture_admission(*args, **kwargs):
        result = real_admit(*args, **kwargs)
        captured["result"] = result
        return result

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(lab_module, "admit_start_surface", capture_admission)
        materialization_failure = _step_load_config(ctx)

    admitted, surface = captured["result"]
    assert materialization_failure is admitted.runtime_materialization_failure
    assert materialization_failure is not None
    assert "aptl.provisioner.runtime-materialization-unsupported" in (
        materialization_failure.error
    )
    assert "backend=shared-docker" in materialization_failure.error
    assert ctx.admitted_start is None
    assert ctx.admitted_surface is None

    # The two tests below concern the later env-pack Compose model.  Make the
    # captured, already-admitted surface available to those direct step calls;
    # the public startup path above proved it stops before reaching them.
    ctx.admitted_start = admitted
    ctx.admitted_surface = surface
    ctx.stateful_artifact_ownership = surface.stateful_artifact_ownership
    return ctx, materialization_failure


@pytest.mark.integration
def test_fresh_init_default_fails_closed_on_shared_docker(admitted_fresh_lab):
    """The high-authority default pack stops before deployment preparation."""
    ctx, failure = admitted_fresh_lab

    assert failure.success is False
    assert not (ctx.project_dir / "config" / "soc_certs").exists()
    assert not (
        ctx.project_dir / ".aptl" / "lifecycle" / "workspace-ownership-v1.json"
    ).exists()


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

    ctx, _failure = admitted_fresh_lab
    # The configured default is the bundled env-pack, and admission must have
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

    ctx, _failure = admitted_fresh_lab
    surface = ctx.admitted_surface
    assert surface is not None
    assert surface.source_kind is ScenarioSourceKind.ENV_PACK
    assert (Path(ctx.project_dir) / "docker-compose.yml").is_file()
    assert surface.bundle_root != ctx.project_dir
    assert not (surface.bundle_root / "docker-compose.yml").exists()
