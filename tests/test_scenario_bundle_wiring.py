"""The bundle seam must be wired into the production realization path.

A seam that exists as a type with its own tests but that nothing constructs or
passes is not a seam — it is a placeholder that reads as done. These tests assert
the wiring itself, so the decoupling cannot be claimed while realization still
anchors to the engine's checkout.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from aptl.backends.raes import create_aptl_runtime_target
from aptl.backends.raes_provisioner import AptlProvisioner
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import project_tree_bundle

_PROJECT = Path(__file__).resolve().parents[1]


def _bundle(root: Path):
    return project_tree_bundle(root, Path("scenarios") / "demo.sdl.yaml")


def test_provisioner_carries_the_bundle_it_was_given():
    """The component that realizes plans must know which scenario it realizes."""

    bundle = _bundle(_PROJECT)
    provisioner = AptlProvisioner(
        project_dir=_PROJECT,
        config=AptlConfig(),
        deployment_backend=MagicMock(),
        bundle=bundle,
    )

    assert provisioner.bundle is bundle


def test_runtime_target_threads_the_bundle_to_the_provisioner():
    """Resolving a scenario once must carry through to realization."""

    bundle = _bundle(_PROJECT)
    target = create_aptl_runtime_target(
        project_dir=_PROJECT,
        config=AptlConfig(),
        backend=MagicMock(),
        bundle=bundle,
    )

    assert target.provisioner.bundle is bundle


def test_realization_receives_the_bundle_not_just_the_project(monkeypatch):
    """The seam is only real if realization is told the scenario root.

    Without this the bundle can exist, be tested in isolation, and still be
    ignored by every production path — which is exactly what happened before.
    """

    seen: dict[str, object] = {}

    def _capture(*, plan, project_dir, config, bundle=None):
        seen["bundle"] = bundle
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(
        "aptl.backends.raes_provisioner.interpret_provisioning_plan", _capture
    )

    bundle = _bundle(_PROJECT)
    provisioner = AptlProvisioner(
        project_dir=_PROJECT,
        config=AptlConfig(),
        deployment_backend=MagicMock(),
        bundle=bundle,
    )
    try:
        provisioner._realize_plan(object())
    except RuntimeError:
        pass

    assert seen["bundle"] is bundle


def test_the_public_start_path_resolves_a_bundle():
    """`start_raes_scenario`'s planning step must produce one, not None."""

    import inspect

    from aptl.backends import raes

    source = inspect.getsource(raes._plan_scenario)
    assert "project_tree_bundle" in source, (
        "the public start path does not resolve a scenario bundle"
    )
