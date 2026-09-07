"""The plugin's release artifacts never ride out with core's (issue #879).

The release job builds core into ``dist/`` and uploads that whole directory with
a glob, under core's tag and build attestation. A plugin artifact that landed
there would be published as part of a core release -- which is the precise
opposite of "independently releasable" -- and nothing would notice, because the
upload is a glob and the tag is core's either way.

``scripts/ci/assert_release_artifact_boundary.py`` is the gate. These tests drive
it over real directory contents, so removing the check or loosening it to a
warning goes red here. The gate also has to prove the *positive* half: a
distribution that cannot produce both a wheel and an sdist from its own root is
not releasable, whatever its metadata claims.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE = REPO_ROOT / "scripts" / "ci" / "assert_release_artifact_boundary.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "checks.yml"

CORE_ARTIFACTS = ("aptl_labs-5.2.0-py3-none-any.whl", "aptl_labs-5.2.0.tar.gz")
PLUGIN_ARTIFACTS = (
    "aptl_techvault_verifier-0.2.0-py3-none-any.whl",
    "aptl_techvault_verifier-0.2.0.tar.gz",
)


def _populate(directory: Path, names: tuple[str, ...]) -> Path:
    """Create ``directory`` holding one empty file per artifact name."""

    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_bytes(b"")
    return directory


def _run(core: Path, plugin: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), str(core), str(plugin)],
        capture_output=True,
        text=True,
    )


def test_separately_built_artifacts_pass(tmp_path: Path) -> None:
    result = _run(
        _populate(tmp_path / "dist", CORE_ARTIFACTS),
        _populate(tmp_path / "plugin-dist", PLUGIN_ARTIFACTS),
    )

    assert result.returncode == 0, result.stderr
    assert "aptl_labs" in result.stdout


def test_a_plugin_artifact_in_the_release_glob_fails(tmp_path: Path) -> None:
    """The regression the gate exists for: core's upload sweeping up a plugin."""

    result = _run(
        _populate(tmp_path / "dist", CORE_ARTIFACTS + PLUGIN_ARTIFACTS),
        _populate(tmp_path / "plugin-dist", PLUGIN_ARTIFACTS),
    )

    assert result.returncode != 0
    assert "aptl_techvault_verifier" in result.stderr


def test_a_plugin_directory_missing_an_artifact_kind_fails(tmp_path: Path) -> None:
    """A wheel alone is not a releasable distribution."""

    result = _run(
        _populate(tmp_path / "dist", CORE_ARTIFACTS),
        _populate(tmp_path / "plugin-dist", PLUGIN_ARTIFACTS[:1]),
    )

    assert result.returncode != 0
    assert "wheel and an sdist" in result.stderr


@pytest.mark.parametrize("missing", ["dist", "plugin-dist"])
def test_an_empty_or_absent_directory_fails_rather_than_reporting_clean(
    tmp_path: Path, missing: str
) -> None:
    """Absence that cannot be proved is a failure, not a clean boundary."""

    core = _populate(tmp_path / "dist", CORE_ARTIFACTS)
    plugin = _populate(tmp_path / "plugin-dist", PLUGIN_ARTIFACTS)
    for artifact in (tmp_path / missing).iterdir():
        artifact.unlink()

    result = _run(core, plugin)

    assert result.returncode != 0
    assert "no build artifacts" in result.stderr


def test_ci_runs_the_gate_and_the_pack_identity_tests() -> None:
    """The gates exist in CI, not only in this repository's intentions.

    Issue #879's second half was that nothing installed the verifier and nothing
    executed the one test that resolves the real pack identity. A test that only
    checked the scripts would have passed throughout that.
    """

    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]

    identity_job = jobs["pack-identity-compatibility"]
    identity_steps = " ".join(
        str(step.get("run", "")) for step in identity_job["steps"]
    )
    assert "tests/test_env_pack_bundle.py" in identity_steps
    assert "tests/test_plugin_pack_compatibility.py" in identity_steps
    assert "plugins/aptl-techvault-verifier" in identity_steps

    release_steps = " ".join(
        str(step.get("run", "")) for step in jobs["verifier-release-artifacts"]["steps"]
    )
    assert "assert_release_artifact_boundary.py" in release_steps
    assert "plugins/aptl-techvault-verifier" in release_steps

    # And the fast suite runs with the verifier installed, so the plugin's own
    # contract tests exercise the installed distribution.
    python_steps = " ".join(
        str(step.get("run", "")) for step in jobs["python-tests"]["steps"]
    )
    assert "plugins/aptl-techvault-verifier" in python_steps
