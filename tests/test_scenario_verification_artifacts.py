"""Built-artifact proof for the scenario-adapter boundary.

Two claims, and both need a real built wheel installed into a clean
environment rather than the checkout.

First, the code boundary: the wheel registers the entry points a scenario owns,
they resolve into the scenario's own top-level package, and the *framework*
package carries no scenario knowledge — in either the importable copy or the
bundled ``_labdata/src`` copy, since ``ASSET_ROOTS`` ships ``src`` twice over.

Second, the install: one install of one distribution is enough for semantic
verification to reach a verdict. That is the point of the adapter shipping with
the backend, and it is what an operator on the packaged path (DEP-008,
``pipx install aptl-labs``, no git clone) actually gets.

Every compatibility context is derived from the pack ``env_pack_bundle()``
admits (#879). A digest copied into this file would let the test agree with a
stale declaration, which is exactly how the original mismatch survived a
passing suite.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

from aptl.core.scenario_bundle import env_pack_bundle
from aptl.validation.scenario_verification import EXTENSION_API_VERSION

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Answer-key knowledge that must never appear in the framework package. Each
#: is a real string in the adapter today, so the negative assertion has teeth.
#:
#: Deliberately not the lab's container names: the framework legitimately knows
#: `aptl-kali` and `aptl-wazuh-manager` because they are APTL's own Compose
#: services, which it snapshots, reaches over SSH and exposes endpoints for.
#: What it must not hold is the scenario's *verdict* logic -- which components
#: serve which operator group, and which participant operations qualify it.
ANSWER_KEY_MARKERS = (
    b"provision.node.wazuh-manager",
    b"mcp.red.ssh-authentication-attack",
)

#: The adapter reads the range through core's operations surface. Supplying it
#: as a double keeps this contract evidence over installed artifacts; it is not
#: live proof, which belongs to the ``APTL_LIVE_GATE`` gate.
OPERATIONS_DOUBLE = """
from types import SimpleNamespace
class Operations:
    def reachability_from(self, origin):
        return SimpleNamespace(reached=True, diagnostics=())
    def shared_network_targets(self, origin):
        return (("target", "192.0.2.10"),)
"""


def _build_wheel(output: Path) -> Path:
    """Build the distribution with the repository's locked build toolchain."""

    if shutil.which("uv") is None:
        pytest.skip("uv is required for the repository's locked build proof")
    completed = subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--out-dir",
            str(output),
            str(REPO_ROOT),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    # A build failure is a failure, never a skip -- but say why. Without the
    # backend's stderr this surfaces as a bare CalledProcessError and reads like
    # a broken test rather than a missing locked build dependency.
    assert completed.returncode == 0, (
        f"building the wheel with the locked toolchain failed:\n{completed.stderr}"
    )
    wheels = sorted(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _members(wheel: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _clean_install(tmp_path: Path, wheel: Path) -> Path:
    """Return a fresh virtual environment holding only the built wheel."""

    venv = tmp_path / "clean-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    pip = venv / ("Scripts/pip.exe" if sys.platform == "win32" else "bin/pip")
    subprocess.run(
        [str(pip), "install", "--no-deps", str(wheel)],
        cwd=venv,
        check=True,
        capture_output=True,
    )
    return venv


def _run(venv: Path, script: str) -> None:
    """Run ``script`` in ``venv``, failing with its stderr on a non-zero exit."""

    completed = subprocess.run(
        [str(_python(venv)), "-c", script],
        cwd=venv,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _admitted_context(tmp_path: Path) -> str:
    """Return a context script bound to the pack env-packs actually admits.

    The identity is resolved here, in a process that has ``raes-env-packs``
    installed, and injected as data. The clean environment under test holds only
    the built wheel, so it could not resolve the pack itself -- and a literal in
    this file would prove nothing about the pack.
    """

    bundle = env_pack_bundle(tmp_path / "admitted-pack", "techvault")
    pack = bundle.pack_identity
    assert pack is not None
    scenario = {
        "identity": bundle.identity,
        "version": pack.pack_version,
        "source_kind": bundle.source_kind.value,
        "content_digest": pack.set_digest,
    }
    return f"""
from aptl.backends.identity import BackendIdentity
from aptl.validation.scenario_verification import (
    EXTENSION_API_VERSION,
    ScenarioIdentity,
    VerificationContext,
    VerificationStatus,
)
from aptl.validation.scenario_verification_discovery import verify_scenario

assert EXTENSION_API_VERSION == {EXTENSION_API_VERSION!r}
ADMITTED = ScenarioIdentity(**{json.dumps(scenario)})
BACKEND = BackendIdentity(
    target_name="aptl",
    target_version="0.1.0",
    profile="full-remote-control-plane",
    provider="docker-compose",
    transport="docker-compose",
)


def context(scenario=ADMITTED, operations=None, containers=()):
    return VerificationContext(
        run_id="artifact-run",
        attempt_id="artifact-attempt",
        scenario=scenario,
        backend=BACKEND,
        operations=operations,
        observations={{"containers": containers}},
    )
"""


@pytest.mark.integration
def test_the_wheel_keeps_scenario_knowledge_out_of_the_framework_package(
    tmp_path: Path,
) -> None:
    """The adapter ships in the wheel; the framework package stays scenario-free."""

    members = _members(_build_wheel(tmp_path / "dist"))

    entry_points = b"\n".join(
        content
        for name, content in members.items()
        if name.endswith("entry_points.txt")
    )
    for group in (
        b"aptl.scenario_verifiers",
        b"aptl.pack_backend_interactions",
        b"aptl.participant_mcp_smoke_plans",
    ):
        assert group in entry_points
    # Every registered target resolves into the adapter package, never into the
    # framework. That is the boundary; the distribution boundary is not.
    assert b"aptl_techvault." in entry_points
    assert b"= aptl.validation" not in entry_points

    assert any(name.startswith("aptl_techvault/") for name in members)

    # ``ASSET_ROOTS`` bundles ``src``, so scenario code ships as both an
    # importable package and a ``_labdata/src`` copy. Neither may sit inside
    # ``aptl/`` itself.
    framework = b"\n".join(
        content
        for name, content in members.items()
        if name.startswith("aptl/")
        and name.endswith(".py")
        and "_labdata/src/aptl_techvault/" not in name
    )
    offenders = [marker for marker in ANSWER_KEY_MARKERS if marker in framework]
    assert not offenders, f"scenario knowledge in the framework package: {offenders}"


@pytest.mark.integration
def test_one_install_reaches_a_verdict_and_records_its_provenance(
    tmp_path: Path,
) -> None:
    """A single install of a single distribution is enough (#879).

    The operator on the packaged path installs one thing. If semantic
    verification needed a second install they could never obtain it, and the
    gate would be permanently blocked for them.
    """

    header = _admitted_context(tmp_path)
    venv = _clean_install(tmp_path, _build_wheel(tmp_path / "dist"))

    _run(
        venv,
        header
        + OPERATIONS_DOUBLE
        + """
report = verify_scenario(
    context(
        operations=Operations(),
        containers=("aptl-kali", "aptl-wazuh-manager", "aptl-suricata"),
    )
)
assert report.status is VerificationStatus.PASSED, report.diagnostics
assert report.plugin_id == "techvault"
assert report.distribution == "aptl-labs"
assert report.distribution_version, "the version comes from installed metadata"
assert report.entry_point == "techvault.aptl"
""",
    )

    # A pack whose content moved on is content this release never qualified,
    # even though the adapter is installed and the scenario name still matches.
    _run(
        venv,
        header
        + """
from dataclasses import replace
stale = replace(ADMITTED, content_digest="sha256:" + "b" * 64)
report = verify_scenario(context(scenario=stale))
assert report.status is VerificationStatus.BLOCKED
assert "scenario content" in " ".join(report.diagnostics), report.diagnostics
""",
    )

    # And a released version never qualified is equally unadmitted, even at
    # content the adapter does qualify.
    _run(
        venv,
        header
        + """
from dataclasses import replace
report = verify_scenario(context(scenario=replace(ADMITTED, version="99.0.0")))
assert report.status is VerificationStatus.BLOCKED
""",
    )


@pytest.mark.integration
def test_an_unknown_scenario_blocks_rather_than_borrowing_an_adapter(
    tmp_path: Path,
) -> None:
    """Shipping adapters must not hand an unrelated scenario a verdict.

    This is what the retired "zero adapters" rule was protecting, and it still
    has to hold with adapters in the wheel: a scenario with no adapter of its
    own gets ``blocked``, never TechVault's answer key.
    """

    header = _admitted_context(tmp_path)
    venv = _clean_install(tmp_path, _build_wheel(tmp_path / "dist"))

    _run(
        venv,
        header
        + """
from dataclasses import replace
other = replace(ADMITTED, identity="some-other-scenario")
report = verify_scenario(context(scenario=other))
assert report.status is VerificationStatus.BLOCKED
assert report.plugin_id == ""
assert "no compatible scenario verifier" in " ".join(report.diagnostics)
""",
    )
