"""Built-artifact proof for the scenario-verification extension boundary.

Two things are being proved, and both need real artifacts rather than the
checkout. First, that core ships zero adapters: its wheel registers nothing in
the seam's entry-point group and carries no answer key, in either the importable
package or the bundled ``_labdata/src`` copy. Second, that the verifier is an
independently installable, independently releasable distribution: it builds a
wheel and an sdist from its own root, declares the released core it imports,
installs and uninstalls without an editable checkout, and is discovered from
installed metadata.

Every compatibility context here is derived from the pack ``env_pack_bundle()``
actually admits (#879). A digest copied into this file would let the test agree
with a stale plugin declaration -- which is exactly how the original mismatch
survived a passing suite.
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
from aptl.validation.scenario_verification import (
    EXTENSION_API_MIN_CORE_RELEASE,
    EXTENSION_API_VERSION,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "aptl-techvault-verifier"

ANSWER_KEY_MARKERS = (
    b"aptl-live-gate-invalid",
    b"mcp.red.ssh-authentication-attack",
    b"kali nmap + failed-ssh-auth",
)

#: Driven by the installed plugin through core's operations surface. The wheel
#: test supplies these as fakes, so this is contract evidence, not live proof.
OPERATIONS_DOUBLE = """
from types import SimpleNamespace
class Operations:
    def reachability_from(self, origin):
        return SimpleNamespace(reached=True, diagnostics=())
    def shared_network_targets(self, origin):
        return (("target", "192.0.2.10"),)
    def tcp_reachable_from(self, origin, address, port):
        return True
    def execute_in_node(self, origin, argv, *, timeout_seconds):
        return True
    def collect_evidence(self, **kwargs):
        kwargs["trigger"]()
        assert kwargs["alert_matches"](
            {"rule": {}, "marker": "aptl-live-gate-invalid"}
        )
        assert not kwargs["alert_matches"]({"rule": {}, "marker": "unrelated"})
        return SimpleNamespace(observed=True, diagnostics=())
"""


def _build(source: Path, output: Path, *, sdist: bool = False) -> list[Path]:
    """Build ``source`` with the repository's locked build toolchain."""

    if shutil.which("uv") is None:
        pytest.skip("uv is required for the repository's locked build proof")
    completed = subprocess.run(
        [
            "uv",
            "build",
            "--wheel" if not sdist else "--sdist",
            "--no-build-isolation",
            "--out-dir",
            str(output),
            str(source),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    # A build failure is a failure, never a skip -- but say why. Without the
    # backend's own stderr this surfaces as a bare CalledProcessError and reads
    # like a broken test rather than a missing locked build dependency.
    assert completed.returncode == 0, (
        f"building {source.name} with the locked toolchain failed:\n"
        f"{completed.stderr}"
    )
    return sorted(output.glob("*.whl" if not sdist else "*.tar.gz"))


def _build_wheel(source: Path, output: Path) -> Path:
    wheels = _build(source, output)
    assert len(wheels) == 1
    return wheels[0]


def _wheel_members(wheel: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _metadata(members: dict[str, bytes]) -> str:
    """Return the wheel's core metadata as text."""

    return "\n".join(
        content.decode("utf-8")
        for name, content in members.items()
        if name.endswith(".dist-info/METADATA")
    )


def _python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _run(venv: Path, script: str) -> None:
    """Run ``script`` in ``venv``, failing with its stderr if it exits non-zero."""

    completed = subprocess.run(
        [str(_python(venv)), "-c", script],
        cwd=venv,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _pip(venv: Path, *arguments: str) -> None:
    executable = venv / ("Scripts/pip.exe" if sys.platform == "win32" else "bin/pip")
    subprocess.run(
        [str(executable), *arguments], cwd=venv, check=True, capture_output=True
    )


def _admitted_context(tmp_path: Path) -> str:
    """Return a context script bound to the pack env-packs actually admits.

    The identity is resolved here, in a process that has ``raes-env-packs``
    installed, and injected as data. The clean virtual environment under test
    deliberately has only core and the plugin, so it could not resolve the pack
    itself -- and a literal in this file would prove nothing about the pack.
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
def test_core_wheel_ships_no_adapter_and_no_answer_key(tmp_path: Path) -> None:
    """Zero adapters means zero adapters, in both wheel payload locations."""

    core_wheel = _build_wheel(REPO_ROOT, tmp_path / "core-dist")
    core_members = _wheel_members(core_wheel)

    core_entry_points = b"\n".join(
        content
        for name, content in core_members.items()
        if name.endswith("entry_points.txt")
    )
    assert b"aptl.scenario_verifiers" not in core_entry_points
    assert b"aptl.participant_mcp_smoke_plans" not in core_entry_points
    assert not any("aptl_techvault_verifier" in name for name in core_members)
    # ASSET_ROOTS bundles `src`, so the answer keys would ship twice over:
    # inspect the importable package and the bundled copy alike.
    payload = b"\n".join(
        content for name, content in core_members.items() if name.endswith(".py")
    )
    assert not any(marker in payload for marker in ANSWER_KEY_MARKERS)


@pytest.mark.integration
def test_the_verifier_builds_as_an_independently_releasable_distribution(
    tmp_path: Path,
) -> None:
    """A locally importable package is not yet a releasable artifact (#879).

    Release readiness is four separate claims: both artifact kinds build from
    the plugin's own root, the wheel registers the seam entry points, it declares
    the released core whose extension types it imports, and it supports the same
    Python versions core does -- otherwise TechVault verification silently
    vanishes on a host APTL supports.
    """

    output = tmp_path / "plugin-dist"
    wheel = _build_wheel(PLUGIN_ROOT, output)
    sdists = _build(PLUGIN_ROOT, output, sdist=True)

    assert len(sdists) == 1
    assert wheel.name.startswith("aptl_techvault_verifier-")
    assert sdists[0].name.startswith("aptl_techvault_verifier-")

    members = _wheel_members(wheel)
    entry_points = b"\n".join(
        content for name, content in members.items()
        if name.endswith("entry_points.txt")
    )
    assert b"aptl.scenario_verifiers" in entry_points
    assert b"techvault.aptl" in entry_points
    assert b"aptl.participant_mcp_smoke_plans" in entry_points
    assert b"guided-purple.techvault-attacker-target" in entry_points
    assert ANSWER_KEY_MARKERS[0] in b"\n".join(members.values())

    metadata = _metadata(members)
    # The exact floor, not merely the presence of a header: a floor below the
    # release that first carried this extension API lets pip install the pair
    # and then fail at import, before version admission can refuse it. The
    # specifiers are compared as a set because wheel metadata normalizes their
    # order.
    assert _core_requirement(metadata) == {
        f">={EXTENSION_API_MIN_CORE_RELEASE}",
        "<6",
    }

    core_wheel = _build_wheel(REPO_ROOT, tmp_path / "core")
    core_metadata = _metadata(_wheel_members(core_wheel))
    plugin_python = _requires_python(metadata)
    assert plugin_python == _requires_python(core_metadata), (
        "a narrower plugin floor leaves a host APTL supports with no TechVault "
        "verification and no statement that it is unsupported"
    )


def _core_requirement(metadata: str) -> set[str]:
    """Return the version specifiers the wheel declares against core."""

    for line in metadata.splitlines():
        if line.startswith("Requires-Dist:") and "aptl-labs" in line:
            specifiers = line.split(":", 1)[1].strip().removeprefix("aptl-labs")
            return {part.strip() for part in specifiers.split(",") if part.strip()}
    raise AssertionError(
        "the plugin imports core's public verifier types, so its distribution "
        "must declare the released core range that supplies them"
    )


def _requires_python(metadata: str) -> str:
    """Return the ``Requires-Python`` constraint declared in wheel metadata."""

    for line in metadata.splitlines():
        if line.startswith("Requires-Python:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("wheel metadata declares no Requires-Python")


@pytest.mark.integration
def test_core_only_install_blocks_until_the_verifier_wheel_is_installed(
    tmp_path: Path,
) -> None:
    """The seam, end to end, over installed artifacts and the admitted pack."""

    core_wheel = _build_wheel(REPO_ROOT, tmp_path / "core-dist")
    plugin_wheel = _build_wheel(PLUGIN_ROOT, tmp_path / "plugin-dist")
    header = _admitted_context(tmp_path)

    venv = tmp_path / "clean-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    _pip(venv, "install", "--no-deps", str(core_wheel))

    # Core alone: no verdict is possible, and that is terminal, not a pass.
    _run(
        venv,
        header
        + """
report = verify_scenario(context())
assert report.status is VerificationStatus.BLOCKED
assert report.status is not VerificationStatus.PASSED
assert report.distribution == ""
""",
    )

    _pip(venv, "install", "--no-deps", str(plugin_wheel))

    # Installed: the qualified pack runs, and provenance is host-observed.
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
assert report.distribution == "aptl-techvault-verifier"
assert report.distribution_version, "the version comes from installed metadata"
assert report.entry_point == "techvault.aptl"
""",
    )

    # A pack whose content moved on is content this release never qualified,
    # even though the plugin is installed and its scenario name still matches.
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

    # And a released version the plugin never qualified is equally unadmitted,
    # even at content the plugin does qualify.
    _run(
        venv,
        header
        + """
from dataclasses import replace
unqualified = replace(ADMITTED, version="99.0.0")
report = verify_scenario(context(scenario=unqualified))
assert report.status is VerificationStatus.BLOCKED
""",
    )

    # Uninstall returns the environment to blocked; reinstall restores the
    # verdict. Neither step involves an editable checkout or a source path.
    _pip(venv, "uninstall", "-y", "aptl-techvault-verifier")
    _run(
        venv,
        header
        + """
report = verify_scenario(context())
assert report.status is VerificationStatus.BLOCKED
""",
    )
    _pip(venv, "install", "--no-deps", str(plugin_wheel))
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
""",
    )
