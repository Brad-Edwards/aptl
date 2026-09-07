"""Prove the plugin's release artifacts never ride out with core's (issue #879).

The release job builds core into ``dist/`` and uploads that directory with a
glob. A plugin artifact that ended up there would be published under the core
release's tag and attestation, which is exactly what "independently releasable"
must not mean. So this asserts the separation in both directions:

- every artifact in core's release directory belongs to ``aptl-labs``;
- the plugin's own directory builds a wheel *and* an sdist for the plugin
  distribution, so a release can be cut from it without an editable checkout.

Absence that cannot be proved is a failure: an empty or missing directory exits
non-zero rather than reporting a clean boundary.
"""

from __future__ import annotations

from pathlib import Path
import sys

#: Distribution names, as they appear normalized in an artifact filename.
CORE_DISTRIBUTION = "aptl_labs"
PLUGIN_DISTRIBUTION = "aptl_techvault_verifier"


def _artifacts(directory: Path) -> list[Path]:
    """Return the build artifacts in ``directory``, or fail if there are none."""

    if not directory.is_dir():
        sys.exit(f"error: {directory} is not a directory")
    found = sorted(
        path
        for path in directory.iterdir()
        if path.suffix in {".whl", ".gz"} or path.name.endswith(".tar.gz")
    )
    if not found:
        sys.exit(f"error: {directory} contains no build artifacts to check")
    return found


def _normalized(name: str) -> str:
    """Return an artifact filename's distribution part, normalized."""

    return name.split("-", 1)[0].replace("-", "_").replace(".", "_").lower()


def main(argv: list[str]) -> int:
    """Check the core and plugin artifact directories against each other."""

    if len(argv) != 2:
        sys.exit("usage: assert_release_artifact_boundary.py <core-dist> <plugin-dist>")
    core_dir, plugin_dir = (Path(value) for value in argv)

    strays = [
        path.name
        for path in _artifacts(core_dir)
        if _normalized(path.name) != CORE_DISTRIBUTION
    ]
    if strays:
        sys.exit(
            f"error: {core_dir} is uploaded by the release glob but carries "
            f"artifacts from another distribution: {', '.join(strays)}"
        )

    plugin_artifacts = _artifacts(plugin_dir)
    foreign = [
        path.name
        for path in plugin_artifacts
        if _normalized(path.name) != PLUGIN_DISTRIBUTION
    ]
    if foreign:
        sys.exit(
            f"error: {plugin_dir} carries artifacts from another distribution: "
            f"{', '.join(foreign)}"
        )
    suffixes = {
        "wheel" if path.name.endswith(".whl") else "sdist"
        for path in plugin_artifacts
    }
    if suffixes != {"wheel", "sdist"}:
        sys.exit(
            f"error: {plugin_dir} must build both a wheel and an sdist for an "
            f"independent release; found {sorted(suffixes)}"
        )

    print(
        f"ok: {len(plugin_artifacts)} plugin artifacts build separately and "
        f"{core_dir}/ carries only {CORE_DISTRIBUTION}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
