"""Pure value parsing helpers for Docker materialization readback."""

from __future__ import annotations

from pathlib import PurePosixPath


def metadata_dimension_matches(actual: str, expected: object) -> bool:
    """Match one selected filesystem dimension, treating omission as open."""

    return expected in ("", None) or actual == str(expected)


def npm_entrypoint_paths(package: dict[str, object]) -> tuple[str, ...]:
    """Return safe relative main/bin paths declared by an npm package."""

    candidates: list[object] = [package.get("main")]
    package_bin = package.get("bin")
    if isinstance(package_bin, dict):
        candidates.extend(package_bin.values())
    else:
        candidates.append(package_bin)

    paths: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        normalized = candidate.removeprefix("./")
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            continue
        rendered = str(path)
        if rendered not in paths:
            paths.append(rendered)
    return tuple(paths)


def samba_domain_info(output: str) -> dict[str, str]:
    """Parse the bounded key/value surface emitted by ``samba-tool``."""

    observed: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            observed[key.strip().casefold()] = value.strip()
    return observed


__all__ = (
    "metadata_dimension_matches",
    "npm_entrypoint_paths",
    "samba_domain_info",
)
