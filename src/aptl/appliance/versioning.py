"""Bounded version and wheel-name parsing for appliance releases."""

from __future__ import annotations

_VERSION_SUFFIX = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.+-")


def is_appliance_version(value: str) -> bool:
    """Return whether a version has three numeric parts and a safe suffix."""

    major, dot, remainder = value.partition(".")
    minor, second_dot, patch_and_suffix = remainder.partition(".")
    if not dot or not second_dot or not major.isdigit() or not minor.isdigit():
        return False
    patch_length = 0
    for character in patch_and_suffix:
        if not character.isdigit():
            break
        patch_length += 1
    patch = patch_and_suffix[:patch_length]
    suffix = patch_and_suffix[patch_length:]
    return bool(patch) and all(character in _VERSION_SUFFIX for character in suffix)


def aptl_wheel_version(name: str, *, prefix: str = "aptl_labs-") -> str | None:
    """Extract a validated normalized APTL version from one wheel path."""

    filename = name.rsplit("/", 1)[-1]
    if not filename.startswith(prefix) or not filename.endswith(".whl"):
        return None
    version, separator, tags = filename[len(prefix) :].partition("-")
    normalized = version.replace("_", "-")
    if not separator or not tags or not is_appliance_version(normalized):
        return None
    return normalized
