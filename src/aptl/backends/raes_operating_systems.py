"""Finite operating-system support and guest readback for the RAES backend."""

from __future__ import annotations

import re
from collections.abc import Mapping

from raes_backend_protocols.capabilities import OperatingSystemCompatibility
from raes_contracts.realization_observation import ObservedOperatingSystemIdentity

# RAES 4.1 requires OS support to be a coupled family/distribution/release
# domain.  These are the bounded Linux releases used by APTL's trusted Compose
# services and generic container substrates.  Unknown or newer releases are not
# silently treated as compatible: they need an explicit row before admission.
APTL_OPERATING_SYSTEMS = (
    OperatingSystemCompatibility("linux", "debian", frozenset({"12"})),
    OperatingSystemCompatibility(
        "linux", "ubuntu", frozenset({"20.04", "22.04", "24.04"})
    ),
    OperatingSystemCompatibility("linux", "rocky-linux", frozenset({"8", "9"})),
    OperatingSystemCompatibility(
        "linux",
        "x-aptl:alpine",
        frozenset({"3.18", "3.19", "3.20", "3.21", "3.22"}),
    ),
    OperatingSystemCompatibility(
        "linux", "x-aptl:amazon-linux", frozenset({"2", "2023"})
    ),
    OperatingSystemCompatibility("linux", "x-aptl:centos", frozenset({"7", "8", "9"})),
    OperatingSystemCompatibility(
        "linux",
        "x-aptl:kali",
        frozenset({"2024.4", "2025.1", "2025.2", "2025.3"}),
    ),
)

_DISTRIBUTION_NAMES = {
    "debian": "debian",
    "ubuntu": "ubuntu",
    "rocky": "rocky-linux",
    "rockylinux": "rocky-linux",
    "rhel": "red-hat-enterprise-linux",
    "alpine": "x-aptl:alpine",
    "amzn": "x-aptl:amazon-linux",
    "centos": "x-aptl:centos",
    "kali": "x-aptl:kali",
}
_MAX_OS_RELEASE_BYTES = 4096
_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def parse_os_release(payload: bytes | str) -> ObservedOperatingSystemIdentity | None:
    """Parse a bounded Linux ``/etc/os-release`` payload.

    Only the non-sensitive ``ID`` and ``VERSION_ID`` fields are accepted.  The
    resulting identity must fall inside APTL's declared finite compatibility
    rows; malformed, unknown, or newer releases therefore fail closed.
    """

    text = _decode_os_release(payload)
    fields = _parse_os_release_fields(text) if text is not None else None
    return _supported_os_identity(fields) if fields is not None else None


def _decode_os_release(payload: bytes | str) -> str | None:
    """Decode a bounded strict UTF-8 os-release document."""

    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    text = None
    if isinstance(raw, bytes) and len(raw) <= _MAX_OS_RELEASE_BYTES:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
    return text


def _parse_os_release_fields(text: str) -> dict[str, str] | None:
    """Parse unique printable os-release assignments without shell expansion."""

    fields: dict[str, str] = {}
    valid = True
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or _KEY_RE.fullmatch(key) is None or key in fields:
            valid = False
            break
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                valid = False
                break
            value = value[1:-1]
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
            valid = False
            break
        fields[key] = value
    return fields if valid else None


def _supported_os_identity(
    fields: Mapping[str, str],
) -> ObservedOperatingSystemIdentity | None:
    """Resolve parsed fields only inside APTL's finite support declaration."""

    distribution = _DISTRIBUTION_NAMES.get(fields.get("ID", "").lower())
    version = fields.get("VERSION_ID", "")
    if distribution is None or not version:
        return None
    supported = any(
        row.family == "linux"
        and row.distribution == distribution
        and version in row.versions
        for row in APTL_OPERATING_SYSTEMS
    )
    return (
        ObservedOperatingSystemIdentity(
            family="linux", distribution=distribution, version=version
        )
        if supported
        else None
    )


def operating_system_rows_payload() -> list[Mapping[str, object]]:
    """Return the envelope carrier representation of the finite support rows."""

    return [
        {
            "family": row.family,
            "distribution": row.distribution,
            "versions": sorted(row.versions),
        }
        for row in APTL_OPERATING_SYSTEMS
    ]
