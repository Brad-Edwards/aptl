"""The check record ``aptl doctor`` reports, and the helpers its checks share.

:mod:`aptl.core.doctor` runs the workspace and host-tool checks, and
:mod:`aptl.core._doctor_runtime` runs the Docker engine checks (#1218). Both
build their results from this module, so the engine checks need nothing from
:mod:`aptl.core.doctor` and the two modules form no import cycle.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

PROBE_TIMEOUT_SECONDS = 30
NO_PROJECT_DIRECTORY = "the project directory does not exist (see project-config)"
_VERSION_TEXT = re.compile(r"v?(\d+)\.(\d+)[0-9A-Za-z.+-]{0,40}")

Which = Callable[[str], str | None]


class CheckStatus(str, Enum):
    """Verdict of one doctor check; the values are stable output words."""

    PASSED = "pass"
    WARNING = "warn"
    FAILED = "fail"
    SKIPPED = "skip"


@dataclass(frozen=True)
class DoctorCheck:
    """One observed prerequisite, with the fix when it is not met."""

    check_id: str
    status: CheckStatus
    summary: str
    fix: str = ""


def skipped(check_id: str, reason: str) -> DoctorCheck:
    """Return a check that could not run, and why."""

    return DoctorCheck(check_id, CheckStatus.SKIPPED, f"Not checked: {reason}.")


def version_text(raw: object) -> str | None:
    """Return a bounded version string, or ``None`` for anything else."""

    text = str(raw or "").strip()
    return text if _VERSION_TEXT.fullmatch(text) else None


def major_minor(raw: object) -> tuple[int, int] | None:
    """Parse ``major.minor`` from a version string such as ``v20.11.1``."""

    match = _VERSION_TEXT.fullmatch(str(raw or "").strip())
    return (int(match.group(1)), int(match.group(2))) if match else None
