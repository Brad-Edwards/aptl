"""Safety helpers for Docker Compose named-volume seeding."""

import re
from pathlib import PurePosixPath

from aptl.core.deployment.errors import BackendSeedError
from aptl.utils.redaction import redact

_SAFE_SEED_RELPATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SEED_STDERR_HINT_MAX = 500


def redacted_stderr_hint(stderr: str | None) -> str:
    """Return a redacted, length-bounded stderr fragment for a seed log."""

    if not stderr or not stderr.strip():
        return ""
    redacted = redact(stderr).strip()
    if len(redacted) > _SEED_STDERR_HINT_MAX:
        redacted = "…" + redacted[-_SEED_STDERR_HINT_MAX:]
    return f" — stderr: {redacted}"


def assert_safe_relpath(relpath: str) -> None:
    """Reject a seed relpath that is unsafe to embed in a shell command."""

    if ".." in PurePosixPath(relpath).parts or not _SAFE_SEED_RELPATH.fullmatch(
        relpath
    ):
        raise BackendSeedError(f"Unsafe seed relpath rejected: {relpath!r}")
