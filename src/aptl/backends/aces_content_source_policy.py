"""Content-placement source policy: what a scenario may name as `source:` (#816).

Split out of ``aces_content_realization.py`` (module-length budget). A
retroactive Codex security review of merged PR #812 found that content-
placement source resolution only checked project-root containment, never
*which* file was selected — a scenario could name ``.env`` (real operator
credentials) as its source, target a participant-accessible node like kali,
and the file would be copied in. The author-set ``sensitive`` flag on the
content spec is self-reported metadata; it never gated this.

``forbidden_source_reason`` is checked before, and independent of, the
project-containment check both content-realization entry points already
run: a path can be entirely inside the project root and still be something
a scenario must never be able to select.
"""

from __future__ import annotations

# Pure secret material with no legitimate scenario-content use, regardless
# of project-root containment: a content placement naming one of these as
# its source could copy a real operator credential into any addressed
# node, including one a lab participant can reach (e.g. kali over SSH).
_FORBIDDEN_SOURCE_PREFIXES = (
    ".git/",
    "config/soc_certs/",
    "config/wazuh_indexer_ssl_certs/",
)

# keys/ and config/lab-ssh/ are the one exception: they hold both the
# public/combined authorized_keys files legitimately distributed onto
# target nodes and the SEC #417 pivot private keys intentionally placed
# onto their designated node (src/aptl/core/ssh.py). A blanket deny would
# break those already-shipped placements, so instead only the exact
# filenames that module generates are allowed; anything else under these
# directories is unexpected and rejected the same as a forbidden path.
_KEY_MATERIAL_PREFIXES = ("keys/", "config/lab-ssh/")
_ALLOWED_KEY_SOURCE_NAMES = frozenset(
    {
        "keys/aptl_lab_key.pub",
        "keys/authorized_keys",
        "keys/target_authorized_keys",
        "keys/victim_authorized_keys",
        "config/lab-ssh/kali_pivot_key",
        "config/lab-ssh/kali_pivot_key.pub",
        "config/lab-ssh/workstation_pivot_key",
        "config/lab-ssh/workstation_pivot_key.pub",
    }
)


def forbidden_source_reason(source_name: str) -> str | None:
    """Return a reason code if `source_name` must never be a content source."""

    normalized = source_name.lstrip("/")
    checks = (
        (
            normalized == ".env" or normalized.startswith(".env."),
            "source-is-environment-file",
        ),
        (
            normalized == ".git"
            or any(normalized.startswith(prefix) for prefix in _FORBIDDEN_SOURCE_PREFIXES),
            "source-is-forbidden-path",
        ),
        (
            any(normalized.startswith(prefix) for prefix in _KEY_MATERIAL_PREFIXES)
            and normalized not in _ALLOWED_KEY_SOURCE_NAMES,
            "source-is-unlisted-key-material",
        ),
    )
    for is_match, reason in checks:
        if is_match:
            return reason
    return None
