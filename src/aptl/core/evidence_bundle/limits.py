"""Versioned resource-limit profile for evidence-bundle export.

Limits are part of the versioned bundle contract, not hidden CLI defaults
(EXP-008 preflight "Verification is streaming and resource-bounded"). The
verifier enforces the SAME profile identifier while streaming, so a bundle
declares the bounds a third party must apply before allocating.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BundleLimits:
    """Hard bounds enforced before allocation, both at build and verify time."""

    profile_id: str
    max_entries: int
    max_member_bytes: int
    max_total_bytes: int
    max_path_length: int
    max_path_depth: int
    max_metadata_bytes: int
    max_decompress_ratio: int
    max_parser_depth: int
    max_jsonl_row_bytes: int
    max_jsonl_rows: int


#: The v1 default profile. Generous enough for real runs, tight enough that a
#: hostile archive cannot exhaust memory before the bounds fire.
DEFAULT_LIMITS = BundleLimits(
    profile_id="aptl-evidence-bundle-limits/v1",
    max_entries=100_000,
    max_member_bytes=512 * 1024 * 1024,
    max_total_bytes=8 * 1024 * 1024 * 1024,
    max_path_length=255,
    max_path_depth=16,
    max_metadata_bytes=4 * 1024 * 1024,
    max_decompress_ratio=200,
    max_parser_depth=64,
    max_jsonl_row_bytes=8 * 1024 * 1024,
    max_jsonl_rows=5_000_000,
)


__all__ = ["BundleLimits", "DEFAULT_LIMITS"]
