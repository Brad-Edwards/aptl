"""Dependency-light identity for APTL's RAES backend target."""

from __future__ import annotations

from dataclasses import dataclass

APTL_RAES_TARGET_NAME = "aptl"
APTL_RAES_TARGET_VERSION = "0.1.0"
APTL_RAES_TARGET_PROFILE = "full-remote-control-plane"


@dataclass(frozen=True)
class BackendIdentity:
    """Which backend serves a plan, including its selected capability profile."""

    target_name: str
    target_version: str
    profile: str
    provider: str = ""
    transport: str = ""


__all__ = [
    "APTL_RAES_TARGET_NAME",
    "APTL_RAES_TARGET_PROFILE",
    "APTL_RAES_TARGET_VERSION",
    "BackendIdentity",
]
