"""Suricata named-volume seeding and source-ownership repair.

Split out of :mod:`aptl.core.credentials` (ADR-028/ADR-043): the credential
*rendering* path and the Suricata *seed* path share the same project-rooted
containment primitives but are otherwise independent concerns. Keeping them in
separate modules holds each below the file-length limit and lets the seed logic
evolve without touching the credential renderer.

Under ADR-043 the checked-in Suricata runtime inputs are copied into Compose
named volumes by a root seed container at lab start rather than rendered or
bind-mounted, so the upstream image entrypoint's ``chown`` can never rewrite
host-side ownership.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.core.credentials import (
    PathContainmentError,
    _canonical_generated_path,
    _resolve_within_project,
)
from aptl.core.seed_spec import NamedVolumeSeed, SeedFile
from aptl.utils.logging import get_logger

log = get_logger("suricata_seed")

# Suricata runtime-input sources (checked in, never written). Under ADR-043
# these are copied into Compose named volumes by a root seed container at lab
# start rather than rendered/bind-mounted, so the upstream image entrypoint's
# chown can never rewrite host-side ownership.
_SURICATA_CONFIG_SOURCE_RELPATH = Path("config/suricata")
_SURICATA_MISP_RULES_SOURCE_RELPATH = Path("config/suricata/rules/misp")

# Suricata runtime files copied into the seed volumes. The config seed holds
# the engine config plus the operator-authored local rules; the MISP volume
# holds the four IOC rule baselines the sync service later overwrites.
_SURICATA_CONFIG_SEED_FILES = (
    ("suricata.yaml", "suricata.yaml"),
    ("rules/local.rules", "rules/local.rules"),
)
_SURICATA_MISP_RULE_FILES = (
    "misp-iocs.rules",
    "misp-md5.list",
    "misp-sha1.list",
    "misp-sha256.list",
)

# Compose volume keys. The deployment backend resolves the real, Compose
# project-scoped name as ``<project>_<suffix>`` (ADR-043 forbids explicit
# global volume names). docker-compose.yml must declare these same keys.
SURICATA_CONFIG_SEED_VOLUME = "suricata_config_seed"
SURICATA_MISP_RULES_VOLUME = "suricata_misp_rules"

# Pre-ADR-043 host bind directory for the MISP rules. Prior lab runs left it
# owned by the in-container ``suricata`` UID (991 == ``systemd-network`` on
# Ubuntu hosts), so the host operator cannot delete it. The seed step retires
# this one canonical, contained path via a root container.
_SURICATA_LEGACY_MISP_RELPATH = Path(".aptl/suricata/rules/misp")


@dataclass(frozen=True)
class SuricataSourceOwnershipResult:
    """Result of restoring checked-in Suricata seed source ownership."""

    success: bool
    repaired: tuple[str, ...] = ()
    error: str = ""


def _suricata_config_source_files(project_dir: Path) -> tuple[Path, ...]:
    """Return the checked-in Suricata config seed sources (containment-checked)."""
    config_src = _resolve_within_project(
        project_dir, _SURICATA_CONFIG_SOURCE_RELPATH,
    )
    paths: list[Path] = []
    for src_rel, _dest_rel in _SURICATA_CONFIG_SEED_FILES:
        paths.append(config_src / src_rel)
    return tuple(paths)


def _foreign_owned_sources(source_files: tuple[Path, ...], uid: int) -> list[Path]:
    """Return the existing *source_files* not owned by *uid*."""
    return [
        path
        for path in source_files
        if path.is_file() and path.stat().st_uid != uid
    ]


def _chown_direct(paths: list[Path], uid: int, gid: int) -> list[Path]:
    """``chown`` each path to *uid*/*gid*; return those still foreign-owned.

    Stops at the first :class:`PermissionError` (an unprivileged process
    cannot chown any of them) and re-stats to report which remain foreign,
    so the caller can decide whether to escalate via ``sudo``.
    """
    for path in paths:
        try:
            os.chown(path, uid, gid)
        except PermissionError:
            break
    return [p for p in paths if p.stat().st_uid != uid]


def _sudo_chown_error(stderr: str, paths_arg: list[str], uid: int, gid: int) -> str:
    """Build the actionable error message for a failed ``sudo chown``."""
    stderr = stderr.strip()
    if "a password is required" in stderr or "sudo:" in stderr:
        hint = f"sudo chown {uid}:{gid} " + " ".join(paths_arg)
        return (
            f"Suricata config sources are not writable — run "
            f"'{hint}' manually or configure passwordless sudo for chown"
        )
    return stderr or "Suricata config ownership restore failed"


def _restore_via_sudo(
    still_foreign: list[Path], uid: int, gid: int, project_dir: Path,
) -> SuricataSourceOwnershipResult:
    """Escalate the ownership repair through passwordless ``sudo chown``."""
    paths_arg = [str(p) for p in still_foreign]
    try:
        perm_result = subprocess.run(
            ["sudo", "-n", "chown", f"{uid}:{gid}", *paths_arg],
            capture_output=True,
            text=True,
            cwd=project_dir,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SuricataSourceOwnershipResult(
            success=False,
            error=(
                f"Suricata config sources are owned by another user and "
                f"could not be restored: {exc}"
            ),
        )

    if perm_result.returncode != 0:
        return SuricataSourceOwnershipResult(
            success=False,
            error=_sudo_chown_error(perm_result.stderr, paths_arg, uid, gid),
        )

    repaired = tuple(str(p.relative_to(project_dir)) for p in still_foreign)
    log.info(
        "Restored Suricata config source ownership via sudo: %s",
        ", ".join(repaired),
    )
    return SuricataSourceOwnershipResult(success=True, repaired=repaired)


def ensure_suricata_config_source_ownership(
    project_dir: Path,
) -> SuricataSourceOwnershipResult:
    """Return checked-in Suricata seed sources to the invoking operator's uid/gid.

    Pre-ADR-043 lab runs bind-mounted ``config/suricata/suricata.yaml`` and
    ``config/suricata/rules/local.rules``; the Suricata entrypoint left them
    owned by UID 991 (``systemd-network`` on Ubuntu). ADR-043 seeds from
    named volumes instead, but an older checkout may still carry foreign
    ownership, which blocks ``pre-commit`` hooks that open the files for
    write (EOF fixer). This is a narrow, idempotent repair — it only
    touches the two canonical seed sources when their owner is not the
    current uid.
    """
    uid = os.getuid()
    gid = os.getgid()
    try:
        source_files = _suricata_config_source_files(project_dir)
    except PathContainmentError as exc:
        return SuricataSourceOwnershipResult(success=False, error=str(exc))

    foreign = _foreign_owned_sources(source_files, uid)
    still_foreign = _chown_direct(foreign, uid, gid) if foreign else []
    if still_foreign:
        return _restore_via_sudo(still_foreign, uid, gid, project_dir)

    repaired = tuple(str(p.relative_to(project_dir)) for p in foreign)
    if repaired:
        log.info(
            "Restored Suricata config source ownership: %s",
            ", ".join(repaired),
        )
    return SuricataSourceOwnershipResult(success=True, repaired=repaired)


def build_suricata_volume_seeds(project_dir: Path) -> tuple[NamedVolumeSeed, ...]:
    """Build the ADR-043 named-volume seed specs for Suricata runtime inputs.

    Returns two :class:`NamedVolumeSeed`\\ s — the config seed
    (``suricata.yaml`` + ``rules/local.rules``) and the MISP rule volume
    (the four IOC baselines) — for the deployment backend to materialize
    into Compose project-scoped named volumes. Replaces the previous
    ``.aptl/`` host render: under ADR-043 nothing checked-in is bind-mounted
    onto a path the Suricata image entrypoint chowns, so host ownership is
    never rewritten.

    Each source path is resolved through the existing containment check, so
    a symlink escaping the project root is rejected before any seed
    container runs. No I/O is performed here beyond ``stat``\\ s; the backend
    runs the seed containers.

    The MISP seed carries the canonical, symlink-checked legacy
    ``.aptl/suricata/rules/misp`` bind directory as ``legacy_retire_path``
    when it still exists, so the backend can retire that UID-991-owned tree.

    Raises:
        PathContainmentError: if a source path escapes the project root, or
            the legacy retire path resolves through a symlinked component.
        FileNotFoundError: if a required source file is missing.
        NotADirectoryError: if a source directory is missing or not a dir.
    """
    config_src = _resolve_within_project(
        project_dir, _SURICATA_CONFIG_SOURCE_RELPATH
    )
    if not config_src.is_dir():
        raise NotADirectoryError(
            f"Suricata config source dir not found: {config_src}"
        )
    config_files: list[SeedFile] = []
    for src_rel, dest_rel in _SURICATA_CONFIG_SEED_FILES:
        source_file = config_src / src_rel
        if not source_file.is_file():
            raise FileNotFoundError(
                f"Suricata config seed source not found: {source_file}"
            )
        config_files.append(SeedFile(src=src_rel, dest=dest_rel))

    misp_src = _resolve_within_project(
        project_dir, _SURICATA_MISP_RULES_SOURCE_RELPATH
    )
    if not misp_src.is_dir():
        raise NotADirectoryError(
            f"Suricata MISP rule baseline dir not found: {misp_src}"
        )
    misp_files: list[SeedFile] = []
    for filename in _SURICATA_MISP_RULE_FILES:
        source_file = misp_src / filename
        if not source_file.is_file():
            raise FileNotFoundError(
                f"Suricata MISP rule baseline not found: {source_file}"
            )
        misp_files.append(SeedFile(src=filename, dest=filename))

    # Canonicalize the legacy bind dir for containment (rejecting a
    # symlinked chain) even though we only retire it when it exists — a
    # fresh checkout has nothing to clean up.
    legacy = _canonical_generated_path(
        project_dir, _SURICATA_LEGACY_MISP_RELPATH
    )
    legacy_retire = legacy if legacy.exists() else None

    config_seed = NamedVolumeSeed(
        volume_suffix=SURICATA_CONFIG_SEED_VOLUME,
        source_dir=config_src,
        files=tuple(config_files),
    )
    misp_seed = NamedVolumeSeed(
        volume_suffix=SURICATA_MISP_RULES_VOLUME,
        source_dir=misp_src,
        files=tuple(misp_files),
        legacy_retire_path=legacy_retire,
    )
    return (config_seed, misp_seed)
