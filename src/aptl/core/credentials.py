"""Config file credential rendering.

Renders credentialized service configuration from the checked-in
``config/`` baseline files into the project's ignored ``.aptl/config/``
state tree. The checked-in source files are never written — they are
source-owned templates (see ADR-028: Runtime-Rendered Service Config).
``aptl lab start`` mounts the rendered copies into the containers.

The render functions own construction of both their canonical
project-relative *source* path and *output* path, and validate
containment against the resolved project root before any I/O — on both
ends. Symlinks under either canonical location pointing outside the
project are rejected. ADR-007's "Security Guardrail: Project-Rooted
Credential Writes" (issue #266) still applies; ADR-028 only changes
*where* the credentialized result is written (the ignored ``.aptl/``
state tree instead of back over ``config/``).
"""

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape as xml_escape

from aptl.core.seed_spec import NamedVolumeSeed, SeedFile
from aptl.utils.logging import get_logger

log = get_logger("credentials")

# Matches: password: "anything" (with optional surrounding whitespace)
_PASSWORD_PATTERN = re.compile(r'(password:\s*)"[^"]*"')

# Matches: <key>anything</key> (used only within pre-extracted <cluster> blocks)
_KEY_PATTERN = re.compile(r"<key>[^<]*</key>")

# Canonical project-relative source templates (checked in, never written).
_DASHBOARD_SOURCE_RELPATH = Path("config/wazuh_dashboard/wazuh.yml")
_MANAGER_SOURCE_RELPATH = Path("config/wazuh_cluster/wazuh_manager.conf")
# Suricata runtime-input sources (checked in, never written). Under ADR-043
# these are copied into Compose named volumes by a root seed container at lab
# start rather than rendered/bind-mounted, so the upstream image entrypoint's
# chown can never rewrite host-side ownership.
_SURICATA_CONFIG_SOURCE_RELPATH = Path("config/suricata")
_SURICATA_MISP_RULES_SOURCE_RELPATH = Path("config/suricata/rules/misp")

# Canonical project-relative rendered outputs (under the ignored .aptl/
# state tree). docker-compose.yml mounts exactly these paths; keep the
# two in sync.
RENDERED_DASHBOARD_RELPATH = Path(".aptl/config/wazuh_dashboard/wazuh.yml")
RENDERED_MANAGER_RELPATH = Path(".aptl/config/wazuh_cluster/wazuh_manager.conf")

# Root of the rendered-config tree.
_RENDERED_CONFIG_ROOT = Path(".aptl/config")

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

# Host-side permissions. The directory is owner-only (``0o700``) — that
# is the real access control for local users, since nobody but the owner
# can traverse into it. The files themselves are ``0o644`` deliberately:
# each is bind-mounted into a container whose process may run under a UID
# that does not match the host UID that ran ``aptl lab start`` (the Wazuh
# Dashboard image runs as a non-root user), so an owner-only file would
# leave the container unable to read its own config. ``0o644`` under a
# ``0o700`` parent is still unreadable by other local users, and ``.aptl/``
# is gitignored, so the credential never reaches the repo. (ADR-028's
# ``0o600`` ideal is relaxed here for exactly this bind-mount-readability
# reason.)
_DIR_MODE = 0o700
_FILE_MODE = 0o644


class PathContainmentError(ValueError):
    """Raised when a resolved config path escapes the project root.

    Subclasses :class:`ValueError` for backward compatibility — every
    historical caller that does ``except ValueError`` keeps working —
    but lets policy code (e.g. ``_step_sync_credentials``) match on
    the narrow type so unrelated parsing/validation ``ValueError``\\ s
    are not misclassified as security guardrail breaches.
    """


class CredentialRenderError(ValueError):
    """Raised when a credential template cannot be rendered safely.

    The most important case: a substitution that matched **zero** times.
    Since the rendered file is a mandatory Compose bind-mount source
    (ADR-028), silently emitting a verbatim copy would let the lab start
    with the placeholder/stale credential baked into the template. A
    zero-match render is therefore an error, not a warning.

    Subclasses :class:`ValueError` (not :class:`PathContainmentError`) so
    ``_step_sync_credentials`` reports it as a generic render failure
    rather than a security-guardrail breach — both abort lab start.
    """


def _resolve_within_project(
    project_dir: Path, relative_path: Path,
) -> Path:
    """Resolve ``project_dir / relative_path`` and assert containment.

    Both sides are resolved (symlinks followed) before the
    ``is_relative_to`` check so a symlink under the canonical relative
    location cannot escape the project root.

    Used for the *input* template, where a symlink that still resolves
    inside the project is acceptable. Generated outputs use the stricter
    :func:`_canonical_generated_path`.

    Raises:
        PathContainmentError: if the resolved target is not contained
            under the resolved project root.
    """
    project_root = project_dir.resolve()
    target = (project_dir / relative_path).resolve()
    if not target.is_relative_to(project_root):
        raise PathContainmentError(
            f"Resolved config path {target} escapes project root"
            f" {project_root}; refusing to read or write."
        )
    return target


def _canonical_generated_path(
    project_dir: Path, output_relpath: Path,
) -> Path:
    """Return ``<project_root>/<output_relpath>``, rejecting symlinked chains.

    Unlike :func:`_resolve_within_project` — which accepts any path that
    *resolves* inside the project root — a generated credential artifact
    must sit at exactly the literal expected location with **no symlink
    rewriting anywhere in the chain**. A symlink at e.g. ``.aptl/config``
    pointing at ``.`` or at a tracked file would otherwise pass a plain
    containment check (the target is still inside the project) and let
    the renderer write the live credential straight back into a
    checked-in file — exactly the exposure ADR-028 removes. So the
    resolved path must equal the literal expectation.

    Raises:
        PathContainmentError: if resolving the path changes it (a
            symlink in the chain) or it escapes the project root.
    """
    project_root = project_dir.resolve()
    expected = project_root / output_relpath
    actual = (project_dir / output_relpath).resolve()
    if actual != expected:
        raise PathContainmentError(
            f"Generated output {(project_dir / output_relpath)} resolves to "
            f"{actual}, not the expected {expected}; refusing to render "
            "through a symlinked path component."
        )
    return expected


def _enforce_mode(path: Path, mode: int, kind: str) -> None:
    """``chmod`` *path* to *mode* and (on POSIX) verify it stuck.

    The rendered-config tree's permissions are part of the artifact
    contract — the ``0o700`` directory is the host-side access control,
    and a ``0o644`` file is what the non-root container process needs to
    read its bind mount — not a best-effort diagnostic. So a ``chmod``
    that errors, or that the filesystem silently ignores, fails the
    render rather than letting lab start succeed with wrong permissions.
    Off POSIX (where file modes are advisory) the chmod is best-effort
    and not verified.

    Raises:
        CredentialRenderError: on POSIX, if the chmod errored or the
            effective mode does not match *mode*.
    """
    try:
        path.chmod(mode)
    except (OSError, NotImplementedError) as exc:
        if os.name == "posix":
            raise CredentialRenderError(
                f"Could not set required mode {oct(mode)} on rendered-config "
                f"{kind} {path}: {exc}"
            ) from exc
        log.debug("chmod %s on %s not honoured on this platform: %s",
                  oct(mode), path, exc)  # pragma: no cover - platform-dependent
        return  # pragma: no cover - platform-dependent
    if os.name != "posix":  # pragma: no cover - platform-dependent
        return
    effective = path.stat().st_mode & 0o777
    if effective != mode:
        raise CredentialRenderError(
            f"Rendered-config {kind} {path} retained mode {oct(effective)}, "
            f"required {oct(mode)} (filesystem may not honour POSIX modes); "
            "refusing to render credentials here"
        )


def _ensure_secure_dir(directory: Path) -> None:
    """Create *directory* (and parents) and enforce ``0o700`` on it.

    Parents are created with the OS default mode; *directory* itself is
    ``0o700`` (owner-only) — the real host-side access control for the
    credentialized files underneath, since no other local user can
    traverse into it, even though the files themselves are ``0o644`` so a
    container process can read them across a bind mount. A chmod that
    fails or doesn't stick aborts the render (see :func:`_enforce_mode`).
    """
    directory.mkdir(parents=True, exist_ok=True)
    _enforce_mode(directory, _DIR_MODE, "directory")


def _atomic_write_secure(target: Path, content: str) -> None:
    """Write *content* to *target* atomically, then chmod it to ``_FILE_MODE``.

    Writes to a freshly created temp file in *target*'s (already
    containment-checked) parent directory, then ``os.replace`` onto
    *target*, so a reader never sees a partially written credential file.
    The temp file is created by :func:`tempfile.mkstemp` with an
    unpredictable name and ``O_CREAT | O_EXCL | O_NOFOLLOW`` semantics
    (mode ``0o600`` transiently), so a pre-planted ``<name>.tmp`` symlink
    can neither redirect the secret outside the project nor be renamed
    into *target*; the parent dir was resolved and containment-checked by
    the caller before this point. The final ``chmod`` widens the file to
    ``_FILE_MODE`` (``0o644``) so the container process can read it across
    its bind mount — the ``0o700`` parent directory is what keeps other
    local users out.
    """
    parent = target.parent
    fd, tmp_name = tempfile.mkstemp(
        dir=parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    # Defence in depth: the temp file lives in the containment-checked
    # parent under an unpredictable name, but assert it anyway so this
    # module's project-rooting guarantee holds for the temp path too.
    if not tmp.resolve().is_relative_to(parent.resolve()):  # pragma: no cover - defensive
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise PathContainmentError(
            f"Temp render path {tmp} escapes its output directory {parent}"
        )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        # mkstemp created the temp file 0o600; os.replace adopts that mode
        # onto target (and, if target is a symlink, replaces the link
        # itself rather than following it). The temp file disappears on a
        # successful rename; on failure the cleanup below removes it so a
        # secret-bearing temp file is never left behind. The chmod that
        # follows widens it from the transient 0o600 to _FILE_MODE.
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _enforce_mode(target, _FILE_MODE, "file")


def _render_secure(
    project_dir: Path,
    source_relpath: Path,
    output_relpath: Path,
    transform: Callable[[str], str],
) -> Path:
    """Render a credentialized config file from a checked-in template.

    Reads ``project_dir / source_relpath`` (never written), applies
    *transform*, and writes the result to ``project_dir / output_relpath``
    under the ignored ``.aptl/config/`` tree with restrictive
    permissions and an atomic rename.

    The source template is containment-checked against the project root;
    the generated output is held to the stricter no-symlinked-chain rule
    (:func:`_canonical_generated_path`) so a symlink among
    ``.aptl/config/...`` cannot redirect the credential outside the
    project — or back into a tracked file.

    Args:
        project_dir: APTL project root.
        source_relpath: Project-relative path of the checked-in template.
        output_relpath: Project-relative path of the rendered output
            (must live under ``.aptl/config/``).
        transform: Maps the template's text to the rendered text; raises
            :class:`CredentialRenderError` if the substitution matched
            nothing.

    Returns:
        The path of the rendered output file.

    Raises:
        PathContainmentError: if the resolved source escapes the project
            root, or a generated path component is a symlink.
        CredentialRenderError: if the credential substitution matched
            zero times in the template.
        FileNotFoundError: if the source template does not exist.
    """
    source_path = _resolve_within_project(project_dir, source_relpath)
    if not source_path.exists():
        raise FileNotFoundError(f"Config template not found: {source_path}")

    rendered = transform(source_path.read_text())

    # Reject a symlinked generated path *before* we mkdir/chmod through
    # it (a symlink at .aptl/config or the output file could otherwise
    # redirect the chmod/write at a tracked file or outside the project).
    output_path = _canonical_generated_path(project_dir, output_relpath)
    _ensure_secure_dir(project_dir / _RENDERED_CONFIG_ROOT)
    _ensure_secure_dir(output_path.parent)
    # The mkdir calls above create real directories; re-verify so a
    # pre-existing component that was a symlink (and thus rejected) can't
    # have been re-introduced between the first check and the write.
    _canonical_generated_path(project_dir, output_relpath)

    _atomic_write_secure(output_path, rendered)
    return output_path


def _dashboard_transform(api_password: str) -> Callable[[str], str]:
    """Build the ``password: "..."`` substitution for the dashboard config."""
    # Escape characters that would break YAML double-quoted strings.
    safe_pw = api_password.replace("\\", "\\\\").replace('"', '\\"')

    def transform(content: str) -> str:
        new_content, count = _PASSWORD_PATTERN.subn(
            lambda m: f'{m.group(1)}"{safe_pw}"', content
        )
        if count == 0:
            raise CredentialRenderError(
                "No 'password: \"...\"' line found in the dashboard config "
                "template; refusing to render a copy with the template's "
                "placeholder/stale password"
            )
        log.info("Rendered %d password occurrence(s) in dashboard config", count)
        return new_content

    return transform


def _manager_transform(cluster_key: str) -> Callable[[str], str]:
    """Build the ``<cluster><key>...</key>`` substitution for the manager config.

    Finds ``<cluster>`` blocks by string search (O(n), no backtracking),
    then replaces ``<key>`` only within each block so non-cluster ``<key>``
    elements (e.g. ``<indexer><ssl><key>``) are left alone (#183).
    """
    safe_key = xml_escape(cluster_key)

    def transform(content: str) -> str:
        count = 0
        result: list[str] = []
        pos = 0
        while True:
            block_start = content.find("<cluster>", pos)
            if block_start == -1:
                result.append(content[pos:])
                break
            block_end = content.find("</cluster>", block_start)
            if block_end == -1:
                result.append(content[pos:])
                break
            block_end += len("</cluster>")
            result.append(content[pos:block_start])
            block = content[block_start:block_end]
            new_block, n = _KEY_PATTERN.subn(
                lambda _, _safe_key=safe_key: f"<key>{_safe_key}</key>", block
            )
            count += n
            result.append(new_block)
            pos = block_end

        new_content = "".join(result)
        if count == 0:
            raise CredentialRenderError(
                "No <cluster><key>...</key> element found in the manager "
                "config template; refusing to render a copy with the "
                "template's placeholder/stale cluster key"
            )
        log.info("Rendered %d cluster <key> occurrence(s) in manager config",
                 count)
        return new_content

    return transform


def sync_dashboard_config(project_dir: Path, api_password: str) -> Path:
    """Render the Wazuh Dashboard config (wazuh.yml) with the real API password.

    Reads the checked-in template at
    ``<project_dir>/config/wazuh_dashboard/wazuh.yml``, replaces the
    ``password: "..."`` value, and writes the result to
    ``<project_dir>/.aptl/config/wazuh_dashboard/wazuh.yml`` (the path
    ``docker-compose.yml`` mounts into the dashboard container). The
    checked-in template is never modified.

    Args:
        project_dir: APTL project root.
        api_password: The real API password to inject.

    Returns:
        The path of the rendered output file.

    Raises:
        PathContainmentError: if the resolved source escapes the project
            root, or a generated path component is a symlink.
        CredentialRenderError: if the ``password: "..."`` line is absent
            from the template.
        FileNotFoundError: if the checked-in template does not exist.
    """
    return _render_secure(
        project_dir,
        _DASHBOARD_SOURCE_RELPATH,
        RENDERED_DASHBOARD_RELPATH,
        _dashboard_transform(api_password),
    )


def sync_manager_config(project_dir: Path, cluster_key: str) -> Path:
    """Render the Wazuh Manager config with the real cluster key.

    Reads the checked-in template at
    ``<project_dir>/config/wazuh_cluster/wazuh_manager.conf``, replaces
    the ``<key>...</key>`` elements inside ``<cluster>`` blocks, and
    writes the result to
    ``<project_dir>/.aptl/config/wazuh_cluster/wazuh_manager.conf`` (the
    path ``docker-compose.yml`` mounts into the manager container). The
    checked-in template is never modified.

    Args:
        project_dir: APTL project root.
        cluster_key: The real cluster key to inject.

    Returns:
        The path of the rendered output file.

    Raises:
        PathContainmentError: if the resolved source escapes the project
            root, or a generated path component is a symlink.
        CredentialRenderError: if no ``<cluster><key>`` element is present
            in the template.
        FileNotFoundError: if the checked-in template does not exist.
    """
    return _render_secure(
        project_dir,
        _MANAGER_SOURCE_RELPATH,
        RENDERED_MANAGER_RELPATH,
        _manager_transform(cluster_key),
    )


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
