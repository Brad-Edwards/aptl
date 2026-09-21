#!/usr/bin/env python3
"""Stage the exact non-secret source payload proven for hosted workshop seats."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path
from typing import Final


LAB_COMMIT: Final = "e9373f5bec57b2c315c4a9c5d7ab837983b19595"
CERT_HELPER_COMMIT: Final = "ec54ee2da2cd59c58eb17f1dd7737483901b1838"
PROFILE_COMMIT: Final = "583e100853ac42240de4827678a20d94edb93d7d"
CERT_HELPER_PATH: Final = Path("config/wazuh-certs-tool.sh")
PATCH_PATH: Final = Path("tools/workshop/hosted-seat-kali-node.patch")
HELPER_PATH: Final = Path("tools/workshop/hosted_seat.py")
PATCH_SHA256: Final = "71ea3832154d25ce8004e9bd9da8275282f4ff33bdf771ae7e50a8bf34376f4c"
HELPER_SHA256: Final = (
    "d9668f172322a4a7d05c325d384afc33e7e66353864465b18c5f64b604e9f4f4"
)


def _run(
    argv: list[str],
    *,
    cwd: Path,
    stdout: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.PIPE,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_repository(repo_root: Path) -> Path:
    repo = repo_root.resolve()
    resolved = (
        _run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo,
            stdout=subprocess.PIPE,
        )
        .stdout.decode()
        .strip()
    )
    if Path(resolved).resolve() != repo:
        raise ValueError("repo root must be the APTL Git top-level directory")
    for commit in (LAB_COMMIT, CERT_HELPER_COMMIT, PROFILE_COMMIT):
        _run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=repo)
    patch = repo / PATCH_PATH
    if _sha256(patch) != PATCH_SHA256:
        raise ValueError("hosted-seat Kali patch does not match its admitted digest")
    if _sha256(repo / HELPER_PATH) != HELPER_SHA256:
        raise ValueError("hosted-seat helper does not match its admitted digest")
    return repo


def _extract_commit(repo: Path, commit: str, destination: Path) -> None:
    archive = destination.parent / f".{destination.name}.tar"
    _run(
        [
            "git",
            "archive",
            "--format=tar",
            f"--output={archive}",
            commit,
        ],
        cwd=repo,
    )
    destination.mkdir(mode=0o750)
    with tarfile.open(archive, mode="r:") as source:
        source.extractall(destination, filter="data")
    archive.unlink()


def _git_file(repo: Path, commit: str, relative: Path) -> bytes:
    return _run(
        ["git", "show", f"{commit}:{relative.as_posix()}"],
        cwd=repo,
        stdout=subprocess.PIPE,
    ).stdout


def stage_payload(repo_root: Path, output_dir: Path) -> Path:
    """Create one immutable-input bundle without credentials or generated state."""

    repo = _require_repository(repo_root)
    output = output_dir.absolute()
    output.mkdir(mode=0o750)
    if stat.S_IMODE(output.stat().st_mode) not in {0o700, 0o750}:
        raise ValueError("new payload directory must have mode 0700 or 0750")

    lab_source = output / "lab-source"
    profile_source = output / "profile-source"
    _extract_commit(repo, LAB_COMMIT, lab_source)
    _extract_commit(repo, PROFILE_COMMIT, profile_source)

    cert_helper = lab_source / CERT_HELPER_PATH
    cert_helper.write_bytes(_git_file(repo, CERT_HELPER_COMMIT, CERT_HELPER_PATH))
    cert_helper.chmod(0o755)

    patch = repo / PATCH_PATH
    _run(["git", "apply", "--check", str(patch)], cwd=lab_source)
    _run(["git", "apply", str(patch)], cwd=lab_source)

    helper = output / "hosted_seat.py"
    shutil.copyfile(repo / HELPER_PATH, helper)
    helper.chmod(0o755)

    manifest = {
        "schema": "aptl.hosted-seat-payload/v1",
        "lab_commit": LAB_COMMIT,
        "certificate_helper": {
            "commit": CERT_HELPER_COMMIT,
            "path": CERT_HELPER_PATH.as_posix(),
            "sha256": _sha256(cert_helper),
        },
        "profile_commit": PROFILE_COMMIT,
        "kali_patch": {
            "path": PATCH_PATH.as_posix(),
            "sha256": PATCH_SHA256,
        },
        "hosted_seat_helper": {
            "path": HELPER_PATH.as_posix(),
            "sha256": HELPER_SHA256,
        },
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o644)
    return manifest_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stage the exact source layers for the hosted-seat runbook."
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    manifest = stage_payload(arguments.repo_root, arguments.output_dir)
    print(json.dumps({"manifest": str(manifest)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
