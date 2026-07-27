"""The hashed requirements exports are complete, pinned, and machine-maintained.

CI installs Python dependencies with ``pip install --require-hashes -r
requirements/<x>.txt`` (issue #847). That flag only buys anything if the file it
reads is (a) genuinely hash-pinned and (b) still a faithful projection of
``uv.lock``. A hand-edited or stale export would keep the flag - and the
appearance of verification - while pinning the wrong artifacts.

So the invariant this file defends is not "the files exist". It is that every
export is fully hash-pinned, that each one is owned by an ``uv-export``
pre-commit hook rather than by a human, and that every file CI claims to install
is actually produced by one of those hooks. Freshness itself is enforced by
running those hooks in the required "Pre-commit hooks" job; this test makes sure
the hook set cannot develop a hole.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_DIR = REPO_ROOT / "requirements"
PRE_COMMIT_CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
UV_HOOK_REPO = "https://github.com/astral-sh/uv-pre-commit"


def _requirements_files() -> list[Path]:
    found = sorted(REQUIREMENTS_DIR.glob("*.txt"))
    assert found, "requirements/ holds no exports - CI has nothing hash-pinned to install"
    return found


def _uv_hook_repo() -> dict:
    config = yaml.safe_load(PRE_COMMIT_CONFIG.read_text(encoding="utf-8"))
    repo = next((r for r in config["repos"] if r.get("repo") == UV_HOOK_REPO), None)
    assert repo is not None, f"{UV_HOOK_REPO} is not configured; the exports would be hand-maintained"
    return repo


def _exported_paths() -> set[str]:
    """Output paths the configured `uv-export` hooks write."""
    paths = set()
    for hook in _uv_hook_repo()["hooks"]:
        if hook["id"] != "uv-export":
            continue
        args = hook["args"]
        # `uv export ... -o <path>`
        assert "-o" in args, f"uv-export hook {hook.get('alias')} does not name an output file"
        paths.add(args[args.index("-o") + 1])
    return paths


@pytest.mark.parametrize(
    "requirements", _requirements_files(), ids=lambda p: p.name
)
def test_every_requirement_is_pinned_and_hashed(requirements: Path) -> None:
    text = requirements.read_text(encoding="utf-8")
    # Join backslash continuations so each requirement is one logical record.
    records = re.sub(r"\\\n\s*", " ", text).splitlines()

    checked = 0
    for record in records:
        record = record.strip()
        if not record or record.startswith("#"):
            continue
        # `-e .`-style lines and pip flags are not third-party requirements.
        if record.startswith("-"):
            continue
        name = record.split()[0]
        assert "==" in name, f"{requirements.name}: '{name}' is not pinned to an exact version"
        assert "--hash=sha256:" in record, f"{requirements.name}: '{name}' carries no hash"
        checked += 1

    assert checked, f"{requirements.name} pins nothing - an empty export would silently install nothing"


def test_every_third_party_hook_repo_is_sha_pinned() -> None:
    """pre-commit executes hook code from `rev`, so a tag is a code-execution hole.

    Tags are movable. Anyone who can retarget one upstream gets arbitrary code
    execution on contributor machines and clean CI runners without touching this
    repository. That is sharpest for the uv hooks, which *generate* the hashed
    requirements: hashing the exported packages buys nothing if a compromised
    generator can pick malicious artifacts and emit hashes to match them.
    """
    config = yaml.safe_load(PRE_COMMIT_CONFIG.read_text(encoding="utf-8"))
    unpinned = []
    for repo in config["repos"]:
        if repo.get("repo") == "local":
            continue
        rev = str(repo.get("rev", ""))
        if not re.fullmatch(r"[0-9a-f]{40}", rev):
            unpinned.append(f"{repo.get('repo')}@{rev}")
    assert not unpinned, (
        f"pre-commit repos must be pinned to a full commit SHA, not a mutable tag: {unpinned}"
    )


def test_the_build_backend_is_hash_pinned_in_every_export() -> None:
    """Otherwise PEP 517 build isolation fetches it unpinned, around the hashes.

    `--require-hashes` constrains what pip *resolves* for the project's
    dependencies. A source install still builds the project, and by default that
    happens in an isolated environment whose `[build-system].requires` are
    fetched from PyPI with no hash checking. Shipping the backend inside each
    export is what makes `--no-build-isolation` possible, which is what closes
    that hole.
    """
    for requirements in _requirements_files():
        text = requirements.read_text(encoding="utf-8")
        assert re.search(r"^hatchling==", text, re.MULTILINE), (
            f"{requirements.name} omits the build backend; a source install "
            "against it would resolve hatchling unpinned"
        )


def test_uv_lock_hook_keeps_the_lock_current() -> None:
    """Without this hook the exports would faithfully reflect a stale lock."""
    ids = {hook["id"] for hook in _uv_hook_repo()["hooks"]}
    assert "uv-lock" in ids


def test_every_export_on_disk_is_owned_by_a_hook() -> None:
    """A hand-added requirements file would never be regenerated."""
    on_disk = {str(p.relative_to(REPO_ROOT)) for p in _requirements_files()}
    orphans = on_disk - _exported_paths()
    assert not orphans, f"requirements files with no uv-export hook to regenerate them: {sorted(orphans)}"


def test_every_requirements_file_ci_installs_exists() -> None:
    """Catch a rename that leaves CI pointing at a path no hook produces."""
    referenced: set[str] = set()
    sources = [
        *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
        REPO_ROOT / "web" / "Dockerfile.api",
        REPO_ROOT / "containers" / "misp-suricata-sync" / "Dockerfile",
    ]
    for source in sources:
        referenced.update(
            re.findall(r"--require-hashes\s+-r\s+(\S+)", source.read_text(encoding="utf-8"))
        )
    assert referenced, "no --require-hashes install found; the pinning wiring is gone"

    exported = _exported_paths()
    for path in referenced:
        # The Dockerfiles copy the file in and install it by a context-relative
        # path, so compare on the repo-relative suffix.
        normalized = path.lstrip("/")
        assert (REPO_ROOT / normalized).is_file(), f"CI installs {path}, which does not exist"
        assert normalized in exported, f"{path} is installed by CI but no uv-export hook writes it"
