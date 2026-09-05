"""Supply-chain pinning invariants (issue #847, ADR-026).

Everything this repository's builds pull from a network must be fetched by
content, not by a mutable label. A tag such as ``ubuntu:22.04``, ``@v4``, or a
bare ``pip install foo`` resolves to whatever the registry serves at build time,
so a compromised or simply re-tagged upstream silently changes what CI executes
and what ships in a lab image.

These are the four pinning surfaces OpenSSF Scorecard's ``Pinned-Dependencies``
check evaluates, encoded as tests so a regression fails locally and in the
required pre-commit job rather than being noticed later on the public badge.

The accepted command forms below were established empirically against
``gcr.io/openssf/scorecard`` rather than guessed: notably, ``pip install
--require-hashes -r <file>`` and an editable local install (``pip install -e .
--no-deps``) both count as pinned, while a non-editable ``pip install .`` and a
bare ``pip install --upgrade pip`` do not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"


def _tracked(pattern: str) -> list[Path]:
    return sorted(p for p in REPO_ROOT.glob(pattern) if p.is_file())


# ---------------------------------------------------------------- base images

# `FROM <image>@sha256:<64 hex>`, optionally `AS <stage>`.
_FROM = re.compile(r"^\s*FROM\s+(?P<ref>\S+)", re.IGNORECASE | re.MULTILINE)
_DIGEST_PINNED = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def _dockerfiles() -> list[Path]:
    found = [
        p
        for p in REPO_ROOT.rglob("Dockerfile*")
        if p.is_file()
        and "node_modules" not in p.parts
        and "site" not in p.parts
        and ".venv" not in p.parts
        and not p.name.endswith(".py")
    ]
    assert found, "no Dockerfiles discovered - the glob is wrong, not the repo"
    return sorted(found)


@pytest.mark.parametrize("dockerfile", _dockerfiles(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_dockerfile_base_images_are_digest_pinned(dockerfile: Path) -> None:
    text = dockerfile.read_text(encoding="utf-8")
    # Names of earlier build stages are internal references, not registry pulls.
    stages = {
        m.group(1).lower()
        for m in re.finditer(r"^\s*FROM\s+\S+\s+AS\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
    }
    unpinned = [
        ref
        for ref in (m.group("ref") for m in _FROM.finditer(text))
        if ref.lower() not in stages and ref.lower() != "scratch" and not _DIGEST_PINNED.match(ref)
    ]
    assert not unpinned, (
        f"{dockerfile.relative_to(REPO_ROOT)} pulls a mutable tag: {unpinned}. "
        "Pin it as image:tag@sha256:<digest>; Dependabot's docker ecosystem keeps the digest current."
    )


def test_dependabot_watches_every_dockerfile_directory() -> None:
    """A digest pin that nothing refreshes rots into a stale, unpatched base."""
    import yaml

    config = yaml.safe_load((REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    watched = set()
    for update in config["updates"]:
        if update["package-ecosystem"] != "docker":
            continue
        # Dependabot accepts a single `directory` or a `directories` list.
        entries = update.get("directories") or [update["directory"]]
        watched.update(entry.rstrip("/") or "/" for entry in entries)
    needed = {f"/{p.parent.relative_to(REPO_ROOT)}" for p in _dockerfiles()}
    assert needed <= watched, f"no docker Dependabot entry for: {sorted(needed - watched)}"


# ------------------------------------------------------------ github actions

_USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)", re.MULTILINE)
_SHA_PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


@pytest.mark.parametrize(
    "workflow", _tracked(".github/workflows/*.yml"), ids=lambda p: p.name
)
def test_actions_are_sha_pinned(workflow: Path) -> None:
    unpinned = [
        ref
        for ref in (m.group("ref") for m in _USES.finditer(workflow.read_text(encoding="utf-8")))
        # `./local-action` is first-party content already in the checkout.
        if not ref.startswith("./") and not _SHA_PINNED.match(ref)
    ]
    assert not unpinned, f"{workflow.name} uses a mutable action ref: {unpinned}"


# --------------------------------------------------------------- npm and pip

# Shell files that drive builds or provision a shipped artifact. Scenario
# fixtures are excluded deliberately - see
# test_scenario_fixture_scripts_are_out_of_scope below.
_BUILD_SHELL = [
    "mcp/build-all-mcps.sh",
    "tools/vale-lint-all.sh",
    "appliance/guest/provision-offline.sh",
]

_NPM_INSTALL = re.compile(r"\bnpm\s+install\b")
_PIP_INSTALL = re.compile(r"(?:^|\s|&&\s*)(?:python\s+-m\s+)?pip\s+install\b")


def _pinning_sources() -> list[Path]:
    return (
        _tracked(".github/workflows/*.yml")
        + _dockerfiles()
        + [REPO_ROOT / rel for rel in _BUILD_SHELL if (REPO_ROOT / rel).is_file()]
    )


@pytest.mark.parametrize(
    "source", _pinning_sources(), ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_npm_installs_use_ci_not_install(source: Path) -> None:
    """`npm ci` installs exactly the lockfile; `npm install` may silently re-resolve."""
    offenders = [
        line.strip()
        for line in source.read_text(encoding="utf-8").splitlines()
        # Prose explaining why `npm ci` replaced `npm install` is not a command.
        if not line.strip().startswith("#") and _NPM_INSTALL.search(line)
    ]
    assert not offenders, (
        f"{source.relative_to(REPO_ROOT)} uses `npm install`; use `npm ci` so the "
        f"lockfile is authoritative: {offenders}"
    )


@pytest.mark.parametrize(
    "source", _pinning_sources(), ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_pip_installs_are_hash_pinned_or_local(source: Path) -> None:
    """Every pip install resolves by hash, or installs only this project's own code.

    `--require-hashes -r <file>` verifies each third-party artifact against
    ``requirements/*.txt``. The local forms - an editable root or a bounded
    ``./plugins/<safe-name>`` path with ``--no-deps``, and a ``dist/*.whl
    --no-deps`` artifact this same job just built - pull nothing from a registry,
    so they carry no third-party supply-chain risk. ``--no-deps`` is what makes
    that true: without it pip would resolve dependencies off-lock.

    A fourth form is accepted: a closed offline install (`--no-index` plus an
    exact `==` pin), used by the appliance guest provisioner. `--no-index` means
    pip contacts no index at all, so there is no mutable upstream a hash could
    protect against - the wheels come from a staged wheelhouse inside a
    content-identified payload (``src/aptl/appliance/offline.py``). Scorecard
    flags it because its parser does not model `--no-index`; the condition below
    is what keeps that judgement honest, because dropping `--no-index` or the
    version pin fails this test rather than silently reopening a network fetch.
    """
    offenders = []
    # Multi-line shell continuations make one logical command.
    text = re.sub(r"\\\n\s*", " ", source.read_text(encoding="utf-8"))
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not _PIP_INSTALL.search(stripped):
            continue
        for command in re.split(r"&&|\|\|", stripped):
            if not _PIP_INSTALL.search(command):
                continue
            hashed = "--require-hashes" in command
            local_source = (
                re.search(r"\s-e\s+\.(\s|$|\\)", command)
                or re.search(
                    r"\s-e\s+\./plugins/[a-z0-9][a-z0-9-]*(\s|$|\\)",
                    command,
                )
                or re.search(r"\sdist/\S*\.whl(\s|$|\\)", command)
            )
            closed_offline = "--no-index" in command and "==" in command
            if not (hashed or closed_offline or (local_source and "--no-deps" in command)):
                offenders.append(command.strip())
    assert not offenders, (
        f"{source.relative_to(REPO_ROOT)} has an unpinned pip install: {offenders}. "
        "Use `pip install --require-hashes -r requirements/<x>.txt`, or "
        "`pip install -e . --no-deps` for this project's own code."
    )


# ------------------------------------------------------------ release signing


def test_release_artifacts_are_attested_and_the_bundle_ships() -> None:
    """Released artifacts carry SLSA provenance, and it reaches the release page.

    Two halves, both required. Recording an attestation without attaching the
    bundle leaves anyone who downloaded a tarball with nothing local to verify
    against; attaching a bundle without the write permission just fails the job.
    """
    import yaml

    workflow_text = (WORKFLOW_DIR / "release-please.yml").read_text(encoding="utf-8")
    publish = yaml.safe_load(workflow_text)["jobs"]["publish"]

    assert publish["permissions"].get("attestations") == "write"
    assert publish["permissions"].get("id-token") == "write", "sigstore signing needs OIDC"

    attest = next(
        (s for s in publish["steps"] if s.get("uses", "").startswith("actions/attest-build-provenance@")),
        None,
    )
    assert attest is not None, "release artifacts are published without build provenance"
    assert attest["with"]["subject-path"], "the attestation names no subject artifact"

    # Sign before publishing, so a signing failure cannot leave an unattested
    # artifact already on PyPI.
    step_names = [s.get("uses", "") for s in publish["steps"]]
    attest_at = next(i for i, u in enumerate(step_names) if u.startswith("actions/attest-build-provenance@"))
    publish_at = next(i for i, u in enumerate(step_names) if u.startswith("pypa/gh-action-pypi-publish@"))
    assert attest_at < publish_at, "provenance must be attested before the artifact is published"

    # Prove the bundle is actually uploaded, not merely mentioned. A substring
    # check would pass on a comment or an unused variable, which is exactly the
    # false assurance this test exists to avoid: the upload step must place the
    # bundle somewhere, and then hand that location to `gh release upload`.
    upload = next(
        (s for s in publish["steps"] if "gh release upload" in s.get("run", "")),
        None,
    )
    assert upload is not None, "no step uploads assets to the release"

    run = upload["run"]
    assert "${{ steps.attest.outputs.bundle-path }}" in str(upload.get("env", {})), (
        "the upload step never receives the attestation bundle produced by the attest step"
    )
    destination = re.search(r'cp\s+"\$BUNDLE"\s+"?([^"\s]+)', run)
    assert destination, "the upload step does not copy the attestation bundle anywhere"
    bundle_path = destination.group(1)
    assert bundle_path.endswith(".intoto.jsonl"), bundle_path

    # The copied bundle must fall under one of the globs handed to gh.
    uploaded_globs = re.search(r"gh release upload\s+\S+\s+(.*)", run)
    assert uploaded_globs, run
    globs = [g for g in uploaded_globs.group(1).split() if not g.startswith("--")]
    bundle_dir = bundle_path.rsplit("/", 1)[0] if "/" in bundle_path else ""
    assert any(g.rsplit("/", 1)[0] == bundle_dir for g in globs), (
        f"the attestation bundle is written to {bundle_path!r}, which none of the "
        f"uploaded globs {globs} cover"
    )


@pytest.mark.parametrize(
    "source", _pinning_sources(), ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_source_builds_do_not_re_open_an_unhashed_resolver(source: Path) -> None:
    """A source build must not spin up an isolated, unhashed build environment.

    This is the subtle half of the hashed-install contract. `--no-deps` governs
    the project's *dependencies*; it says nothing about `[build-system].requires`.
    Left alone, `pip install -e .` and `python -m build` each create a PEP 517
    isolated environment and fetch the build backend straight from PyPI with no
    hash checking - a second, unverified resolver running underneath the one we
    just pinned. `--no-build-isolation` / `--no-isolation` (against the
    hatchling that every `requirements/*.txt` now carries) is what shuts it.
    """
    text = re.sub(r"\\\n\s*", " ", source.read_text(encoding="utf-8"))
    offenders = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for command in re.split(r"&&|\|\|", stripped):
            # An editable/source install of this project.
            local_editable = re.search(r"\s-e\s+\.(\s|$)", command) or re.search(
                r"\s-e\s+\./plugins/[a-z0-9][a-z0-9-]*(\s|$)", command
            )
            if re.search(r"pip\s+install\b", command) and local_editable:
                if "--no-build-isolation" not in command:
                    offenders.append(command.strip())
            # A wheel/sdist build of this project.
            if re.search(r"python\s+-m\s+build\b", command) and "--no-isolation" not in command:
                offenders.append(command.strip())
    assert not offenders, (
        f"{source.relative_to(REPO_ROOT)} builds from source with PEP 517 isolation "
        f"enabled, which resolves the build backend unpinned: {offenders}"
    )


def test_scenario_content_is_not_an_aptl_supply_chain_input() -> None:
    """Scenario-owned scripts are acquired from packs, not shipped by APTL."""

    assert not (REPO_ROOT / "scenarios").exists()
    assert all("scenarios" not in path.parts for path in _pinning_sources())
