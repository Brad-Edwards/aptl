"""APTL's owned lab-machinery fixture pack (issue #985).

Core tests of the generic lab machinery -- pack admission, content resolution,
realization and the live gate -- use this small pack instead of the released
TechVault one, so an unrelated pack release cannot break them. The pack lives in
``tests/fixtures/packs/`` and is admitted through the production resolver
(:func:`aptl.core.scenario_bundle.env_pack_bundle`), which runs env-packs' own
``validate_pack`` and content-manifest gates exactly as for a released pack.

Deliberately import-safe: unlike ``tests.helpers`` it reads no project ``.env``
and runs no lab script, so a test module may import it at collection time.
Artifact digests are computed from the checked-in bytes rather than read from
the pack's manifest, so a test comparing a resolved digest to one of these
compares two independent observations. See ``docs/testing/lab-fixture-pack.md``
for how the pack is maintained.

Named without a ``test_`` prefix so pytest does not collect it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from aptl.core.scenario_bundle import ScenarioBundle, env_pack_bundle

FIXTURE_PACK_IDENTITY = "materialization-envelope"
FIXTURE_PACK_SOURCE = (
    Path(__file__).resolve().parent / "fixtures" / "packs" / FIXTURE_PACK_IDENTITY
)
FIXTURE_SDL = FIXTURE_PACK_SOURCE / "sdl" / f"{FIXTURE_PACK_IDENTITY}.sdl.yaml"


@dataclass(frozen=True)
class FixtureArtifact:
    """One pack artifact, as a content placement names it."""

    artifact_id: str
    digest: str
    media_type: str


def _artifact(artifact_id: str, relpath: str, media_type: str) -> FixtureArtifact:
    data = (FIXTURE_PACK_SOURCE / relpath).read_bytes()
    return FixtureArtifact(
        artifact_id=artifact_id,
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        media_type=media_type,
    )


NOTICE = _artifact(
    "materialization-envelope-notice", "assets/content/notice.txt", "text/plain"
)
TREE = _artifact(
    "materialization-envelope-tree", "assets/content/tree.tar", "application/x-tar"
)


def admit_fixture_pack(staging_root: Path) -> ScenarioBundle:
    """Stage and validate the fixture pack under ``staging_root``."""

    return env_pack_bundle(
        staging_root, FIXTURE_PACK_IDENTITY, source_pack=FIXTURE_PACK_SOURCE
    )


__all__ = [
    "FIXTURE_PACK_IDENTITY",
    "FIXTURE_PACK_SOURCE",
    "FIXTURE_SDL",
    "FixtureArtifact",
    "NOTICE",
    "TREE",
    "admit_fixture_pack",
]
