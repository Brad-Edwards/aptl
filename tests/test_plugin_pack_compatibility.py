"""Installed plugins are qualified against the pack APTL actually admits (#879).

The defect this gate exists to catch: a plugin declares an exact scenario
content digest, the pack it names is upgraded, and nothing notices because every
other test builds its context out of the plugin's own declaration. Agreement with
yourself is not evidence.

So the admitted identity here comes from ``env_pack_bundle()`` -- the same
env-packs validation path a real boot resolves -- and never from a literal copied
into this file. A digest or version drift between an installed plugin and the
admitted pack fails here, at the seam the drift actually breaks.

The distributions are asserted present rather than skipped over: a plugin that
is installed nowhere is exactly the second half of #879, and a test that
vacuously passes when its subject is absent would have hidden it.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

import pytest

from aptl.core.scenario_bundle import PackIdentity, env_pack_bundle
from aptl.validation.scenario_verification import ENTRY_POINT_GROUP

pytestmark = pytest.mark.integration

#: The pack every TechVault plugin in this repository is written against.
PACK_IDENTITY = "techvault"

#: Entry-point group each plugin family registers its exact selector under.
PACK_INTERACTION_GROUP = "aptl.pack_backend_interactions"

#: Selector both families use for TechVault on the APTL backend.
SELECTOR = "techvault.aptl"


@pytest.fixture(scope="module")
def admitted(tmp_path_factory: pytest.TempPathFactory) -> PackIdentity:
    """Return the pack identity env-packs admits, from the real resolver."""

    staging = tmp_path_factory.mktemp("admitted-pack")
    bundle = env_pack_bundle(Path(staging), PACK_IDENTITY)
    identity = bundle.pack_identity
    assert identity is not None, "the env-pack resolver must return a pack identity"
    return identity


def _entry_point(group: str) -> metadata.EntryPoint:
    """Return the one installed TechVault entry point in ``group``."""

    matches = [
        entry_point
        for entry_point in metadata.entry_points(group=group)
        if entry_point.name == SELECTOR
    ]
    assert len(matches) == 1, (
        f"exactly one {SELECTOR!r} entry point must be installed in {group!r}; "
        f"found {len(matches)}. Install the plugin that registers it."
    )
    return matches[0]


def test_the_verifier_is_installed_and_qualified_for_the_admitted_pack(
    admitted: PackIdentity,
) -> None:
    """The verifier's qualified scenario is the pack APTL resolves, exactly."""

    verifier = _entry_point(ENTRY_POINT_GROUP).load()
    scenarios = [target.scenario for target in verifier.qualified_targets]

    assert admitted.set_digest in {scenario.content_digest for scenario in scenarios}, (
        "the verifier declares scenario content that env-packs does not admit; "
        "a pack release requires a verifier release that qualifies its digest"
    )
    for scenario in scenarios:
        assert scenario.identity == admitted.pack_id
        assert scenario.version == admitted.pack_version
        assert scenario.content_digest == admitted.set_digest


def test_the_pack_interaction_provider_matches_the_admitted_pack(
    admitted: PackIdentity,
) -> None:
    """The serving-interaction provider is bound to the same admitted release."""

    provider = _entry_point(PACK_INTERACTION_GROUP).load()

    assert provider.supported_pack_id == admitted.pack_id
    assert provider.supported_pack_versions == (admitted.pack_version,)
    assert provider.supported_pack_set_digests == (admitted.set_digest,)
