"""TechVault's serving labels live in its out-of-tree provider distribution."""

from __future__ import annotations

import pytest

from aptl.backends.identity import BackendIdentity
from aptl.backends.pack_interaction import PackBackendInteractionContext
from aptl.backends.raes_profiles import OPERATOR_GROUP_VOCABULARY
from aptl.core.scenario_bundle import PackIdentity
from aptl_techvault.serving import TechVaultPackInteraction


PACK = PackIdentity(
    pack_id="techvault",
    pack_version="0.1.0",
    set_digest="sha256:6300b3d539ab9c1e2287b9852e5408e1811516b818a7acf015f045cb3c9c5b89",
)
BACKEND = BackendIdentity("aptl", "0.1.0", "full-remote-control-plane")


def _context(*addresses: str) -> PackBackendInteractionContext:
    return PackBackendInteractionContext(
        pack=PACK,
        backend=BACKEND,
        component_addresses=tuple(sorted(addresses)),
        operator_groups=OPERATOR_GROUP_VOCABULARY,
    )


def test_provider_returns_a_total_mapping_for_an_admitted_subset() -> None:
    provider = TechVaultPackInteraction()
    context = _context(
        "provision.node.misp",
        "provision.node.victim",
        "provision.node.webapp",
    )

    result = provider.resolve(context)

    assert {
        membership.component_address: membership.groups
        for membership in result.memberships
    } == {
        "provision.node.misp": ("soc",),
        "provision.node.victim": ("victim",),
        "provision.node.webapp": ("enterprise",),
    }


def test_provider_is_bound_to_the_released_shuffle_contract() -> None:
    provider = TechVaultPackInteraction()

    assert provider.supported_pack_set_digests == (PACK.set_digest,)


def test_provider_does_not_adopt_backend_apparatus_as_pack_components() -> None:
    with pytest.raises(ValueError, match="unsupported-component-address"):
        TechVaultPackInteraction().resolve(
            _context("provision.node.aptl-grafana-otel", "provision.node.cortex")
        )


def test_unknown_component_fails_instead_of_returning_a_partial_mapping() -> None:
    context = _context("provision.node.misp", "provision.node.not-in-techvault")
    provider = TechVaultPackInteraction()

    with pytest.raises(ValueError, match="unsupported-component-address"):
        provider.resolve(context)
