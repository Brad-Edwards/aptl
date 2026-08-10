"""Contract and discovery tests for the deployment-serving interaction seam."""

from __future__ import annotations

from importlib import metadata
from types import SimpleNamespace

import pytest

from aptl.backends.identity import BackendIdentity
from aptl.backends.pack_interaction import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    ComponentGroupMembership,
    PackBackendInteractionContext,
    PackBackendInteractionResult,
)
from aptl.backends.pack_interaction_discovery import (
    PackBackendInteractionError,
    resolve_pack_backend_interaction,
)
from aptl.backends.raes_profiles import CORE_PROFILES, OPERATOR_GROUP_VOCABULARY
from aptl.core.config import ContainerSettings
from aptl.core.scenario_bundle import PackIdentity


PACK = PackIdentity(
    pack_id="techvault",
    pack_version="0.1.0",
    set_digest="sha256:" + "a" * 64,
)
BACKEND = BackendIdentity(
    target_name="aptl",
    target_version="0.1.0",
    profile="full-remote-control-plane",
)


def _context(*addresses: str) -> PackBackendInteractionContext:
    return PackBackendInteractionContext(
        pack=PACK,
        backend=BACKEND,
        component_addresses=tuple(addresses or ("provision.node.a", "provision.node.b")),
        operator_groups=OPERATOR_GROUP_VOCABULARY,
    )


class _Provider:
    provider_id = "test-provider"
    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.0",)
    supported_pack_set_digests = (PACK.set_digest,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles = ("full-remote-control-plane",)
    backend_transports: tuple[str, ...] = ()

    def __init__(self, memberships: tuple[ComponentGroupMembership, ...]):
        self.memberships = memberships
        self.calls = 0

    def resolve(self, context: PackBackendInteractionContext) -> PackBackendInteractionResult:
        self.calls += 1
        return PackBackendInteractionResult(memberships=self.memberships)


class _Dist:
    name = "test-pack-interaction"
    version = "9.9.9"


class _EntryPoint:
    dist = _Dist()

    def __init__(self, name: str, target: object):
        self.name = name
        self._target = target
        self.loaded = False

    def load(self) -> object:
        self.loaded = True
        if isinstance(self._target, BaseException):
            raise self._target
        return self._target


def _install(monkeypatch: pytest.MonkeyPatch, *entry_points: _EntryPoint) -> None:
    monkeypatch.setattr(
        "aptl.backends.pack_interaction_discovery._entry_points",
        lambda: list(entry_points),
    )


def _provider_contract(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "provider_id": "test-provider",
        "extension_api_version": EXTENSION_API_VERSION,
        "supported_pack_id": "techvault",
        "supported_pack_versions": ("0.1.0",),
        "supported_pack_set_digests": (PACK.set_digest,),
        "backend_target_name": "aptl",
        "backend_target_versions": ("0.1.0",),
        "backend_profiles": ("full-remote-control-plane",),
        "backend_transports": (),
        "resolve": lambda context: PackBackendInteractionResult(
            memberships=tuple(
                ComponentGroupMembership(address, ())
                for address in context.component_addresses
            )
        ),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_operator_group_vocabulary_has_one_code_owned_source() -> None:
    assert OPERATOR_GROUP_VOCABULARY == tuple(
        (*ContainerSettings.model_fields, *CORE_PROFILES)
    )
    assert len(OPERATOR_GROUP_VOCABULARY) == len(set(OPERATOR_GROUP_VOCABULARY))
    assert "web" not in OPERATOR_GROUP_VOCABULARY


def test_core_distribution_registers_no_pack_interaction_provider() -> None:
    aptl_entry_points = [
        entry_point
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP)
        if getattr(entry_point, "dist", None) is not None
        and entry_point.dist.name in {"aptl", "aptl-labs"}
    ]

    assert aptl_entry_points == []


def test_no_exact_provider_uses_the_total_unprofiled_default(monkeypatch) -> None:
    other = _EntryPoint("otherpack.aptl", RuntimeError("must not load"))
    _install(monkeypatch, other)

    resolved = resolve_pack_backend_interaction(_context())

    assert other.loaded is False
    assert resolved.provider_id == "aptl.core.unprofiled-default"
    assert resolved.memberships == (
        ComponentGroupMembership("provision.node.a", ()),
        ComponentGroupMembership("provision.node.b", ()),
    )
    assert resolved.mapping_digest.startswith("sha256:")


def test_exact_provider_is_loaded_once_and_host_metadata_is_recorded(monkeypatch) -> None:
    provider = _Provider(
        (
            ComponentGroupMembership("provision.node.a", ("soc",)),
            ComponentGroupMembership("provision.node.b", ()),
        )
    )
    entry_point = _EntryPoint("techvault.aptl", provider)
    _install(monkeypatch, entry_point)

    resolved = resolve_pack_backend_interaction(_context())

    assert provider.calls == 1
    assert resolved.provider_id == "test-provider"
    assert resolved.distribution == "test-pack-interaction"
    assert resolved.distribution_version == "9.9.9"
    assert resolved.entry_point == "techvault.aptl"
    assert resolved.memberships[0].groups == ("soc",)


@pytest.mark.parametrize(
    "memberships",
    [
        (ComponentGroupMembership("provision.node.a", ()),),
        (
            ComponentGroupMembership("provision.node.a", ()),
            ComponentGroupMembership("provision.node.a", ()),
        ),
        (
            ComponentGroupMembership("provision.node.a", ()),
            ComponentGroupMembership("provision.node.b", ()),
            ComponentGroupMembership("provision.node.extra", ()),
        ),
        (
            ComponentGroupMembership("provision.node.a", ("web",)),
            ComponentGroupMembership("provision.node.b", ()),
        ),
    ],
)
def test_malformed_provider_mapping_fails_closed(monkeypatch, memberships) -> None:
    _install(monkeypatch, _EntryPoint("techvault.aptl", _Provider(memberships)))

    with pytest.raises(PackBackendInteractionError, match="mapping-invalid"):
        resolve_pack_backend_interaction(_context())


def test_ambiguous_compatible_providers_fail_before_resolving(monkeypatch) -> None:
    memberships = (
        ComponentGroupMembership("provision.node.a", ()),
        ComponentGroupMembership("provision.node.b", ()),
    )
    first_provider = _Provider(memberships)
    second_provider = _Provider(memberships)
    first = _EntryPoint("techvault.aptl", first_provider)
    second = _EntryPoint("techvault.aptl", second_provider)
    _install(monkeypatch, first, second)

    with pytest.raises(PackBackendInteractionError, match="provider-ambiguous"):
        resolve_pack_backend_interaction(_context())

    assert first.loaded is second.loaded is True
    assert first_provider.calls == second_provider.calls == 0


def test_a_broken_exact_provider_never_falls_back(monkeypatch) -> None:
    _install(
        monkeypatch,
        _EntryPoint("techvault.aptl", RuntimeError("credential=do-not-report")),
    )

    with pytest.raises(PackBackendInteractionError, match="provider-load-failed") as exc:
        resolve_pack_backend_interaction(_context())

    assert "credential" not in str(exc.value)


@pytest.mark.parametrize(
    "provider",
    [
        pytest.param(
            _provider_contract(extension_api_version=None),
            id="missing-extension-api-version",
        ),
        pytest.param(
            _provider_contract(provider_id="not a safe provider id"),
            id="malformed-provider-id",
        ),
        pytest.param(
            _provider_contract(resolve="not-callable"),
            id="non-callable-resolve",
        ),
    ],
)
def test_malformed_provider_contract_fails_closed(monkeypatch, provider) -> None:
    _install(monkeypatch, _EntryPoint("techvault.aptl", provider))

    with pytest.raises(PackBackendInteractionError, match="provider-malformed"):
        resolve_pack_backend_interaction(_context())


def test_provider_resolve_exception_fails_closed(monkeypatch) -> None:
    def fail(_context: PackBackendInteractionContext) -> PackBackendInteractionResult:
        raise RuntimeError("credential=do-not-report")

    _install(
        monkeypatch,
        _EntryPoint("techvault.aptl", _provider_contract(resolve=fail)),
    )

    with pytest.raises(PackBackendInteractionError, match="provider-resolve-failed") as exc:
        resolve_pack_backend_interaction(_context())

    assert "credential" not in str(exc.value)


def test_invalid_context_fails_before_discovery(monkeypatch) -> None:
    entry_point = _EntryPoint("techvault.aptl", RuntimeError("must not load"))
    _install(monkeypatch, entry_point)

    with pytest.raises(PackBackendInteractionError, match="context-invalid"):
        resolve_pack_backend_interaction(
            _context("provision.node.b", "provision.node.a")
        )

    assert entry_point.loaded is False


def test_incompatible_provider_does_not_claim_and_uses_default(monkeypatch) -> None:
    provider = _Provider(
        (
            ComponentGroupMembership("provision.node.a", ()),
            ComponentGroupMembership("provision.node.b", ()),
        )
    )
    provider.supported_pack_set_digests = ("sha256:" + "b" * 64,)
    _install(monkeypatch, _EntryPoint("techvault.aptl", provider))

    resolved = resolve_pack_backend_interaction(_context())

    assert resolved.provider_id == "aptl.core.unprofiled-default"
    assert provider.calls == 0


def test_only_compatible_provider_is_selected_from_same_selector(monkeypatch) -> None:
    memberships = (
        ComponentGroupMembership("provision.node.a", ("soc",)),
        ComponentGroupMembership("provision.node.b", ()),
    )
    stale = _Provider(memberships)
    stale.supported_pack_versions = ("0.0.9",)
    compatible = _Provider(memberships)
    compatible.provider_id = "compatible-provider"
    _install(
        monkeypatch,
        _EntryPoint("techvault.aptl", stale),
        _EntryPoint("techvault.aptl", compatible),
    )

    resolved = resolve_pack_backend_interaction(_context())

    assert resolved.provider_id == "compatible-provider"
    assert stale.calls == 0
    assert compatible.calls == 1


def test_transport_constraint_matches_the_actual_backend_transport(monkeypatch) -> None:
    memberships = (
        ComponentGroupMembership("provision.node.a", ()),
        ComponentGroupMembership("provision.node.b", ()),
    )
    provider = _Provider(memberships)
    provider.backend_transports = ("ssh-compose",)
    _install(monkeypatch, _EntryPoint("techvault.aptl", provider))
    context = PackBackendInteractionContext(
        pack=PACK,
        backend=BackendIdentity(
            target_name="aptl",
            target_version="0.1.0",
            profile="full-remote-control-plane",
            transport="ssh-compose",
        ),
        component_addresses=("provision.node.a", "provision.node.b"),
        operator_groups=OPERATOR_GROUP_VOCABULARY,
    )

    resolved = resolve_pack_backend_interaction(context)

    assert resolved.provider_id == "test-provider"
