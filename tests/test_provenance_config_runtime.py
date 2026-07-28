"""Tests for the REP-003 config-identity and runtime-facts providers (#452).

The config provider is the preflight's "versioned safe effective-config
projection beside the strict AptlConfig owner": an explicit allowlist of
apparatus-relevant fields, never ``model_dump()`` of the whole config and
never a raw hash of the config file (which would fold ``.env`` and credential
locators into an identity).
"""

import pytest

from pydantic import BaseModel

from aptl.core.config import AptlConfig, DeploymentConfig, LabSettings
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext
from aptl.core.provenance.providers.config_identity import (
    CONFIG_PROVIDER_ID,
    SAFE_CONFIG_SCHEMA_VERSION,
    ConfigIdentityProvider,
    safe_config_projection,
)
from aptl.core.provenance.providers.runtime_facts import (
    RUNTIME_PROVIDER_ID,
    RuntimeFactsProvider,
)
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    SealPoint,
)


def _context(provider_id, *, max_entries=64, timeout_s=30, clock=None):
    registration = ProvenanceProviderRegistration(
        provider_id=provider_id,
        implementation_version="1.0.0",
        provenance_kind=provider_id,
        owner_adapter="tests",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key=f"{provider_id}-required",
        limits=ProvenanceLimits(
            max_bytes=1_000_000, max_entries=max_entries, timeout_s=timeout_s
        ),
    )
    return ProvenanceContext(
        registration=registration, clock=clock or (lambda: 0.0), started_at=0.0
    )


class TestSafeConfigProjection:
    """The projection is an explicit allowlist, versioned, and secret-free."""

    def test_projection_is_versioned(self):
        projection = safe_config_projection(AptlConfig())
        assert projection["schema_version"] == SAFE_CONFIG_SCHEMA_VERSION

    def test_apparatus_relevant_fields_are_included(self):
        projection = safe_config_projection(AptlConfig())
        assert projection["deployment_provider"] == "docker-compose"
        assert projection["run_storage_backend"] == "local"
        assert "containers" in projection
        assert "participant_models" in projection

    def test_ssh_credential_locators_are_excluded(self):
        """ssh_key is a credential locator; ssh_host/user are host details."""
        config = AptlConfig(
            deployment=DeploymentConfig(
                provider="ssh-compose",
                ssh_host="10.1.2.3",
                ssh_user="operator",
                ssh_key="/home/operator/.ssh/id_ed25519",
                remote_dir="/srv/aptl",
            )
        )
        rendered = repr(safe_config_projection(config))
        assert "10.1.2.3" not in rendered
        assert "operator" not in rendered
        assert "id_ed25519" not in rendered
        assert "/srv/aptl" not in rendered

    def test_deployment_mode_survives_even_when_host_details_do_not(self):
        """Validity needs the mode; it does not need the host."""
        config = AptlConfig(
            deployment=DeploymentConfig(provider="ssh-compose", ssh_host="10.1.2.3")
        )
        assert safe_config_projection(config)["deployment_provider"] == "ssh-compose"

    def test_local_run_storage_path_is_excluded(self):
        projection = safe_config_projection(AptlConfig())
        assert "local_path" not in repr(projection)

    def test_participant_model_identity_is_included(self):
        """Model identity must be reconstructable from the record."""
        config = AptlConfig()
        config.experiment.participant_models.claude = "claude-opus-4-5-20251101"
        projection = safe_config_projection(config)
        assert projection["participant_models"]["claude"] == "claude-opus-4-5-20251101"

    def test_projection_never_contains_a_secret_shaped_value(self):
        from aptl.utils.redaction import redact

        projection = safe_config_projection(AptlConfig())
        assert redact(projection) == projection

    def test_projection_is_not_a_whole_config_dump(self):
        """A model_dump() would sweep in every future field, secret or not.

        Asserted against what must be ABSENT: the raw nested config objects.
        A set-cardinality comparison would pass for almost any return value,
        including an empty dict.
        """
        projection = safe_config_projection(AptlConfig())
        # A dump would surface the raw nested section names. ``containers`` is
        # excluded from this list deliberately: the projection legitimately
        # owns that key, but it holds flat boolean toggles rather than the model.
        for raw_section in ("lab", "deployment", "run_storage", "experiment", "lifecycle_policy"):
            assert raw_section not in projection
        for value in projection.values():
            assert not isinstance(value, BaseModel)
        assert all(
            isinstance(flag, bool) for flag in projection["containers"].values()
        )

    def test_projection_still_carries_the_fields_it_promises(self):
        """Guards the exclusion test above from passing on an empty projection."""
        projection = safe_config_projection(AptlConfig())
        for expected in (
            "schema_version",
            "lab_name",
            "deployment_provider",
            "run_storage_backend",
            "containers",
            "participant_models",
        ):
            assert expected in projection


class TestConfigIdentityProvider:
    """Config identity is one leaf derived from the safe projection."""

    def test_collects_a_single_config_identity_leaf(self):
        result = ConfigIdentityProvider(AptlConfig()).collect(_context(CONFIG_PROVIDER_ID))
        assert result.status is ProvenanceStatus.COLLECTED
        assert [leaf.logical_id for leaf in result.leaves] == ["effective-config"]

    def test_changing_one_safe_field_changes_the_identity(self):
        base = ConfigIdentityProvider(AptlConfig()).collect(_context(CONFIG_PROVIDER_ID))
        changed = ConfigIdentityProvider(
            AptlConfig(lab=LabSettings(name="other-lab"))
        ).collect(_context(CONFIG_PROVIDER_ID))
        assert base.leaves != changed.leaves

    def test_changing_an_excluded_field_does_not_change_the_identity(self):
        """An ssh host is not apparatus content; it must not perturb identity."""
        base = ConfigIdentityProvider(
            AptlConfig(deployment=DeploymentConfig(provider="ssh-compose"))
        ).collect(_context(CONFIG_PROVIDER_ID))
        with_host = ConfigIdentityProvider(
            AptlConfig(
                deployment=DeploymentConfig(provider="ssh-compose", ssh_host="10.9.9.9")
            )
        ).collect(_context(CONFIG_PROVIDER_ID))
        assert base.leaves == with_host.leaves

    def test_absent_config_is_unavailable(self):
        result = ConfigIdentityProvider(None).collect(_context(CONFIG_PROVIDER_ID))
        assert result.status is ProvenanceStatus.UNAVAILABLE

    def test_identity_is_stable_across_collections(self):
        first = ConfigIdentityProvider(AptlConfig()).collect(_context(CONFIG_PROVIDER_ID))
        second = ConfigIdentityProvider(AptlConfig()).collect(_context(CONFIG_PROVIDER_ID))
        assert first.leaves == second.leaves


class _StubContainer:
    def __init__(self, name, image_digest="sha256:" + "f" * 64, image="img:tag"):
        self.name = name
        self.image = image
        self.image_id = "container-id-volatile"
        self.image_digest = image_digest
        self.status = "running"
        self.health = "healthy"
        self.labels = {"com.example": "x"}
        self.networks = {}
        self.ports = []


class _StubSoftware:
    python_version = "3.12.1"
    docker_version = "27.0"
    compose_version = "2.29"
    wazuh_manager_version = "4.9"
    wazuh_indexer_version = "2.16"
    aptl_version = "0.2.0"
    raes_version = "2.0.0"


class _StubSnapshot:
    def __init__(self, containers=None):
        self.timestamp = "2026-01-01T00:00:00Z"
        self.software = _StubSoftware()
        self.containers = containers or [_StubContainer("aptl-victim")]

    def to_dict(self):
        return {"timestamp": self.timestamp, "containers": [c.name for c in self.containers]}


class TestRuntimeFactsProvider:
    """Image identities and tool versions, with volatile data kept out."""

    def test_collects_image_digest_and_tool_version_leaves(self):
        result = RuntimeFactsProvider(_StubSnapshot()).collect(_context(RUNTIME_PROVIDER_ID))
        assert result.status is ProvenanceStatus.COLLECTED
        names = {leaf.logical_id for leaf in result.leaves}
        assert "image/aptl-victim" in names
        assert "tool-versions" in names

    def test_a_changed_image_digest_changes_only_that_leaf(self):
        before = RuntimeFactsProvider(_StubSnapshot()).collect(_context(RUNTIME_PROVIDER_ID))
        after = RuntimeFactsProvider(
            _StubSnapshot(containers=[_StubContainer("aptl-victim", "sha256:" + "0" * 64)])
        ).collect(_context(RUNTIME_PROVIDER_ID))
        before_ids = {leaf.logical_id: leaf.digest for leaf in before.leaves}
        after_ids = {leaf.logical_id: leaf.digest for leaf in after.leaves}
        assert before_ids["tool-versions"] == after_ids["tool-versions"]
        assert before_ids["image/aptl-victim"] != after_ids["image/aptl-victim"]

    def test_volatile_state_does_not_perturb_identity(self):
        """Health, status, and container id are observations, not identity."""
        stable = _StubContainer("aptl-victim")
        volatile = _StubContainer("aptl-victim")
        volatile.status = "restarting"
        volatile.health = "unhealthy"
        volatile.image_id = "different-volatile-id"
        before = RuntimeFactsProvider(_StubSnapshot([stable])).collect(
            _context(RUNTIME_PROVIDER_ID)
        )
        after = RuntimeFactsProvider(_StubSnapshot([volatile])).collect(
            _context(RUNTIME_PROVIDER_ID)
        )
        assert before.leaves == after.leaves

    def test_a_container_without_an_immutable_digest_is_declared_not_guessed(self):
        """A tag can never stand in for the selected immutable digest."""
        result = RuntimeFactsProvider(
            _StubSnapshot([_StubContainer("aptl-victim", image_digest="")])
        ).collect(_context(RUNTIME_PROVIDER_ID))
        assert "aptl-victim" in result.payload["images_without_digest"]
        assert not any("image/aptl-victim" == leaf.logical_id for leaf in result.leaves)

    def test_container_labels_are_not_embedded(self):
        """Hostile labels must not become record keys or unbounded content."""
        container = _StubContainer("aptl-victim")
        container.labels = {"evil" * 500: "x" * 5000}
        result = RuntimeFactsProvider(_StubSnapshot([container])).collect(
            _context(RUNTIME_PROVIDER_ID)
        )
        assert "evilevil" not in repr(result.payload)

    def test_absent_snapshot_is_unavailable(self):
        result = RuntimeFactsProvider(None).collect(_context(RUNTIME_PROVIDER_ID))
        assert result.status is ProvenanceStatus.UNAVAILABLE

    def test_more_containers_than_the_budget_is_truncated(self):
        containers = [_StubContainer(f"aptl-node-{index}") for index in range(20)]
        result = RuntimeFactsProvider(_StubSnapshot(containers)).collect(
            _context(RUNTIME_PROVIDER_ID, max_entries=5)
        )
        assert result.status is ProvenanceStatus.TRUNCATED

    def test_payload_records_the_range_snapshot_identity(self):
        result = RuntimeFactsProvider(_StubSnapshot()).collect(_context(RUNTIME_PROVIDER_ID))
        assert result.payload["range_snapshot_identity"].startswith("sha256:")

    def test_tool_versions_are_recorded(self):
        result = RuntimeFactsProvider(_StubSnapshot()).collect(_context(RUNTIME_PROVIDER_ID))
        assert result.payload["tool_versions"]["aptl"] == "0.2.0"
        assert result.payload["tool_versions"]["raes"] == "2.0.0"

    @pytest.mark.parametrize("name", ["", "bad name", "x" * 300])
    def test_a_hostile_container_name_is_rejected(self, name):
        result = RuntimeFactsProvider(_StubSnapshot([_StubContainer(name)])).collect(
            _context(RUNTIME_PROVIDER_ID)
        )
        assert result.status is ProvenanceStatus.FAILED
