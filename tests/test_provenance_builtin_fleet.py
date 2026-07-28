"""Tests for the REP-003 built-in provider fleet and run wiring (issue #452).

Covers the composed default registry, the seal profile, and the end-to-end
collect-and-publish path — including the honest posture when a source genuinely
does not exist for a plain lab start (no admitted plan, no participants).
"""

import json

import pytest

from aptl.core.config import AptlConfig
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.record import PROVENANCE_RECORD_PATH, PROVISIONAL_RECORD_PATH
from aptl.core.provenance.registrations import (
    BUILTIN_REGISTRATIONS,
    DEFAULT_PROVENANCE_REGISTRY,
    DEFAULT_SEAL_PROFILE,
    build_default_providers,
    collect_run_provenance,
)
from aptl.core.runstore import LocalRunStore

_RUN_ID = "run_20260101T000000Z"


class _StubSoftware:
    python_version = "3.12.1"
    docker_version = "27.0"
    compose_version = "2.29"
    wazuh_manager_version = ""
    wazuh_indexer_version = ""
    aptl_version = "0.2.0"
    raes_version = "2.0.0"


class _StubContainer:
    def __init__(self, name):
        self.name = name
        self.image = "img:tag"
        self.image_id = "volatile"
        self.image_digest = "sha256:" + "f" * 64
        self.status = "running"
        self.health = "healthy"


class _StubSnapshot:
    def __init__(self):
        self.timestamp = "2026-01-01T00:00:00Z"
        self.software = _StubSoftware()
        self.containers = [_StubContainer("aptl-victim")]

    def to_dict(self):
        return {"timestamp": self.timestamp, "containers": ["aptl-victim"]}


class _StubPlan:
    """Minimal admitted plan: the canonical record requires this context."""

    plan_id = "plan-1"
    policy_version = "aptl-admission/v1"
    source_set_digest = "sha256:" + "c" * 64
    plan_digest = "sha256:" + "d" * 64
    trials = ()
    capture_bindings = ()


class TestBuiltinRegistrations:
    """Every built-in provider is declared exactly once, with real bounds."""

    def test_every_builtin_id_is_unique(self):
        ids = [item.provider_id for item in BUILTIN_REGISTRATIONS]
        assert len(ids) == len(set(ids))

    def test_the_declared_families_cover_the_requirement(self):
        ids = {item.provider_id for item in BUILTIN_REGISTRATIONS}
        assert ids == {
            "apparatus",
            "experiment",
            "participant",
            "detection-content",
            "dependency-artifacts",
            "config-identity",
            "runtime-facts",
        }

    def test_every_registration_declares_positive_limits(self):
        for item in BUILTIN_REGISTRATIONS:
            assert item.limits.max_bytes > 0
            assert item.limits.max_entries > 0
            assert item.limits.timeout_s > 0

    def test_the_default_profile_validates_against_the_default_registry(self):
        DEFAULT_SEAL_PROFILE.validate_against(DEFAULT_PROVENANCE_REGISTRY)

    def test_the_registry_declaration_digest_is_stable(self):
        assert (
            DEFAULT_PROVENANCE_REGISTRY.declaration_digest()
            == DEFAULT_PROVENANCE_REGISTRY.declaration_digest()
        )

    def test_adding_a_provider_requires_only_a_registration(self):
        """The extension seam: a new source is one registration, not a rewrite."""
        from aptl.core.provenance.registry import (
            ProvenanceLimits,
            ProvenanceProviderRegistration,
            ProvenanceProviderRegistry,
            SealPoint,
        )

        extra = ProvenanceProviderRegistration(
            provider_id="future-source",
            implementation_version="1.0.0",
            provenance_kind="future",
            owner_adapter="tests",
            seal_point=SealPoint.RUN_READY_TO_SEAL,
            requiredness_policy_key="future-required",
            limits=ProvenanceLimits(max_bytes=1, max_entries=1, timeout_s=1),
        )
        extended = ProvenanceProviderRegistry(BUILTIN_REGISTRATIONS + (extra,))
        assert extended.get("future-source") is not None


class TestDefaultFleet:
    """The composed fleet reports honestly about sources that do not exist."""

    def test_fleet_covers_every_registered_provider(self):
        providers = build_default_providers(
            project_dir=".", config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert {p.provider_id for p in providers} == {
            item.provider_id for item in BUILTIN_REGISTRATIONS
        }

    def test_absent_plan_and_participants_are_unavailable_not_missing(self, tmp_path):
        """A plain lab start has no admitted plan; that is disclosed, not hidden."""
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert collection.sections["experiment"].status is ProvenanceStatus.UNAVAILABLE
        assert collection.sections["participant"].status is ProvenanceStatus.UNAVAILABLE
        declared = {item.provider_id for item in collection.limitations}
        assert {"experiment", "participant"} <= declared

    def test_present_sources_are_collected(self, tmp_path):
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert collection.sections["apparatus"].status is ProvenanceStatus.COLLECTED
        assert collection.sections["config-identity"].status is ProvenanceStatus.COLLECTED
        assert collection.sections["runtime-facts"].status is ProvenanceStatus.COLLECTED

    def test_detection_content_is_collected_when_rules_exist(self, tmp_path):
        rules = tmp_path / "config" / "suricata" / "rules"
        rules.mkdir(parents=True)
        (rules / "local.rules").write_text("alert tcp any any -> any any (sid:1;)")
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert collection.sections["detection-content"].status is ProvenanceStatus.COLLECTED

    def test_collection_is_deterministic(self, tmp_path):
        first = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        second = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert first.projection() == second.projection()

    def test_the_whole_collection_survives_the_store_secret_invariant(self, tmp_path):
        """Real providers against a real config must publish without redaction drift."""
        from aptl.core.provenance.record import publish_provenance_record

        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        collection = collect_run_provenance(
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_StubSnapshot(),
            admitted_plan=_StubPlan(),
        )
        path = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=collection
        )
        loaded = json.loads(path.read_bytes())
        assert loaded["seal_state"] == "ready-to-seal"
        assert loaded["run_id"] == _RUN_ID

    def test_published_record_lands_at_the_declared_run_relative_path(self, tmp_path):
        from aptl.core.provenance.record import publish_provenance_record

        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        collection = collect_run_provenance(
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_StubSnapshot(),
            admitted_plan=_StubPlan(),
        )
        publish_provenance_record(store=store, run_id=_RUN_ID, collection=collection)
        assert (store.get_run_path(_RUN_ID) / PROVENANCE_RECORD_PATH).exists()

    def test_no_host_path_leaks_into_the_record(self, tmp_path):
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert str(tmp_path) not in json.dumps(collection.projection())


class TestLabWiring:
    """The lab-start step publishes provenance without becoming a seal."""

    def test_step_publishes_a_record(self, tmp_path):
        from aptl.core.lab import _publish_run_provenance

        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        _publish_run_provenance(
            store=store,
            run_id=_RUN_ID,
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_StubSnapshot(),
        )
        assert (store.get_run_path(_RUN_ID) / PROVISIONAL_RECORD_PATH).exists()

    def test_step_is_best_effort_and_never_raises(self, tmp_path):
        """A provenance failure must not turn a running lab into a failed start."""
        from aptl.core.lab import _publish_run_provenance

        store = LocalRunStore(tmp_path / "runs")
        # No create_run: publication will fail internally.
        _publish_run_provenance(
            store=store,
            run_id="../escape",
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_StubSnapshot(),
        )

    def test_republishing_the_same_run_is_idempotent(self, tmp_path):
        from aptl.core.lab import _publish_run_provenance

        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        for _ in range(2):
            _publish_run_provenance(
                store=store,
                run_id=_RUN_ID,
                project_dir=tmp_path,
                config=AptlConfig(),
                snapshot=_StubSnapshot(),
            )
        assert (store.get_run_path(_RUN_ID) / PROVISIONAL_RECORD_PATH).exists()


@pytest.mark.fuzz
class TestFleetFuzz:
    """The fleet stays typed under hostile project trees."""

    def test_hostile_detection_tree_never_escapes_a_typed_outcome(self, tmp_path):
        import os

        rules = tmp_path / "config" / "suricata" / "rules"
        rules.mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.rules").write_text("SECRET")
        os.symlink(outside / "secret.rules", rules / "link.rules")
        (rules / "deep").mkdir()
        (rules / "deep" / "a.rules").write_text("x")

        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_StubSnapshot()
        )
        assert collection.sections["detection-content"].status in set(ProvenanceStatus)
        assert "SECRET" not in json.dumps(collection.projection())
