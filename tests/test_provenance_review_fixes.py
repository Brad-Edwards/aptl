"""Regression tests for the REP-003 pre-push review findings (issue #452).

Three defects the codex review surfaced:

1. Lab startup published the CANONICAL ready-to-seal record without the
   admitted trial or realized participant context. Because publication is
   create-once, the real seal-boundary collector could never correct it — the
   authoritative write would conflict with the startup artifact.
2. ``range_identity`` hashed ``RangeSnapshot.to_dict()`` wholesale, folding
   volatile observation state (timestamp, container status/health) into a
   stable identity.
3. The ``wazuh-allowlists`` detection root admitted every non-dot file, which
   is directory discovery rather than a non-secret source allowlist.
"""

import json

import pytest

from aptl.core.config import AptlConfig
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext
from aptl.core.provenance.providers.detection import (
    DETECTION_ROOTS,
    DetectionContentProvider,
)
from aptl.core.provenance.providers.runtime_facts import RuntimeFactsProvider
from aptl.core.provenance.record import (
    PROVENANCE_RECORD_PATH,
    PROVISIONAL_RECORD_PATH,
    ProvenanceContextError,
    publish_provenance_record,
    publish_provisional_provenance_record,
)
from aptl.core.provenance.registrations import collect_run_provenance
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    SealPoint,
)
from aptl.core.runstore import LocalRunStore

_RUN_ID = "run_20260101T000000Z"


def _context(provider_id, *, max_bytes=1_000_000, max_entries=64, timeout_s=30):
    registration = ProvenanceProviderRegistration(
        provider_id=provider_id,
        implementation_version="1.0.0",
        provenance_kind=provider_id,
        owner_adapter="tests",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key=f"{provider_id}-required",
        limits=ProvenanceLimits(
            max_bytes=max_bytes, max_entries=max_entries, timeout_s=timeout_s
        ),
    )
    return ProvenanceContext(registration=registration, clock=lambda: 0.0, started_at=0.0)


class _StubPlan:
    plan_id = "plan-1"
    policy_version = "aptl-admission/v1"
    source_set_digest = "sha256:" + "c" * 64
    plan_digest = "sha256:" + "d" * 64
    trials = ()
    capture_bindings = ()


class _StubSoftware:
    python_version = "3.12.1"
    docker_version = "27.0"
    compose_version = "2.29"
    wazuh_manager_version = ""
    wazuh_indexer_version = ""
    aptl_version = "0.2.0"
    raes_version = "2.0.0"


class _RealisticSnapshot:
    """A snapshot whose ``to_dict()`` includes the volatile fields the real one does."""

    def __init__(self, *, timestamp="2026-01-01T00:00:00Z", status="running", health="healthy"):
        self.timestamp = timestamp
        self.software = _StubSoftware()
        self.containers = [_Container(status=status, health=health)]

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "containers": [
                {
                    "name": c.name,
                    "image": c.image,
                    "image_id": c.image_id,
                    "image_digest": c.image_digest,
                    "status": c.status,
                    "health": c.health,
                }
                for c in self.containers
            ],
        }


class _Container:
    def __init__(self, *, status="running", health="healthy"):
        self.name = "aptl-victim"
        self.image = "img:tag"
        self.image_id = "volatile-id"
        self.image_digest = "sha256:" + "f" * 64
        self.status = status
        self.health = health


class TestSealBoundaryOwnership:
    """The canonical ready-to-seal path requires authoritative run context."""

    def test_publishing_without_an_admitted_plan_is_refused(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_RealisticSnapshot()
        )
        with pytest.raises(ProvenanceContextError):
            publish_provenance_record(
                store=store, run_id=_RUN_ID, collection=collection
            )

    def test_publishing_with_an_admitted_plan_is_allowed(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        collection = collect_run_provenance(
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_RealisticSnapshot(),
            admitted_plan=_StubPlan(),
        )
        path = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=collection
        )
        assert path.name == "run-provenance.json"

    def test_the_provisional_record_uses_a_distinct_path(self, tmp_path):
        """Startup must not occupy the canonical ready-to-seal path."""
        assert PROVISIONAL_RECORD_PATH != PROVENANCE_RECORD_PATH
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_RealisticSnapshot()
        )
        path = publish_provisional_provenance_record(
            store=store, run_id=_RUN_ID, collection=collection
        )
        assert path.name != "run-provenance.json"

    def test_the_provisional_record_does_not_claim_ready_to_seal(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        collection = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_RealisticSnapshot()
        )
        path = publish_provisional_provenance_record(
            store=store, run_id=_RUN_ID, collection=collection
        )
        assert json.loads(path.read_bytes())["seal_state"] == "provisional"

    def test_a_provisional_record_does_not_block_the_later_canonical_write(self, tmp_path):
        """The whole point: startup provenance must not foreclose the seal write."""
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        startup = collect_run_provenance(
            project_dir=tmp_path, config=AptlConfig(), snapshot=_RealisticSnapshot()
        )
        publish_provisional_provenance_record(
            store=store, run_id=_RUN_ID, collection=startup
        )
        sealed = collect_run_provenance(
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_RealisticSnapshot(),
            admitted_plan=_StubPlan(),
        )
        path = publish_provenance_record(store=store, run_id=_RUN_ID, collection=sealed)
        assert path.exists()

    def test_lab_startup_writes_only_the_provisional_artifact(self, tmp_path):
        from aptl.core.lab import _publish_run_provenance

        store = LocalRunStore(tmp_path / "runs")
        store.create_run(_RUN_ID)
        _publish_run_provenance(
            store=store,
            run_id=_RUN_ID,
            project_dir=tmp_path,
            config=AptlConfig(),
            snapshot=_RealisticSnapshot(),
        )
        run_path = store.get_run_path(_RUN_ID)
        assert (run_path / PROVISIONAL_RECORD_PATH).exists()
        assert not (run_path / PROVENANCE_RECORD_PATH).exists()


class TestStableRangeIdentity:
    """Volatile observation state must not perturb a stable identity."""

    def test_a_changed_snapshot_timestamp_does_not_change_identity(self):
        first = RuntimeFactsProvider(
            _RealisticSnapshot(timestamp="2026-01-01T00:00:00Z")
        ).collect(_context("runtime-facts"))
        second = RuntimeFactsProvider(
            _RealisticSnapshot(timestamp="2026-06-30T12:34:56Z")
        ).collect(_context("runtime-facts"))
        assert first.leaves == second.leaves

    def test_changed_container_status_and_health_do_not_change_identity(self):
        healthy = RuntimeFactsProvider(
            _RealisticSnapshot(status="running", health="healthy")
        ).collect(_context("runtime-facts"))
        degraded = RuntimeFactsProvider(
            _RealisticSnapshot(status="restarting", health="unhealthy")
        ).collect(_context("runtime-facts"))
        assert healthy.leaves == degraded.leaves

    def test_a_changed_image_digest_still_changes_identity(self):
        """The stable projection must not become blind to real apparatus change."""
        base = _RealisticSnapshot()
        changed = _RealisticSnapshot()
        changed.containers[0].image_digest = "sha256:" + "0" * 64
        assert (
            RuntimeFactsProvider(base).collect(_context("runtime-facts")).leaves
            != RuntimeFactsProvider(changed).collect(_context("runtime-facts")).leaves
        )

    def test_the_volatile_snapshot_remains_available_as_an_observation(self):
        result = RuntimeFactsProvider(_RealisticSnapshot()).collect(
            _context("runtime-facts")
        )
        assert "range_snapshot_observation" in result.payload


class TestDetectionAllowlistIsExplicit:
    """Unknown files stay unread rather than being admitted for lacking a dot."""

    def test_no_root_admits_an_unbounded_wildcard(self):
        for root in DETECTION_ROOTS:
            assert root.suffixes or root.filenames, (
                f"root {root.root_id} admits every non-dot file"
            )

    def test_an_undeclared_extensionless_file_is_not_read(self, tmp_path):
        lists = tmp_path / "config" / "wazuh_cluster" / "etc" / "lists"
        lists.mkdir(parents=True)
        (lists / "active-response-whitelist").write_text("10.0.0.1\n")
        (lists / "db-password").write_text("hunter2")

        result = DetectionContentProvider(tmp_path).collect(_context("detection-content"))
        names = {leaf.logical_id for leaf in result.leaves}
        assert any("active-response-whitelist" in name for name in names)
        assert not any("db-password" in name for name in names)

    def test_an_undeclared_secret_never_reaches_a_digest(self, tmp_path):
        """A digest of a low-entropy secret is an offline confirmation oracle."""
        import hashlib

        lists = tmp_path / "config" / "wazuh_cluster" / "etc" / "lists"
        lists.mkdir(parents=True)
        (lists / "api-token").write_bytes(b"s3cr3t")
        forbidden = hashlib.sha256(b"s3cr3t").hexdigest()

        result = DetectionContentProvider(tmp_path).collect(_context("detection-content"))
        assert forbidden not in repr(result.leaves)

    def test_the_declared_allowlist_file_is_still_covered(self, tmp_path):
        lists = tmp_path / "config" / "wazuh_cluster" / "etc" / "lists"
        lists.mkdir(parents=True)
        (lists / "active-response-whitelist").write_text("10.0.0.1\n")
        result = DetectionContentProvider(tmp_path).collect(_context("detection-content"))
        assert result.status is ProvenanceStatus.COLLECTED


class TestHostProbeIsComposedNotInherited:
    """The live ``docker info`` probe is a composition decision, not a default.

    Test-quality review found 12 provider constructions transparently spawning
    a real ``docker info`` subprocess because the live probe was the
    constructor default. Fixing the 12 call sites would have left the trap for
    the next one; the category fix moves the probe into the fleet composition.
    """

    def test_the_constructor_default_performs_no_probe(self, monkeypatch):
        import aptl.core.hostenv as hostenv

        def explode():  # pragma: no cover - must never be reached
            raise AssertionError("constructing the provider must not probe Docker")

        monkeypatch.setattr(hostenv, "docker_mode", explode)
        result = RuntimeFactsProvider(_RealisticSnapshot()).collect(
            _context("runtime-facts")
        )
        assert result.status is ProvenanceStatus.COLLECTED
        assert result.payload["host_facts"] == {}

    def test_the_production_fleet_still_wires_the_real_probe(self):
        """The category fix must not silently drop host facts from the record."""
        from aptl.core.provenance.providers.runtime_facts import default_host_facts
        from aptl.core.provenance.registrations import build_default_providers

        providers = build_default_providers(
            project_dir=".", config=AptlConfig(), snapshot=_RealisticSnapshot()
        )
        runtime = next(p for p in providers if p.provider_id == "runtime-facts")
        assert runtime._host_facts is default_host_facts

    def test_default_host_facts_still_reports_the_allowlisted_keys(self, monkeypatch):
        import aptl.core.hostenv as hostenv
        from aptl.core.provenance.providers.runtime_facts import default_host_facts

        monkeypatch.setattr(hostenv, "docker_mode", lambda: "linux-native")
        facts = default_host_facts()
        assert set(facts) == {"os", "arch", "kernel", "python", "docker_mode"}
        assert facts["docker_mode"] == "linux-native"
