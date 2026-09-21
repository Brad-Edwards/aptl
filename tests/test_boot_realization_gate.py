"""Fail-closed contracts for the installed-wheel boot realization gate (#993).

The boot job's job is to catch realization regressions the unit suite cannot
see, so the gate's own failure modes are the thing that must not rot. Every
case here is a realization defect that has, or plausibly could, reach a running
lab: content that never landed, a unit that was never enabled, a service that
died after start, a listener that never bound, a host binding that does not
match what the scenario declared, a published port nothing can reach, and a
workflow that was registered but never driven.

The gate's decision is a pure function over observed facts, so these run
without Docker. The observation side is exercised live by the boot job itself —
faking it here would only prove the fake.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from raes_contracts.workflow import (
    WorkflowExecutionState,
    WorkflowHistoryEvent,
    WorkflowHistoryEventType,
    WorkflowStatus,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "assert_boot_realization.py"


def _load_script():
    """Load the CI script as a module.

    Registered in ``sys.modules`` before execution because its frozen
    dataclasses resolve their own module while the class body runs.
    """

    spec = importlib.util.spec_from_file_location("assert_boot_realization", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_GATE = _load_script()
BootExpectation = _GATE.BootExpectation
BootObservation = _GATE.BootObservation
boot_realization_failures = _GATE.boot_realization_failures
read_workflow_run = _GATE.read_workflow_run

_EXPECTED = BootExpectation(
    node_address="provision.node.smoke-box",
    content_path="/etc/ssh/sshd_config.d/10-aptl-smoke.conf",
    content_text="Port 2022\n",
    unit_name="ssh.service",
    container_port=2022,
    protocol="tcp",
    host_ip="127.0.0.1",
    host_port=32022,
    endpoint_banner_prefix="SSH-",
    workflow_address="runtime.apply.orchestration.workflow.smoke-control",
)


def _workflow_payload(status: WorkflowStatus = WorkflowStatus.SUCCEEDED) -> dict:
    """Render a real RAES execution-state envelope, not a hand-written stub.

    The gate parses these with the contract model, so a stub that omits
    required fields would test the parser rather than the state.
    """

    return WorkflowExecutionState(
        workflow_status=status,
        run_id="run_20260101T000000Z",
        started_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:01Z",
        terminal_reason=None if status is WorkflowStatus.PENDING else "completed",
    ).to_payload()


def _history_payload() -> tuple[dict, ...]:
    return (
        WorkflowHistoryEvent(
            event_type=WorkflowHistoryEventType.WORKFLOW_COMPLETED,
            timestamp="2026-01-01T00:00:01Z",
        ).to_payload(),
    )


_ARGV = [
    "--node-address",
    _EXPECTED.node_address,
    "--content-path",
    _EXPECTED.content_path,
    "--content-text",
    _EXPECTED.content_text,
    "--unit-name",
    _EXPECTED.unit_name,
    "--container-port",
    str(_EXPECTED.container_port),
    "--protocol",
    _EXPECTED.protocol,
    "--host-ip",
    _EXPECTED.host_ip,
    "--host-port",
    str(_EXPECTED.host_port),
    "--workflow-address",
    _EXPECTED.workflow_address,
]


def _raise(error: Exception):
    def _fail(*_args, **_kwargs):
        raise error

    return _fail


def _config():
    return SimpleNamespace(
        deployment=SimpleNamespace(provider="docker-compose", project_name="lab")
    )


def _ownership(project_name: str):
    return SimpleNamespace(
        load=lambda _dir, _name: SimpleNamespace(project_name=project_name)
    )


def _observation(**overrides) -> BootObservation:
    base = dict(
        container_names=("c0ffee",),
        content="Port 2022\n",
        unit={
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "SubState": "running",
            "Result": "success",
        },
        listeners=frozenset({("tcp", 2022)}),
        bindings=frozenset({("127.0.0.1", 32022, 2022, "tcp")}),
        endpoint_reachable=True,
        endpoint_banner="SSH-2.0-OpenSSH_10.0",
        workflow=_workflow_payload(),
        workflow_history=_history_payload(),
    )
    base.update(overrides)
    return BootObservation(**base)


def test_a_fully_realized_boot_reports_no_failures():
    """The positive case must pass, or every negative below proves nothing."""

    assert boot_realization_failures(_EXPECTED, _observation()) == []


class TestContainerResolution:
    """Exactly one project-owned container may answer for the node."""

    def test_no_container_for_the_declared_node_fails(self):
        failures = boot_realization_failures(
            _EXPECTED, _observation(container_names=())
        )

        assert any("smoke-box" in failure for failure in failures)

    def test_more_than_one_matching_container_fails(self):
        """Ambiguity is a failure, not a reason to pick the first."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(container_names=("c0ffee", "decaf"))
        )

        assert any("smoke-box" in failure for failure in failures)


class TestRequiredContentExecution:
    """Content the service depends on must actually be on the node."""

    def test_absent_content_fails(self):
        failures = boot_realization_failures(_EXPECTED, _observation(content=None))

        assert any(_EXPECTED.content_path in failure for failure in failures)

    def test_content_present_but_different_fails(self):
        """Presence is not placement: the bytes are the claim."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(content="Port 22\n")
        )

        assert any(_EXPECTED.content_path in failure for failure in failures)

    def test_the_failure_does_not_echo_the_observed_content(self):
        """A content body never enters gate output (preflight: no config dumps)."""

        secret = "Port 22\nThisMustNotBePrinted 1\n"
        failures = boot_realization_failures(_EXPECTED, _observation(content=secret))

        assert failures
        assert all("ThisMustNotBePrinted" not in failure for failure in failures)


class TestServiceSetup:
    """A declared unit must be enabled, active, and not failed."""

    @pytest.mark.parametrize(
        "field,value",
        [
            ("UnitFileState", "disabled"),
            ("ActiveState", "inactive"),
            ("Result", "exit-code"),
        ],
    )
    def test_a_unit_that_is_not_enabled_active_and_successful_fails(self, field, value):
        unit = dict(_observation().unit)
        unit[field] = value

        failures = boot_realization_failures(_EXPECTED, _observation(unit=unit))

        assert any(_EXPECTED.unit_name in failure for failure in failures)

    def test_an_unreadable_unit_fails_rather_than_passing_vacuously(self):
        failures = boot_realization_failures(_EXPECTED, _observation(unit={}))

        assert any(_EXPECTED.unit_name in failure for failure in failures)


class TestListenerAndPortReadback:
    """The listener, the declared binding, and reachability must all agree."""

    def test_a_service_that_never_bound_the_declared_port_fails(self):
        failures = boot_realization_failures(
            _EXPECTED, _observation(listeners=frozenset())
        )

        assert any("2022" in failure for failure in failures)

    def test_a_listener_on_the_package_default_port_fails(self):
        """The content moved the port; binding 22 means it never took effect."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(listeners=frozenset({("tcp", 22)}))
        )

        assert any("2022" in failure for failure in failures)

    def test_the_declared_protocol_is_carried(self):
        """A bound udp/2022 does not satisfy a declared tcp/2022."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(listeners=frozenset({("udp", 2022)}))
        )

        assert any("2022" in failure for failure in failures)

    def test_a_host_binding_on_another_port_fails(self):
        failures = boot_realization_failures(
            _EXPECTED,
            _observation(bindings=frozenset({("127.0.0.1", 32023, 2022, "tcp")})),
        )

        assert any("32022" in failure for failure in failures)

    def test_a_wildcard_host_binding_fails(self):
        """ADR-034: an omitted host address binds loopback, never every interface."""

        failures = boot_realization_failures(
            _EXPECTED,
            _observation(bindings=frozenset({("0.0.0.0", 32022, 2022, "tcp")})),
        )

        assert any("32022" in failure for failure in failures)

    def test_an_additional_wildcard_binding_fails_even_when_loopback_is_present(self):
        """A correct binding does not excuse a second one exposing the host."""

        failures = boot_realization_failures(
            _EXPECTED,
            _observation(
                bindings=frozenset(
                    {
                        ("127.0.0.1", 32022, 2022, "tcp"),
                        ("0.0.0.0", 32022, 2022, "tcp"),
                    }
                )
            ),
        )

        assert failures

    def test_a_binding_to_the_wrong_container_port_fails(self):
        """The host side matching is not the publication the scenario declared.

        A host binding carries a destination. `127.0.0.1:32022 -> 22` and
        `-> 2022` are different realizations, and the other checks do not
        separate them: the listener check proves 2022 is bound somewhere in the
        namespace, and the greeting proves an SSH daemon answered — which it
        would, on 22.
        """

        failures = boot_realization_failures(
            _EXPECTED,
            _observation(bindings=frozenset({("127.0.0.1", 32022, 22, "tcp")})),
        )

        assert any("32022" in failure for failure in failures)

    def test_container_port_bindings_are_parsed_from_inspect_output(self):
        """The observation must carry the destination, not drop it.

        The shared `owned_bindings` helper answers a different question — is
        this host port occupied — and returns no container port at all, so the
        gate parses the port map itself.
        """

        ports = {
            "2022/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32022"}],
            "22/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32023"}],
        }

        assert _GATE.published_bindings(ports) == frozenset(
            {
                ("127.0.0.1", 32022, 2022, "tcp"),
                ("127.0.0.1", 32023, 22, "tcp"),
            }
        )

    def test_an_unpublished_container_port_is_not_a_binding(self):
        """An exposed-but-unpublished port has no host side to compare."""

        assert _GATE.published_bindings({"2022/tcp": None}) == frozenset()

    def test_a_wildcard_host_address_is_carried_verbatim(self):
        """`0.0.0.0` must stay visible so the binding check can reject it."""

        ports = {"2022/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32022"}]}

        assert _GATE.published_bindings(ports) == frozenset(
            {("0.0.0.0", 32022, 2022, "tcp")}
        )

    def test_a_published_port_nothing_answers_on_fails(self):
        """Inspect output is a claim; the connection is the effect."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(endpoint_reachable=False, endpoint_banner="")
        )

        assert any("32022" in failure for failure in failures)

    def test_a_connection_the_service_never_answers_fails(self):
        """Docker publishes the host port whether or not anything listens.

        With the userland proxy in front, `connect()` succeeds against a
        container port nothing is bound to, so a bare connection check passes
        on the publication alone. The declared service's own greeting is what
        proves the service answered.
        """

        failures = boot_realization_failures(
            _EXPECTED, _observation(endpoint_banner="")
        )

        assert any("32022" in failure for failure in failures)

    def test_another_service_answering_the_port_fails(self):
        """The right port answered by the wrong service is not realization."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(endpoint_banner="220 smtp ready")
        )

        assert any("32022" in failure for failure in failures)

    def test_the_failure_does_not_echo_the_observed_banner(self):
        """A greeting is remote output; it never enters gate output."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(endpoint_banner="HTTP/1.1 401 MustNotBePrinted")
        )

        assert failures
        assert all("MustNotBePrinted" not in failure for failure in failures)

    def test_a_gate_with_no_expected_greeting_accepts_the_connection(self):
        """The greeting is an optional seam, not a hardcoded SSH assumption."""

        from dataclasses import replace

        expected = replace(_EXPECTED, endpoint_banner_prefix="")

        assert (
            boot_realization_failures(expected, _observation(endpoint_banner=""))
            == []
        )


class TestOrchestrationWorkflow:
    """A registered workflow is not a driven one."""

    def test_a_missing_workflow_result_fails(self):
        failures = boot_realization_failures(_EXPECTED, _observation(workflow=None))

        assert any(_EXPECTED.workflow_address in failure for failure in failures)

    def test_a_pending_workflow_fails(self):
        """PENDING is the truthful registered state, not an outcome."""

        failures = boot_realization_failures(
            _EXPECTED,
            _observation(
                workflow=_workflow_payload(WorkflowStatus.PENDING), workflow_history=()
            ),
        )

        assert any(_EXPECTED.workflow_address in failure for failure in failures)

    def test_a_failed_workflow_fails(self):
        failures = boot_realization_failures(
            _EXPECTED, _observation(workflow=_workflow_payload(WorkflowStatus.FAILED))
        )

        assert any(_EXPECTED.workflow_address in failure for failure in failures)

    def test_a_terminal_workflow_with_no_history_fails(self):
        """A terminal state with no event stream was not walked."""

        failures = boot_realization_failures(
            _EXPECTED, _observation(workflow_history=())
        )

        assert any(_EXPECTED.workflow_address in failure for failure in failures)

    def test_an_unparsable_workflow_payload_fails_closed(self):
        failures = boot_realization_failures(
            _EXPECTED, _observation(workflow={"workflow_status": "succeeded"})
        )

        assert any(_EXPECTED.workflow_address in failure for failure in failures)


class TestRunArchiveDiscovery:
    """The run archive is discovered, but the workflow is parsed, not guessed."""

    def _write_run(self, runs: Path, run_id: str, address: str, payload: dict) -> Path:
        directory = runs / run_id / "orchestration" / address
        directory.mkdir(parents=True)
        # A run directory carries the run record at its root; the gate uses
        # that marker to tell a run from the store's own infrastructure.
        (runs / run_id / "manifest.json").write_text("{}", encoding="utf-8")
        (directory / "result.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        (directory / "history.jsonl").write_text(
            json.dumps({"event_type": "workflow_completed"}) + "\n", encoding="utf-8"
        )
        return directory

    def test_the_run_stores_own_lock_directory_is_not_a_run(self, tmp_path):
        """`runs/locks` sits beside the runs and must not read as a second one.

        A live lab archive holds it, so treating every child directory as a run
        made the gate refuse a perfectly good boot as ambiguous.
        """

        runs = tmp_path / "runs"
        self._write_run(
            runs,
            "run_20260101T000000Z",
            _EXPECTED.workflow_address,
            _workflow_payload(),
        )
        locks = runs / "locks"
        locks.mkdir()
        (locks / "run_20260101T000000Z.lock").write_text("", encoding="utf-8")

        result, history = read_workflow_run(runs, _EXPECTED.workflow_address)

        assert result == _workflow_payload()
        assert len(history) == 1

    def test_the_single_run_directory_is_read(self, tmp_path):
        runs = tmp_path / "runs"
        self._write_run(
            runs,
            "run_20260101T000000Z",
            _EXPECTED.workflow_address,
            _workflow_payload(),
        )

        result, history = read_workflow_run(runs, _EXPECTED.workflow_address)

        assert result == _workflow_payload()
        assert len(history) == 1

    def test_a_missing_run_archive_reads_as_absent_rather_than_raising(self, tmp_path):
        result, history = read_workflow_run(
            tmp_path / "runs", _EXPECTED.workflow_address
        )

        assert result is None
        assert history == ()

    def test_a_run_for_another_workflow_does_not_satisfy_this_one(self, tmp_path):
        runs = tmp_path / "runs"
        self._write_run(
            runs,
            "run_20260101T000000Z",
            "runtime.apply.orchestration.workflow.some-other",
            _workflow_payload(),
        )

        result, _history = read_workflow_run(runs, _EXPECTED.workflow_address)

        assert result is None

    def test_more_than_one_run_directory_is_ambiguous_and_fails(self, tmp_path):
        runs = tmp_path / "runs"
        for run_id in ("run_20260101T000000Z", "run_20260102T000000Z"):
            self._write_run(
                runs, run_id, _EXPECTED.workflow_address, _workflow_payload()
            )

        with pytest.raises(ValueError, match="run"):
            read_workflow_run(runs, _EXPECTED.workflow_address)

    @pytest.mark.parametrize("address", ["..", ".", ""])
    def test_a_traversing_workflow_address_is_rejected(self, tmp_path, address):
        """The address is an identity, never a path the caller can steer."""

        runs = tmp_path / "runs"
        (runs / "run_20260101T000000Z").mkdir(parents=True)

        with pytest.raises(ValueError, match="workflow address"):
            read_workflow_run(runs, address)

    def test_a_slashed_workflow_address_stays_inside_the_archive(self, tmp_path):
        """A separator in the address is flattened, exactly as the writer does."""

        runs = tmp_path / "runs"
        self._write_run(
            runs,
            "run_20260101T000000Z",
            ".._.._etc",
            _workflow_payload(),
        )

        result, _history = read_workflow_run(runs, "../../etc")

        assert result == _workflow_payload()


class TestObservationFailuresExplainThemselves:
    """A gate that cannot observe must say what stopped it.

    Reporting only the exception type turned an ambiguous run archive into
    "could not be observed: ValueError", which says nothing an operator can
    act on. These messages are the gate's own bounded text about its own
    inputs, never remote output.
    """

    def test_the_ambiguous_run_archive_message_names_the_problem(self, tmp_path):
        runs = tmp_path / "runs"
        for run_id in ("run_20260101T000000Z", "run_20260102T000000Z"):
            directory = runs / run_id
            directory.mkdir(parents=True)
            (directory / "manifest.json").write_text("{}", encoding="utf-8")

        with pytest.raises(ValueError) as caught:
            read_workflow_run(runs, _EXPECTED.workflow_address)

        assert "run" in str(caught.value)
        assert "2" in str(caught.value)

    def test_main_reports_the_reason_not_only_the_exception_type(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            _GATE, "_observe", _raise(ValueError("expected exactly one run directory"))
        )
        monkeypatch.setattr(_GATE, "find_config", lambda _path: tmp_path / "aptl.json")
        monkeypatch.setattr(_GATE, "load_config", lambda _path: _config())
        monkeypatch.setattr(
            _GATE, "WorkspaceOwnership", _ownership("aptl-test-project")
        )
        monkeypatch.setattr(_GATE, "get_backend", lambda _config, _dir: object())

        exit_code = _GATE.main(["assert_boot_realization.py", str(tmp_path), *_ARGV])

        assert exit_code == 2
        assert "expected exactly one run directory" in capsys.readouterr().err


def test_every_failure_is_reported_not_just_the_first():
    """One boot must surface every realization defect it actually has."""

    failures = boot_realization_failures(
        _EXPECTED,
        _observation(
            content=None,
            unit={"UnitFileState": "disabled"},
            listeners=frozenset(),
            bindings=frozenset(),
            endpoint_reachable=False,
            endpoint_banner="",
            workflow=None,
        ),
    )

    assert len(failures) >= 5


class TestFixtureDeclaresOnlyCorroborableState:
    """Everything the boot scenario declares must be readable back (SEM-218).

    APTL refuses to corroborate a dimension it cannot observe rather than
    approximating it, and the RAES handoff then fails the whole lab start. A
    single over-declared field — `unit_type: service` was the one that caught
    this — turns the boot gate from a five-minute pass into a five-minute
    failure with no unit-level warning. These read the shipped fixture through
    the backend's own support predicates so that regression costs seconds.
    """

    FIXTURE = ROOT / "tests" / "fixtures" / "materialization-envelope.sdl.yaml"

    def _runtime(self):
        from raes import parse_sdl_file

        return parse_sdl_file(self.FIXTURE).nodes["smoke-box"].runtime

    def test_every_declared_service_unit_is_observable(self):
        from aptl.backends.raes_runtime_guest_observation import (
            _service_unit_shape_supported,
        )

        units = self._runtime().service_manager_units

        assert units, "the fixture must still declare a service unit"
        for unit in units:
            assert _service_unit_shape_supported(unit), (
                f"{unit.unit_name} declares a dimension APTL cannot read back; "
                f"the RAES handoff will refuse the lab start"
            )

    def test_every_declared_filesystem_entry_is_observable(self):
        from aptl.backends.raes_runtime_guest_observation import (
            _filesystem_shape_supported,
        )

        for entry in self._runtime().filesystem_inventory:
            assert _filesystem_shape_supported(entry)
