"""Declared operator interactive access must actually be reachable.

TechVault declares SSH access for its red and blue operators
(`agents.*.interactive_access`). RAES carries that in the participant model, not
the provisioning plan, so the deployment never saw it: no relay started, the
nodes sit on internal networks, and host-run clients pointed at a port nothing
published (issue #1006).
"""

from __future__ import annotations

import socket
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from unittest.mock import MagicMock

import pytest

from aptl.backends.raes_operator_access import operator_access_decision
from aptl.core.deployment import _operator_access as access_mod
from aptl.core.deployment import _operator_access_proof as proof_mod
from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    WorkspaceOwnership,
)
from aptl.core.deployment._operator_access import ComposeOperatorAccessMixin
from aptl.core.deployment._operator_access_endpoints import (
    OPERATOR_ACCESS_ENDPOINTS,
    OPERATOR_ACCESS_IMAGE,
)
from aptl.core.deployment._operator_access_proof import (
    operator_access_details,
    ssh_banner_reachable,
)
from aptl.core.deployment.realization import DeploymentOperatorAccess
from aptl.core.host_ports import published_port_specs


# --------------------------------------------------------------------------- #
# admission
# --------------------------------------------------------------------------- #


@dataclass
class _Access:
    target_ref: str
    channel: str


@dataclass
class _Agent:
    interactive_access: dict = field(default_factory=dict)


@dataclass
class _Scenario:
    agents: dict = field(default_factory=dict)


def test_declared_ssh_access_to_a_known_target_is_admitted():
    scenario = _Scenario(
        agents={"red-team-operator": _Agent({"kali-ssh": _Access("kali", "ssh")})}
    )

    decision = operator_access_decision(scenario)

    assert [
        (a.agent, a.access_id, a.target_node, a.channel) for a in decision.accesses
    ] == [("red-team-operator", "kali-ssh", "kali", "ssh")]
    assert decision.unrealizable == ()


def test_access_the_backend_cannot_realize_is_refused_not_dropped():
    """An unreachable declared access is a different environment, so refuse it."""
    scenario = _Scenario(
        agents={
            "red-team-operator": _Agent({"rdp": _Access("kali", "rdp")}),
            "someone": _Agent({"ssh": _Access("mainframe", "ssh")}),
        }
    )

    decision = operator_access_decision(scenario)

    assert decision.accesses == ()
    assert {a.access_id for a in decision.unrealizable} == {"rdp", "ssh"}


def test_scenario_without_agents_declares_no_access():
    decision = operator_access_decision(_Scenario())

    assert decision.accesses == ()
    assert decision.unrealizable == ()


# --------------------------------------------------------------------------- #
# host port publication
# --------------------------------------------------------------------------- #


def test_relay_ports_go_through_the_host_port_resolver(tmp_path: Path):
    """Remapped like any published port, so a busy 2023 still reaches Kali."""
    specs = {
        spec.env_var: spec
        for spec in published_port_specs(tmp_path, {"kali", "soc"})
        if spec.service.startswith("aptl-operator-ssh-")
    }

    # mcp-red already resolves this exact variable; keep it stable.
    assert specs["APTL_HP_KALI_SSH_PROXY_2023"].default_port == 2023
    assert specs["APTL_HP_KALI_SSH_PROXY_2023"].host_ip == "127.0.0.1"
    assert specs["APTL_HP_SOC_WORKSTATION_SSH_2024"].host_ip == "127.0.0.1"


def test_inactive_profiles_publish_no_relay_ports(tmp_path: Path):
    specs = [
        spec
        for spec in published_port_specs(tmp_path, {"wazuh"})
        if spec.service.startswith("aptl-operator-ssh-")
    ]

    assert specs == []


# --------------------------------------------------------------------------- #
# realization
# --------------------------------------------------------------------------- #


class _Backend(ComposeOperatorAccessMixin):
    """A backend with a real on-disk workspace, recording docker commands.

    Ownership is real (receipts are written under a temporary workspace), so
    these tests prove relays and the access network are receipted, not merely
    labelled.
    """

    def __init__(
        self,
        workspace: Path,
        *,
        target_networks=("aptl-wabc_aptl-redteam",),
        fail_on=(),
        exec_fails=False,
    ):
        self._project_dir = workspace
        self._ownership = WorkspaceOwnership.ensure(workspace, "aptl")
        self._project_name = self._ownership.project_name
        self._resource_attempt_id = "attempt-test"
        self.exec_fails = exec_fails
        self.commands: list[list[str]] = []
        self.target_networks = target_networks
        self.fail_on = fail_on
        self._native_ids = iter(f"{n:064x}" for n in range(1, 1000))

    def _ensure_resource_ownership(self, *, attempt_id=None):
        return self._ownership

    def _ownership_daemon_id(self) -> str:
        return "test-daemon"

    def _resolve_owned_network_id(self, selector: str) -> str:
        raise OwnershipConflictError("network ownership is absent or ambiguous")

    def _resolve_owned_container_id(self, selector: str) -> str:
        raise OwnershipConflictError("container ownership is unrecorded")

    def ensure_generic_base_image(self, image_ref: str) -> list[str]:
        self.commands.append(["build", image_ref])
        return []

    def container_exec(self, name, cmd, *, timeout=None):
        self.commands.append(["exec", name, *cmd])
        return subprocess.CompletedProcess(cmd, 1 if self.exec_fails else 0, "", "")

    def container_inspect(self, name: str) -> dict:
        return {
            "Name": "/" + self._ownership.container_name(name),
            "NetworkSettings": {"Networks": {n: {} for n in self.target_networks}},
        }

    def _run(self, cmd, timeout=None):
        self.commands.append(list(cmd))
        failed = any(cmd[: len(prefix)] == list(prefix) for prefix in self.fail_on)
        creates = cmd[:3] in (["docker", "run", "-d"], ["docker", "network", "create"])
        stdout = next(self._native_ids) if creates and not failed else ""
        return subprocess.CompletedProcess(cmd, 1 if failed else 0, stdout, "")


_KALI = DeploymentOperatorAccess(
    access_id="kali-ssh", agent="red-team-operator", target_node="kali", channel="ssh"
)


def test_relay_is_published_on_loopback_with_least_privilege(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    monkeypatch.delenv("APTL_HP_KALI_SSH_PROXY_2023", raising=False)
    backend = _Backend(tmp_path)
    ownership = backend._ownership

    assert backend.activate_operator_access((_KALI,)) == []

    run = next(c for c in backend.commands if c[:3] == ["docker", "run", "-d"])
    assert "127.0.0.1:2023:2023" in run
    assert not any(part.startswith("0.0.0.0") for part in run)
    for flag in ("--read-only", "no-new-privileges:true", "ALL"):
        assert flag in run
    # Names are workspace-scoped, so concurrent labs cannot collide.
    assert run[run.index("--name") + 1] == ownership.container_name(
        "aptl-operator-ssh-kali"
    )
    # The relay targets the target's real, workspace-scoped container name.
    assert f"APTL_PROXY_TARGET_HOST={ownership.container_name('aptl-kali')}" in run
    assert f"aptl.workspace.id={ownership.workspace_id}" in run
    assert run[-1] == OPERATOR_ACCESS_IMAGE
    # Joined to the target's own network, which is how it reaches an internal node.
    assert any(
        c[:4] == ["docker", "network", "connect", "aptl-wabc_aptl-redteam"]
        for c in backend.commands
    )


def test_relay_and_access_network_are_receipt_owned(monkeypatch, tmp_path):
    """Teardown removes only receipt-owned resources, so both must be receipted."""
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path)

    assert backend.activate_operator_access((_KALI,)) == []

    ownership = backend._ownership
    [relay] = ownership.receipts("container")
    assert relay.semantic_name == "aptl-operator-ssh-kali"
    assert relay.managed_by == "direct"
    [network] = ownership.receipts("network")
    assert network.semantic_name == "aptl-operator-access"


def test_relay_honours_a_remapped_host_port(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    monkeypatch.setenv("APTL_HP_KALI_SSH_PROXY_2023", "32023")
    backend = _Backend(tmp_path)

    assert backend.activate_operator_access((_KALI,)) == []

    run = next(c for c in backend.commands if c[:3] == ["docker", "run", "-d"])
    assert "127.0.0.1:32023:2023" in run


def test_no_declared_access_starts_nothing(tmp_path):
    backend = _Backend(tmp_path)

    assert backend.activate_operator_access(()) == []
    assert backend.commands == []


def test_target_not_on_any_network_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, target_networks=())

    failures = backend.activate_operator_access((_KALI,))

    assert failures
    assert "kali is not running on a network" in failures[0]


def test_relay_that_cannot_join_its_target_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, fail_on=(("docker", "network", "connect"),))

    failures = backend.activate_operator_access((_KALI,))

    assert failures
    assert "could not join" in failures[0]


_SOC = DeploymentOperatorAccess(
    access_id="soc-workstation-ssh",
    agent="blue-team-operator",
    target_node="soc-workstation",
    channel="ssh",
)
_OPERATOR_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOperatorKeyMaterialForTests operator"
)


def test_declared_identity_without_a_delivered_key_is_authorized(monkeypatch, tmp_path):
    """Declared access with no usable credential is not access.

    TechVault declares SSH access to the SOC workstation but delivers no key for
    its `analyst` identity, so the backend installs the operator's public key
    for exactly that user.
    """
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, target_networks=("aptl_aptl-security",))

    assert (
        backend.activate_operator_access((_SOC,), operator_public_key=_OPERATOR_KEY)
        == []
    )

    [authorize] = [
        c for c in backend.commands if c[:2] == ["exec", "aptl-soc-workstation"]
    ]
    # The key is a discrete argument to a fixed script, never shell text.
    assert authorize[-1] == _OPERATOR_KEY
    assert not any(_OPERATOR_KEY in part for part in authorize[:-1])


def test_key_is_installed_with_the_target_user_privileges_not_root(
    monkeypatch, tmp_path
):
    """Root writing into a participant's home is the escalation, not the goal.

    The declared identity is a scenario participant in a deliberately
    vulnerable range, so a process running as that user is expected, and it
    owns every path the installer touches. As root each step followed the
    symlinks it controls, so it could redirect the write, the chown and the
    chmod onto a root-owned file (issue #1105). The installer therefore drops
    to that identity before touching anything.
    """
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, target_networks=("aptl_aptl-security",))

    backend.activate_operator_access((_SOC,), operator_public_key=_OPERATOR_KEY)

    [authorize] = [
        c for c in backend.commands if c[:2] == ["exec", "aptl-soc-workstation"]
    ]
    argv = authorize[2:]
    assert argv[:4] == ["runuser", "-u", "analyst", "--"]
    # Nothing left in the command runs with root's privileges.
    assert "chown" not in " ".join(argv)


def test_installer_refuses_a_redirected_authorized_keys(monkeypatch, tmp_path):
    """Failing closed beats writing a key somewhere sshd will never read."""
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, target_networks=("aptl_aptl-security",))

    backend.activate_operator_access((_SOC,), operator_public_key=_OPERATOR_KEY)

    [authorize] = [
        c for c in backend.commands if c[:2] == ["exec", "aptl-soc-workstation"]
    ]
    script = next(part for part in authorize if "authorized_keys" in part)
    for guard in ('[ -L "$dir" ]', '[ -L "$keys" ]', '[ ! -f "$keys" ]'):
        assert guard in script, guard


def test_scenario_delivered_key_is_not_overwritten(monkeypatch, tmp_path):
    """Kali's authorized key arrives with the scenario's own SSH bundle."""
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path)

    assert (
        backend.activate_operator_access((_KALI,), operator_public_key=_OPERATOR_KEY)
        == []
    )

    assert not [c for c in backend.commands if c[0] == "exec"]


def test_missing_operator_key_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, target_networks=("aptl_aptl-security",))

    failures = backend.activate_operator_access((_SOC,), operator_public_key=None)

    assert failures
    assert "no valid operator public key" in failures[0]
    assert not [c for c in backend.commands if c[:3] == ["docker", "run", "-d"]]


def test_malformed_operator_key_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(tmp_path, target_networks=("aptl_aptl-security",))

    failures = backend.activate_operator_access(
        (_SOC,), operator_public_key="ssh-ed25519 AAAA$(reboot)"
    )

    assert failures
    assert "no valid operator public key" in failures[0]


def test_authorization_that_fails_in_the_target_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(access_mod, "_prove_endpoints", lambda endpoints: [])
    backend = _Backend(
        tmp_path, target_networks=("aptl_aptl-security",), exec_fails=True
    )

    failures = backend.activate_operator_access(
        (_SOC,), operator_public_key=_OPERATOR_KEY
    )

    assert failures
    assert "could not authorize analyst" in failures[0]


def test_unreachable_endpoint_fails_the_realization(monkeypatch):
    """A relay that starts but reaches no SSH server is not realized access."""
    monkeypatch.setenv("APTL_HP_KALI_SSH_PROXY_2023", str(_free_port()))

    failures = proof_mod._prove_endpoints(
        [OPERATOR_ACCESS_ENDPOINTS["kali"]], timeout=0, interval=0
    )

    assert len(failures) == 1
    assert "did not reach an SSH server" in failures[0]


# --------------------------------------------------------------------------- #
# proof and reporting
# --------------------------------------------------------------------------- #


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _serve_once(payload: bytes) -> int:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _accept():
        conn, _ = server.accept()
        conn.sendall(payload)
        conn.close()
        server.close()

    threading.Thread(target=_accept, daemon=True).start()
    return port


def test_ssh_banner_is_what_proves_reachability():
    assert ssh_banner_reachable("127.0.0.1", _serve_once(b"SSH-2.0-OpenSSH_10.0\r\n"))


def test_a_listener_that_is_not_ssh_does_not_count():
    """An open port is not access; the far side must identify as SSH."""
    assert not ssh_banner_reachable("127.0.0.1", _serve_once(b"HTTP/1.1 200 OK\r\n"))


def test_closed_port_is_not_reachable():
    assert not ssh_banner_reachable("127.0.0.1", _free_port())


def test_admitted_access_is_reported_with_its_planned_endpoint(monkeypatch):
    monkeypatch.setenv("APTL_HP_KALI_SSH_PROXY_2023", "32023")

    [detail] = operator_access_details((_KALI,))

    assert detail["access_id"] == "kali-ssh"
    # Written before the relay exists, so it must not claim reachability.
    assert detail["state"] == "admitted"
    assert detail["planned_host_ip"] == "127.0.0.1"
    assert detail["planned_host_port"] == 32023
    assert detail["environment_visible"] is True


@pytest.mark.parametrize("target", sorted(OPERATOR_ACCESS_ENDPOINTS))
def test_every_endpoint_publishes_on_loopback_only(target):
    endpoint = OPERATOR_ACCESS_ENDPOINTS[target]
    run = access_mod._relay_run_command(
        endpoint,
        _KALI,
        external_name="relay",
        labels={},
        network="net",
        target_host="target",
        host_port=endpoint.default_port,
    )
    published = run[run.index("-p") + 1]
    assert published.startswith("127.0.0.1:")


# --------------------------------------------------------------------------- #
# lab start step
# --------------------------------------------------------------------------- #


def _lab_ctx(tmp_path: Path, *, accesses, backend):
    from types import SimpleNamespace

    from aptl.backends.raes_operator_access import OperatorAccessDecision
    from aptl.core.lab import _LabStartContext

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=True)
    ctx.backend = backend
    ctx.admitted_start = SimpleNamespace(
        target=SimpleNamespace(
            provisioner=SimpleNamespace(
                operator_access=OperatorAccessDecision(accesses=tuple(accesses))
            )
        )
    )
    return ctx


def test_step_runs_after_capture_activation():
    """Kali's access terminates at the capture broker, which serves only once active."""
    from aptl.core.lab import (
        _LAB_START_STEPS,
        _step_activate_capture_apparatus,
        _step_activate_operator_access,
        _step_test_ssh,
    )

    names = [step.__name__ for step in _LAB_START_STEPS]
    position = names.index(_step_activate_operator_access.__name__)
    assert names.index(_step_activate_capture_apparatus.__name__) < position
    assert position < names.index(_step_test_ssh.__name__)


def test_step_is_a_no_op_without_declared_access(tmp_path):
    from aptl.core.lab import _step_activate_operator_access

    backend = MagicMock()
    ctx = _lab_ctx(tmp_path, accesses=(), backend=backend)

    assert _step_activate_operator_access(ctx) is None
    backend.activate_operator_access.assert_not_called()


def test_step_fails_the_start_when_access_is_unreachable(tmp_path):
    from aptl.core.lab import _step_activate_operator_access

    backend = MagicMock()
    backend.activate_operator_access.return_value = ["kali did not answer SSH"]
    ctx = _lab_ctx(tmp_path, accesses=(_KALI,), backend=backend)

    result = _step_activate_operator_access(ctx)

    assert result is not None
    assert result.success is False
    assert "aptl.operator-access.unreachable" in result.error
    backend.activate_operator_access.assert_called_once()
    assert backend.activate_operator_access.call_args.args[0] == (_KALI,)


def test_step_succeeds_when_every_access_is_proven(tmp_path):
    from aptl.core.lab import _step_activate_operator_access

    backend = MagicMock()
    backend.activate_operator_access.return_value = []
    ctx = _lab_ctx(tmp_path, accesses=(_KALI,), backend=backend)

    assert _step_activate_operator_access(ctx) is None


def test_proof_failure_is_what_activation_returns(monkeypatch, tmp_path):
    """Access is proven, not assumed: a failed proof must fail activation.

    Every other activation test stubs the proof to succeed, so deleting the
    proof call or discarding its result would pass them all.
    """
    seen: list[str] = []

    def failing_proof(endpoints):
        seen.extend(endpoint.relay_container for endpoint in endpoints)
        return ["kali relay reached no SSH server"]

    monkeypatch.setattr(access_mod, "_prove_endpoints", failing_proof)
    backend = _Backend(tmp_path, target_networks=("aptl-wabc_aptl-redteam",))

    failures = backend.activate_operator_access(
        (_KALI, _SOC), operator_public_key=_OPERATOR_KEY
    )

    assert failures == ["kali relay reached no SSH server"]
    assert seen == ["aptl-operator-ssh-kali", "aptl-operator-ssh-soc-workstation"]


def test_real_proof_runs_when_nothing_answers(monkeypatch, tmp_path):
    """With the real proof in place, an endpoint nothing serves fails activation."""
    monkeypatch.setenv("APTL_HP_KALI_SSH_PROXY_2023", str(_free_port()))
    monkeypatch.setattr(proof_mod, "_READY_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(proof_mod, "_READY_INTERVAL_SECONDS", 0)
    backend = _Backend(tmp_path)

    failures = backend.activate_operator_access((_KALI,))

    assert len(failures) == 1
    assert "did not reach an SSH server" in failures[0]
