"""Fail-closed tests for provider-observed runtime realization concerns (#876).

These pin the backend half of raes 3.1.0's runtime non-approximation gate: APTL
reads each declared per-node runtime concern back off the realized container and
discloses the observed value at its payload path, so RAES's own
``realization_disclosure`` gate can compare declared-vs-observed. A concern APTL
cannot be seen to have realized is disclosed as an omission (a rejected EXACT
declaration), never an echo of the plan, and a realized secret value is
disclosed as a commitment, never raw.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from raes.explicitness import ExplicitnessClass, ExplicitnessProvenance
from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)
from raes_contracts.runtime_state import RuntimeSnapshot
from raes_processor.semantics.realization import (
    CONCERN_PAYLOAD_PATH,
    REALIZATION_DOMAIN,
    CompiledRealizationRequirement,
    realization_disclosure,
)

from raes_contracts.apparatus import RealizationVerificationScope

from aptl.backends.raes_diagnostics import snapshot_after_apply
from aptl.backends.raes_manifest import create_aptl_manifest
from aptl.backends.raes_observation import observe_realization
from aptl.backends.raes_realization_model import AptlRealization, NodeRealization
from aptl.core.deployment.errors import BackendTimeoutError

_ADDRESS = "provision.node.vm"
_CONTAINER = "aptl-vm"
_GATE_REJECT = "runtime.backend-contract-invalid"


class _Backend:
    """A deployment backend whose realized container inventory the test controls."""

    project_name = "aptl"

    def __init__(
        self,
        inspect,
        *,
        exec_results=None,
        exec_raises=False,
        exists=True,
        listeners=None,
        listeners_raise=False,
    ):
        self._inspect = inspect
        self._exec_results = exec_results or {}
        self._exec_raises = exec_raises
        self._exists = exists
        self._listeners = listeners or {}
        self._listeners_raise = listeners_raise

    def container_exists(self, name):
        return self._exists and name in self._inspect

    def container_inspect(self, name):
        return self._inspect.get(name, {})

    def container_exec(self, name, cmd, *, timeout=None):
        if self._exec_raises:
            raise BackendTimeoutError("docker exec timed out")
        table = self._exec_results.get(name, {})
        returncode, stdout = table.get(cmd[0], (1, ""))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    def observe_container_listeners(self, name):
        if self._listeners_raise:
            raise BackendTimeoutError("listener sidecar timed out")
        return self._listeners.get(name)

    def host_list_lab_networks(self, name_prefix):
        return []


def _inspect(*, env=(), ports=None, cap_add=(), cap_drop=(), mounts=()):
    """Build a realized-container ``docker inspect`` dict."""

    return {
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Platform": "linux",
        "NetworkSettings": {"Networks": {}},
        "Config": {"Env": list(env)},
        "HostConfig": {
            "PortBindings": ports or {},
            "CapAdd": list(cap_add),
            "CapDrop": list(cap_drop),
        },
        "Mounts": list(mounts),
    }


def _runtime(**kwargs) -> RuntimeConfiguration:
    return RuntimeConfiguration.model_validate(kwargs)


def _node_realization(runtime: RuntimeConfiguration) -> NodeRealization:
    return NodeRealization(
        address=_ADDRESS,
        name="vm",
        aliases=(),
        profiles=(),
        backend_services=("vm",),
        container_name=_CONTAINER,
        services=(),
        networks=(),
        static_addresses=(),
        runtime=runtime,
    )


def _plan(runtime: RuntimeConfiguration) -> ProvisioningPlan:
    payload = {
        "name": "vm",
        "node_type": "vm",
        "os_family": "linux",
        "spec": {"node": {"runtime": runtime.model_dump(mode="json", by_alias=True)}},
    }
    resource = PlannedResource(
        address=_ADDRESS,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload=payload,
    )
    op = ProvisionOp(
        action=ChangeAction.CREATE,
        address=_ADDRESS,
        resource_type="node",
        payload=payload,
    )
    return ProvisioningPlan(resources={_ADDRESS: resource}, operations=[op])


def _observe(runtime: RuntimeConfiguration, backend: _Backend):
    plan = _plan(runtime)
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(runtime),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    return plan, observe_realization(backend, realization, plan, Path("."))


def _gate(runtime: RuntimeConfiguration, backend: _Backend, kind: str):
    """Drive RAES's own disclosure gate end-to-end for one EXACT concern."""

    plan, observations = _observe(runtime, backend)
    snapshot = snapshot_after_apply(plan, RuntimeSnapshot(), observations)
    requirement = CompiledRealizationRequirement(
        field_path=f"nodes.vm.runtime.{kind}",
        address=_ADDRESS,
        domain=REALIZATION_DOMAIN,
        requirement_kind=kind,
        explicitness=ExplicitnessClass.EXACT,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
    )
    diagnostics, provenance = realization_disclosure((requirement,), plan, snapshot)
    return [d.code for d in diagnostics], provenance, observations


# --------------------------------------------------------------------------- #
# runtime-environment
# --------------------------------------------------------------------------- #

_ENV_PATH = CONCERN_PAYLOAD_PATH["runtime-environment"]


def _env_runtime(value="bar", classification="plain"):
    return _runtime(
        environment=[
            {
                "name": "FOO",
                "value": value,
                "value_classification": classification,
                "provenance": "compose",
                "source": "x",
            }
        ]
    )


def test_environment_realized_and_matched_is_disclosed_and_passes():
    runtime = _env_runtime("bar")
    backend = _Backend({_CONTAINER: _inspect(env=["FOO=bar", "PATH=/usr/bin"])})
    codes, provenance, observations = _gate(runtime, backend, "runtime-environment")
    assert codes == []
    assert _ENV_PATH in observations[_ADDRESS].concerns
    assert [p.provenance for p in provenance] == [ExplicitnessProvenance.AUTHOR_DECLARED]


def test_environment_realized_differently_is_rejected():
    runtime = _env_runtime("bar")
    backend = _Backend({_CONTAINER: _inspect(env=["FOO=WRONG"])})
    codes, _provenance, _observations = _gate(runtime, backend, "runtime-environment")
    assert _GATE_REJECT in codes


def test_environment_absent_variable_is_omitted_and_rejected():
    runtime = _env_runtime("bar")
    backend = _Backend({_CONTAINER: _inspect(env=["PATH=/usr/bin"])})
    codes, _provenance, observations = _gate(runtime, backend, "runtime-environment")
    assert _ENV_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_environment_secret_fixture_discloses_commitment_not_raw_value():
    runtime = _env_runtime("planted", classification="secret_fixture")
    backend = _Backend({_CONTAINER: _inspect(env=["FOO=planted"])})
    codes, _provenance, observations = _gate(runtime, backend, "runtime-environment")
    assert codes == []
    disclosed = observations[_ADDRESS].concerns[_ENV_PATH]
    assert "planted" not in str(disclosed)
    assert disclosed[0]["value_commitment"].startswith("raes-runtime-value-jcs-sha256-v1:")
    assert "value" not in disclosed[0]


def test_environment_operator_secret_is_presence_only():
    runtime = _runtime(
        environment=[
            {
                "name": "OP",
                "value": "",
                "value_classification": "operator_secret",
                "provenance": "operator",
                "source": "env",
            }
        ]
    )
    # The operator boundary supplies a real value at runtime; APTL must never
    # read or disclose it, only that the variable is present.
    backend = _Backend({_CONTAINER: _inspect(env=["OP=super-secret-value"])})
    codes, _provenance, observations = _gate(runtime, backend, "runtime-environment")
    assert codes == []
    disclosed = observations[_ADDRESS].concerns[_ENV_PATH]
    assert "super-secret-value" not in str(disclosed)
    assert disclosed[0]["value_present"] is True
    assert "value_commitment" not in disclosed[0]


def test_environment_undeclared_operator_value_is_rejected():
    # The contract declares the variable with no value, so "realized" means
    # realized empty. A value arriving out of band -- an operator `.env` entry
    # the scenario never authored -- is undeclared range content, and the gate
    # must reject it rather than treat the declaration as a wildcard.
    runtime = _env_runtime("", classification="plain")
    backend = _Backend({_CONTAINER: _inspect(env=["FOO=false"])})
    codes, _provenance, _observations = _gate(runtime, backend, "runtime-environment")
    assert _GATE_REJECT in codes


def test_environment_declared_valueless_realized_empty_passes():
    # The same declaration realized as the contract states it -- present and
    # empty -- is the honest match, so nothing is rejected.
    runtime = _env_runtime("", classification="plain")
    backend = _Backend({_CONTAINER: _inspect(env=["FOO="])})
    codes, _provenance, observations = _gate(runtime, backend, "runtime-environment")
    assert codes == []
    assert observations[_ADDRESS].concerns[_ENV_PATH][0]["value_present"] is False


def test_environment_probe_missing_config_fails_closed():
    runtime = _env_runtime("bar")
    inspect = _inspect(env=["FOO=bar"])
    del inspect["Config"]
    backend = _Backend({_CONTAINER: inspect})
    codes, _provenance, observations = _gate(runtime, backend, "runtime-environment")
    assert _ENV_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


# --------------------------------------------------------------------------- #
# published-ports
# --------------------------------------------------------------------------- #

_PORTS_PATH = CONCERN_PAYLOAD_PATH["published-ports"]


def _ports_runtime(host_ip="127.0.0.1", host_port=8080):
    return _runtime(
        network={
            "published_ports": [
                {
                    "container_port": 8080,
                    "protocol": "tcp",
                    "host_ip": host_ip,
                    "host_port": host_port,
                }
            ]
        }
    )


def test_published_port_realized_and_matched_passes():
    runtime = _ports_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect(ports={"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]})}
    )
    codes, _provenance, observations = _gate(runtime, backend, "published-ports")
    assert codes == []
    assert _PORTS_PATH in observations[_ADDRESS].concerns


def test_published_port_omitted_host_ip_corroborated_on_loopback():
    # An author who omits host_ip is realized on loopback (ADR-034); the observer
    # expects the loopback binding, not the raw declared empty string.
    runtime = _ports_runtime(host_ip="")
    backend = _Backend(
        {_CONTAINER: _inspect(ports={"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]})}
    )
    codes, _provenance, _observations = _gate(runtime, backend, "published-ports")
    assert codes == []


def test_published_port_not_bound_is_omitted_and_rejected():
    runtime = _ports_runtime()
    backend = _Backend({_CONTAINER: _inspect(ports={})})
    codes, _provenance, observations = _gate(runtime, backend, "published-ports")
    assert _PORTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_published_port_different_host_port_is_rejected():
    runtime = _ports_runtime(host_port=8080)
    backend = _Backend(
        {_CONTAINER: _inspect(ports={"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "9999"}]})}
    )
    codes, _provenance, _observations = _gate(runtime, backend, "published-ports")
    assert _GATE_REJECT in codes


def test_published_port_wildcard_bind_does_not_satisfy_loopback_declaration():
    # A container bound to all interfaces (empty HostIp is Docker's 0.0.0.0
    # default) is broader than the declared loopback; corroborating it would
    # disclose the narrower authored address and let the EXACT gate pass an
    # over-exposed port (issue #876 security review).
    runtime = _ports_runtime(host_ip="127.0.0.1")
    backend = _Backend(
        {_CONTAINER: _inspect(ports={"8080/tcp": [{"HostIp": "", "HostPort": "8080"}]})}
    )
    codes, _provenance, observations = _gate(runtime, backend, "published-ports")
    assert _PORTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_published_port_explicit_wildcard_bind_does_not_satisfy_loopback_declaration():
    runtime = _ports_runtime(host_ip="127.0.0.1")
    backend = _Backend(
        {_CONTAINER: _inspect(ports={"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]})}
    )
    codes, _provenance, _observations = _gate(runtime, backend, "published-ports")
    assert _GATE_REJECT in codes


def test_undeclared_published_port_is_rejected():
    # Cycle-7 review: the concrete lingering-port case. A reused container keeps
    # port 9000 the current contract no longer declares; the observer must refuse
    # rather than emit only declared 8080 and report the node ready while 9000
    # stays reachable.
    runtime = _ports_runtime()  # declares only 8080
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                ports={
                    "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}],
                    "9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9000"}],
                }
            )
        }
    )
    codes, _provenance, observations = _gate(runtime, backend, "published-ports")
    assert _PORTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_wildcard_declared_port_realized_only_on_loopback_is_rejected():
    # The other direction: a port declared on all interfaces but realized only on
    # loopback is under-exposed and must not be echoed back as an exact match.
    runtime = _ports_runtime(host_ip="0.0.0.0")
    backend = _Backend(
        {_CONTAINER: _inspect(ports={"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]})}
    )
    codes, _provenance, observations = _gate(runtime, backend, "published-ports")
    assert _PORTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


# --------------------------------------------------------------------------- #
# linux-capabilities
# --------------------------------------------------------------------------- #

_CAPS_PATH = CONCERN_PAYLOAD_PATH["linux-capabilities"]


def _systemd_units():
    return [{"unit_id": "svc", "unit_name": "svc.service", "active_state": "active"}]


def test_capabilities_realized_among_init_grants_still_matches():
    # A systemd node legitimately gets APTL's init capabilities beyond the
    # declared one; the observer allows exactly that fixed init baseline plus the
    # declared set and discloses the declared policy.
    runtime = _runtime(
        linux_capabilities={"add": ["CAP_NET_ADMIN"]},
        service_manager_units=_systemd_units(),
    )
    backend = _Backend(
        {_CONTAINER: _inspect(cap_add=["NET_ADMIN", "SYS_ADMIN", "SYS_NICE"])}
    )
    codes, _provenance, observations = _gate(runtime, backend, "linux-capabilities")
    assert codes == []
    assert _CAPS_PATH in observations[_ADDRESS].concerns


def test_capability_beyond_declared_and_init_baseline_is_rejected():
    # Cycle-7 review: a capability the container grants that is neither declared
    # nor part of APTL's init baseline is excess privilege. A non-systemd node
    # gets no init baseline, so an undeclared SYS_ADMIN must fail closed rather
    # than pass behind the echoed declared policy.
    runtime = _runtime(linux_capabilities={"add": ["CAP_NET_ADMIN"]})
    backend = _Backend(
        {_CONTAINER: _inspect(cap_add=["NET_ADMIN", "SYS_ADMIN"])}
    )
    codes, _provenance, observations = _gate(runtime, backend, "linux-capabilities")
    assert _CAPS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_capabilities_not_granted_is_omitted_and_rejected():
    runtime = _runtime(linux_capabilities={"add": ["CAP_NET_ADMIN"]})
    backend = _Backend({_CONTAINER: _inspect(cap_add=["SYS_ADMIN"])})
    codes, _provenance, observations = _gate(runtime, backend, "linux-capabilities")
    assert _CAPS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_capabilities_process_runtime_facts_are_not_corroborable():
    # `effective` is a process-runtime fact APTL does not realize through docker
    # capability flags; a policy asserting it is not corroborable and is dropped.
    runtime = _runtime(
        linux_capabilities={"add": ["CAP_NET_ADMIN"], "effective": ["CAP_NET_ADMIN"]}
    )
    backend = _Backend({_CONTAINER: _inspect(cap_add=["NET_ADMIN"])})
    codes, _provenance, observations = _gate(runtime, backend, "linux-capabilities")
    assert _CAPS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_capabilities_declared_drop_that_is_actually_granted_is_rejected():
    # The container reports CAP_SYS_ADMIN in both CapAdd and CapDrop; an authored
    # policy that drops it must not be certified while it is still granted, or a
    # workload could retain the capability behind an echoed drop (security).
    runtime = _runtime(linux_capabilities={"drop": ["CAP_SYS_ADMIN"]})
    backend = _Backend(
        {_CONTAINER: _inspect(cap_add=["SYS_ADMIN"], cap_drop=["SYS_ADMIN"])}
    )
    codes, _provenance, observations = _gate(runtime, backend, "linux-capabilities")
    assert _CAPS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


# --------------------------------------------------------------------------- #
# runtime-mounts (bind/tmpfs only)
# --------------------------------------------------------------------------- #

_MOUNTS_PATH = CONCERN_PAYLOAD_PATH["runtime-mounts"]


def _bind_mount_runtime(read_only=True):
    return _runtime(
        mounts=[
            {
                "target": "/data",
                "source": "/host/data",
                "source_kind": "bind",
                "read_only": read_only,
            }
        ]
    )


def test_bind_mount_realized_and_matched_passes():
    runtime = _bind_mount_runtime()
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                mounts=[
                    {
                        "Type": "bind",
                        "Source": "/host/data",
                        "Destination": "/data",
                        "RW": False,
                    }
                ]
            )
        }
    )
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert codes == []
    assert _MOUNTS_PATH in observations[_ADDRESS].concerns


def test_bind_mount_absent_is_omitted_and_rejected():
    runtime = _bind_mount_runtime()
    backend = _Backend({_CONTAINER: _inspect(mounts=[])})
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert _MOUNTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_bind_mount_wrong_source_is_rejected():
    runtime = _bind_mount_runtime()
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                mounts=[
                    {
                        "Type": "bind",
                        "Source": "/host/elsewhere",
                        "Destination": "/data",
                        "RW": False,
                    }
                ]
            )
        }
    )
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert _MOUNTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_undeclared_bind_mount_is_rejected():
    # Cycle-7 review: a bind mount the container carries that the contract does
    # not declare is excess host access and must fail closed.
    runtime = _bind_mount_runtime()  # declares only /data
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                mounts=[
                    {"Type": "bind", "Source": "/host/data", "Destination": "/data", "RW": False},
                    {"Type": "bind", "Source": "/host/secret", "Destination": "/secret", "RW": True},
                ]
            )
        }
    )
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert _MOUNTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_systemd_cgroup_bind_is_a_known_baseline_not_excess():
    # A systemd node's init adds the /sys/fs/cgroup bind; it is the one baseline
    # mount docker inspect reports, so it must not count as undeclared excess.
    runtime = _runtime(
        mounts=[{"target": "/data", "source": "/host/data", "source_kind": "bind", "read_only": True}],
        service_manager_units=_systemd_units(),
    )
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                mounts=[
                    {"Type": "bind", "Source": "/host/data", "Destination": "/data", "RW": False},
                    {"Type": "bind", "Source": "/sys/fs/cgroup", "Destination": "/sys/fs/cgroup", "RW": True},
                ]
            )
        }
    )
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert codes == []
    assert _MOUNTS_PATH in observations[_ADDRESS].concerns


def _tmpfs_mount_runtime(read_only=True):
    return _runtime(
        mounts=[
            {
                "target": "/scratch",
                "source_kind": "tmpfs",
                "read_only": read_only,
            }
        ]
    )


def test_tmpfs_mount_realized_and_matched_passes():
    runtime = _tmpfs_mount_runtime(read_only=True)
    backend = _Backend(
        {_CONTAINER: _inspect(mounts=[{"Type": "tmpfs", "Destination": "/scratch", "RW": False}])}
    )
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert codes == []
    assert _MOUNTS_PATH in observations[_ADDRESS].concerns


def test_tmpfs_mount_wrong_read_only_state_is_rejected():
    # A tmpfs mount realized read-write against a read-only declaration is a
    # material mismatch; the RW comparison must apply to tmpfs, not just bind
    # (issue #876 core review).
    runtime = _tmpfs_mount_runtime(read_only=True)
    backend = _Backend(
        {_CONTAINER: _inspect(mounts=[{"Type": "tmpfs", "Destination": "/scratch", "RW": True}])}
    )
    codes, _provenance, observations = _gate(runtime, backend, "runtime-mounts")
    assert _MOUNTS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


# --------------------------------------------------------------------------- #
# service-listeners
# --------------------------------------------------------------------------- #

_LISTENERS_PATH = CONCERN_PAYLOAD_PATH["service-listeners"]


def _listeners(sockets=(), unix_socket_paths=()):
    """Build the trusted-observation result the backend returns for a container."""

    from aptl.core.deployment._proc_net_listeners import ContainerListeners

    return {
        _CONTAINER: ContainerListeners(
            sockets=tuple(sockets), unix_socket_paths=frozenset(unix_socket_paths)
        )
    }


def _listener_runtime():
    return _runtime(
        service_listeners=[
            {
                "service_listener_id": "svc_http",
                "service": "http",
                "address": "0.0.0.0",
                "port": 8080,
                "protocol": "tcp",
                "scope": "wildcard",
            }
        ]
    )


def test_service_listener_realized_and_matched_passes():
    runtime = _listener_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(sockets=[("tcp", "0.0.0.0", 8080)]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert codes == []
    assert _LISTENERS_PATH in observations[_ADDRESS].concerns


def test_service_listener_not_listening_is_omitted_and_rejected():
    runtime = _listener_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(sockets=[("tcp", "0.0.0.0", 22)]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_service_listener_probe_timeout_fails_closed():
    runtime = _listener_runtime()
    backend = _Backend({_CONTAINER: _inspect()}, listeners_raise=True)
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_service_listener_unreadable_observation_fails_closed():
    # A refused disclosure (None) is not an assumed match: the gate rejects.
    runtime = _listener_runtime()
    backend = _Backend({_CONTAINER: _inspect()})  # no listeners configured -> None
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def _loopback_listener_runtime():
    return _runtime(
        service_listeners=[
            {
                "service_listener_id": "svc_http",
                "service": "http",
                "address": "127.0.0.1",
                "port": 8080,
                "protocol": "tcp",
                "scope": "loopback_only",
            }
        ]
    )


def test_service_listener_wildcard_socket_does_not_satisfy_loopback_declaration():
    # A service listening on 0.0.0.0 is reachable beyond a declared 127.0.0.1
    # boundary; an observed wildcard socket must not corroborate a concrete
    # declaration (issue #876 security review).
    runtime = _loopback_listener_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(sockets=[("tcp", "0.0.0.0", 8080)]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_service_listener_concrete_socket_matches_loopback_declaration():
    runtime = _loopback_listener_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(sockets=[("tcp", "127.0.0.1", 8080)]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert codes == []
    assert _LISTENERS_PATH in observations[_ADDRESS].concerns


def _unix_listener_runtime():
    return _runtime(
        service_listeners=[
            {
                "service_listener_id": "svc_sock",
                "service": "app",
                "protocol": "unix",
                "socket_path": "/run/app.sock",
            }
        ]
    )


def test_unix_listener_present_socket_is_disclosed_and_passes():
    runtime = _unix_listener_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(unix_socket_paths=["/run/app.sock"]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert codes == []
    assert _LISTENERS_PATH in observations[_ADDRESS].concerns


def test_unix_listener_absent_socket_is_omitted_and_rejected():
    runtime = _unix_listener_runtime()
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(unix_socket_paths=["/run/other.sock"]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_undeclared_network_listener_is_rejected():
    # Cycle-7 review: a workload that opens a tcp/udp port the contract does not
    # declare is excess exposure and must fail closed, not be omitted from
    # attestation while the port stays reachable.
    runtime = _listener_runtime()  # declares only tcp 8080
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(
            sockets=[("tcp", "0.0.0.0", 8080), ("tcp", "0.0.0.0", 9000)]
        ),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_wildcard_declared_listener_realized_on_loopback_is_rejected():
    # A listener declared on all interfaces but realized only on loopback is
    # under-exposed and must not corroborate the authored wildcard.
    runtime = _listener_runtime()  # declares tcp 0.0.0.0:8080
    backend = _Backend(
        {_CONTAINER: _inspect()},
        listeners=_listeners(sockets=[("tcp", "127.0.0.1", 8080)]),
    )
    codes, _provenance, observations = _gate(runtime, backend, "service-listeners")
    assert _LISTENERS_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_symbolic_listener_address_fails_closed():
    # Cycle-7 review: an unresolved symbolic ($VAR) address cannot be scope
    # checked, so any observed socket on the port must NOT corroborate it -- a
    # workload could otherwise bind all interfaces behind the symbolic address.
    # RAES's typed model rejects a `$` address, so this is a defensive guard
    # exercised at the function boundary rather than through a validated runtime.
    from aptl.backends.raes_runtime_observation import _listener_present
    from aptl.core.deployment._proc_net_listeners import ContainerListeners

    listener = SimpleNamespace(
        protocol="tcp", port=8080, address="$PUBLIC_IP", socket_path=""
    )
    observed = ContainerListeners(
        sockets=(("tcp", "0.0.0.0", 8080),), unix_socket_paths=frozenset()
    )
    assert _listener_present(listener, observed) is False


def test_init_capability_baseline_matches_the_substrate_init_requirements():
    # Drift guard: the capability baseline the observer subtracts must equal the
    # capabilities APTL's own systemd init actually grants (raes_base_substrate).
    from aptl.backends.raes_base_substrate import InitRequirements
    from aptl.backends.raes_runtime_observation import (
        _INIT_CAPABILITY_BASELINE,
        _normalized_capabilities,
    )

    assert _INIT_CAPABILITY_BASELINE == _normalized_capabilities(
        InitRequirements().capabilities
    )


# --------------------------------------------------------------------------- #
# forwarding-agents: corroborated against the realized mount footprint (#875)
# --------------------------------------------------------------------------- #

_FORWARDING_PATH = CONCERN_PAYLOAD_PATH["forwarding-agents"]


def _log_forwarder_runtime():
    """A log forwarder whose tailed source lives under a declared volume mount."""

    return _runtime(
        mounts=[
            {"target": "/logs", "source": "db_data", "source_kind": "volume", "read_only": True}
        ],
        forwarding_agents=[
            {
                "forwarding_agent_id": "db-postgres-forwarder",
                "implementation": "wazuh_agent",
                "agent_kind": "log_forwarder",
                "sources": [
                    {
                        "source_id": "postgres-log",
                        "kind": "tailed_path",
                        "location": "/logs/pg_log/postgresql.log",
                        "parse_format": "syslog",
                    }
                ],
                "ship_targets": [
                    {
                        "target_id": "manager",
                        "target_node_ref": "wazuh-manager",
                        "ingestion_port": 1514,
                        "enrollment_port": 1515,
                        "protocol": "tcp",
                        "enrollment_identity_classification": "operator_secret",
                    }
                ],
                "buffer_policy": {
                    "buffer_policy_id": "db-postgres-forwarder-buffer",
                    "crypto": "aes",
                },
            }
        ],
    )


def _content_sync_runtime():
    """A content sync whose unix-socket reload channel is served by a volume mount."""

    return _runtime(
        mounts=[
            {
                "target": "/var/run/suricata",
                "source": "suricata_command_socket",
                "source_kind": "volume",
                "read_only": False,
            }
        ],
        forwarding_agents=[
            {
                "forwarding_agent_id": "misp-ioc-to-suricata",
                "implementation": "misp_suricata_sync",
                "agent_kind": "content_sync",
                "sources": [
                    {
                        "source_id": "misp-attributes",
                        "kind": "api_pull",
                        "location": "https://misp",
                        "parse_format": "misp_json",
                        "selector": "aptl:enforce",
                    }
                ],
                "transforms": [
                    {
                        "transform_id": "ioc-to-suricata-rules",
                        "kind": "ioc_to_rule",
                        "sid_namespace": "3000000",
                    }
                ],
                "reload_channels": [
                    {
                        "reload_channel_id": "suricata-command-socket",
                        "target_ref": "suricata",
                        "kind": "unix_socket",
                    }
                ],
            }
        ],
    )


def _forwarding_gate(runtime: RuntimeConfiguration, backend: _Backend):
    """Drive the disclosure gate for the configuration-scope forwarding concern.

    forwarding-agents is the one concern raes compiles with a non-null
    verification scope, so the gate needs both the manifest (which declares the
    corroboration APTL performs) and an EXACT requirement carrying the
    ``configuration`` scope.
    """

    plan, observations = _observe(runtime, backend)
    snapshot = snapshot_after_apply(plan, RuntimeSnapshot(), observations)
    requirement = CompiledRealizationRequirement(
        field_path="nodes.vm.runtime.forwarding_agents",
        address=_ADDRESS,
        domain=REALIZATION_DOMAIN,
        requirement_kind="forwarding-agents",
        explicitness=ExplicitnessClass.EXACT,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        verification_scope=RealizationVerificationScope.CONFIGURATION,
    )
    diagnostics, _provenance = realization_disclosure(
        (requirement,), plan, snapshot, manifest=create_aptl_manifest()
    )
    return [d.code for d in diagnostics], snapshot, observations


def test_log_forwarder_with_realized_source_mount_is_corroborated():
    runtime = _log_forwarder_runtime()
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                mounts=[{"Type": "volume", "Source": "db_data", "Destination": "/logs", "RW": False}]
            )
        }
    )
    codes, snapshot, observations = _forwarding_gate(runtime, backend)
    assert codes == []
    assert _FORWARDING_PATH in observations[_ADDRESS].concerns
    disclosures = [
        d for d in snapshot.realization_observations if d.requirement_kind == "forwarding-agents"
    ]
    assert disclosures and disclosures[0].verification_scope is (
        RealizationVerificationScope.CONFIGURATION
    )


def test_content_sync_reload_socket_mount_is_corroborated():
    runtime = _content_sync_runtime()
    backend = _Backend(
        {
            _CONTAINER: _inspect(
                mounts=[
                    {
                        "Type": "volume",
                        "Source": "suricata_command_socket",
                        "Destination": "/var/run/suricata",
                        "RW": True,
                    }
                ]
            )
        }
    )
    codes, _snapshot, observations = _forwarding_gate(runtime, backend)
    assert codes == []
    assert _FORWARDING_PATH in observations[_ADDRESS].concerns


def test_forwarding_agent_without_realized_footprint_is_dropped_and_rejected():
    # The declared tailed source has no covering mount on the realized container,
    # so the agent is not corroborated: the concern is dropped and the EXACT
    # requirement is rejected rather than handed a fabricated match.
    runtime = _log_forwarder_runtime()
    backend = _Backend({_CONTAINER: _inspect(mounts=[])})
    codes, _snapshot, observations = _forwarding_gate(runtime, backend)
    assert _FORWARDING_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_log_forwarder_on_node_declaring_no_mounts_is_dropped_and_rejected():
    # A sidecar that declares a tailed source but no mount to carry it cannot
    # reach that path: nothing in the contract delivers the file and nothing in
    # the container corroborates it. The concern is dropped and the requirement
    # rejected, so an agent tailing a path that does not exist is never reported
    # as realized SIEM coverage.
    runtime = _runtime(
        forwarding_agents=_log_forwarder_runtime().model_dump(mode="json")["forwarding_agents"]
    )
    assert not runtime.mounts
    backend = _Backend({_CONTAINER: _inspect(mounts=[])})
    codes, _snapshot, observations = _forwarding_gate(runtime, backend)
    assert _FORWARDING_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


def test_forwarding_agent_without_observable_footprint_is_dropped():
    # A configuration-scope agent whose only source is a network pull with no
    # unix-socket reload channel declares no host-observable mount footprint, so
    # it cannot be corroborated: honest absence, rejected not fabricated.
    runtime = _runtime(
        forwarding_agents=[
            {
                "forwarding_agent_id": "misp-ioc-to-suricata",
                "implementation": "misp_suricata_sync",
                "agent_kind": "content_sync",
                "sources": [
                    {
                        "source_id": "misp-attributes",
                        "kind": "api_pull",
                        "location": "https://misp",
                        "parse_format": "misp_json",
                        "selector": "aptl:enforce",
                    }
                ],
                "transforms": [
                    {
                        "transform_id": "ioc-to-suricata-rules",
                        "kind": "ioc_to_rule",
                        "sid_namespace": "3000000",
                    }
                ],
                "reload_channels": [
                    {
                        "reload_channel_id": "suricata-command-socket",
                        "target_ref": "suricata",
                        "kind": "unix_socket",
                    }
                ],
            }
        ]
    )
    # No suricata_command_socket mount is realized, so the reload channel's
    # serving volume is absent from the container.
    backend = _Backend({_CONTAINER: _inspect(mounts=[])})
    codes, _snapshot, observations = _forwarding_gate(runtime, backend)
    assert _FORWARDING_PATH not in observations[_ADDRESS].concerns
    assert _GATE_REJECT in codes


# --------------------------------------------------------------------------- #
# node without runtime concerns is untouched
# --------------------------------------------------------------------------- #


def test_node_without_runtime_declares_no_runtime_concerns():
    runtime = _runtime()
    backend = _Backend({_CONTAINER: _inspect()})
    _plan_, observations = _observe(runtime, backend)
    concerns = observations[_ADDRESS].concerns
    assert concerns == {("node_type",): "vm", ("os_family",): "linux"}
