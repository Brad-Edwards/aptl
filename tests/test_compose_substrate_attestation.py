"""The generic base container's posture attestation (issue #955).

One closed-world check decides whether a realized container carries exactly the
posture APTL would create now. It governs both the create path (read back before
any service content lands) and the reuse path (a stale container from an earlier
policy is recreated, not adopted). A missing or malformed inspect field is an
unknown posture, never an empty safe set.
"""

from __future__ import annotations

import copy

import pytest

from aptl.backends.raes_base_substrate import (
    BaseContainerSpec,
    InitRequirements,
    PublishedPort,
    VolumeMount,
)
from aptl.core.deployment._compose_substrate_attestation import (
    substrate_posture_mismatch,
)

_PREFIX = "proj"


def _init_spec(**overrides) -> BaseContainerSpec:
    fields = {
        "node_address": "provision.node.db",
        "container_name": "aptl-db",
        "image_ref": "aptl/generic-systemd-base-debian:latest",
        "runs_services": True,
        "init": InitRequirements(),
        "published_ports": (
            PublishedPort(container_port=5432, host_ip="127.0.0.1"),
            PublishedPort(container_port=22, host_ip="127.0.0.1", host_port=2022),
        ),
        "volume_mounts": (
            VolumeMount(target="/var/lib/postgresql", source="db_data"),
            VolumeMount(target="/seed", source="db_seed", read_only=True),
        ),
    }
    fields.update(overrides)
    return BaseContainerSpec(**fields)


def _realized(spec: BaseContainerSpec) -> dict:
    """The inspect payload of a daemon that honored ``spec`` exactly."""

    init = spec.init
    capabilities = [*(init.capabilities if init else ()), *spec.backend_run_capabilities]
    return {
        "AppArmorProfile": "docker-default",
        "HostConfig": {
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "private",
            "UsernsMode": "",
            "UTSMode": "",
            "CgroupnsMode": "private",
            "CapAdd": [f"CAP_{cap}" for cap in capabilities] or None,
            "CapDrop": None,
            "SecurityOpt": ["writable-cgroups=true"] if init else None,
            "Devices": [],
            "DeviceCgroupRules": None,
            "Binds": [f"{_PREFIX}_{m.source}:{m.target}" for m in spec.volume_mounts]
            or None,
            "Tmpfs": {path: "" for path in init.tmpfs} if init else None,
            "PortBindings": {
                f"{port.container_port}/{port.protocol}": [
                    {
                        "HostIp": port.host_ip,
                        "HostPort": "" if port.host_port is None else str(port.host_port),
                    }
                ]
                for port in spec.published_ports
            },
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": f"{_PREFIX}_{mount.source}",
                "Destination": mount.target,
                "RW": not mount.read_only,
            }
            for mount in spec.volume_mounts
        ],
    }


def _mismatch(info, spec) -> str | None:
    return substrate_posture_mismatch(info, spec, volume_prefix=_PREFIX)


def test_a_container_honoring_the_spec_matches():
    spec = _init_spec()

    assert _mismatch(_realized(spec), spec) is None


def test_a_plain_provider_substrate_with_its_measured_grant_matches():
    spec = BaseContainerSpec(
        node_address="provision.node.ad",
        container_name="aptl-ad",
        image_ref="aptl/generic-samba-ad-base:latest",
        runs_services=False,
        use_image_command=True,
        backend_run_capabilities=("SYS_ADMIN",),
    )

    assert _mismatch(_realized(spec), spec) is None


def test_the_retired_privileged_recipe_is_refused():
    """The field case: a warm lab's container from before this change."""

    spec = _init_spec(published_ports=(), volume_mounts=())
    info = _realized(spec)
    info["HostConfig"].update(
        {
            "CgroupnsMode": "host",
            "CapAdd": ["SYS_ADMIN", "SYS_NICE", "SYS_RESOURCE"],
            "SecurityOpt": ["seccomp:unconfined", "apparmor:unconfined"],
            "Binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
        }
    )
    info["Mounts"] = [
        {
            "Type": "bind",
            "Source": "/sys/fs/cgroup",
            "Destination": "/sys/fs/cgroup",
            "RW": True,
        }
    ]

    assert _mismatch(info, spec) is not None


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(
            lambda i: i["HostConfig"].update(Privileged=True), "privileged", id="privileged"
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(PidMode="host"),
            "shared-host-namespace",
            id="host-pid",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(IpcMode="host"),
            "shared-host-namespace",
            id="host-ipc",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(UsernsMode="host"),
            "shared-host-namespace",
            id="host-userns",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(UTSMode="container:other"),
            "shared-host-namespace",
            id="joined-uts",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(
                Devices=[{"PathOnHost": "/dev/kmsg", "PathInContainer": "/dev/kmsg"}]
            ),
            "undeclared-device-or-capability-drop",
            id="device",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(DeviceCgroupRules=["c 1:3 mr"]),
            "undeclared-device-or-capability-drop",
            id="device-cgroup-rule",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(CapDrop=["NET_RAW"]),
            "undeclared-device-or-capability-drop",
            id="capability-drop",
        ),
        pytest.param(
            lambda i: i.update(AppArmorProfile="unconfined"),
            "apparmor-profile",
            id="apparmor-unconfined",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
            "capabilities",
            id="added-capability",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(
                SecurityOpt=["writable-cgroups=true", "seccomp=unconfined"]
            ),
            "security-options",
            id="unconfined-seccomp",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(SecurityOpt=None),
            "security-options",
            id="cgroups-not-writable",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(CgroupnsMode="host"),
            "cgroup-namespace",
            id="host-cgroup-namespace",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(Tmpfs={"/run": ""}),
            "tmpfs",
            id="tmpfs",
        ),
        pytest.param(
            lambda i: i["HostConfig"]["PortBindings"].update(
                {"22/tcp": [{"HostPort": "2222"}]}
            ),
            "published-ports",
            id="undeclared-port",
        ),
        pytest.param(
            lambda i: i["HostConfig"].update(
                Binds=["/sys/fs/cgroup:/sys/fs/cgroup:rw"]
            ),
            "host-bind",
            id="host-bind",
        ),
        pytest.param(
            lambda i: i["Mounts"][0].update(RW=False),
            "volume-mounts",
            id="volume-access-mode",
        ),
        pytest.param(
            lambda i: i["Mounts"][0].update(Name="proj_other"),
            "volume-mounts",
            id="volume-source",
        ),
        pytest.param(
            lambda i: i["Mounts"].pop(0), "volume-mounts", id="missing-volume"
        ),
        pytest.param(
            lambda i: i["Mounts"].append(
                {"Type": "volume", "Name": "proj_extra", "Destination": "/extra", "RW": True}
            ),
            "volume-mounts",
            id="undeclared-named-volume",
        ),
    ],
)
def test_each_drift_is_named(mutate, reason):
    spec = _init_spec()
    info = copy.deepcopy(_realized(spec))
    mutate(info)

    assert _mismatch(info, spec) == reason


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda i: i.pop("HostConfig"), id="no-hostconfig"),
        pytest.param(lambda i: i["HostConfig"].pop("Privileged"), id="no-privileged"),
        pytest.param(
            lambda i: i["HostConfig"].update(Privileged="false"), id="privileged-str"
        ),
        pytest.param(lambda i: i["HostConfig"].pop("PidMode"), id="no-pid-mode"),
        pytest.param(
            lambda i: i["HostConfig"].pop("CgroupnsMode"), id="no-cgroupns-mode"
        ),
        pytest.param(lambda i: i["HostConfig"].update(CapAdd="SYS_ADMIN"), id="capadd-str"),
        pytest.param(
            lambda i: i["HostConfig"].update(SecurityOpt=[1]), id="securityopt-int"
        ),
        pytest.param(lambda i: i["HostConfig"].update(Tmpfs=["/run"]), id="tmpfs-list"),
        pytest.param(lambda i: i.pop("AppArmorProfile"), id="no-apparmor"),
        pytest.param(lambda i: i.pop("Mounts"), id="no-mounts"),
        pytest.param(lambda i: i.update(Mounts=["x"]), id="mount-not-object"),
        pytest.param(lambda i: i["HostConfig"].update(Binds="x"), id="binds-str"),
    ],
)
def test_a_missing_or_malformed_field_is_an_unknown_posture(mutate):
    spec = _init_spec()
    info = copy.deepcopy(_realized(spec))
    mutate(info)

    assert _mismatch(info, spec) == "inspect-malformed"


@pytest.mark.parametrize("info", [None, {}, [], "container"])
def test_a_missing_payload_is_an_unknown_posture(info):
    assert _mismatch(info, _init_spec()) == "inspect-malformed"


def test_an_image_declared_anonymous_volume_is_allowed():
    spec = _init_spec()
    info = _realized(spec)
    info["Mounts"].append(
        {"Type": "volume", "Name": "c" * 64, "Destination": "/var/lib/anon", "RW": True}
    )

    assert _mismatch(info, spec) is None


def test_a_host_without_apparmor_reports_no_profile_and_still_matches():
    # SELinux hosts and Docker Desktop's VM run without AppArmor.
    spec = _init_spec()
    info = _realized(spec)
    info["AppArmorProfile"] = ""

    assert _mismatch(info, spec) is None


def test_capability_names_compare_with_or_without_the_cap_prefix():
    spec = _init_spec(init=InitRequirements(capabilities=("NET_ADMIN",)))
    info = _realized(spec)
    info["HostConfig"]["CapAdd"] = ["net_admin"]

    assert _mismatch(info, spec) is None


def test_a_plain_node_carries_no_tmpfs_or_security_option():
    spec = BaseContainerSpec(
        node_address="provision.node.web",
        container_name="aptl-web",
        image_ref="debian:13-slim",
        runs_services=False,
    )
    info = _realized(spec)

    assert _mismatch(info, spec) is None
    info["HostConfig"]["SecurityOpt"] = ["writable-cgroups=true"]
    assert _mismatch(info, spec) == "security-options"


@pytest.mark.parametrize(
    ("binding", "reason"),
    [
        pytest.param(
            {"HostIp": "0.0.0.0", "HostPort": ""}, "published-ports", id="widened-host-ip"
        ),
        pytest.param(
            {"HostIp": "127.0.0.2", "HostPort": ""}, "published-ports", id="changed-host-ip"
        ),
        pytest.param(
            {"HostIp": "127.0.0.1", "HostPort": "15432"},
            None,
            id="ephemeral-declaration-accepts-assigned-port",
        ),
    ],
)
def test_the_host_side_of_an_ephemeral_binding_is_compared(binding, reason):
    spec = _init_spec()
    info = _realized(spec)
    info["HostConfig"]["PortBindings"]["5432/tcp"] = [binding]

    assert _mismatch(info, spec) == reason


@pytest.mark.parametrize(
    "binding",
    [
        pytest.param({"HostIp": "127.0.0.1", "HostPort": "2222"}, id="changed-host-port"),
        pytest.param({"HostIp": "127.0.0.1", "HostPort": ""}, id="fixed-port-now-ephemeral"),
        pytest.param({"HostIp": "", "HostPort": "2022"}, id="widened-to-all-interfaces"),
    ],
)
def test_a_changed_fixed_host_binding_is_not_reused(binding):
    """core-F1: a changed host address or fixed port must not keep the old publish."""

    spec = _init_spec()
    info = _realized(spec)
    info["HostConfig"]["PortBindings"]["22/tcp"] = [binding]

    assert _mismatch(info, spec) == "published-ports"


def test_a_malformed_port_binding_entry_is_an_unknown_posture():
    spec = _init_spec()
    info = _realized(spec)
    info["HostConfig"]["PortBindings"]["22/tcp"] = ["127.0.0.1:2022"]

    assert _mismatch(info, spec) == "inspect-malformed"
