"""Fresh desired-versus-observed appliance boundary verdict."""

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.appliance_boundary_inventory import (
    BoundaryEnforcementObservation,
    BoundaryEndpoint,
    BoundaryProbeObservation,
    DockerAuthorityHolder,
    GuestBoundaryObservation,
    HostBoundaryObservation,
    qualify_appliance_boundary,
)


POLICY_DIGEST = "sha256:" + "1" * 64
PAYLOAD_DIGEST = "sha256:" + "2" * 64


def _binding() -> ApplianceBoundaryBinding:
    return ApplianceBoundaryBinding(
        policy_digest=POLICY_DIGEST,
        payload_digest=PAYLOAD_DIGEST,
        aces_plan_digest="sha256:" + "4" * 64,
        boot_id="boot-42",
        guest_daemon_id="daemon-42",
        host_observation_id="host-42",
    )


def _policy() -> ApplianceBoundaryPolicy:
    return ApplianceBoundaryPolicy.model_validate(
        {
            "schema_version": "aptl.appliance-boundary/v1",
            "policy_id": "default",
            "generation": 1,
            "default_deny": True,
            "platform_anchors": {
                "participant": "org.aptl.appliance.zone=participant",
                "management": "org.aptl.appliance.zone=management",
                "egress": "org.aptl.appliance.zone=egress",
            },
            "fixed_crossings": [],
            "egress_authorities": [],
            "guest_publications": [
                {
                    "audience": "participant",
                    "address": "127.0.0.1",
                    "port": 443,
                    "protocol": "tcp",
                },
                {
                    "audience": "recovery",
                    "address": "127.0.0.1",
                    "port": 9443,
                    "protocol": "tcp",
                },
            ],
            "docker_authority": {
                "allowed_holder_labels": [],
                "require_guest_daemon": True,
            },
        }
    )


def _host() -> HostBoundaryObservation:
    return HostBoundaryObservation(
        observation_id="host-42",
        policy_digest=POLICY_DIGEST,
        payload_digest=PAYLOAD_DIGEST,
        boot_id="boot-42",
        complete=True,
        listeners=(
            BoundaryEndpoint(
                audience="participant",
                address="127.0.0.1",
                port=443,
                protocol="tcp",
            ),
            BoundaryEndpoint(
                audience="recovery",
                address="127.0.0.1",
                port=9443,
                protocol="tcp",
            ),
        ),
        forbidden_reachability_passed=True,
    )


def _guest() -> GuestBoundaryObservation:
    return GuestBoundaryObservation(
        policy_digest=POLICY_DIGEST,
        aces_plan_digest="sha256:" + "4" * 64,
        boot_id="boot-42",
        guest_daemon_id="daemon-42",
        enforcements=(
            BoundaryEnforcementObservation(
                authority="platform",
                source_digest=POLICY_DIGEST,
                enforcement_digest="sha256:" + "3" * 64,
                families=("bridge", "inet"),
                default_deny_observed=True,
            ),
        ),
        observation_complete=True,
        probes=(
            BoundaryProbeObservation(
                identity="management-to-egress",
                expectation="reachable",
                passed=True,
            ),
            BoundaryProbeObservation(
                identity="kali-to-metadata",
                expectation="blocked",
                passed=True,
            ),
        ),
        docker_authority_holders=(),
    )


def test_fresh_host_and_guest_observations_produce_one_pass_inventory() -> None:
    result = qualify_appliance_boundary(_policy(), _binding(), _host(), _guest())

    assert result.passed is True
    assert result.findings == ()
    assert result.inventory["host"]["observation_id"] == "host-42"
    assert result.inventory["guest"]["guest_daemon_id"] == "daemon-42"


def test_missing_physical_host_observation_is_fatal() -> None:
    result = qualify_appliance_boundary(_policy(), _binding(), None, _guest())

    assert result.passed is False
    assert result.findings == ("boundary.host-observation-missing",)


def test_unknown_listener_and_stale_identity_fail_closed() -> None:
    host = _host().model_copy(
        update={
            "boot_id": "old-boot",
            "listeners": (
                *_host().listeners,
                BoundaryEndpoint(
                    audience="participant",
                    address="127.0.0.1",
                    port=55000,
                    protocol="tcp",
                ),
            ),
        }
    )

    result = qualify_appliance_boundary(_policy(), _binding(), host, _guest())

    assert result.passed is False
    assert result.findings == (
        "boundary.host-boot-identity-mismatch",
        "boundary.host-listener-unapproved",
    )


def test_docker_authority_must_be_guest_scoped_and_least_privileged() -> None:
    holder = DockerAuthorityHolder(
        identity="deployment-owner",
        label_selector="org.aptl.appliance.role=deployment-authority",
        daemon_id="physical-host-daemon",
        access="socket",
        privileged=True,
        host_pid_namespace=False,
        host_network_namespace=False,
        device_count=0,
    )
    guest = _guest().model_copy(update={"docker_authority_holders": (holder,)})

    result = qualify_appliance_boundary(_policy(), _binding(), _host(), guest)

    assert result.passed is False
    assert result.findings == (
        "boundary.guest-docker-authority-unapproved",
        "boundary.guest-docker-daemon-mismatch",
        "boundary.guest-docker-authority-overprivileged",
    )
