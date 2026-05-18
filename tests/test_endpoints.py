"""Tests for the snapshot endpoint registry (ADR-036).

Covers ``parse_host_port`` (focused parser over the backend-normalized
``ContainerSnapshot.ports`` shape) and the two registry-driven builders
``build_service_endpoints`` / ``build_ssh_endpoints``.

ADR-036 contract that these tests pin down:

- Host-published port comes from runtime ``ContainerSnapshot.ports``, not
  from the registry.
- A registered container whose runtime ports don't expose the registry's
  expected target port + protocol → endpoint is omitted (not exception).
- Stopped containers are skipped.
- The registry carries no credential material. ``ServiceEndpoint``
  still has a ``credentials`` field for backward shape but its value
  is the dataclass default empty string; ``RangeSnapshot.to_dict()``'s
  redactor (tested in ``tests/test_snapshot.py``) is the redaction
  boundary regardless.
"""

from aptl.core.endpoints import (
    ENDPOINT_REGISTRY,
    EndpointRegistryEntry,
    build_service_endpoints,
    build_ssh_endpoints,
    parse_host_port,
)
from aptl.core.snapshot import ContainerSnapshot


class TestParseHostPort:
    """``parse_host_port`` matches strictly on target port + protocol."""

    def test_ipv4_published(self):
        ports = ["0.0.0.0:2022->22/tcp"]
        assert parse_host_port(ports, target_port=22, protocol="tcp") == 2022

    def test_ipv6_published(self):
        ports = ["[::]:2022->22/tcp"]
        assert parse_host_port(ports, target_port=22, protocol="tcp") == 2022

    def test_loopback_published(self):
        ports = ["127.0.0.1:8443->443/tcp"]
        assert parse_host_port(ports, target_port=443, protocol="tcp") == 8443

    def test_exposed_but_not_published_returns_none(self):
        # "22/tcp" means the container exposes 22 but no host mapping
        # exists; we cannot tell the user where to connect.
        ports = ["22/tcp"]
        assert parse_host_port(ports, target_port=22, protocol="tcp") is None

    def test_wrong_target_port_returns_none(self):
        ports = ["0.0.0.0:2022->22/tcp"]
        assert parse_host_port(ports, target_port=80, protocol="tcp") is None

    def test_wrong_protocol_returns_none(self):
        # 5353:53/udp must not satisfy a 53/tcp lookup.
        ports = ["0.0.0.0:5353->53/udp"]
        assert parse_host_port(ports, target_port=53, protocol="tcp") is None

    def test_udp_protocol_match(self):
        ports = ["0.0.0.0:5353->53/udp"]
        assert parse_host_port(ports, target_port=53, protocol="udp") == 5353

    def test_malformed_entries_skipped(self):
        ports = ["garbage", "->22/tcp", "0.0.0.0:->22/tcp", "0.0.0.0:abc->22/tcp"]
        assert parse_host_port(ports, target_port=22, protocol="tcp") is None

    def test_empty_list_returns_none(self):
        assert parse_host_port([], target_port=22, protocol="tcp") is None

    def test_first_matching_entry_wins(self):
        # Both IPv4 and IPv6 bindings for the same target. Either host
        # port is acceptable; we just need a deterministic non-None.
        ports = ["0.0.0.0:2022->22/tcp", "[::]:2022->22/tcp"]
        assert parse_host_port(ports, target_port=22, protocol="tcp") == 2022

    def test_picks_correct_entry_among_many(self):
        # Wazuh manager container exposes several ports; we want the
        # 55000 mapping specifically.
        ports = [
            "0.0.0.0:1514->1514/tcp",
            "0.0.0.0:1515->1515/tcp",
            "0.0.0.0:514->514/udp",
            "0.0.0.0:55000->55000/tcp",
        ]
        assert parse_host_port(ports, target_port=55000, protocol="tcp") == 55000

    def test_protocol_defaults_to_tcp(self):
        ports = ["0.0.0.0:2022->22/tcp"]
        assert parse_host_port(ports, target_port=22) == 2022


class TestEndpointRegistry:
    """The hardcoded registry covers exactly the endpoints today's
    ``snapshot.py`` maps did."""

    def test_registry_has_expected_containers(self):
        names = {e.container_name for e in ENDPOINT_REGISTRY}
        assert names == {
            "aptl-wazuh-dashboard",
            "aptl-wazuh-indexer",
            "aptl-wazuh-manager",
            "aptl-victim",
            "aptl-kali",
            "aptl-reverse",
        }

    def test_service_entries_have_url_scheme_and_target_port(self):
        for entry in ENDPOINT_REGISTRY:
            if entry.kind == "service":
                assert entry.url_scheme, (
                    f"{entry.container_name} missing url_scheme"
                )
                assert entry.target_port > 0
                assert entry.ssh_user is None

    def test_ssh_entries_have_user_and_target_port_22(self):
        for entry in ENDPOINT_REGISTRY:
            if entry.kind == "ssh":
                assert entry.ssh_user, f"{entry.container_name} missing ssh_user"
                assert entry.target_port == 22
                assert entry.url_scheme is None

    def test_every_entry_declares_transport_protocol(self):
        # `transport_protocol` is what `parse_host_port` matches against
        # the Docker port string. ADR-036's "target-port + protocol"
        # boundary must be registry-owned, not parser-defaulted.
        for entry in ENDPOINT_REGISTRY:
            assert entry.transport_protocol in ("tcp", "udp"), (
                f"{entry.container_name} transport_protocol "
                f"{entry.transport_protocol!r} is not a recognized L4 protocol"
            )

    def test_url_scheme_and_transport_protocol_are_disjoint(self):
        # url_scheme is the application-layer URL scheme (https/http/ssh).
        # transport_protocol is the L4 transport (tcp/udp). They live in
        # different fields so a registry edit cannot conflate them — the
        # exact failure mode codex review cycle 1 flagged.
        l4_protocols = {"tcp", "udp", "sctp"}
        for entry in ENDPOINT_REGISTRY:
            if entry.url_scheme is not None:
                assert entry.url_scheme not in l4_protocols, (
                    f"{entry.container_name} url_scheme {entry.url_scheme!r} "
                    "looks like an L4 transport, not an application scheme"
                )

    def test_dashboard_target_port_is_container_side(self):
        # ADR-036 anti-pattern: hardcoding the host-published port in
        # the registry. Compose maps `443:5601` for `aptl-wazuh-dashboard`,
        # so 5601 is the container-side target_port and 443 is the host
        # port that `parse_host_port` derives at runtime.
        entry = next(
            e for e in ENDPOINT_REGISTRY
            if e.container_name == "aptl-wazuh-dashboard"
        )
        assert entry.target_port == 5601
        assert entry.url_scheme == "https"
        assert entry.transport_protocol == "tcp"


class TestBuildServiceEndpoints:
    """``build_service_endpoints`` derives host ports from runtime data."""

    def test_dashboard_uses_runtime_host_port_not_target(self):
        # Real lab: `wazuh.dashboard` publishes host 443 -> container
        # 5601 in docker-compose.yml. The new registry annotates the
        # container-side target 5601 and the derivation pulls the host
        # port from the runtime inventory, so a Compose-side host port
        # change requires only a Compose edit (the ADR-036 seam).
        containers = [
            ContainerSnapshot(
                name="aptl-wazuh-dashboard",
                status="Up 5 minutes (healthy)",
                ports=["0.0.0.0:443->5601/tcp"],
            ),
        ]
        endpoints = build_service_endpoints(containers)
        assert len(endpoints) == 1
        assert endpoints[0].name == "Wazuh Dashboard"
        assert endpoints[0].port == 443
        assert endpoints[0].url == "https://localhost:443"
        assert endpoints[0].protocol == "https"

    def test_all_wazuh_services_when_running(self):
        containers = [
            ContainerSnapshot(
                name="aptl-wazuh-dashboard",
                status="Up 5 minutes",
                ports=["0.0.0.0:443->5601/tcp"],
            ),
            ContainerSnapshot(
                name="aptl-wazuh-indexer",
                status="Up 5 minutes",
                ports=["0.0.0.0:9200->9200/tcp"],
            ),
            ContainerSnapshot(
                name="aptl-wazuh-manager",
                status="Up 5 minutes",
                ports=[
                    "0.0.0.0:1514->1514/tcp",
                    "0.0.0.0:55000->55000/tcp",
                ],
            ),
        ]
        endpoints = build_service_endpoints(containers)
        by_name = {e.name: e for e in endpoints}
        assert set(by_name) == {"Wazuh Dashboard", "Wazuh Indexer", "Wazuh API"}
        assert by_name["Wazuh Indexer"].port == 9200
        assert by_name["Wazuh API"].port == 55000

    def test_skips_stopped_containers(self):
        containers = [
            ContainerSnapshot(
                name="aptl-wazuh-dashboard",
                status="Exited (0) 2 minutes ago",
                ports=["0.0.0.0:443->5601/tcp"],
            ),
        ]
        assert build_service_endpoints(containers) == []

    def test_omits_endpoint_when_host_port_missing(self):
        # Running container, registered, but the runtime ports list
        # doesn't expose the registry's target port (race or partial
        # readiness). Per ADR-036, omit — do NOT fall back to a stale
        # hardcoded host port.
        containers = [
            ContainerSnapshot(
                name="aptl-wazuh-dashboard",
                status="Up 5 minutes",
                ports=[],
            ),
        ]
        assert build_service_endpoints(containers) == []

    def test_ignores_unregistered_containers(self):
        containers = [
            ContainerSnapshot(
                name="aptl-unregistered-service",
                status="Up 5 minutes",
                ports=["0.0.0.0:1234->1234/tcp"],
            ),
        ]
        assert build_service_endpoints(containers) == []

    def test_empty_input(self):
        assert build_service_endpoints([]) == []

    def test_no_credential_literals_in_built_endpoint(self):
        # The registry carries no credential literals (see
        # `EndpointRegistryEntry` docstring): ADR-029 redacts
        # `ServiceEndpoint.credentials` at `RangeSnapshot.to_dict()`,
        # so a source-side literal would be dead data. The on-the-wire
        # `credentials` field stays for backward shape but is the
        # dataclass default empty string.
        containers = [
            ContainerSnapshot(
                name="aptl-wazuh-manager",
                status="Up 5 minutes",
                ports=["0.0.0.0:55000->55000/tcp"],
            ),
        ]
        endpoints = build_service_endpoints(containers)
        assert len(endpoints) == 1
        assert endpoints[0].credentials == ""
        # Registry-level invariant: no EndpointRegistryEntry carries
        # credential material as an attribute.
        assert not hasattr(ENDPOINT_REGISTRY[0], "credentials")


class TestBuildSSHEndpoints:
    """``build_ssh_endpoints`` mirrors the service builder."""

    def test_victim_ssh(self):
        containers = [
            ContainerSnapshot(
                name="aptl-victim",
                status="Up 5 minutes",
                ports=["0.0.0.0:2022->22/tcp"],
            ),
        ]
        endpoints = build_ssh_endpoints(containers)
        assert len(endpoints) == 1
        assert endpoints[0].name == "Victim"
        assert endpoints[0].port == 2022
        assert endpoints[0].user == "labadmin"
        assert "labadmin@localhost" in endpoints[0].command
        assert "-p 2022" in endpoints[0].command

    def test_all_ssh_containers(self):
        containers = [
            ContainerSnapshot(
                name="aptl-victim",
                status="Up 5 minutes",
                ports=["0.0.0.0:2022->22/tcp"],
            ),
            ContainerSnapshot(
                name="aptl-kali",
                status="Up 5 minutes",
                ports=["0.0.0.0:2023->22/tcp"],
            ),
            ContainerSnapshot(
                name="aptl-reverse",
                status="Up 5 minutes",
                ports=["0.0.0.0:2027->22/tcp"],
            ),
        ]
        endpoints = build_ssh_endpoints(containers)
        assert {e.port for e in endpoints} == {2022, 2023, 2027}

    def test_skips_stopped_containers(self):
        containers = [
            ContainerSnapshot(
                name="aptl-kali",
                status="Exited (137) 1 minute ago",
                ports=["0.0.0.0:2023->22/tcp"],
            ),
        ]
        assert build_ssh_endpoints(containers) == []

    def test_skips_non_ssh_containers(self):
        containers = [
            ContainerSnapshot(
                name="aptl-wazuh-manager",
                status="Up 5 minutes",
                ports=["0.0.0.0:55000->55000/tcp"],
            ),
            ContainerSnapshot(
                name="aptl-unregistered",
                status="Up 5 minutes",
                ports=["0.0.0.0:1234->22/tcp"],
            ),
        ]
        assert build_ssh_endpoints(containers) == []

    def test_omits_endpoint_when_host_port_missing(self):
        containers = [
            ContainerSnapshot(
                name="aptl-victim",
                status="Up 5 minutes",
                ports=[],
            ),
        ]
        assert build_ssh_endpoints(containers) == []

    def test_kali_ssh_user(self):
        containers = [
            ContainerSnapshot(
                name="aptl-kali",
                status="Up 5 minutes",
                ports=["0.0.0.0:2023->22/tcp"],
            ),
        ]
        endpoints = build_ssh_endpoints(containers)
        assert len(endpoints) == 1
        assert endpoints[0].user == "kali"

    def test_empty_input(self):
        assert build_ssh_endpoints([]) == []


class TestRegistryEntryShape:
    """``EndpointRegistryEntry`` is a frozen dataclass."""

    def test_entry_is_frozen(self):
        import dataclasses
        entry = ENDPOINT_REGISTRY[0]
        try:
            entry.container_name = "mutated"  # type: ignore[misc]
        except dataclasses.FrozenInstanceError:
            return
        except AttributeError:
            return
        raise AssertionError("EndpointRegistryEntry should be frozen")

    def test_entry_kind_constraint(self):
        for entry in ENDPOINT_REGISTRY:
            assert entry.kind in ("service", "ssh")

    def test_constructable_directly(self):
        entry = EndpointRegistryEntry(
            container_name="aptl-x",
            display_name="X",
            kind="service",
            target_port=80,
            url_scheme="http",
        )
        assert entry.container_name == "aptl-x"
        assert entry.transport_protocol == "tcp"  # default
        assert entry.ssh_user is None
        # Registry intentionally does not carry credentials (see
        # `EndpointRegistryEntry` docstring).
        assert not hasattr(entry, "credentials")

    def test_udp_transport_protocol_drives_parser(self):
        # A hypothetical UDP service must select the UDP mapping from the
        # Docker port string instead of silently relying on the TCP
        # default. This is the failure mode the disjoint fields prevent.
        from aptl.core.endpoints import (
            build_service_endpoints,
        )

        udp_entry = EndpointRegistryEntry(
            container_name="aptl-test-udp",
            display_name="Test UDP",
            kind="service",
            target_port=5353,
            url_scheme="udp",
            transport_protocol="udp",
        )
        # Swap one registry entry in temporarily through monkeypatching.
        import aptl.core.endpoints as ep_mod
        original = ep_mod.ENDPOINT_REGISTRY
        ep_mod.ENDPOINT_REGISTRY = (udp_entry,)
        try:
            containers = [
                ContainerSnapshot(
                    name="aptl-test-udp",
                    status="Up 1 minute",
                    # Both a TCP and a UDP mapping at the same target;
                    # registry must pick UDP, not the parser's default.
                    ports=[
                        "0.0.0.0:5353->5353/tcp",
                        "0.0.0.0:53000->5353/udp",
                    ],
                ),
            ]
            endpoints = build_service_endpoints(containers)
            assert len(endpoints) == 1
            assert endpoints[0].port == 53000
        finally:
            ep_mod.ENDPOINT_REGISTRY = original
