"""Guest adapter tests for signed loopback publications."""

import pytest

from aptl.appliance.loopback_proxy import build_proxy_bindings
from tests.test_appliance_boundary_inventory import _policy


def test_proxy_bindings_preserve_signed_loopback_destinations() -> None:
    bindings = build_proxy_bindings(_policy(), adapter_address="10.0.2.15")

    assert [(item.listen_address, item.listen_port) for item in bindings] == [
        ("10.0.2.15", 443),
        ("10.0.2.15", 9443),
    ]
    assert [(item.target_address, item.target_port) for item in bindings] == [
        ("127.0.0.1", 443),
        ("127.0.0.1", 9443),
    ]


def test_proxy_bindings_reject_non_tcp_publication() -> None:
    policy = _policy().model_copy(
        update={
            "guest_publications": [
                _policy().guest_publications[0].model_copy(update={"protocol": "udp"})
            ]
        }
    )

    with pytest.raises(ValueError, match="TCP"):
        build_proxy_bindings(policy, adapter_address="10.0.2.15")
