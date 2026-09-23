"""Run the loopback publications declared by a verified seat launch."""

from __future__ import annotations

import argparse
from pathlib import Path

from aptl.appliance.loopback_proxy import build_proxy_bindings, serve_proxy_bindings
from aptl.appliance.seat.launch_descriptor import verify_seat_launch

_LAUNCH_DESCRIPTOR = Path("/run/aptl-launch/appliance-launch.json")
_ADAPTER_ADDRESS = "10.0.2.15"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=("proxy",))
    parser.parse_args()
    _descriptor, policy = verify_seat_launch(_LAUNCH_DESCRIPTOR)
    serve_proxy_bindings(
        build_proxy_bindings(policy, adapter_address=_ADAPTER_ADDRESS)
    )


if __name__ == "__main__":
    main()
