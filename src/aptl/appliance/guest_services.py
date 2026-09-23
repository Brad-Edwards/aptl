"""Run the loopback publications declared by a verified seat launch."""

from __future__ import annotations

import argparse
from pathlib import Path

from aptl.appliance.loopback_proxy import build_proxy_bindings, serve_proxy_bindings
from aptl.appliance.seat.launch_descriptor import verify_seat_launch


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=("proxy",))
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--adapter-address", default="10.0.2.15")
    args = parser.parse_args()
    _descriptor, policy = verify_seat_launch(args.descriptor)
    serve_proxy_bindings(
        build_proxy_bindings(policy, adapter_address=args.adapter_address)
    )


if __name__ == "__main__":
    main()
