# TechVault DNS Inventory

This bundle captures the SCN-010 steady-state inventory for APTL issue #336:
the `dns` Compose service realized as container `aptl-dns`.

The target is a first-party custom build from `containers/dns/`, observed as:

- Image: `aptl-dns@sha256:98deb7dcc1ef3e3435bfeb4a9bffaac8a177636da8505164fba9eeee7508ec75`
- Runtime OS: Ubuntu 22.04.5 LTS
- DNS implementation: BIND 9.18.39-0ubuntu0.22.04.3-Ubuntu
- Service identity: `ns1.techvault.local`
- Networks: `dmz-net` `172.20.1.22`, `internal-net` `172.20.2.27`, `security-net` `172.20.0.25`

## Scope

The capture follows the ACES participant-discoverable asset inventory
methodology. It records Docker/Compose provenance, image history, runtime
configuration, network attachments, host-published ports, capabilities,
mounts, processes, package inventory, Trivy/Syft SBOM evidence, Trivy
vulnerability evidence, local users/groups, BIND config, zone files, AXFR
logical DNS state, and filesystem metadata/checksums for load-bearing paths.

ACES issue #426 and the merged ACES DNS runtime work in PR #427 are consumed
by this branch. The catalogued DNS resolver, zone, RRset, SOA/MX/SRV/PTR/A
record, logging, transfer, and dynamic-update facts are encoded in
`scenarios/techvault.sdl.yaml` under `nodes.techvault.dns.runtime.dns_services`.
No known ACES expressivity gap remains for the catalogued DNS steady-state
facts.

## Limits

The capture is non-destructive: it used the already-running local lab and did not run
`aptl lab stop -v && aptl lab start`. Treat the evidence as a frozen
steady-state observation, not as clean-lab rebuild proof.

AXFR was observed from localhost inside `aptl-dns`; the bundle does not claim
that non-local clients can perform zone transfers. Scanner output is
time-sensitive. Syft CycloneDX output was normalized by
`normalize-syft-cyclonedx.jq` to strip `syft:location:*` component properties;
filesystem provenance is recorded separately.

## Verification

Useful local checks:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/dns
uv run aptl aces-inventory gaps docs/aces/inventory/dns
uv run pytest tests/test_dns_inventory.py -q
```

The reusable capture commands are in `capture-evidence.sh`. The mapping from
captured facts to ACES SDL fields is in `mapping-ledger.yaml`.
