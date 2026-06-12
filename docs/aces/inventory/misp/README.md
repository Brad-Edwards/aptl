# MISP Inventory

This bundle is the SCN-010 / issue #346 steady-state asset inventory for the
`aptl-misp` container in TechVault. The target service is the `misp` Compose
service running `ghcr.io/misp/misp-docker/misp-core:latest`, resolved at capture
time to `ghcr.io/misp/misp-docker/misp-core@sha256:992fd95b8d9698a18e1acdd7dbf5e8d03b32a03fd80e4bcbcff77bc7f17768cd`.

The capture used the already-running local lab per operator direction. It was
non-destructive and did not run `aptl lab stop -v && aptl lab start`; treat this
as current-running steady-state evidence, not as clean-lab rebuild proof.

## Encoded Result

`scenarios/techvault.sdl.yaml` now encodes:

- MISP image identity, history, rootfs layers, local realization inputs, and
  absent supply-chain attestation evidence.
- Runtime container policy, healthcheck, mounts, endpoint `172.20.0.16` on
  `security-net`, host publication `8443:443`, environment, capabilities,
  process tree, local users/groups, package inventory, SBOM scanner evidence,
  and Trivy findings.
- `runtime.service_listeners` for HTTP/HTTPS, loopback MISP ZMQ, loopback
  supervisor, Docker embedded DNS, GPG-agent sockets, supervisor socket,
  `/dev/log`, and PHP-FPM's Unix socket. ACES #431 is consumed for these
  listener semantics. No known ACES expressivity gap remains for the catalogued
  MISP steady-state inventory.
- MISP 2.5.36 web/API routes for `/users/login` and `/events/restSearch`,
  MISP-local users/org/roles/API-key metadata in `runtime.identity_authorities`,
  and MISP threat-intelligence platform state in `runtime.platform_applications`
  covering reference content objects and admin settings.
- Relationships from MISP to `misp-db` and `misp-redis`, plus the
  `misp-suricata-sync` HTTPS/API relationship. The `misp-db` companion full
  inventory is owned by #347; remaining companion full inventories are #348 and #349.

## Evidence Highlights

- OS/runtime: Debian GNU/Linux 13 (trixie), PHP 8.4.16, nginx 1.26.3,
  Python 3.12.13, MariaDB client 11.8.6.
- MISP app version: `{"major":2, "minor":5, "hotfix":36}`.
- Runtime counts: 17,516 filesystem entries, 12,549 checksummed files,
  238 dpkg packages, 593 Trivy vulnerability findings, 21 local users,
  42 local groups, 49 steady-state processes, and 15 unique service listeners.
- MISP logical state: one admin user, one local organisation, six roles, one
  API-key metadata row, six admin settings, one event, six attributes, zero
  objects, seven tags, 165 taxonomies, 112 galaxies, 49,300 galaxy clusters,
  122 warninglists, two feeds, zero sharing groups, and 388 object templates.
  The live event is `APTL Lab - Known Threat Actors` with three `ip-src` IOCs
  and three `pattern-in-traffic` IOCs.
- Participant discovery: `aptl-misp-suricata-sync` resolves `misp` and
  `aptl-misp`, reaches TCP 443 and TCP 80, and verifies TLS with the lab CA.
  `aptl-kali` cannot reach `172.20.0.16:443` from its current network vantage.

## Limits

- This is not a destructive fresh-lab reset or byte-identical rebuild proof.
- Scenario fixture secrets are retained unmasked in the evidence and SDL. The
  live TLS key and active MISP config files are represented by target-file
  metadata and SHA-256 digests in the filesystem evidence.
- Docker embedded DNS listener ports are backend-generated and ephemeral; the
  SDL records them as node-local runtime listeners with provenance and caveat
  text rather than as MISP application services.
- The snapshot contains one MISP event and six attributes; the bundle records
  row-level event, attribute, event-tag, and tag evidence in `misp-state.txt`.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/misp
uv run aptl aces-inventory gaps docs/aces/inventory/misp
uv run pytest tests/test_misp_inventory.py -q
```
