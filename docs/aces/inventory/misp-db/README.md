# MISP DB Inventory

This bundle is the SCN-010 / issue #347 steady-state asset inventory for the
`aptl-misp-db` container in TechVault. The target service is the `misp-db`
Compose service running `mariadb:10.11`, resolved at capture time to
`mariadb@sha256:407fccb51e710f34752c1a3ef9b936d1f55f38d4ac7fa043b3759742d266fd9a`.

The capture used the already-running local lab per operator direction. It was
non-destructive and did not run `aptl lab stop -v && aptl lab start`; treat this
as current-running steady-state evidence, not as clean-lab rebuild proof.

## Encoded Result

`scenarios/techvault.sdl.yaml` now encodes:

- MariaDB image identity, Docker history, Trivy rootfs layers, local Compose
  realization input, and absent supply-chain attestation evidence.
- Runtime container policy, healthcheck, named volume mount, endpoint
  `172.20.0.17` on `security-net`, environment, capabilities, process identity,
  local users/groups, package inventory, software components, SBOM scanner
  evidence, and Trivy findings.
- `runtime.service_listeners` for MariaDB TCP/3306 on IPv4 and IPv6 wildcard
  addresses, the MariaDB Unix socket, and Docker embedded DNS. ACES #431 is
  consumed for listener semantics.
- `runtime.database_services` for the MariaDB/MySQL wire-protocol service,
  including five observed databases, 235 captured table entries across `misp`,
  `mysql`, and `sys`, seven database-local roles, and SHOW GLOBAL VARIABLES
  settings. Brad-Edwards/aces#388 is consumed for database logical-state
  semantics.
- MISP-to-MariaDB relationship semantics through the typed
  `relationships.misp-connects-mariadb.database_access` payload, targeting the
  `misp` logical database and database-local `misp` role.
- Content/account anchors for the data volume, key MariaDB config/table files,
  all MISP table cardinalities, local passwd users, and database roles.

No known ACES expressivity gap remains for the catalogued MISP DB steady-state
inventory. MariaDB global privilege booleans observed in `mysql.global_priv`
are preserved in database role descriptions, while raw authentication material
is not encoded.

## Evidence Highlights

- OS/runtime: Ubuntu 22.04.5 LTS (Jammy), MariaDB 10.11.16.
- Runtime counts: 434 filesystem entries, 416 checksummed files, 151 dpkg
  packages, 100 Trivy vulnerability findings, 20 local users, 40 local groups,
  one steady-state MariaDB process, and five unique service listeners.
- Database state: five databases (`information_schema`, `misp`, `mysql`,
  `performance_schema`, `sys`), 235 captured table rows, seven database-local
  user/host roles, and 15 captured server settings.
- MISP table cardinalities include zero events, attributes, and objects; two
  feeds; 165 taxonomies; 112 galaxies; 56,341 galaxy clusters; 321,235 galaxy
  elements; 122 warninglists; and 2,509,058 warninglist entries.
- Participant discovery: `aptl-misp` resolves `misp-db` / `aptl-misp-db` to
  `172.20.0.17`, reaches TCP/3306, and verifies `SELECT VERSION(), DATABASE()`
  as the `misp` database user. `aptl-kali` cannot reach `172.20.0.17:3306`
  from its current network vantage.

## Limits

- This is not a destructive fresh-lab reset or byte-identical rebuild proof.
- `MYSQL_PASSWORD` and `MYSQL_ROOT_PASSWORD` are retained as scenario fixture
  evidence. Raw table data remains out of scope for this bounded inventory;
  table files are represented by metadata and selected checksums.
- Docker embedded DNS listener ports and endpoint IDs are backend-generated;
  the SDL records them as node-local or ephemeral runtime facts with provenance
  rather than as authored application services.
- `information_schema` and `performance_schema` are recorded as observed
  databases, but the bounded schema query did not enumerate their table rows.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/misp-db
uv run aptl aces-inventory gaps docs/aces/inventory/misp-db
uv run pytest tests/test_misp_db_inventory.py -q
```
