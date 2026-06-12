# DB Steady-State Inventory

This directory is the SCN-010 / issue #331 inventory bundle for the TechVault
`db` container. It applies the ACES-owned asset inventory methodology
documented in
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>
to the realized `aptl-db` PostgreSQL container.

The capture used an already-running local lab on 2026-05-22T03:56:16Z. It did not run
`aptl lab stop -v && aptl lab start`, because that would destroy the user's
current Docker volumes and lab state. Treat this as a frozen post-start
steady-state artifact for the observed lab instance, not as clean-lab rebuild proof or byte-identical equivalence proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-db` |
| Compose service | `db` |
| TechVault profile | `enterprise` |
| Source class | `upstream-image` |
| Source package | `postgres:16-alpine` plus `containers/db/init/` bind-mounted initialization scripts |
| Image digest | `postgres@sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50` |
| Runtime OS | Alpine Linux v3.23 |
| PostgreSQL version | 16.13 |
| Runtime command | `postgres -c logging_collector=on -c log_directory=pg_log -c log_filename=postgresql.log -c log_statement=all -c log_connections=on -c log_disconnections=on` |
| Listener | `0.0.0.0:5432` and `:::5432` |
| Network identity | `aptl_aptl-internal` IPv4 `172.20.2.11` |
| Data volume | `aptl_db_data:/var/lib/postgresql/data` |
| Init bind mount | `containers/db/init:/docker-entrypoint-initdb.d:ro` |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt` |
| Docker Compose service intent is represented by the Compose service slice. | `evidence/compose-service.db.json` |
| Upstream image identity, config, history, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.db-data.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| Init-script source inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| OS packages and PostgreSQL manifests visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt` |
| Patch state is machine-readable. | `evidence/trivy-vulnerabilities.json`, `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| Catalogued data-volume and init-script filesystem paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or explicit claim boundaries. | `mapping-ledger.yaml` |

## Capture Findings

- The database is the upstream `postgres:16-alpine` image, not an APTL custom
  build. The TechVault-authored inputs are the Compose runtime configuration
  and the two initialization SQL scripts under `containers/db/init/`.
- The image reports Alpine Linux v3.23 and PostgreSQL 16.13.
- PostgreSQL listens on TCP 5432 on both IPv4 and IPv6 wildcard interfaces
  inside the container. Docker attaches the container only to the internal
  TechVault network at `172.20.2.11`; no host port is published.
- The named volume `aptl_db_data` is mounted at `/var/lib/postgresql/data` and
  contains the generated PostgreSQL cluster, logs, WAL, catalog files, and
  postmaster runtime files captured in this snapshot.
- The initialization bind mount is read-only and contains `01-schema.sql` and
  `02-seed-data.sql`.
- The container runs as the `postgres` Unix user after entrypoint setup. PID 1
  is the PostgreSQL postmaster, with logger, checkpointer, background writer,
  WAL writer, autovacuum launcher, and logical replication launcher processes.
- Trivy 0.70.0 reported 34 package vulnerability findings at
  scan time: 1 critical,
  11 high, 20
  medium, and 2 low.
- The resolved `POSTGRES_PASSWORD=techvault_db_pass` fixture value is retained
  unmasked in committed evidence and classified as scenario fixture content in
  the SDL.

## ACES Mapping Result

Current ACES SDL encodes the DB node identity, upstream image pin, upstream
image history/layers, init-script source inputs, network attachment, service
exposure, healthcheck, runtime mount table, data-volume and init-script
filesystem inventory with metadata and checksums, container host/security
configuration, health observations, process set, runtime environment,
capability/restart/resource policy, Alpine package inventory, Trivy package
findings, local Linux identity database, first-class PostgreSQL database
service state added by Brad-Edwards/aces#388 (databases, roles, tables,
listeners, and settings), content entries for high-value config/init/log files,
and the DB log forwarding relationship to Wazuh.

No known ACES expressivity gap remains for the catalogued DB steady-state
inventory facts in this ledger. Full Alpine root filesystem cataloguing outside
the PostgreSQL data volume and init-script bind mount is recorded as a capture boundary, not as an ACES expressivity blocker.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/db
aptl aces-inventory gaps docs/aces/inventory/db
```

## Known Limits

- The evidence came from a running lab, not a destructive clean reset. It is a
  frozen observation of that realized lab state, not proof that a fresh
  `aptl lab stop -v && aptl lab start` reproduces byte-identical state.
- The filesystem inventory catalogs the PostgreSQL data volume and init-script
  bind mount visible at steady state. It does not claim full Alpine root
  filesystem equivalence outside those catalogued surfaces.
- Database heap/WAL/log files can change as PostgreSQL runs. Their checksums are
  snapshot facts for this frozen capture.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
