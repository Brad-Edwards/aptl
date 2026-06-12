# MISP Redis Inventory

This bundle is the SCN-010 / issue 348 steady-state asset inventory for the
`aptl-misp-redis` container in TechVault. The target service is the `misp-redis`
Compose service running `redis:7-alpine`, resolved at capture time to
`redis@sha256:7aec734b2bb298a1d769fd8729f13b8514a41bf90fcdd1f38ec52267fbaa8ee6`.

The capture used the already-running local lab per operator direction. It was
non-destructive and did not run `aptl lab stop -v && aptl lab start`; treat this
as current-running steady-state evidence, not as clean-lab rebuild proof.

## Encoded Result

`scenarios/techvault.sdl.yaml` (via `scenarios/techvault/nodes/misp-redis.sdl.yaml`)
now encodes:

- Redis image identity, the upstream `redis:7-alpine` build history (17
  instructions), 8 rootfs layers, the image config, the local Compose
  realization input, and the present-but-unverified SLSA provenance / SPDX SBOM
  registry attestation.
- Runtime container policy (restart, 128 MiB memory limit, runc, masked/read-only
  proc paths), the anonymous `/data` volume mount (image `VOLUME /data`; no named
  Compose volume), PID 1 `redis-server` running as the `redis` service account
  (uid 999) with no effective capabilities, the security-net endpoint
  (DHCP-assigned `172.20.0.2`, no host-published ports), environment, local
  users/groups, 17 apk packages, the redis/gosu software components, SBOM scanner
  evidence, and 101 Trivy findings.
- `runtime.service_listeners` for the Redis RESP listener on the IPv4 and IPv6
  wildcard (`bind '* -::*'`) plus the Docker embedded DNS TCP/UDP listeners.
  ACES #431 is consumed for listener semantics.
- `runtime.datastore_services` for the Redis `key_value` store: engine `redis`,
  the mandatory persistence profile (RDB save points `3600 1` / `300 100` /
  `60 10000`, AOF disabled, `noeviction`, `maxmemory 0`), the observed populated
  logical DBs (`db0`/`db1`/`db13`) as `logical_db` partitions with datatype
  census, transport security (`none`; plaintext RESP), and 18 captured CONFIG
  settings — including the `requirepass` scenario-fixture value preserved and
  classified `secret_fixture` (the disclosed credential that reproduces this
  asset). This is the first TechVault node to populate the non-relational
  `runtime.datastore_services` surface; Redis is deliberately NOT shoehorned into
  the relational `runtime.database_services`.
- `runtime.app_authorizations` for the Redis ACL (`resource_vocabulary:
  redis_acl`): the single built-in `default` user (enabled, `sanitize-payload`,
  password-required; the credential value is the disclosed fixture recorded in
  the `requirepass` setting) with a full-access permission grant (`+@all` over
  `~*` keys and `&*` channels).
- MISP-to-Redis relationship semantics through
  `relationships.misp-connects-redis`, now targeting the typed Redis datastore
  service; participant discovery confirms MISP reaches `misp-redis:6379` while
  MISP-side auth remains unobserved.

No known ACES expressivity gap remains for the catalogued MISP Redis steady-state
inventory. The Redis auth fixture is a disclosed scenario realization fact —
preserved verbatim in the evidence and encoded as a `secret_fixture` value in the
SDL (per ACES #471) so the asset can be reproduced — not an operator secret.

## Evidence Highlights

- OS/runtime: Alpine Linux 3.21.7, Redis 7.4.8 (standalone), jemalloc-5.3.0.
- Runtime counts: 17 apk packages, 101 Trivy vulnerability findings (4 critical,
  46 high, 47 medium, 4 low), 18 local users, 36 local groups, one steady-state
  `redis-server` process (PID 1, uid 999), and four unique service listeners.
- Datastore state: `key_value`, 16 logical DBs configured; `db0` (125 keys),
  `db1` (9 keys), and `db13` (22 keys) populated at the snapshot (volatile,
  MISP-driven); RDB persistence at the configured save points, AOF off,
  `noeviction`, `maxmemory 0`.
- Authentication: a single `default` Redis ACL user with `~* &* +@all` and
  `requirepass` enforced; the fixture password is preserved as scenario content.
- Participant discovery: `aptl-misp` resolves `misp-redis` / `aptl-misp-redis`
  to `172.20.0.2` and reaches TCP/6379; `aptl-kali` cannot reach the security-net
  address from its current network vantage.

## Limits

- This is not a destructive fresh-lab reset or byte-identical rebuild proof.
- The Redis auth fixture (`redis-server --requirepass redispassword`) is a
  checked-in scenario realization fact — the provisioning input that reproduces
  this asset — preserved verbatim in the evidence and encoded as a
  `secret_fixture` value in the SDL. It is a disclosed lab credential, not an
  operator secret; generic operator-secret shapes are still scrubbed.
- `misp-redis` declares no named volume; `/data` is backed by an anonymous Docker
  volume (image `VOLUME /data`). The keyspace, per-DB key counts, datatype
  census, and `dump.rdb` are MISP-driven runtime state that drift continuously;
  they are captured as a point-in-time snapshot and `dump.rdb` is excluded from
  content checksums (it can embed cached secret material). The SDL encodes the
  stable shape (key-value model, configured 16 logical DBs, persistence posture)
  with the observed population marked as a snapshot caveat.
- `misp-redis` has no Compose healthcheck (MISP depends on it with
  `service_started`), no on-disk `redis.conf` (configuration is supplied entirely
  via the Compose command), and no scenario-declared vulnerabilities; package
  CVEs are realized-form findings, not authored weaknesses.
- Docker embedded DNS listener ports are backend-generated and ephemeral; the SDL
  records them as node-local runtime listeners with provenance.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/misp-redis
uv run aptl aces-inventory gaps docs/aces/inventory/misp-redis
uv run pytest tests/test_misp_redis_inventory.py -q
```
