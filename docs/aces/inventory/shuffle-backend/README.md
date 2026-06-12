# Shuffle Backend Inventory

This bundle is the SCN-010 / issue #360 completion-grade steady-state asset
inventory for the `aptl-shuffle-backend` container in TechVault. The target
service is the `shuffle-backend` Compose service (profile `soc`,
family `defensive-soc-app`) running `ghcr.io/shuffle/shuffle-backend:latest`,
resolved at capture time to
`ghcr.io/shuffle/shuffle-backend@sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d`.

The image digest is unchanged from the #353 methodology smoke pass (same image
identity, layers, and attestation), but this pass captures and encodes the full
runtime, application, identity, platform, and relationship surface. It is the
completion artifact, not a smoke test.

The capture used the already-running local lab per operator direction. It was
non-destructive and did not run `aptl lab stop -v && aptl lab start`; treat this
as current-running steady-state evidence, not as clean-lab rebuild proof. The
capture ran at `2026-06-05T06:11:11Z` with Trivy `0.70.0`.

## Encoded Result

`scenarios/techvault/nodes/shuffle-backend.sdl.yaml` (composed into
`scenarios/techvault.sdl.yaml`) now encodes:

- Shuffle backend image identity, history, rootfs layers, and the registry
  SLSA provenance attestation status (captured, not verified).
- Runtime container policy (restart `unless_stopped`, 1 GiB memory limit, runc),
  `runtime.health=null` because no healthcheck is declared in Compose, the
  `aptl_shuffle_data:/shuffle-database` volume mount, the writable
  `/var/run/docker.sock` bind encoded as both a runtime mount and a
  `local_control_interfaces` entry, the PID 1 `./shufflebackend` process
  (root, working dir `/app`, a 119,680,431-byte Go binary), 8 compose-declared
  `SHUFFLE_*` environment variables plus the image `PATH`, including the
  scenario fixture values for `SHUFFLE_DEFAULT_APIKEY`,
  `SHUFFLE_DEFAULT_PASSWORD`, and `SHUFFLE_OPENSEARCH_PASSWORD`, and the
  `security-net` endpoint at
  `172.20.0.20` with no host-published ports (intra-cluster only per
  SEC-006 / ADR-034).
- `runtime.service_listeners` for the wildcard Shuffle API on `:::5001` and the
  two Docker embedded DNS sockets (TCP and UDP on `127.0.0.11`), plus
  `runtime.local_identity` for 17 local users and 35 local groups.
  No known ACES expressivity gap remains for the catalogued shuffle-backend
  steady-state inventory.
- The Shuffle REST API routes (`/api/v1/health` unauthenticated;
  `/api/v1/workflows`, `/apps`, `/users` behind a Bearer API key) under
  `runtime.applications`, the Shuffle org / admin user / admin API-key metadata
  under `runtime.identity_authorities`, and the
  Shuffle SOAR platform state under `runtime.platform_applications`
  (`platform_kind: soar`).
- Package state: 21 Alpine apk packages, the Go `go.mod` dependency manifest,
  157 Go modules as `runtime.software_components`, and 90 Trivy
  `runtime.package_vulnerabilities`.
- The relationship from `shuffle-backend` to `shuffle-opensearch` (datastore,
  `https:9200`, basic auth, TLS verification disabled), encoded as both a
  `platform_application` `upstream_binding` and a `relationships.sdl.yaml` edge
  with a minimal `shuffle-opensearch` companion node stub. Inbound consumers
  (the shuffle-orborus worker, the shuffle-frontend proxy, and the Wazuh
  custom-shuffle alert integration) are observed but owned by future
  SOC-companion inventories.

## Evidence Highlights

- OS/runtime: Alpine Linux 3.22.2, PID 1 `./shufflebackend` running as root,
  working directory `/app`, listener `:::5001` (IPv6 wildcard, HTTP).
- Runtime counts: 2293 filesystem-tree entries, 1309 checksummed files, 16
  curated `filesystem_inventory` paths, 21 apk OS packages, 157 Go modules,
  90 Trivy vulnerability findings (3 critical, 36 high, 25 medium, 23 low,
  3 unknown), 17 local users, 35 local groups, and 3 service listeners.
- Shuffle SOAR logical state (persisted in the shuffle-opensearch datastore,
  OpenSearch 2.14.0; the `aptl_shuffle_data` volume is empty at steady state):
  org `default` (id `08b070b1-0ffd-4990-8b0f-ae1596d6121c`), 1 user `admin`
  (id `c98f23e2-5fd4-4907-9bef-5cd8d46fc8ca`, role admin, active, unverified),
  8 installed workflow-apps (Shuffle AI, Shuffle Subflow x2 versions, Shuffle
  Tools, Sigma, Yara, email, http), a 313-entry OpenAPI app catalogue, 934
  workflow executions (dominated by the periodic self-test workflow
  `05a2f423-080f-4c3d-bad2-ed7474138487` FINISHED), 0 operator-authored
  workflows, and 933 org files.
- Participant discovery: the shuffle-orborus worker resolves and reaches
  `http://shuffle-backend:5001`; Kali's reachability from its current vantage is
  recorded.

## Limits

- This is a steady-state snapshot of the current-running lab; it is not a
  destructive fresh-lab reset or byte-identical rebuild proof.
- SBOM and vulnerability results are scanner state tied to the captured Trivy
  `0.70.0` version and advisory-database state, not permanent truth.
- Scenario fixture secrets are retained verbatim in the committed capture:
  `SHUFFLE_DEFAULT_APIKEY`, the scenario admin password, and the OpenSearch
  password are TechVault scenario content.
- Inbound consumers (shuffle-orborus, shuffle-frontend, the Wazuh
  custom-shuffle integration) are documented as future SOC-companion
  inventories; only the shuffle-opensearch datastore relationship is encoded.
- Shuffle persistent application state lives in the shuffle-opensearch datastore,
  not in the `aptl_shuffle_data` volume, which is empty at steady state.
- Registry-visible SLSA provenance attestation manifests are captured but not
  cryptographically verified (signatures, transparency-log inclusion, and
  builder identity are out of scope for an upstream-image asset pass).

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/shuffle-backend
uv run aptl aces-inventory gaps docs/aces/inventory/shuffle-backend
uv run pytest tests/test_shuffle_backend_inventory.py -q
```
