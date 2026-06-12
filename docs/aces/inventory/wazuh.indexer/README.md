# Wazuh Indexer Steady-State Inventory

This directory is the SCN-010 / issue #341 inventory bundle for the TechVault
`wazuh.indexer` container. It applies the ACES-owned asset inventory methodology
to the realized `aptl-wazuh-indexer` container, an upstream Wazuh fork of
OpenSearch 2.19.1 packaged as `wazuh/wazuh-indexer:4.12.0`.

This capture is non-destructive. It used the existing running lab as authorized
by the user on 2026-06-05 and did not run `aptl lab stop -v && aptl lab start`.
Use it as a frozen observation of that local steady state, not as clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-wazuh-indexer` |
| Compose service | `wazuh.indexer` |
| Source class | `upstream-image-plus-mounted-configuration` |
| Image | `wazuh/wazuh-indexer:4.12.0` |
| Image digest | `wazuh/wazuh-indexer@sha256:3691b3b27658695aad0c6879b412a001caf233ebbc1a5ba15647053aa03a2299` |
| Runtime OS | Amazon Linux 2023.8.20250818 |
| Runtime command | `/entrypoint.sh` → `opensearchwrapper` (PID 1 is the OpenSearch JDK java process, UID 1000) |
| Reachable participant ports | TCP 9200 (HTTPS REST API), TCP 9300 (OpenSearch transport, cluster-internal only) |
| Network identity | `security-net` 172.20.0.12 |
| Host-published ports | 9200/tcp on 0.0.0.0 and :: |
| OpenSearch version | 2.19.1 (Wazuh-indexer 4.12.0/rc1, build hash `dae2bfc93896178873b43cdf4781f183c72b238f`) |
| Cluster | single-node `opensearch` cluster, uuid `u-vGl1n0Q7e-SKz1tWvb-w`, status green |
| Indices | 41 indices, 102 primary shards, 1,053,842 documents, ~1.39 GB store (per-index uuid/doc-count/store-size + per-family mapping schema encoded via ACES #468/#469 — see ACES Mapping Result) |
| Plugins | 18 installed OpenSearch plugins at 2.19.1.0 (alerting, anomaly-detection, asynchronous-search, cross-cluster-replication, geospatial, index-management, job-scheduler, knn, ml, neural-search, notifications, notifications-core, observability, performance-analyzer, reports-scheduler, security, security-analytics, sql) |
| Internal users | 6 OpenSearch Security built-in users (`admin`, `kibanaserver`, `kibanaro`, `logstash`, `readall`, `snapshotrestore`); bcrypt hashes captured verbatim |
| Package inventory | 110 RPM packages and 840 Syft SBOM components |
| Trivy vulnerability findings | 276 total: critical 0, high 135, medium 123, low 18 (130 unique CVE IDs) |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose service intent and upstream image identity are recorded. | `evidence/compose-service.wazuh.indexer.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-buildx-imagetools.image.raw.json` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| Persistent volume is recorded. | `evidence/docker-volume.wazuh-indexer-data.json` |
| OpenSearch logical state is recorded. | `evidence/wazuh-indexer-state.txt`, `evidence/wazuh-indexer-api-probe.json`, `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Structured index mappings + template bodies are recorded and encoded as typed mappings/templates. | `evidence/wazuh-indexer-templates.json.gz`, `evidence/wazuh-indexer-family-mappings.json.gz`, `evidence/wazuh-indexer-index-mappings-census.json` |
| OS packages and SBOM component inventories are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is the upstream Wazuh indexer 4.12.0 image at
  `wazuh/wazuh-indexer@sha256:3691b3b27658695aad0c6879b412a001caf233ebbc1a5ba15647053aa03a2299`.
  APTL contributes Compose wiring, the bind-mounted `opensearch.yml` and
  `internal_users.yml`, and the generated TLS PEM material under
  `config/wazuh_indexer_ssl_certs/`.
- The realized runtime OS is Amazon Linux 2023. As with the Wazuh manager
  image, `ss`, `netstat`, `ip`, `mount`, and `ps` are not in the image;
  listener and process evidence combines Docker inspect/network records,
  `/proc/net/*`, and a `/proc/[0-9]*/{status,cmdline}` enumeration.
- PID 1 is the OpenSearch JDK Java process (`/usr/share/wazuh-indexer/jdk/bin/java
  ... org.opensearch.bootstrap.OpenSearch`) running as the `wazuh-indexer`
  user with a 2 GB Docker memory limit, `memlock=-1` (unbounded), `nofile=65536`,
  `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`, and an empty effective capability set
  (`CapEff=0`, with the Docker default bounding set `CapBnd=a80425fb`).
- The Docker healthcheck `curl -ks https://localhost:9200` is graded healthy
  because the OpenSearch Security plugin returns HTTP/1.1 401 Unauthorized
  without credentials; that response is the readiness signal Compose consumes.
  Authenticated state queries used `INDEXER_USERNAME` / `INDEXER_PASSWORD`
  from the lab `.env` passed only via `docker exec` env vars; raw values are
  never written to evidence.
- OpenSearch reported version 2.19.1 (`build_hash
  dae2bfc93896178873b43cdf4781f183c72b238f`, build_type `rpm`), single-node
  cluster `opensearch` (uuid `u-vGl1n0Q7e-SKz1tWvb-w`, status green, 41
  indices, 102 primary shards, 1,053,842 documents, ~1.39 GB store at snapshot
  time) and the node carries `cluster_manager`, `data`, `ingest`, and
  `remote_cluster_client` roles. The cluster `uuid` and these aggregate
  cardinality/size totals are encoded on `RuntimeDatastoreCluster` (ACES #468).
- 18 OpenSearch plugins are installed at 2.19.1.0, including the
  `opensearch-security`, `opensearch-security-analytics`,
  `opensearch-performance-analyzer`, and the OpenSearch Alerting / ML /
  Notifications stacks. Plugin **names and per-plugin versions** are encoded as
  typed `RuntimeDatastoreEnginePlugin` entries (ACES #470), alongside the rest of
  the node engine provenance (`build_hash`, JVM heap, publish endpoints).
- Indexed content is the standard TechVault Wazuh layout: `wazuh-alerts-4.x-*`
  daily indices, `wazuh-archives-4.x-*` daily indices,
  `wazuh-monitoring-2026.*w` weekly indices, `wazuh-statistics-2026.*w`
  weekly indices, the `wazuh-states-vulnerabilities-wazuh.manager` system
  index, plus the bootstrap OpenSearch system indices
  (`.kibana_1`, `.opendistro_security`, `.opensearch-observability`,
  `.plugins-ml-config`). Each index's **name, shard geometry, and health** are
  encoded as a `RuntimeDatastorePartition`; each index's `uuid`, doc count,
  store size, creation date, and open/closed status are encoded on the same
  `RuntimeDatastorePartition` (ACES #468), and the per-family structured field
  mapping (up to 947 leaf fields for `wazuh-archives-*`) is encoded as a
  `RuntimeDatastoreMapping` with its field-type census (ACES #469).
- Persistence is rooted at `path.home=/usr/share/wazuh-indexer`,
  `path.data=/var/lib/wazuh-indexer` (backed by the `wazuh-indexer-data`
  named volume), `path.logs=/var/log/wazuh-indexer`. No snapshot repository
  is registered (no `path.repo`).
- Transport security is OpenSearch Security mutual TLS using bind-mounted
  PEM material under `/usr/share/wazuh-indexer/certs/`. The admin DN
  allowlist is `CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US`; transport
  hostname verification is disabled (default Wazuh-indexer posture).
  Private-key checksum values are retained as in-range scenario evidence.
- The OpenSearch Security HTTP authc chain has six declared domains; only
  `basic_internal_auth_domain` (order 4, basic auth, internal backend) is
  HTTP-enabled. The two LDAP authz domains are disabled. The realized
  authentication path is therefore basic auth against the internal users
  authority on the HTTP layer.
- Six built-in internal users live in the bind-mounted
  `internal_users.yml`: `admin` (reserved), `kibanaserver` (reserved),
  `kibanaro`, `logstash`, `readall`, `snapshotrestore`. Bcrypt hashes,
  reserved/hidden flags, role memberships, and the three demo attributes on
  `kibanaro` are kept.
- Runtime package state is encoded from the normalized Syft CycloneDX SBOM
  (840 components, JDK + bundled OpenSearch jars) and RPM package list
  (110 packages). Trivy captured 276 vulnerability findings (130 unique
  CVE IDs) at scan time: 135 HIGH, 123 MEDIUM, 18 LOW, zero CRITICAL.
- Docker-history strings containing braced shell parameter syntax were
  normalized in SDL to shell-equivalent `$VAR` spelling because ACES reserves
  `${...}` for scenario variables. The raw byte-exact history is preserved in
  `evidence/docker-history.image.txt` and `evidence/docker-history.image.jsonl`.

## ACES Mapping Result

Current ACES SDL encodes most catalogued Wazuh indexer facts: node identity,
upstream image provenance, transport listeners, host-published ports, runtime
mounts, container host configuration, Docker health, process/environment/
capability policy, filesystem inventory, local identity database, package and
vulnerability inventory, and the typed OpenSearch datastore service —
cluster identity, node membership/roles, per-index partition shard geometry,
persistence, `transport_security`, `settings`, and plugin/template **names** —
plus the OpenSearch Security internal users, roles, role mappings, and
authc/authz chain on `runtime.identity_authorities`. The
`runtime.datastore_services` spine (with `engine=opensearch`,
`data_model=search_index`, `partition_kind=index`) carries the
OpenSearch-specific surface.

### ACES expressivity — fully encoded

Three catalogued observable surfaces previously had no typed ACES home and were
recorded as `blocked_by_aces_gap` facts pending upstream ACES work. **Those ACES
surfaces have now landed on aces `dev` and every surface is encoded from the
captured evidence. No known ACES expressivity gap remains:**

- **Search-index cardinality, size, and identity** — per-index `uuid`,
  `doc_count`, `doc_count_deleted`, `store_size_bytes`, `creation_timestamp`,
  `open_closed_status`, and the cluster-level `uuid` + aggregate
  `node_count`/`shard_total`/`shard_primaries`/`doc_count`/`store_size_bytes`,
  now typed on `RuntimeDatastoreCluster`/`RuntimeDatastorePartition`.
  → resolved by **[Brad-Edwards/aces#468](https://github.com/Brad-Edwards/aces/issues/468)**.
- **Structured index mapping + template-body inventory** — the field→type
  census each index family enforces (wazuh-archives mappings reach 947 leaf
  fields) and the index-template bodies that seed them, now typed on
  `RuntimeDatastoreMapping` (per-family schema geometry, field-type census,
  dynamic policy, schema digest) and the structured `RuntimeDatastoreTemplate`
  (index_patterns, settings_summary, template digest).
  → resolved by **[Brad-Edwards/aces#469](https://github.com/Brad-Edwards/aces/issues/469)**.
- **Datastore node engine provenance** — engine `version`, `build_hash`,
  `build_type`, JVM heap posture, the http/transport publish endpoint split, and
  typed per-plugin versions, now typed on `RuntimeDatastoreNode` +
  `RuntimeDatastoreEnginePlugin` + `RuntimeDatastoreNodeEndpoint`.
  → resolved by **[Brad-Edwards/aces#470](https://github.com/Brad-Edwards/aces/issues/470)**.

The capture does not assert a destructive clean-lab reset, byte-identical
rebuildability, full root filesystem equivalence outside the scoped capture, or
attack-induced state changes.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/wazuh.indexer
uv run aptl aces-inventory gaps docs/aces/inventory/wazuh.indexer
```

## Known Limits

- The evidence came from an already-running lab, not a destructive fresh reset.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- osquery `apt_sources`, `installed_applications`, and `programs` were not
  applicable or unavailable in the digest-pinned Linux osquery scanner image.
- The Wazuh indexer image lacks the normal runtime inspection tools (`ss`,
  `netstat`, `ip`, `mount`, `ps`), so Docker inspect, `/proc/net/*`, and
  `/proc/[0-9]*` enumeration are part of the listener / network / process
  evidence path.
- The OpenSearch security plugin's full role catalogue is bound to the
  `opensearch-security` plugin's source; this inventory records the realized
  role-set names, reserved/hidden flags, and high-level permission shape
  rather than every individual role's exhaustive `index_permissions`
  spec.
