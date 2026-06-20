# TheHive Elasticsearch Steady-State Inventory

This directory is the SCN-010 / issue #352 inventory bundle for the TechVault
`thehive-es` container. It applies the ACES-owned asset inventory methodology
to the realized `aptl-thehive-es` container at the established granularity bar
(issue #330 depth), following the wazuh-indexer datastore precedent (same
Elasticsearch/OpenSearch family).

`thehive-es` is the Elasticsearch companion in the SOC stack: upstream
`docker.elastic.co/elasticsearch/elasticsearch:7.17.28`, single-node, with
`xpack.security` disabled. The realized TheHive config uses **local Lucene**
indexing (`index.search.backend = lucene`, directory `/data/index`), so this ES
is **not** TheHive's active index backend and TheHive holds no outbound
connection to it. Cortex uses this ES backend and creates the `cortex_6` index;
the ES-internal `.geoip_databases` index is also present. Primary TheHive
case/alert data lives in Cassandra (`thehive-cassandra`). It is inventoried as
the participant datastore node `nodes.techvault.thehive-es`.
On security-net only; ports 9200/9300 are not host-published. There is **no
thehive→es data connection** (index-backend is lucene), so no such relationship
is encoded.
**No known ACES expressivity gap remains** for the catalogued steady-state
facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-10 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **Near-gap, resolved without distortion.** The ACES `search_index` datastore
> profile mandates at least one structured mapping manifest. At steady state the
> ES-internal `.geoip_databases` system index rejects the public `_mapping` /
> `_field_caps` APIs, while Cortex's `cortex_6` mapping is visible normally.
> Both mappings are captured via the operator `_cluster/state/metadata` vantage
> and encoded without changing the `search_index` data model. No ACES issue was
> required.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-thehive-es` |
| Compose service | `thehive-es` |
| TechVault profile | `soc` |
| Family | datastore |
| Source class | `upstream-registry-image-datastore` |
| Image | `docker.elastic.co/elasticsearch/elasticsearch:7.17.28` (upstream registry) |
| Registry digest | `docker.elastic.co/elasticsearch/elasticsearch@sha256:f2ce8a4c644a35762e6e115c9a373c5cd20df03c2dd75cb0a570011934cdffd1` |
| Runtime OS | Ubuntu 20.04.6 LTS |
| Engine | Elasticsearch 7.17.28 (lucene 8.11.3), single-node, `xpack.security` disabled |
| Cluster | `docker-cluster` (uuid `ohJNVSX-TDyF6XOwPk-HLw`), health yellow, 1 node |
| Indices | `.geoip_databases` (ES-internal) and `cortex_6` (Cortex backend); **no TheHive indices** (TheHive uses local Lucene) |
| Reachable participant ports | none host-published; 9200 (REST/HTTP) + 9300 (transport) on security-net |
| Network identity | `security-net` 172.20.0.5 (only network) |
| Memory limit | 1 GiB (`ES_JAVA_OPTS -Xms512m -Xmx512m`) |
| Package inventory | 128 dpkg packages |
| Trivy vulnerability findings | 94 image-layer findings: 23 high, 55 medium, 16 low |
| Local identity | 20 users, 40 groups, 0 sudo rules |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.thehive_es_data.json`, `evidence/docker-top.txt`, `evidence/docker-logs.thehive-es.txt`, `evidence/runtime-baseline.txt` |
| Datastore state and index mapping are recorded. | `evidence/elasticsearch-state.txt`, `evidence/thehive-es-index-mappings.json` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt.gz`, `evidence/filesystem-checksums.txt.xz` |
| Application/runtime versions are recorded. | `evidence/language-manifests.txt` |
| Attacker (kali) vantage is recorded. | `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; lab must be running with the soc profile up)
bash docs/aces/inventory/thehive-es/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/thehive-es
aptl aces-inventory gaps docs/aces/inventory/thehive-es

# Re-run the bundle's correspondence tests
pytest tests/test_thehive_es_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/thehive-es.sdl.yaml`; its datastore, package, CVE,
filesystem, and identity blocks are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.thehive-es` |
| Elasticsearch datastore (engine, cluster, node, partition, mapping, transport, settings) | `nodes.techvault.thehive-es.runtime.datastore_services` (search_index profile) |
| REST / transport listeners | `nodes.techvault.thehive-es.runtime.service_listeners` (9200, 9300) |

All 18 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- The `/usr/share/elasticsearch/data` volume content (runtime index state) is
  excluded from the filesystem manifest (top-level rows only); index state is in
  `elasticsearch-state.txt` + the datastore mappings instead.
- The steady-state indices are `.geoip_databases` and `cortex_6`; mappings are
  captured via the operator `_cluster/state/metadata` vantage.
- `xpack.security.enabled=false` — 9200/9300 carry no TLS/auth; compose isolation
  is the only control.
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the datastore at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope. With `index.search.backend = lucene`,
  TheHive does not create indices in this ES at all; the `--es-hostnames` arg is
  inert under the realized config. Cortex does create `cortex_6`.
