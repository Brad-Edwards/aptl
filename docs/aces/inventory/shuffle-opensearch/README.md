# Shuffle OpenSearch Steady-State Inventory

This directory is the SCN-010 / issue #356 inventory bundle for the TechVault
`shuffle-opensearch` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-shuffle-opensearch` container at the
established granularity bar (issue #330 depth), following the
wazuh-indexer / thehive-es datastore precedents (same OpenSearch/Elasticsearch
family).

`shuffle-opensearch` is the **Shuffle SOAR persistence datastore**: upstream
`opensearchproject/opensearch:2.14.0`, single-node, with the Security plugin
**enabled** (HTTPS + basic auth). It holds all Shuffle state across 24 indices
(workflows, executions, apps, organizations, users, notifications, security
config). It is promoted from a stub to the participant datastore node
`nodes.techvault.shuffle-opensearch`. `shuffle-backend` is the sole consumer
(`relationships.shuffle-backend-connects-opensearch`); ports 9200/9300/9600 are
not host-published. **No known ACES expressivity gap remains** for the
catalogued steady-state facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-11 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **Secret fixture.** `OPENSEARCH_INITIAL_ADMIN_PASSWORD` is a committed
> scenario fixture (value present in `docker-compose.yml`) — kept verbatim in
> the SDL `runtime.environment` per the secret-fixture policy (it is redacted in
> the `docker-inspect` evidence and preserved in the authored compose block).

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-shuffle-opensearch` |
| Compose service | `shuffle-opensearch` |
| TechVault profile | `soc` |
| Family | datastore |
| Source class | `upstream-registry-image-datastore` |
| Image | `opensearchproject/opensearch:2.14.0` (upstream registry) |
| Registry digest | `opensearchproject/opensearch@sha256:466a49f379bb8889af29d615475e69b7b990898c6987d28470cd7105df9046ff` |
| Runtime OS | Amazon Linux 2023 |
| Engine | OpenSearch 2.14.0 (lucene 9.10.0), single-node, Security plugin **enabled** |
| Cluster | `docker-cluster` (uuid `smPCS7KBQYWuyqcH7AWKCg`), health yellow (single-node replicas unassigned), 1 node |
| Indices | 24 (workflows, executions, apps, orgs, users, notifications, `.opendistro_security`, …) |
| Reachable participant ports | none host-published; 9200 (REST/HTTPS) + 9300 (transport) + 9600 (perf analyzer) on security-net |
| Network identity | `security-net` 172.20.0.2 (only network) |
| Memory limit | 1 GiB (`OPENSEARCH_JAVA_OPTS -Xms512m -Xmx512m`) |
| Package inventory | 110 rpm packages |
| Trivy vulnerability findings | 410 image-layer findings: 2 critical, 180 high, 210 medium, 18 low |
| Local identity | 14 users, 25 groups, 0 sudo rules |
| Software components | OpenSearch 2.14.0 + 445 embedded Maven/JAR components (SBOM catalogue) |
| Security-plugin internal users | 7 (incl. reserved `admin`), captured via `_plugins/_security` REST |
| PID 1 capabilities | CapEff=0x0 — the non-root JVM holds an EMPTY effective set (CapBnd is the Docker default) |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.shuffle_opensearch_data.json`, `evidence/docker-top.txt`, `evidence/docker-logs.shuffle-opensearch.txt`, `evidence/runtime-baseline.txt` |
| Datastore state and index mappings are recorded. | `evidence/opensearch-state.txt`, `evidence/shuffle-opensearch-index-mappings.json` |
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
bash docs/aces/inventory/shuffle-opensearch/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/shuffle-opensearch
aptl aces-inventory gaps docs/aces/inventory/shuffle-opensearch

# Re-run the bundle's correspondence tests
pytest tests/test_shuffle_opensearch_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/shuffle-opensearch.sdl.yaml`; its datastore, package,
CVE, filesystem, and identity blocks are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.shuffle-opensearch` |
| OpenSearch datastore (engine, cluster, node, 24 partitions, 24 mappings, transport, settings) | `nodes.techvault.shuffle-opensearch.runtime.datastore_services` (search_index profile) |
| REST / transport / perf-analyzer listeners + Docker embedded-DNS loopback sockets | `nodes.techvault.shuffle-opensearch.runtime.service_listeners` (9200, 9300, 9600 wildcard; 127.0.0.11 loopback_only) |
| `shuffle_opensearch_data` volume (all index state) | `nodes.techvault.shuffle-opensearch.runtime.mounts` |
| 445 embedded Maven/JAR components | `nodes.techvault.shuffle-opensearch.runtime.software_components` |
| Security-plugin internal user database | `nodes.techvault.shuffle-opensearch.runtime.identity_authorities.opensearch-security-internal-users` |
| Initial admin password | `secret_fixture` value on `runtime.environment` (committed in `docker-compose.yml`) |

All 20 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- The minimal Amazon Linux 2023 image lacks `find`/`xargs`/`ss`/`netstat`; the
  filesystem manifest was rebuilt via in-container `python` os.walk (precedent
  column format preserved), and listener/connection evidence falls back to
  `/proc/net/*`.
- The `/usr/share/opensearch/data` volume content is excluded from the manifest
  (top-level rows only); index/document state is in the datastore mappings +
  `opensearch-state.txt`.
- `OPENSEARCH_INITIAL_ADMIN_PASSWORD` is a committed scenario fixture, kept
  verbatim; mappings and the Security-plugin internal-user database were read
  with admin auth via the `_mapping` and `_plugins/_security` APIs (the REST API
  redacts password hashes server-side).
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- osquery `installed_applications` / `programs` unavailable in the scanner image;
  `apt_sources` not applicable to the Amazon Linux 2023 target.

## Claims Framing

- This bundle establishes a *spec* for the datastore at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope.
