# TheHive Cassandra Steady-State Inventory

This directory is the SCN-010 / issue #351 inventory bundle for the TechVault
`thehive-cassandra` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-thehive-cassandra` container at the
established granularity bar (issue #330 depth), following the wazuh-indexer
datastore precedent.

`thehive-cassandra` is TheHive's **primary case/alert datastore**: upstream
`cassandra:4.1`, single-node, holding application data in the `thehive`
keyspace. It is inventoried as the participant datastore node
`nodes.techvault.thehive-cassandra`. Reached only on security-net by the
thehive node (`relationships.thehive-connects-cassandra`); CQL/9042, inter-node
7000, and JMX 7199 are not host-published.
**No known ACES expressivity gap remains** for the catalogued steady-state
facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-10 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **Keyspace scoping (no distortion).** The ACES `wide_column` profile requires
> each keyspace partition to carry a `replication_factor`. The four
> SimpleStrategy keyspaces — `thehive` (RF 1), `system_auth` (RF 1),
> `system_distributed` (RF 3), `system_traces` (RF 2) — are encoded as keyspace
> partitions. The LocalStrategy (`system`, `system_schema`) and virtual
> (`system_virtual_schema`, `system_views`) keyspaces have no replication factor
> (Cassandra engine internals) and are recorded in `cassandra-keyspaces.txt`
> evidence rather than fabricated as partitions. The participant-relevant
> `thehive` keyspace is fully encoded.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-thehive-cassandra` |
| Compose service | `thehive-cassandra` |
| TechVault profile | `soc` |
| Family | datastore |
| Source class | `upstream-registry-image-datastore` |
| Image | `cassandra:4.1` (upstream registry) |
| Registry digest | `cassandra@sha256:bfc28ce8118c09cd32840684f5c31b664f505d0f3e46898147864b18ccefcca0` |
| Runtime OS | Debian GNU/Linux 12 (bookworm) |
| Engine | Apache Cassandra 4.1.11, single-node, Murmur3Partitioner |
| Cluster | `thehive` (host `fd42dafe-...`), datacenter1/rack1, 16 vnode tokens, 100% ownership |
| Keyspaces (replicated) | `thehive` RF1, `system_auth` RF1, `system_distributed` RF3, `system_traces` RF2 |
| Reachable participant ports | none host-published; 9042 (CQL) + 7000 (inter-node) + 7199 (JMX, loopback) on security-net |
| Network identity | `security-net` 172.20.0.5 (only network) |
| Memory limit | 1 GiB (`MAX_HEAP_SIZE=512M`) |
| Package inventory | 122 dpkg packages |
| Trivy vulnerability findings | 398 image-layer findings: 15 critical, 55 high, 191 medium, 132 low, 5 unknown |
| Local identity | 19 users, 39 groups, 0 sudo rules |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.thehive_cassandra_data.json`, `evidence/docker-top.txt`, `evidence/docker-logs.thehive-cassandra.txt`, `evidence/runtime-baseline.txt` |
| Datastore state and keyspace replication are recorded. | `evidence/cassandra-state.txt`, `evidence/cassandra-keyspaces.txt` |
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
bash docs/aces/inventory/thehive-cassandra/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/thehive-cassandra
aptl aces-inventory gaps docs/aces/inventory/thehive-cassandra

# Re-run the bundle's correspondence tests
pytest tests/test_thehive_cassandra_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/thehive-cassandra.sdl.yaml`; its datastore, package,
CVE, filesystem, and identity blocks are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.thehive-cassandra` |
| Cassandra datastore (engine, cluster, node, keyspace partitions, transport, settings) | `nodes.techvault.thehive-cassandra.runtime.datastore_services` (wide_column profile) |
| CQL / inter-node / JMX listeners | `nodes.techvault.thehive-cassandra.runtime.service_listeners` (9042, 7000, 7199) |

All 18 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- The `/var/lib/cassandra` volume content (commitlog, data, hints,
  saved_caches) is excluded from the filesystem manifest (top-level rows only);
  schema-level state is in `cassandra-state.txt` + the datastore keyspaces.
- The LocalStrategy (`system`, `system_schema`) and virtual
  (`system_virtual_schema`, `system_views`) keyspaces carry no replication
  factor and are recorded in `cassandra-keyspaces.txt` but not encoded as
  wide_column keyspace partitions.
- The `cassandra:4.1` floating tag has moved past the locally-pinned RepoDigest
  since the lab pulled it; `source.version` records the deployed digest.
- CQL (9042) is cleartext on security-net; the `cassandra.yaml` authenticator
  config was not captured this pass.
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the datastore at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope.
