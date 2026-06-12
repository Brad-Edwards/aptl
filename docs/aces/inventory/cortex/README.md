# Cortex Steady-State Inventory

This directory is the SCN-010 / issue #357 inventory bundle for the TechVault `cortex` container. It applies the ACES asset inventory methodology to the realized `aptl-cortex` service after a clean lab reset/start and after TheHive/Cortex integration was repaired.

`cortex` is the lab's **SOC analyzer engine**: upstream `thehiveproject/cortex:3.1.8` (Cortex 3.1.8-1, Play 2.8.19 on Debian 11), serving HTTP on 9001 (published `9001:9001`, security-net `172.20.0.22`). Cortex stores organization/user metadata in the shared `thehive-es` Elasticsearch service using the `cortex_6` index. The TheHive consumer authenticates with a seeded service account (`aptl-svc@cortex.local`, roles `read,analyze,orgadmin`) whose raw fixture key/password are redacted from evidence.

HTTPS is intentionally deferred for Cortex 3.1.8 under ADR-034 because the bundled Play SSL provider fails at runtime. The repaired integration uses HTTP on the internal Docker network plus Cortex key auth (`auth.provider = ["local", "key"]`). The Elasticsearch index is pre-created by `cortex-index-init` so `relations`, `status`, and `key` are `keyword` fields; otherwise Cortex key-auth term queries miss dynamically-created `text` fields.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-cortex` |
| Compose service | `cortex` |
| TechVault profile | `soc` |
| Family | defensive-soc-app |
| Source class | `upstream-registry-image-application` |
| Image | `thehiveproject/cortex:3.1.8` |
| Registry digest | `thehiveproject/cortex@sha256:ae8b3d72eb5de785513bc33492d93278c32b79d9ff89401463c3a9c577e0bc0b` |
| Runtime OS | Debian GNU/Linux 11 (bullseye) |
| Application | Cortex 3.1.8-1 / Play 2.8.19 / Elastic4Play 1.13.6 |
| Backend | `thehive-es` Elasticsearch over HTTP/9200, index `cortex_6` |
| Reachable participant ports | HTTP `9001` (published to host `9001:9001`; not reachable from Kali because security-net is isolated) |
| Network identity | `security-net` 172.20.0.22 |
| Memory limit | 512 MiB |
| Package inventory | 213 dpkg packages |
| Trivy vulnerability findings | 1060 image-layer findings: 44 critical, 258 high, 307 low, 426 medium, 25 unknown |
| Local identity | 24 users, 44 groups, 0 sudo rules |
| Filesystem manifest | 176 rows, 165 checksummed files |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.cortex_data.json`, `evidence/docker-top.txt`, `evidence/docker-logs.cortex.txt`, `evidence/runtime-baseline.txt` |
| Cortex application state and TheHive auth are recorded. | `evidence/cortex-state.txt`, `evidence/cortex-index-documents.redacted.json`, `evidence/thehive-cortex-auth-current-user.json`, `evidence/participant-discovery.kali.txt` |
| Filesystem and package inventory are recorded. | `evidence/filesystem-tree.txt.gz`, `evidence/filesystem-checksums.txt.xz`, `evidence/os-packages.txt`, `evidence/language-manifests.txt` |
| Required + useful-optional scanners are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/trivy-vulnerabilities.json.xz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Lab must be running after a clean start with the soc profile up.
bash docs/aces/inventory/cortex/capture-evidence.sh

aptl aces-inventory validate docs/aces/inventory/cortex
aptl aces-inventory gaps docs/aces/inventory/cortex
pytest tests/test_cortex_inventory.py -q
```

The authored SDL node lives at `scenarios/techvault/nodes/cortex.sdl.yaml`. Relationship edges are `relationships.cortex-connects-thehive-es` and `relationships.thehive-connects-cortex`.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.cortex` |
| Cortex HTTP API | `nodes.techvault.cortex.runtime.applications.cortex-api` |
| HTTP listener | `nodes.techvault.cortex.runtime.service_listeners` (9001) |
| Local/key auth and seeded APTL service account | `nodes.techvault.cortex.runtime.app_authorizations` |
| Elasticsearch dependency | `relationships.cortex-connects-thehive-es` |
| TheHive consumer integration | `relationships.thehive-connects-cortex` |

All catalogued facts in `mapping-ledger.yaml` are `encoded` or `encoded_with_caveat`; No known ACES expressivity gap remains for the catalogued Cortex steady-state facts.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Capture used `COMPOSE_BAKE=false` because local Docker Compose Buildx Bake hung; this is a local startup workaround, not a scenario setting.
- Cortex HTTPS is deferred by ADR-034; HTTP plus key auth is the realized steady-state integration.
- Raw API key and bootstrap password values are redacted; evidence records identity, role, and auth-success facts.
- `cortex_data` had no analyzer job artifacts at snapshot time; future job output is dynamic state.
- Syft output is normalized by stripping `syft:location:*` properties.
- Some osquery tables are not meaningful from the digest-pinned namespace-sharing scanner; Docker inspect and dpkg evidence cover those facts.

## Claims Framing

This bundle establishes a steady-state asset spec for Cortex at the captured point in time. It does not prove byte-identical rebuildability or future analyzer job behaviour. Any dynamic analyzer jobs created after the snapshot are out of this capture and should be inventoried as time-dynamic/runtime-output work.
