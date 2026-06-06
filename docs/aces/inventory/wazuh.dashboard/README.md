# Wazuh Dashboard Steady-State Inventory

This directory is the SCN-010 / issue #342 inventory bundle for the TechVault `wazuh.dashboard` container. It applies the ACES-owned asset inventory methodology to the realized `aptl-wazuh-dashboard` container.

This capture is non-destructive. It used the existing running lab as authorized by the user on 2026-06-06 and did not run `aptl lab stop -v && aptl lab start`. Use it as a frozen observation of that local steady state, not as clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-wazuh-dashboard` |
| Compose service | `wazuh.dashboard` |
| Source class | `upstream-image-plus-mounted-configuration` |
| Image | `wazuh/wazuh-dashboard:4.12.0` |
| Image digest | `wazuh/wazuh-dashboard@sha256:8f5b50fde67a0b1c4d2321aa26b12bbc5cef21269cf4f6225746f0b946458bd7` |
| Runtime OS | Amazon Linux 2023.8.20250818 |
| Runtime entrypoint | `/entrypoint.sh` as `wazuh-dashboard` |
| Reachable participant port | HTTPS TCP 5601, host-published as TCP 443 |
| Network identity | `security-net` 172.20.0.11 |
| Dashboard / Wazuh versions | OpenSearch Dashboards 2.19.1; Wazuh dashboard 4.12.0 rc1 |
| Package inventory | 108 RPM packages, 1594 Syft SBOM components |
| Trivy vulnerability findings | 378 total: critical 10, high 183, medium 160, low 25 |
| Filesystem evidence | 91312 exported rootfs metadata rows; 78821 checksum rows |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, limits, and checksums are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt`, `evidence/evidence-sha256sums.txt` |
| Compose service intent and upstream image identity are recorded. | `evidence/compose-service.wazuh.dashboard.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt`, `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json` |
| Dashboard configuration and logical surface are recorded with secret redaction. | `evidence/dashboard-config-files.redacted.txt`, `evidence/wazuh-dashboard-state.txt`, `evidence/wazuh-dashboard-probe.json`, `evidence/language-manifests.txt` |
| Persistent dashboard volumes are recorded. | `evidence/docker-volume.wazuh-dashboard-config.json`, `evidence/docker-volume.wazuh-dashboard-custom.json` |
| Filesystem inventory is recorded. | `evidence/filesystem-tree.txt.gz.part-*`, `evidence/filesystem-checksums.txt.xz.part-*` |
| OS packages and SBOM component inventories are recorded. | `evidence/os-packages.txt`, `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Captured facts are mapped to current ACES surfaces. | `mapping-ledger.yaml`, `scenarios/techvault/nodes/wazuh-dashboard.sdl.yaml` |

## Capture Findings

- The runtime image is the upstream Wazuh dashboard 4.12.0 image at `wazuh/wazuh-dashboard@sha256:8f5b50fde67a0b1c4d2321aa26b12bbc5cef21269cf4f6225746f0b946458bd7`. APTL contributes Compose wiring, TLS certificate binds, OpenSearch Dashboards configuration, and generated Wazuh API connection configuration.
- The realized runtime OS is Amazon Linux 2023. The image does not include `find`, `tar`, `ps`, `ss`, `netstat`, `ip`, or `mount`, so runtime evidence combines Docker inspect/network records, `docker top`, osquery namespace sharing, `/proc/net/*` fallback, and host-side `docker export` rootfs capture. The full compressed filesystem manifests are chunked as `filesystem-tree.txt.gz.part-*` and `filesystem-checksums.txt.xz.part-*` so the evidence remains complete while each committed file stays below the repository large-file gate.
- The dashboard reports OpenSearch Dashboards 2.19.1 and Wazuh dashboard 4.12.0 rc1. The Wazuh plugin package reports revision `03` and uses the default route `/app/wz-home`.
- The HTTPS listener is bound on container TCP 5601 and host-published on TCP 443. Unauthenticated `/api/status` returns HTTP 401 JSON; unauthenticated `/` redirects to `/app/login?`.
- Raw Wazuh API credentials, indexer credentials, dashboard credentials, cookies, and private key material are not committed as raw values. SDL records redacted value classifications and selected filesystem entries carry path and metadata only.

## ACES Mapping Result

Current ACES SDL can encode the catalogued Wazuh dashboard facts: node identity, upstream image provenance, transport listener, host-published port, runtime mounts, container host configuration, Docker health, process/environment/capability policy, filesystem inventory, local identity database, package and vulnerability inventory, application routes, and typed `runtime.platform_applications` analytics-dashboard platform state.

No known ACES expressivity gap remains for the catalogued Wazuh dashboard steady-state inventory facts in this ledger. The capture does not assert a destructive clean-lab reset, byte-identical rebuildability, full byte-for-byte root filesystem equivalence from SDL alone, or attack-induced state changes.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/wazuh.dashboard
uv run aptl aces-inventory gaps docs/aces/inventory/wazuh.dashboard
```

## Known Limits

- The evidence came from an already-running lab, not a destructive fresh reset.
- The capture does not prove byte-identical rebuildability or full root filesystem equivalence.
- Vulnerability results are time-sensitive to the Trivy database and advisory feeds.
- osquery `apt_sources`, `installed_applications`, and `programs` were not applicable or unavailable in the digest-pinned Linux osquery scanner image.
- Secret-bearing runtime configuration and private-key material are redacted or omitted from committed evidence.
