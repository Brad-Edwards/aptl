# Wazuh Manager Steady-State Inventory

This directory is the SCN-010 / issue #340 inventory bundle for the TechVault
`wazuh.manager` container. It applies the ACES-owned asset inventory methodology
to the realized `aptl-wazuh-manager` container after ACES #428 added the
`runtime.security_monitoring_managers` surface needed for Wazuh manager state.

This capture is non-destructive. It used the existing running lab as authorized
by the user on 2026-05-29 and did not run `aptl lab stop -v && aptl lab start`.
Use it as a frozen observation of that local steady state, not as clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-wazuh-manager` |
| Compose service | `wazuh.manager` |
| Source class | `upstream-image-plus-mounted-configuration` |
| Image | `wazuh/wazuh-manager:4.12.0` |
| Image digest | `wazuh/wazuh-manager@sha256:dea2fa1e6d5062147b6a85b241f5f501c5f1ba4b817d12bda06f7870a89ad561` |
| Runtime OS | Amazon Linux 2023.8.20250818 |
| Runtime command | `/init` via s6 supervision |
| Reachable participant ports | TCP 1514, TCP 1515, UDP 514, TCP 55000 |
| Network identity | `security-net` 172.20.0.10; `dmz-net` 172.20.1.10; `internal-net` 172.20.2.30 |
| Wazuh version / revision | `v4.12.0` / `rc1` |
| Wazuh agents | 7 available agents in the `default` group |
| Wazuh content | 173 rule files, 123 decoder files, SCA policies, active-response scripts, and CDB lists |
| Package inventory | 118 RPM packages and 322 Syft SBOM components |
| Trivy vulnerability findings | 368 total: critical 8, high 183, medium 157, low 20 |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose service intent and upstream image identity are recorded. | `evidence/compose-service.wazuh.manager.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-buildx-imagetools.image.raw.json` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-network.aptl-dmz.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| Persistent volumes are recorded. | `evidence/docker-volume.wazuh-etc.json`, `evidence/docker-volume.wazuh-logs.json`, `evidence/docker-volume.wazuh-queue.json`, `evidence/docker-volume.wazuh-var-multigroups.json`, `evidence/docker-volume.wazuh-integrations.json`, `evidence/docker-volume.wazuh-active-response.json`, `evidence/docker-volume.wazuh-agentless.json`, `evidence/docker-volume.wazuh-api-configuration.json`, `evidence/docker-volume.wazuh-wodles.json`, `evidence/docker-volume.filebeat-etc.json`, `evidence/docker-volume.filebeat-var.json` |
| Wazuh logical state is recorded. | `evidence/wazuh-manager-state.txt`, `evidence/wazuh-api-probe.json`, `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| OS packages and SBOM component inventories are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is the upstream Wazuh manager 4.12.0 image at
  `wazuh/wazuh-manager@sha256:dea2fa1e6d5062147b6a85b241f5f501c5f1ba4b817d12bda06f7870a89ad561`. APTL contributes Compose wiring, bind-mounted rules/decoders, certificates, and generated configuration.
- The realized runtime OS is Amazon Linux 2023. The image does not include
  `ss`, `netstat`, `ip`, or `mount`; listener and network evidence therefore
  combines Docker inspect/network records with `/proc/net/*` fallback.
- Wazuh reported `v4.12.0` revision `rc1`, with 11 Wazuh daemons running,
  five Wazuh daemons stopped, and Filebeat running as the indexer forwarder.
- The Wazuh manager reported seven available agents in the `default` group:
  DNS, webapp, fileshare, AD, DB, Suricata, and `dc.techvault.local`.
- Loaded Wazuh content is encoded under `runtime.security_monitoring_managers`:
  173 rule XML files, 123 decoder XML files, SCA policies, active-response
  scripts, and CDB lists. File references that came from Wazuh introspection
  but not `filesystem-tree.txt` are represented as Wazuh-state-observed
  filesystem entries without invented stat metadata.
- ACES #434 is consumed through
  `runtime.security_monitoring_managers[].detection_definitions`. The SDL
  encodes 6,121 parsed Wazuh detection definitions: 4,542 rule/correlation-rule
  definitions and 1,579 decoder definitions. The manifest has zero parse errors,
  zero unresolved correlation/parent references, and corpus digest
  `14a7f5a403c4f1546715fa665aa5d026cd0cba2cac37256bce8c28d6edf1e509`.
- Runtime package state is encoded from the normalized Syft CycloneDX SBOM
  (322 components) and RPM package list (118 packages). Trivy captured 368
  vulnerability findings at scan time.
- Raw Wazuh API credentials, indexer credentials, cluster keys, API tokens,
  and private key material are not committed as raw values. SDL records
  redacted value classifications and, for selected filesystem entries, path and
  metadata only.
- Docker-history strings containing braced shell parameter syntax were
  normalized in SDL to shell-equivalent `$VAR` spelling because ACES reserves
  `${...}` for scenario variables. The raw byte-exact history is preserved in
  `evidence/docker-history.image.txt` and `evidence/docker-history.image.jsonl`.

## ACES Mapping Result

Current ACES SDL, including ACES #428, can encode the catalogued Wazuh manager
facts: node identity, upstream image provenance, transport listeners,
host-published ports, runtime mounts, container host configuration, Docker
health, process/environment/capability policy, filesystem inventory, local
identity database, package and vulnerability inventory, and typed Wazuh
security-monitoring manager components, listeners, agents, groups, content
sets, and settings.

No known ACES expressivity gap remains for the catalogued Wazuh manager
steady-state inventory facts in this ledger. The capture does not assert a
destructive clean-lab reset, byte-identical rebuildability, full root filesystem
equivalence outside the scoped capture, or attack-induced state changes.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/wazuh.manager
uv run aptl aces-inventory gaps docs/aces/inventory/wazuh.manager
```

## Known Limits

- The evidence came from an already-running lab, not a destructive fresh reset.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- osquery `apt_sources`, `installed_applications`, and `programs` were not
  applicable or unavailable in the digest-pinned Linux osquery scanner image.
- The Wazuh image lacks some normal runtime inspection tools, so Docker inspect
  and `/proc/net/*` are part of the listener/network evidence path.
