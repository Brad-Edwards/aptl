# Webapp Steady-State Inventory

This directory is the SCN-010 / issue #330 inventory bundle for the TechVault
`webapp` container. It applies the methodology in
`docs/aces/inventory/asset-inventory-methodology.md` to the realized
`aptl-webapp` container.

The capture used an already-running local lab on 2026-05-21. It did not run
`aptl lab stop -v && aptl lab start`; in other words, this bundle does
not run `aptl lab stop -v && aptl lab start`, because that would destroy the
user's current lab state. Treat this as a frozen steady-state artifact for the
observed lab instance, not as a clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-webapp` |
| Compose service | `webapp` |
| TechVault profile | `enterprise` |
| Source class | `custom-build` |
| Source package | `containers/webapp/` plus `containers/_wazuh-agent/` |
| Image tag | `aptl-webapp:latest` |
| Image digest | `aptl-webapp@sha256:7f2c715f953094ae36c10d15fbb038f0fdc6b855fd052236a95ad040410a25e0` |
| Runtime OS | Debian GNU/Linux 13 (trixie) |
| Runtime command | `/usr/bin/python3 /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf` |
| Working directory | `/app` |
| Listener | `0.0.0.0:8080` |
| Network identity | `aptl_aptl-dmz` IPv4 `172.20.1.20`; `aptl_aptl-internal` IPv4 `172.20.2.25` |
| Data volume | `aptl_webapp_logs:/var/log/gunicorn` |
| Privileged runtime surface | `CAP_NET_ADMIN` for in-process Wazuh active response |
| Supervised programs | `gunicorn`, `rsyslog`, in-process Wazuh agent |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt` |
| Docker Compose service intent is represented by the redacted Compose service slice. | `evidence/compose-service.webapp.json` |
| Custom image identity, config, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt` |
| Source package inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-dmz.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.webapp-logs.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages and language manifests visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| Important filesystem paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or gap issues. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is a first-party custom build from
  `containers/webapp/Dockerfile`, with Wazuh agent support copied from
  `containers/_wazuh-agent/`.
- The image uses Debian 13 (trixie) through `python:3.11-slim` lineage, but the
  mutable base tag was not present locally after the build. The observed local
  image digest is therefore the reproducibility anchor for this capture.
- The web application exposes HTTP on `8080/tcp`, bound to `0.0.0.0:8080`
  inside the container and published on host port `8080`.
- The container runs as root and PID 1 is `supervisord`. The load-bearing child
  process set includes `gunicorn`, `rsyslog`, and the in-process Wazuh agent.
- The named volume `aptl_webapp_logs` is mounted at `/var/log/gunicorn`; the
  Wazuh agent tails `access.log` from that path.
- `CAP_NET_ADMIN` is present because the in-process Wazuh agent's
  `firewall-drop` active response needs to manipulate iptables in the webapp
  namespace.
- The Trivy evidence captured 469 package vulnerability findings at scan time:
  17 critical, 76 high, 209 medium, and 167 low.
- Secret-shaped env-var values in Docker/Compose evidence were redacted before
  committing the bundle. The webapp intentionally contains participant-visible
  fixture secrets in checked-in source and runtime endpoints; those are scenario
  facts, not operator-control-plane secrets.

## ACES Mapping Result

Current ACES SDL encodes the webapp's node identity, source image pin,
network links, service exposure, healthcheck, full observed runtime mount table,
focused runtime filesystem inventory with metadata and digests, container
host/security configuration, health observation logs, primary process,
supervised process set, observed runtime environment, Linux capabilities,
restart/resource policy, package inventory, scanner findings, scenario weakness
IDs, relationships, ACES-content entries for source placement, full local
identity database records for the observed `/etc/passwd` and `/etc/group`
surfaces, and local account records for the observed `/etc/passwd` users in
`scenarios/techvault.sdl.yaml`.

ACES #354 is closed and covers the runtime fields for mounts, primary process,
packages, dependency manifests, and scanner-derived package findings. ACES #358
is closed and covers container runtime environment classification, Linux
capability/restart policy, resource limits, and supervised process sets; those
fields are now used by the TechVault SDL.

ACES #363 is closed and covers runtime filesystem metadata, permissions,
ownership, checksums, stability, and first-class digest fields. ACES #364 is
closed and covers container image build provenance: Dockerfile instructions,
image history/layers, copied source mappings, source checksums, image-default
configuration, and attestation status. ACES #365 is closed and covers local
identity database users, UID/GID values, primary groups, GECOS/home/shell
fields, group records, and sudo-rule inventory. ACES #368 is closed and covers
container HostConfig, namespace/security settings, health logs, and full mount
filesystem facts. Those fields are now used by the TechVault SDL.

Full observable parity is still blocked on ACES expressivity gaps, not waived by
the evidence bundle:

- ACES #366: Docker network aliases, endpoint metadata, MACs, DNS names, and
  published host bindings.
- ACES #367: application HTTP route/API/UI inventory.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/webapp
aptl aces-inventory gaps docs/aces/inventory/webapp
```

## Known Limits

- The evidence came from a running lab, not a clean reset.
- The capture does not prove byte-identical rebuildability.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- The ACES SDL records the captured package and scanner inventories from this
  frozen evidence bundle. Vulnerability records remain time-sensitive to the
  Trivy database and advisory feeds.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications. Observable steady-state fields that
  current ACES cannot express are explicitly blocked by ACES #366-#367 rather
  than treated as out of scope.
