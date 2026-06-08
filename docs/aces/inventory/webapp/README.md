# Webapp Steady-State Inventory

This directory is the SCN-010 / issue #330 inventory bundle for the TechVault
`webapp` container. It applies the ACES-owned asset inventory methodology
documented in
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>
to the realized `aptl-webapp` container.

APTL #368 replaces the earlier webapp inventory bundle with a single
non-destructive current-baseline capture from the already-running local lab on
2026-05-25. It did not run `aptl lab stop -v && aptl lab start`; in other
words, this bundle does not destroy the user's current lab state. Treat this as
a reproducible capture of the observed local lab, not as a clean-lab rebuild
proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-webapp` |
| Compose service | `webapp` |
| TechVault profile | `enterprise` |
| Source class | `custom-build` |
| Source package | `containers/webapp/` plus `containers/_wazuh-agent/` |
| Image tag | `aptl-webapp:latest` |
| Image digest | `aptl-webapp@sha256:4a179c1043213c1cfed182c8e472dbe97b07a58f512067ec0c0ea3642425704a` |
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
| Capture commands are reproducible. | `capture-evidence.sh` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Docker Compose service intent is represented by the redacted Compose service slice. | `evidence/compose-service.webapp.json` |
| Custom image identity, config, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt` |
| Source package inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-dmz.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.webapp-logs.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages, language manifests, and SBOM component inventories visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json`, `evidence/syft-sbom.cyclonedx.json` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Catalogued filesystem paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
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
- The Trivy evidence captured 299 package vulnerability findings at scan time:
  6 critical, 32 high, 99 medium, 158 low, and 4 unknown.
- The APTL #368 capture includes Trivy and Syft CycloneDX SBOMs against the
  current local `aptl-webapp:latest` image. The Syft file is a
  package/component-scope CycloneDX JSON SBOM with `syft:location:*`
  properties stripped by `capture-evidence.sh` so it stays within the
  repository's evidence size gate. The stripped properties are file-location
  provenance, not component identity; filesystem provenance remains covered by
  `evidence/filesystem-tree.txt` and `evidence/filesystem-checksums.txt`.
- osquery process and listener tables were captured from a scanner container
  sharing the webapp PID and network namespaces. Docker container and image
  tables were captured through the host Docker socket. Linux osquery 4.9.0 does
  not expose `installed_applications` or `programs`; those table attempts are
  recorded as unavailable in per-table evidence and `capture-limits.txt`.
- Secret-shaped env-var values in Docker/Compose evidence were redacted before
  committing the bundle. The webapp intentionally contains participant-visible
  fixture secrets in checked-in source and runtime endpoints; those are scenario
  facts, not operator-control-plane secrets.

## ACES Mapping Result

Current ACES SDL encodes the webapp's node identity, source image pin,
network links, service exposure, healthcheck, full observed runtime mount table,
catalogued runtime filesystem inventory with metadata and digests, container
host/security configuration, health observation logs, primary process,
supervised process set, observed runtime environment, Linux capabilities,
restart/resource policy, package inventory, scanner findings, scenario weakness
IDs, relationships, ACES-content entries for source placement, full local
identity database records for the observed `/etc/passwd` and `/etc/group`
surfaces, Docker network realization metadata, Flask HTTP route/API/UI
inventory, and local account records for the observed `/etc/passwd` users in
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
fields, group records, and sudo-rule inventory. ACES #366 is closed and covers
Docker network aliases, endpoint IDs, MACs, DNS names, host-published port
bindings, backend network IDs, and bridge/IPAM realization details. ACES #367
is closed and covers application HTTP route/API/UI inventory: paths, methods,
auth/session boundaries, request inputs, responses, redirects, disclosures,
template/static associations, exposed fields, and route-specific vulnerability
placement. ACES #368 is closed and covers container HostConfig,
namespace/security settings, health logs, and full mount filesystem facts. Those
fields are now used by the TechVault SDL.

No known ACES expressivity gap remains for the catalogued webapp steady-state
inventory facts in this ledger. Full root filesystem cataloguing is not blocked
by ACES expressivity; it is a deferred capture/cataloguing scope decision.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/webapp
aptl aces-inventory gaps docs/aces/inventory/webapp
```

## Known Limits

- The evidence came from a running lab, not a clean reset. It is an observation
  of that realized lab state, not proof that a destructive
  `aptl lab stop -v && aptl lab start` reproduces the same state.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- The filesystem inventory intentionally catalogs the authored/custom and
  scenario-relevant runtime paths needed for this high-specificity webapp host
  spec. ACES can express a complete root filesystem inventory if a later issue
  chooses to capture and encode it.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- The ACES SDL records the captured package and scanner inventories from this
  evidence bundle. Vulnerability records remain time-sensitive to the Trivy
  database and advisory feeds.
- The APTL #368 capture is a non-destructive methodology baseline capture, not
  a byte-identical rebuild proof.
- osquery `installed_applications` and `programs` were unavailable in the
  Linux osquery table registry used by the digest-pinned osquery 4.9.0 scanner
  image.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
- Observable steady-state fields that ACES could not express during this pass
  were tracked as blocking ACES issues and have now been consumed in the SDL.
