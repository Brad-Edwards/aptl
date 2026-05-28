# Fileshare Steady-State Inventory

This directory is the SCN-010 / issue #333 inventory bundle for the TechVault
`fileshare` container. It applies the ACES-owned asset inventory methodology to
the realized `aptl-fileshare` container and uses the `webapp` inventory as the
granularity bar.

This capture is non-destructive. It used the already-running local
`aptl-fileshare` container on 2026-05-26 and did not run
`aptl lab stop -v && aptl lab start`. Treat this bundle as a frozen observation
of that local steady state, not as clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-fileshare` |
| Compose service | `fileshare` |
| TechVault profile | `fileshare` |
| Source class | `custom-build` |
| Source package | `containers/fileshare/` plus `containers/_wazuh-agent/` |
| Image tag | `aptl-fileshare:latest` |
| Image digest | `aptl-fileshare@sha256:4defa1d902153bd9a4c552adbf0763a5b9fa48a6bc99acad2df6c4a2fe4c7c59` |
| Runtime OS | Ubuntu 22.04.5 LTS (Jammy Jellyfish) |
| Runtime command | `/usr/bin/python3 /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf` |
| Listener | `0.0.0.0:139`, `0.0.0.0:445`, `:::139`, `:::445` |
| Network identity | `aptl_aptl-internal` IPv4 `172.20.2.12` |
| Data volumes | `aptl_fileshare_data:/srv/shares`, `aptl_fileshare_logs:/var/log/samba` |
| Privileged runtime surface | `CAP_NET_ADMIN` for in-process Wazuh active response |
| Supervised programs | `rsyslog`, `samba`, in-process Wazuh agent |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose service intent is represented by the redacted service slice. | `evidence/compose-service.fileshare.json` |
| Custom image identity, config, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl` |
| Source package inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.fileshare-data.json`, `evidence/docker-volume.fileshare-logs.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages and SBOM component inventories are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json`, `evidence/syft-sbom.cyclonedx.json` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Filesystem and share paths are hashable without committing generated secret contents. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt`, `evidence/share-tree.txt`, `evidence/share-checksums.txt` |
| SMB access behavior is captured from inside the container. | `evidence/smbclient-anonymous-probes.txt`, `evidence/smbclient-svc-fileshare-probes.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is a first-party custom build from
  `containers/fileshare/Dockerfile`, with Wazuh agent support copied from
  `containers/_wazuh-agent/`.
- The image uses `ubuntu:22.04` lineage and the observed local image digest is
  the reproducibility anchor for this capture.
- The fileshare exposes SMB/NetBIOS on TCP 139 and 445 inside the container,
  with no host-published ports.
- The service runs as root under `supervisord`. The load-bearing child process
  set includes `rsyslogd`, `smbd`, Samba helper processes, and the in-process
  Wazuh agent process family.
- The named volume `aptl_fileshare_data` is mounted at `/srv/shares` and
  contains the Public, Engineering, Finance, HR, IT-Backups, and Shared share
  trees. The named volume `aptl_fileshare_logs` is mounted at `/var/log/samba`.
- Anonymous SMB access lists Public and Shared. Anonymous access to
  Engineering, Finance, HR, and IT-Backups returns `NT_STATUS_ACCESS_DENIED`.
- The `svc-fileshare` Samba account is present, but the captured probe shows it
  still cannot list Engineering because no local `Engineering` group membership
  exists in the standalone Samba container.
- `setup-shares.sh` attempts to generate
  `/srv/shares/it-backups/keys/deploy_key`, but the observed runtime state does
  not contain `deploy_key` or `deploy_key.pub`. The likely realized cause is
  that `ssh-keygen` is not available in the image; the bundle records the
  absence rather than treating authored intent as runtime fact.
- The Trivy evidence captured 120 package vulnerability findings at scan time:
  52 medium and 68 low.
- Syft CycloneDX output is normalized by `normalize-syft-cyclonedx.jq` to strip
  `syft:location:*` properties only. Filesystem provenance is retained through
  `filesystem-tree.txt`, `filesystem-checksums.txt`, `share-tree.txt`, and
  `share-checksums.txt`.
- Linux osquery 4.9.0 does not expose `installed_applications` or `programs`;
  those table attempts are recorded as unavailable in per-table evidence and
  `capture-limits.txt`.

## ACES Mapping Result

Current ACES SDL can encode the catalogued fileshare facts: node identity,
source image pin, build provenance, network link, SMB service exposure,
healthcheck, runtime mount table, container host/security configuration, health
logs, primary and supervised processes, runtime environment, Linux capability,
restart/resource policy, package inventory, scanner findings, share filesystem
inventory, typed SMB file-service share configuration/access behavior,
service-local Samba principal records, local identity database, and log/Wazuh
relationships.

No known ACES expressivity gap remains for the catalogued fileshare
steady-state inventory facts in this ledger. The capture does not assert a full
root filesystem catalogue, byte-identical rebuildability, attack-induced state
changes, or a destructive clean-lab reset.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/fileshare
uv run aptl aces-inventory gaps docs/aces/inventory/fileshare
```

## Known Limits

- The evidence came from a running lab, not a destructive fresh reset.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- Generated flag contents and generated SSH private-key material are not
  committed. Their paths, permissions, sizes, and SHA-256 digests or absence
  are recorded instead.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- osquery `installed_applications` and `programs` were unavailable in the
  Linux osquery table registry used by the digest-pinned osquery 4.9.0 scanner
  image.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
