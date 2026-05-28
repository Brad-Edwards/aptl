# Victim Steady-State Inventory

This directory is the SCN-010 / issue #337 inventory bundle for the TechVault
`victim` container. It applies the ACES-owned asset inventory methodology
documented in
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>
to the realized `aptl-victim` container.

The capture is a non-destructive current-baseline observation from the
already-running local lab at `2026-05-28T06:10:02Z`. It did not run
`aptl lab stop -v && aptl lab start`; treat it as a frozen observation of the
local lab state, not as clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-victim` |
| Compose service | `victim` |
| TechVault profile | `victim` |
| Source class | `custom-build` |
| Source package | `containers/victim/`, `containers/base/scripts/`, `containers/base/falco_custom.yaml`, `keys/aptl_lab_key.pub`, `keys/authorized_keys` |
| Image tag | `aptl-victim:latest` |
| Image digest | `aptl-victim@sha256:6ff54c44fdc14d319c7df44e76db5363a440eddb3ee27dae638619daee22f310` |
| Runtime OS | Rocky Linux 9.7 (Blue Onyx) |
| Runtime command | `/usr/local/bin/entrypoint.sh` then `/usr/sbin/init` |
| Listener | SSH on `0.0.0.0:22` and `[::]:22`; rsyslog UDP listener on `0.0.0.0:33904` |
| Network identity | `aptl_aptl-internal` IPv4 `172.20.2.20` |
| Data volumes | `aptl_victim_logs:/var/log`, anonymous Docker volume at `/home` |
| Host mounts | `/sys/fs/cgroup` read-write, repo `keys/` mounted read-only at `/keys` |
| Privileged runtime surface | `CAP_SYS_ADMIN`, `CAP_SYS_NICE`, `CAP_SYS_RESOURCE`, `seccomp:unconfined`, host cgroup namespace |
| Active process set | `systemd`, `systemd-journald`, `rsyslogd`, `sshd` |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Docker Compose service intent is represented by the redacted Compose service slice. | `evidence/compose-service.victim.json` |
| Custom image identity, config, source inputs, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.victim-logs.json`, `evidence/docker-volume.victim-home.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| RPM repositories, packages, language/tool manifests, and SBOM component inventories are recorded. | `evidence/rpm-repositories.txt`, `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Catalogued filesystem paths, secret boundaries, and checksums are recorded. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt`, `evidence/filesystem-sensitive-paths.txt` |
| Systemd unit-file and selected runtime unit states are recorded. | `evidence/systemd-units.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or gap issues. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is a first-party custom build from
  `containers/victim/Dockerfile` using `rockylinux:9` as the mutable base tag.
  The observed local image digest is the reproducibility anchor.
- The container exposes SSH on port 22 inside the internal network only. No host
  ports are published.
- PID 1 is systemd. The observed steady-state process set is systemd,
  systemd-journald, rsyslogd, and sshd.
- The healthcheck is the Compose SSH listener probe
  `ss -tlnp | grep ':22' || exit 1`; Docker reported healthy with five recent
  successful log entries.
- The runtime host/security configuration is intentionally broad for the
  systemd-in-container victim: host cgroup namespace, read-write cgroup mount,
  unconfined seccomp, and `CAP_SYS_ADMIN`, `CAP_SYS_NICE`, and
  `CAP_SYS_RESOURCE`.
- `lab-install.service` failed while enabling Wazuh because
  `/usr/lib/systemd/systemd-sysv-install` was absent. `rsyslog.service`,
  `sshd.service`, and `systemd-journald.service` were active. The
  `systemd-tmpfiles-*` units failed with credentials setup errors.
- Wazuh and Falco packages/configuration are present. Their realized unit
  states are encoded through `nodes.victim.runtime.service_manager_units`.
- The committed SDL encodes 173 runtime filesystem entries,
  173 victim content entries, 19 host-local accounts,
  38 host-local groups, 1 NOPASSWD sudo rule,
  74 systemd service-manager unit records, 190 RPM
  packages, and 61 Trivy package findings.
- Trivy 0.70.0 reported 61 vulnerability findings at scan time:
  2 critical, 40 high,
  18 medium, and 1 low.
- osquery process and listener tables were captured from a scanner container
  sharing the victim PID and network namespaces. Docker container and image
  tables were captured through the host Docker socket. `apt_sources` is not
  applicable to Rocky Linux; Linux osquery 4.9.0 does not expose
  `installed_applications` or `programs` in this scanner image.
- The Syft CycloneDX SBOM is normalized by stripping `syft:location:*`
  properties; filesystem provenance remains captured by the tree and checksum
  evidence files. The Trivy and Syft CycloneDX SBOM files are deterministic
  gzip-compressed minified JSON to satisfy the repository added-file size gate;
  compression is lossless. The compressed SBOMs retain 513 Trivy
  components and 664 Syft components.
- Raw generated flags, private keys, and Wazuh agent key material are absent
  from committed evidence. The SDL records those surfaces through metadata,
  checksums where appropriate, sensitivity classification, and the
  passwordless-sudo scenario weakness ID.

## ACES Mapping Result

Current ACES SDL encodes the victim node identity, source image pin, Dockerfile
recipe, image layers, source inputs, network attachment, SSH service exposure,
healthcheck, full observed runtime mount table, catalogued runtime filesystem
inventory with metadata and digests, container host/security configuration,
primary process, process set, runtime environment, Linux capability policy,
restart/resource policy, package inventory, scanner findings, local Linux
identity database, sudo rule, systemd service-manager unit-file and runtime
lifecycle state, content entries, local account records, and relationship to
Wazuh.

No known ACES expressivity gap remains for the catalogued victim steady-state
inventory facts in this ledger, and the mapping ledger has no
`needs_gap_triage` entries.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/victim
aptl aces-inventory gaps docs/aces/inventory/victim
```

## Known Limits

- The evidence came from a running lab, not a clean reset. It is an observation
  of that realized lab state, not proof that a destructive
  `aptl lab stop -v && aptl lab start` reproduces the same state.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- Raw credential, key, and flag contents are intentionally absent from committed
  evidence.
- The `/keys/aptl_lab_key` operator private key is catalogued by path metadata
  only; its checksum is intentionally omitted.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
