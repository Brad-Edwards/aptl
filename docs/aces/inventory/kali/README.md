# Kali Container Steady-State Inventory

This directory is the SCN-010 / issue #339 inventory bundle for the TechVault
`kali` red-team container. It applies the methodology in
`docs/aces/inventory/asset-inventory-methodology.md` to the realized
`aptl-kali` container and is bound by the architecture preflight in
`docs/aces/inventory/kali-preflight.md`.

The `kali` service image was rebuilt from current `containers/kali/` source
and the `aptl-kali` container recreated from that image immediately before
capture, so the realized container matches HEAD source. The capture otherwise
used the already-running local lab: it did **not run `aptl lab stop -v &&
aptl lab start`**, because that would destroy the user's current lab state.
Treat this as a frozen steady-state artifact for the observed container, not a
clean-lab rebuild proof and not a byte-identical rebuildability proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-kali` |
| Compose service | `kali` (Docker Compose service, profile `kali`) |
| Family | attacker / red team |
| Source class | `custom-build` |
| Source package | `containers/kali/` |
| Image tag | `aptl-kali:latest` |
| Image digest | `aptl-kali@sha256:f524320106669c6885679587510652c8a78ca1961b7545692f0fa8f4695974b9` |
| Base image | `kalilinux/kali-last-release:latest` (mutable upstream tag) |
| Runtime OS | Kali GNU/Linux Rolling 2026.1 (`kali-rolling`) |
| Entrypoint | `/entrypoint.sh` under `/sbin/docker-init` (PID 1) |
| Working directory | `/home/kali` |
| Listener | `0.0.0.0:22` / `[::]:22` (OpenSSH), no host port published |
| Network identity | `aptl_aptl-redteam` 172.20.4.30; `aptl_aptl-dmz` 172.20.1.30; `aptl_aptl-internal` 172.20.2.35 |
| Data volumes | `aptl_kali_operations:/home/kali/operations`, `aptl_kali_captures:/var/log/aptl/captures` |
| Privileged runtime surface | `CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PACCT`; `seccomp:unconfined`; `init: true` |
| Steady-state processes | `docker-init`, the entrypoint keepalive (`sleep infinity`), `sshd` listener |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/grype-version.txt` |
| Docker Compose service intent is represented by the redacted Compose service slice. | `evidence/compose-service.kali.json` |
| Custom image identity, config, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt` |
| Source package inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-redteam.json`, `evidence/docker-network.aptl-dmz.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.kali-operations.json`, `evidence/docker-volume.kali-captures.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages and language manifests visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/trivy-os-packages.json`, `evidence/language-manifests.txt` |
| Patch state is machine-readable. | `evidence/grype-vulnerability-counts.json`, `evidence/grype-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| Catalogued filesystem paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or gap issues. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is a first-party custom build from
  `containers/kali/Dockerfile` on the mutable base tag
  `kalilinux/kali-last-release:latest`. The observed local image digest is the
  reproducibility anchor for this capture.
- PID 1 is `/sbin/docker-init` (Docker's bundled init / tini), enabled by
  Compose `init: true`; the entrypoint keepalive and `sshd` are its children.
- The container exposes OpenSSH on `22/tcp` bound to all interfaces inside the
  container, with **no host port published** — the control plane reaches kali
  by container IP.
- sshd is wired for OBS-003 per-session capture: `Match User kali` sets
  `ForceCommand /usr/local/bin/aptl-wrap-shell.sh`, and `AcceptEnv` admits the
  `APTL_SESSION_ID` / `APTL_RUN_ID` / `APTL_TRACE_ID` scenario identifiers.
- The container holds `CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`, `CAP_NET_ADMIN`,
  `CAP_NET_RAW`, and `CAP_SYS_PACCT`, runs `seccomp:unconfined`, and the
  entrypoint drops `CAP_AUDIT_CONTROL` from the sshd subtree via
  `capsh --drop=cap_audit_control`.
- The container is **healthy but capture-degraded**: the readiness marker
  `/run/aptl-kali-ready` records `sshd=ok`, `wrapper=ok`, `procacct=ok`, and
  `auditd=degraded` — auditd is installed and the ruleset is loaded by the
  entrypoint, but the kernel audit netlink interface is not fully available to
  the container, so `auditctl -l` returns no rules at steady state.
- The image contains 947 dpkg OS packages: `kali-linux-core`,
  `kali-tools-top10`, the AD/enterprise attack toolset (impacket, ldap-utils,
  smbclient, smbmap, enum4linux, bloodhound.py), the OBS-003 capture packages
  (auditd, acct, tcpdump, bsdmainutils, libcap2-bin, acl), `openssh-server`,
  and `nodejs`.
- **Trivy 0.70.0 reported 0 OS-package vulnerabilities**: it detects the image
  as `debian/kali-rolling` and enumerates 947 packages, but has no advisory
  database for the rolling `kali-rolling` release. The patch-state inventory
  therefore uses **Grype 0.112.0** as the primary scanner, which reported 58
  findings (1 critical, 12 high, 26 medium, 19 low). Trivy's 0-finding result
  and package enumeration are retained as cross-check evidence.

## ACES Mapping Result

Current ACES SDL encodes the kali node's identity, source image pin and build
provenance, OS, network attachment and Docker network realization, SSH service
exposure, healthcheck condition, observed runtime mount table, catalogued
runtime filesystem inventory with metadata and digests, primary process and
process set, observed runtime environment, container-wide Linux capability
policy with a subtree-scoped capsh override, restart/resource policy,
container host/security configuration including the Docker `init` PID-1
reaper, seccomp/security_opt posture, and the nine static `extra_hosts`
entries, full dpkg package inventory, Grype scanner findings, full local
identity database, local account records, and the OBS-003 sshd
ForceCommand/AcceptEnv policy in `scenarios/techvault.sdl.yaml`. Kali is the
scenario attacker node and carries no authored scenario weaknesses.

The four ACES expressivity surfaces filed against this inventory landed on
`Brad-Edwards/aces` dev and are now consumed by the kali node:

- ACES #384 / ADR-027 — `runtime.container.init_process` (Docker `init` /
  PID-1 reaper).
- ACES #385 / ADR-028 — `runtime.container.seccomp_profile` and
  `runtime.container.security_opt` (seccomp posture).
- ACES #386 / ADR-030 — `runtime.linux_capabilities.process_overrides`
  (the capsh subtree-scoped `CAP_AUDIT_CONTROL` drop on sshd).
- ACES #387 / ADR-031 — `runtime.ssh_servers` (typed sshd policy carrying
  `ForceCommand`, `AcceptEnv`, `Match` rules, `AllowUsers`).

No known ACES expressivity blocker remains for the catalogued kali
steady-state inventory.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/kali
aptl aces-inventory gaps docs/aces/inventory/kali
```

## Known Limits

- The evidence came from a running lab (with the kali image rebuilt and the
  container recreated from current source), not a destructive clean reset. It
  is a frozen observation of that realized container, not proof that
  `aptl lab stop -v && aptl lab start` reproduces the same state.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- The filesystem inventory intentionally catalogues the APTL-authored/custom
  and scenario-relevant runtime paths. A full Kali tool root filesystem
  enumeration is a deferred capture-scope decision, not blocked by ACES
  expressivity.
- The image is a first-party local build; the BuildKit build emitted SBOM and
  provenance attestation manifests into the local image store, but they are
  not registry-published and were not independently verified.
- Vulnerability results are time-sensitive to the Grype and Trivy databases
  and advisory feeds.
- The `kali_captures` and `kali_operations` named volumes and the
  `/host-ssh-keys` operator bind mount are recorded by mount metadata only;
  their contents are out of scope for this committed bundle per ADR-033 and
  ADR-029.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
