# Reverse-Engineering Workbench Steady-State Inventory

This directory is the SCN-010 / issue #338 inventory bundle for the TechVault
`reverse` container. It applies the ACES-owned asset inventory methodology to
the realized `aptl-reverse` container at the established granularity bar (issue
#330 depth), following the victim/workstation target/systemd archetype
precedents.

`reverse` is the lab's **malware-analysis / reverse-engineering workbench**: a
custom Ubuntu 22.04 systemd container (profile `reverse`) running `sshd`
(published to the host as **2027 -> 22**), `rsyslog`, an in-process **Wazuh
agent** and **Falco** (modern eBPF), and a first-boot-installed toolchain
(**radare2** built from source, **YARA**, **UPX**, **osslsigncode**, **OpenJDK
17**, and pipx-installed **flare-floss** + **flare-capa**). It is inventoried as the participant node
`nodes.techvault.reverse`. Both log-forwarding paths (Wazuh agent + rsyslog)
are encoded as node-level `forwarding_agents`; the realized Wazuh edge is
`relationships.reverse-forwards-wazuh`.
**No known ACES expressivity gap remains** for the catalogued steady-state
facts.

This capture is non-destructive. It used the already-running local `aptl`
project (reverse profile) on 2026-06-10 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **Pre-existing boot defects fixed on this branch.** The `reverse` profile is
> rarely brought up, so three service-definition bugs had gone unnoticed and had
> to be fixed before the container would reach steady state: a missing
> `cgroup: host` (systemd needs the host cgroup namespace), a missing
> `/run/lock` tmpfs (Ubuntu systemd mounts a nested `/run/lock` that the
> AppArmor `docker-default` profile denies), and a `512m` memory limit that
> OOM-killed the first-boot radare2 source build (raised to `2g`). These are
> committed as separate `fix:` commits.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-reverse` |
| Compose service | `reverse` |
| TechVault profile | `reverse` |
| Family | target |
| Source class | `custom-build` |
| Image | `aptl-reverse:latest` (custom build from `containers/reverse/Dockerfile`) |
| Local image config ID | `aptl-reverse@sha256:37f8911050ec6224e435665152d07fd51ce2fb82d476c6d1798dbe4fa1af2f13` |
| Base image | `ubuntu:22.04` (shared APTL base layer) |
| Runtime OS | Ubuntu 22.04.5 LTS |
| Init | systemd (PID 1), `cgroup: host` |
| Analysis toolchain | radare2 (source build), YARA, UPX, osslsigncode, OpenJDK 17, pipx `flare-floss` 3.1.1 + `flare-capa` 9.4.0 — **first-boot, writable layer** |
| Agents | in-process Wazuh agent 4.12.0 + Falco (modern eBPF) + rsyslog forwarder |
| Reachable participant ports | SSH `22` (published to host `2027`); Falco gRPC `8765` (security-net only) |
| Network identity | `security-net` 172.20.0.27 (only network) |
| Capabilities | default Docker set **+ CAP_SYS_ADMIN / CAP_SYS_NICE / CAP_SYS_RESOURCE** (systemd), seccomp:unconfined |
| Memory limit | 2 GiB |
| Package inventory | 506 dpkg packages (running-container state) |
| Trivy vulnerability findings | 77 image-layer findings: 1 high, 37 medium, 39 low |
| Local identity | 27 users, 48 groups; labadmin has a NOPASSWD sudo grant |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose intent and local-build image identity are recorded. | `evidence/compose-service.reverse.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt`, `evidence/docker-buildx-imagetools.image.err` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.reverse_logs.json`, `evidence/docker-volume.reverse-home.json`, `evidence/docker-top.txt`, `evidence/docker-logs.reverse.txt`, `evidence/runtime-baseline.txt` |
| First-boot toolchain install is recorded. | `evidence/reverse-tools-state.txt`, `evidence/language-manifests.txt`, `evidence/systemd-units.txt` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt.gz`, `evidence/filesystem-checksums.txt.xz`, `evidence/filesystem-sensitive-paths.txt` |
| Wazuh agent + rsyslog forwarding state is recorded. | `evidence/wazuh-agent-state.txt`, `evidence/apt-repositories.txt` |
| Observer (manager) and attacker (kali) vantages are recorded. | `evidence/observer-discovery.wazuh-manager.txt`, `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; reverse profile must be up)
bash docs/aces/inventory/reverse/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/reverse
aptl aces-inventory gaps docs/aces/inventory/reverse

# Re-run the bundle's correspondence tests
pytest tests/test_reverse_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/reverse.sdl.yaml`; its bulk blocks (packages, CVEs,
filesystem, local identity, service-manager units) are derived directly from
the committed evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / capabilities / network / ssh / service-manager | `nodes.techvault.reverse` |
| Wazuh agent + rsyslog forwarding | `nodes.techvault.reverse.runtime.forwarding_agents` (`reverse-wazuh-agent`, `reverse-rsyslog-forwarder`) |
| Realized Wazuh forwarding edge | `relationships.reverse-forwards-wazuh` |
| Features / NOPASSWD-sudo weakness | `features.techvault.reverse-*`, `vulnerabilities.reverse-nopasswd-sudo` |
| Local accounts | `accounts.reverse-local-*` |

All 20 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- `docker buildx imagetools inspect` fails for the local-only image tag; image
  identity is the local config ID plus the build recipe.
- The reverse profile was started after fixing three pre-existing
  service-definition bugs (cgroup, /run/lock tmpfs, memory limit). The
  OOM-killed first boot left a stale Wazuh agent registration (id 008
  `reverse-host`, Disconnected); the active one is id 009 with a
  runtime-generated collision-suffixed name.
- The RE toolchain + Wazuh/Falco agents are first-boot writable-layer installs,
  so the image-layer scanners do not see them; runtime state is in
  `os-packages.txt` / `language-manifests.txt` / `reverse-tools-state.txt`.
- The FLARE Python tools are the correct pinned distributions `flare-floss`
  3.1.1 and `flare-capa` 9.4.0. This was **corrected in this PR** (SCN-010 #338):
  the initial capture found `setup-reverse-tools.sh` installing the bare PyPI
  `floss` (an unrelated academic fault-localization tool — analyzed as
  non-malicious: a pure-Python wheel with no install-time code) and `capa`
  unpinned. The script now installs the pinned `flare-floss`/`flare-capa` with
  loud failure handling, and this bundle was re-captured from the corrected box.
- The filesystem manifest excludes the radare2 source/build tree, pipx venv
  payloads, and `~/.cache` (toolchain payload evidenced by the package/SBOM
  surfaces).
- Scenario target secret files under `/keys`, `/etc/ssh`, and
  `/var/ossec/etc/client.keys` are captured verbatim in
  `filesystem-sensitive-paths.txt` and checksummed in
  `filesystem-checksums.txt.xz`.
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the workbench at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope.
- The Wazuh agent registration name is runtime-generated, so the manager-side
  `agents[]` enumeration is intentionally not extended for this node; the
  forwarding is captured by the node `forwarding_agents` + the
  `reverse-forwards-wazuh` relationship.
