# Suricata Sensor Steady-State Inventory

This directory is the SCN-010 / issue #345 inventory bundle for the TechVault
`suricata` container. It applies the ACES-owned asset inventory methodology to
the realized `aptl-suricata` container and uses the completed victim and
mailserver inventories as the granularity bar.

`suricata` is the **first passive network-sensor archetype** inventoried in
TechVault. Its defining behavior originally had no ACES surface and drove two
expressivity gaps (Brad-Edwards/aces#429, #430); both have since landed in ACES
dev (`runtime.network_sensors`, `runtime.network_detection_engines`), so every
catalogued observable — including the sensor posture and the IDS detection
engine — is now encoded in `scenarios/techvault.sdl.yaml` to the same depth as
the other inventories, with no remaining blocker.

The runtime/mount evidence in this bundle was recaptured after ADR-043
(issue #325) on a clean-rebuilt lab: two consecutive
`aptl lab stop -v && aptl lab start` cycles preceded the capture, so it reflects
the named-volume-seeded steady state rather than the pre-fix host-bind topology.
The image-level evidence (SBOM, vulnerability scan, image history) is
**carried forward from the prior capture** because the `jasonish/suricata:7.0`
image config ID is byte-identical (`sha256:66cbeff9c0db…`); only a trivy-DB
refresh would have churned the vuln counts, which is unrelated to this change.

The SDL encoding is authored into the decomposed TechVault module tree
(`scenarios/techvault/nodes/suricata.sdl.yaml` plus the `sections/*` and the
root `forwarding_agents`), reconciled to the ACES #458/#460 harmonized runtime
surfaces (`network_sensors`, `network_detection_engines`, `forwarding_agents`,
`techvault.*`-namespaced refs).

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-suricata` |
| Compose service | `suricata` |
| TechVault profile | `soc` |
| Source class | `upstream-image-plus-mounted-config` |
| Image | `jasonish/suricata:7.0` |
| Image digest (registry manifest list) | `jasonish/suricata@sha256:7b3fa735ba2bc7c1e3e764e6070c0a319935a737ca86e86e86d2640e408295fe` |
| Realized linux/amd64 platform manifest | `sha256:ec2c37d988f0b69fc2dc6cb6ffb4df1d8ae3fe7af63f4f22129df076ae272b9c` |
| Local image config ID | `sha256:66cbeff9c0dbf4b42d4344374c9df1fc0c254023c8ec53ed3feb7ffe815f2d1d` |
| Runtime OS | AlmaLinux 9.7 (Moss Jungle Cat) |
| Engine | Suricata 7.0.15 RELEASE |
| Capture mode | `--pcap` on `interface: any` |
| Runtime command | `suricata --user suricata --group suricata -c /etc/suricata/suricata.yaml --pcap` |
| Reachable participant ports | none — passive sensor, no listening TCP/UDP service |
| Control channel | unix command socket `/var/run/suricata/suricata-command.socket` |
| Network identity | `dmz-net` 172.20.1.50; `internal-net` 172.20.2.50; `security-net` 172.20.0.50 |
| Capabilities | NET_ADMIN, NET_RAW, SYS_NICE |
| App-layer parsers | http, tls, dns, ssh, smtp, ftp, smb |
| Rule sources | `suricata.rules` (65,814), `local.rules` (46), MISP `misp-iocs.rules` (6) |
| Package inventory | 191 rpm packages |
| Trivy vulnerability findings | 18 total: 8 high, 10 medium |
| Local identity | 18 users, 36 groups |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose service intent and upstream image identity are recorded. | `evidence/compose-service.suricata.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-buildx-imagetools.image.raw.json` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-dmz.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.suricata-logs.json`, `evidence/docker-volume.suricata-command-socket.json`, `evidence/docker-top.txt`, `evidence/docker-logs.suricata.txt`, `evidence/runtime-baseline.txt` |
| Suricata engine / sensor logical state is recorded. | `evidence/suricata-state.txt`, `evidence/participant-discovery.kali.txt`, `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| OS packages and SBOM component inventories are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is the upstream `jasonish/suricata:7.0` image. Its canonical
  registry digest (the multi-arch manifest-list digest from
  `docker buildx imagetools inspect`) is
  `sha256:7b3fa735ba2bc7c1e3e764e6070c0a319935a737ca86e86e86d2640e408295fe`; the
  realized linux/amd64 platform manifest is `sha256:ec2c37d988…` and the local
  image config ID is `sha256:66cbeff9c0db…` (these are distinct identities — the
  config ID is not the upstream registry digest).
  The APTL repo contributes the Compose service and the authored
  `config/suricata/suricata.yaml` + `config/suricata/rules/local.rules` — seeded
  into the `suricata_config_seed` named volume and staged into `/etc/suricata` by
  the ADR-043 wrapper entrypoint (issue #325), not bind-mounted — not the upstream
  Dockerfile.
- PID 1 is `suricata … --pcap`, dropped to the `suricata` user/group. The engine
  runs in **packet-capture (IDS) mode on `interface: any`** and is attached to
  the DMZ, internal, and security networks — it observes the traffic of all three.
- The sensor has **no listening TCP/UDP service of its own**; the only bound
  ports inside its network namespace are Docker's embedded resolver. Its sole
  control surface is the unix command socket
  `/var/run/suricata/suricata-command.socket`, shared with
  `aptl-misp-suricata-sync` for rule reloads.
- Live `fast.log` evidence shows active cross-network detection at snapshot time
  (ET CINS, Spamhaus DROP, and protocol-anomaly alerts on flows between other
  TechVault nodes), confirming the engine is inspecting traffic, not idle.
- App-layer parsers enabled: http, tls, dns, ssh, smtp, ftp, smb. Rule sources:
  `suricata.rules` (65,814 rules from `suricata-update`), authored `local.rules`
  (46), and MISP-driven `misp/misp-iocs.rules` (6, written by the sync service).
- `eve.json` was 486 MB at capture and `fast.log` continuously appended; both are
  unbounded transient sensor telemetry. They are recorded as filesystem metadata
  (size/owner/stability=`log`) only and are **not** content-checksummed.
- Trivy captured 18 vulnerability findings (8 high, 10 medium) against the
  AlmaLinux 9 base; vulnerability evidence is time-sensitive to the Trivy
  database and advisory feeds.

## ACES Mapping Result

Current ACES SDL encodes the cleanly-expressible suricata facts: node identity,
upstream image provenance, OS, network attachment to all three networks, runtime
mounts, container host/security configuration, NET_ADMIN/NET_RAW/SYS_NICE
capability posture, operational policy, process set, environment, filesystem
inventory (config + ruleset files, with the telemetry logs as metadata-only),
local identity database, package and vulnerability inventory, the Suricata
software-component identity, the **unix command socket** (as
`runtime.local_control_interfaces`), the **six APTL-authored config/ruleset
files** placed on the node (`suricata.yaml`, `local.rules`, and the four MISP
baselines under `config/suricata/rules/misp`) as `content.suricata-*` File
entries, and the eve.json log-forwarding relationship to the SOC Wazuh manager.

There are **no `accounts` entries**: APTL authors no account on this node. The
`suricata` service user (uid 998) is created by the upstream image build
(`useradd --system … suricata`), so it is captured as observed
`runtime.local_identity`, not as an authored account placement. Of the six
authored content files, five are placed verbatim (on-node checksums match the
repo source exactly); `misp-iocs.rules` is an authored seed that the
`aptl-misp-suricata-sync` service rewrites at runtime, so its content entry
records the authored seed and the realized on-node copy differs.

Two catalogued in-scope observables initially had **no ACES surface** and were
filed as expressivity gaps; both have since landed in ACES dev and are now
**encoded**:

- **Scenario-native network-sensor monitoring posture** — Suricata's passive
  `--pcap` capture across the networks it is attached to.
  [Brad-Edwards/aces#429](https://github.com/Brad-Edwards/aces/issues/429)
  (PR #435) added `runtime.network_sensors`; encoded as
  `nodes.suricata.runtime.network_sensors` (implementation `suricata`,
  monitoring_posture `passive`, capture_mode `pcap`, monitored_network_refs
  dmz/internal/security).
- **Typed IDS/NDR detection-engine service family** — the enabled app-layer
  parsers, rule sources, network zoning, and alert output streams.
  [Brad-Edwards/aces#430](https://github.com/Brad-Edwards/aces/issues/430)
  (PR #437/#438) added `runtime.network_detection_engines`; encoded as
  `nodes.suricata.runtime.network_detection_engines` (app_layer_protocols,
  rule_sources, network_sets, output_streams, unix-socket control channel).

No ACES expressivity blocker remains for the catalogued suricata steady-state
inventory. The capture does not assert a full root filesystem catalogue,
byte-identical rebuildability, attack-induced state changes, or a destructive
clean-lab reset.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/suricata
uv run aptl aces-inventory gaps docs/aces/inventory/suricata
```

## Known Limits

- The evidence came from a running lab (soc profile), not a destructive fresh
  reset.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- `eve.json` and `fast.log` are unbounded transient telemetry, recorded as
  filesystem metadata only, not content-checksummed.
- osquery `apt_sources` is not applicable (AlmaLinux 9 is rpm/dnf), and
  `installed_applications` / `programs` were unavailable in the Linux osquery
  table registry used by the digest-pinned osquery 4.9.0 scanner image.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
- The sensor monitoring posture and typed IDS/NDR detection engine were
  initially blocked on ACES #429/#430; both surfaces landed in ACES dev and are
  now encoded, so no ACES expressivity blocker remains.
