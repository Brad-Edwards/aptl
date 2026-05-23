# AD Steady-State Inventory

This directory is the SCN-010 / issue #332 inventory bundle for the TechVault
`ad` container. It applies the methodology in
`docs/aces/inventory/asset-inventory-methodology.md` to the realized
`aptl-ad` Samba Active Directory Domain Controller.

The capture used a fresh local lab on 2026-05-23 after
`uv run aptl lab stop -v -y && uv run aptl lab start --skip-seed` completed and
`aptl-ad` reached healthy steady state. Treat this as a frozen post-start
steady-state artifact for the observed lab instance, not as byte-identical
rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-ad` |
| Compose service | `ad` |
| TechVault profile | `enterprise` |
| Source class | `custom-build` |
| Source package | `containers/ad/` plus `containers/_wazuh-agent/` |
| Image tag | `aptl-ad:latest` |
| Image digest | `aptl-ad@sha256:5806c59b401c045391be53c0d3e0c4feb6304030e716ff3b12b79415fbb1b052` |
| Runtime OS | Ubuntu 22.04.5 LTS |
| Samba version | 4.15.13-Ubuntu |
| Runtime command | `/usr/bin/python3 /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf` |
| Domain | `TECHVAULT` / `TECHVAULT.LOCAL` (`techvault.local`) |
| Listener set | DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, LDAPS, Global Catalog |
| Network identity | `aptl_aptl-internal` IPv4 `172.20.2.10` |
| Data volumes | `aptl_ad_data:/var/lib/samba`, `aptl_ad_logs:/var/log/samba` |
| Privileged runtime surface | `CAP_SYS_ADMIN` and `CAP_NET_ADMIN` |
| Supervised programs | `samba`, `rsyslog`, in-process Wazuh agent |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt` |
| Docker Compose service intent is represented by the redacted Compose service slice. | `evidence/compose-service.ad.json` |
| Custom image identity, config, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt` |
| Source package inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.ad-data.json`, `evidence/docker-volume.ad-logs.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages and language/tool manifests visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt` |
| Patch state is machine-readable. | `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| Catalogued Samba, supervisor, Wazuh, flag, and generated runtime paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or explicit claim boundaries. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is a first-party custom build from
  `containers/ad/Dockerfile`, with Wazuh agent support copied from
  `containers/_wazuh-agent/`.
- The image uses Ubuntu 22.04 and Samba 4.15.13-Ubuntu. The observed local image
  digest is the reproducibility anchor for this capture.
- Samba provisions the `techvault.local` forest/domain at Windows 2008 R2
  functional level, with account lockout threshold 10, duration 30 minutes,
  and reset-after 15 minutes.
- The domain contains 15 users and 45 groups at capture time. Scenario users,
  service accounts, SPNs, high-risk group memberships, and password policy are
  recorded in the runtime baseline and encoded in the SDL without raw
  passwords.
- The service exposes DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, LDAPS, Global
  Catalog, and dynamic RPC listener surfaces inside the internal network. No
  host ports are published.
- The named volumes `aptl_ad_data` and `aptl_ad_logs` are mounted at
  `/var/lib/samba` and `/var/log/samba`.
- PID 1 is `supervisord`, supervising Samba, rsyslog, and the in-process Wazuh
  agent. The Wazuh agent tails Samba logs and registers as `aptl-ad-agent`.
- Trivy 0.70.0 reported 140 package vulnerability findings at scan time:
  65 medium and 75 low.
- Secret-shaped values in Docker/Compose evidence were redacted before
  committing the bundle. The SDL records only secret classes and scenario
  weakness intent, not raw AD passwords, generated flags, Wazuh keys, or
  Kerberos/Samba secret material.

## ACES Mapping Result

Current ACES SDL encodes the AD node identity, custom image pin, build recipe,
source inputs, network attachment, service exposure, healthcheck, runtime
mounts, selected filesystem inventory with metadata and digests, container
host/security configuration, process set, runtime environment, capabilities,
restart/resource policy, package and scanner inventory summaries, Samba domain
logical state, scenario weakness IDs, content entries, local/domain account
records, and relationships to DNS forwarding and Wazuh telemetry.

No known ACES expressivity gap remains for the catalogued AD steady-state
inventory facts in this ledger. Full raw Samba private database content,
Kerberos key material, Wazuh `client.keys`, generated flags, and raw password
values are redacted as secret material; their observable path/metadata/checksum
shape is recorded where useful.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/ad
aptl aces-inventory gaps docs/aces/inventory/ad
```

## Known Limits

- The inventory is a frozen steady-state observation, not byte-identical
  rebuild proof.
- Generated Samba databases, Kerberos keys, Wazuh enrollment material, and CTF
  flag files can change on a fresh reprovision. Checksums are snapshot facts.
- Raw credential, key, and flag contents are intentionally absent from committed
  evidence.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
